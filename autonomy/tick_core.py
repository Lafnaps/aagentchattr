"""Crash-recoverable planning and ordered execution for one supervisor tick.

The planner is policy only: it reads evidence through an injected adapter and
returns a declarative :class:`TickPlan`.  The small production execution
helper invokes an injected command boundary; neither layer directly knows
about the filesystem, queue, scheduler, process tree, or reporter.

Launch is intentionally split across durable, replayable boundaries::

    PREPARED
      -> PersistLaunchIntent
    LAUNCH_INTENT
      -> ClaimPrepared (exact compare-and-swap; never "first queued task")
    DISPATCH_READY
      -> DispatchAttempt (idempotent)
    RUN_REQUESTED
      -> DispatchAttempt until a nonce-bound RunnerStarted marker exists
    RUNNER_STARTED
      -> the per-attempt owner publishes JobAssigned while the child is suspended
    JOB_ASSIGNED
      -> the per-attempt owner resumes the child and publishes Running evidence
    RUNNING
      -> PersistStopPending when policy requests a stop
    STOP_PENDING
      -> the per-attempt owner stops its Job and proves quiescence
    QUIESCENT
      -> await an exact owner result, then perform the terminal queue transition

The coordinator never owns a Job handle.  Consequently it never marks an
attempt running, requests process termination, or attests quiescence.  Those
are durable facts written by the long-lived per-attempt owner.  If that owner
misses its evidence-supplied deadline, the only safe policy action is a global
HALT; the attempt is never retried from ambiguous process state.

Every command names the exact task, attempt, nonce, expected prior phase and
queue-card digest.  An executor MUST execute commands in plan order, abort on
the first failure, and never execute later commands from a failed plan.  The
planner emits at most one command per task in a tick.  Reporting is supplied
as inert notices and cannot influence decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Protocol, TypeAlias, runtime_checkable

from autonomy.supervisor import (
    Action,
    Cause,
    PolicyError,
    StopPending,
    TaskSnapshot,
    decide_after_stop,
    decide_task,
)


__all__ = [
    "AttemptEvidence",
    "AttemptBoundCommand",
    "AttemptOutcome",
    "AttemptPhase",
    "AttemptRef",
    "AuditEvidence",
    "AuditStatus",
    "BlockAttempt",
    "ClaimPrepared",
    "CommandExecutor",
    "CommandRefusedError",
    "Command",
    "CompleteAttempt",
    "DispatchAttempt",
    "EvidenceIssue",
    "ExpectedFailDisposition",
    "FailAttempt",
    "HaltReason",
    "InProgressAttemptEvidence",
    "IntegerNsClock",
    "ExactAttemptResult",
    "JobAssigned",
    "NonceStopPending",
    "QuiescentEvidence",
    "PersistLaunchIntent",
    "PersistStopPending",
    "PlanState",
    "PreparedCandidate",
    "ReportCode",
    "ReportNotice",
    "ReporterAdapter",
    "RunningEvidence",
    "RunnerStarted",
    "TickCoreError",
    "TickEvidenceAdapter",
    "TickPlan",
    "UnreadableAttemptEvidence",
    "WriteHalt",
    "build_tick_plan",
    "execute_tick_plan",
]


_TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_OWNER_TOKEN_RE = _NONCE_RE
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DWORD_MAX = (1 << 32) - 1
_JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
_JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_BREAKAWAY_FLAGS = (
    _JOB_OBJECT_LIMIT_BREAKAWAY_OK | _JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
)


class TickCoreError(ValueError):
    """An orchestration value is ambiguous, inconsistent, or unsafe."""


class AuditStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"


class AttemptPhase(str, Enum):
    PREPARED = "prepared"
    LAUNCH_INTENT = "launch_intent"
    DISPATCH_READY = "dispatch_ready"
    RUN_REQUESTED = "run_requested"
    RUNNER_STARTED = "runner_started"
    JOB_ASSIGNED = "job_assigned"
    RUNNING = "running"
    STOP_PENDING = "stop_pending"
    QUIESCENT = "quiescent"


class AttemptOutcome(str, Enum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class EvidenceIssue(str, Enum):
    UNKNOWN = "unknown"
    CORRUPT = "corrupt"


class ExpectedFailDisposition(str, Enum):
    """Expected result of queue ``fail``; operator requeue is never used."""

    RETRY_QUEUE = "retry_queue"
    FAILED = "failed"


class HaltReason(str, Enum):
    CLOCK_READ_FAILED = "clock-read-failed"
    CLOCK_INVALID = "clock-invalid"
    AUDIT_READ_FAILED = "audit-read-failed"
    AUDIT_INVALID = "audit-invalid"
    AUDIT_FAILED = "audit-failed"
    EVIDENCE_READ_FAILED = "evidence-read-failed"
    EVIDENCE_INVALID = "evidence-invalid"
    EVIDENCE_UNKNOWN = "evidence-unknown"
    EVIDENCE_CORRUPT = "evidence-corrupt"
    OWNER_UNRESPONSIVE = "owner-unresponsive"
    CANDIDATE_READ_FAILED = "candidate-read-failed"
    CANDIDATE_INVALID = "candidate-invalid"


class PlanState(str, Enum):
    RUNNING = "running"
    HALTED = "halted"


class ReportCode(str, Enum):
    HALT_PLANNED = "halt-planned"
    HALT_ACTIVE = "halt-active"
    RECONCILE = "reconcile"
    LAUNCH_PREPARED = "launch-prepared"


def _exact_int(
    value: object,
    code: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if (
        type(value) is not int
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        raise TickCoreError(code)
    return value


def _task_id(value: object) -> str:
    if type(value) is not str or not _TASK_ID_RE.fullmatch(value):
        raise TickCoreError("task-id-invalid")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _SHA256_RE.fullmatch(value):
        raise TickCoreError("card-sha256-invalid")
    return value


def _owner_token(value: object) -> str:
    if type(value) is not str or not _OWNER_TOKEN_RE.fullmatch(value):
        raise TickCoreError("owner-token-invalid")
    return value


@dataclass(frozen=True, slots=True, order=True)
class AttemptRef:
    task_id: str
    attempt: int
    nonce: str

    def __post_init__(self) -> None:
        _task_id(self.task_id)
        if type(self.attempt) is not int or not 1 <= self.attempt <= 2:
            raise TickCoreError("attempt-invalid")
        if type(self.nonce) is not str or not _NONCE_RE.fullmatch(self.nonce):
            raise TickCoreError("nonce-invalid")


@dataclass(frozen=True, slots=True)
class AuditEvidence:
    status: AuditStatus
    halt_active: bool

    def __post_init__(self) -> None:
        if type(self.status) is not AuditStatus:
            raise TickCoreError("audit-status-invalid")
        if type(self.halt_active) is not bool:
            raise TickCoreError("halt-active-invalid")


@dataclass(frozen=True, slots=True)
class PreparedCandidate:
    """Exact queue card prepared for a nonce-bound launch transaction."""

    ref: AttemptRef
    card_sha256: str
    phase: AttemptPhase = AttemptPhase.PREPARED

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("candidate-ref-invalid")
        _digest(self.card_sha256)
        if self.phase is not AttemptPhase.PREPARED:
            raise TickCoreError("candidate-phase-invalid")


@dataclass(frozen=True, slots=True)
class NonceStopPending:
    """Durable stop trigger bound to the full attempt identity, including nonce.

    Only the coordinator writes this request, and only the matching long-lived
    owner acts on it.  Exact terminal results do not create stop requests: the
    owner publishes them only after quiescence has already been proved.
    """

    ref: AttemptRef
    owner_token: str
    cause: Cause
    detected_ns: int

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("stop-pending-ref-invalid")
        _owner_token(self.owner_token)
        if type(self.cause) is not Cause or self.cause not in (
            Cause.HEARTBEAT_STALE,
            Cause.PROGRESS_STALE,
        ):
            raise TickCoreError("stop-pending-cause-invalid")
        _exact_int(self.detected_ns, "stop-pending-time-invalid")

    def to_policy_pending(self, expected_ref: AttemptRef) -> StopPending:
        if type(expected_ref) is not AttemptRef or expected_ref != self.ref:
            raise TickCoreError("stop-pending-binding-mismatch")
        return StopPending(
            task_id=self.ref.task_id,
            attempt=self.ref.attempt,
            cause=self.cause,
            detected_ns=self.detected_ns,
        )


@dataclass(frozen=True, slots=True)
class RunnerStarted:
    """Durable election of the one process allowed to own this attempt."""

    ref: AttemptRef
    owner_token: str
    owner_pid: int
    started_ns: int

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("runner-started-ref-invalid")
        _owner_token(self.owner_token)
        _exact_int(
            self.owner_pid,
            "runner-started-pid-invalid",
            minimum=1,
            maximum=_DWORD_MAX,
        )
        _exact_int(self.started_ns, "runner-started-time-invalid")


@dataclass(frozen=True, slots=True)
class JobAssigned:
    """Pre-resume proof that the suspended child is in the owner's Job."""

    ref: AttemptRef
    owner_token: str
    payload_pid: int
    job_limit_flags: int
    assigned_ns: int

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("job-assigned-ref-invalid")
        _owner_token(self.owner_token)
        _exact_int(
            self.payload_pid,
            "job-assigned-pid-invalid",
            minimum=1,
            maximum=_DWORD_MAX,
        )
        flags = _exact_int(
            self.job_limit_flags,
            "job-assigned-flags-invalid",
            maximum=_DWORD_MAX,
        )
        if not flags & _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:
            raise TickCoreError("job-assigned-kill-on-close-missing")
        if flags & _JOB_OBJECT_BREAKAWAY_FLAGS:
            raise TickCoreError("job-assigned-breakaway-enabled")
        _exact_int(self.assigned_ns, "job-assigned-time-invalid")


@dataclass(frozen=True, slots=True)
class RunningEvidence:
    """Owner-written proof that resume succeeded and ownership was retained."""

    ref: AttemptRef
    owner_token: str
    confirmed_ns: int

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("running-ref-invalid")
        _owner_token(self.owner_token)
        _exact_int(self.confirmed_ns, "running-time-invalid")


@dataclass(frozen=True, slots=True)
class QuiescentEvidence:
    """Owner-written proof that its whole Job tree is quiescent."""

    ref: AttemptRef
    owner_token: str
    verified_ns: int

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("quiescent-ref-invalid")
        _owner_token(self.owner_token)
        _exact_int(self.verified_ns, "quiescent-time-invalid")


@dataclass(frozen=True, slots=True)
class ExactAttemptResult:
    """Exact primary-process Win32 exit result, published after quiescence."""

    ref: AttemptRef
    owner_token: str
    exit_code: int
    outcome: AttemptOutcome
    observed_ns: int

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("attempt-result-ref-invalid")
        _owner_token(self.owner_token)
        exit_code = _exact_int(
            self.exit_code,
            "attempt-result-exit-code-invalid",
            maximum=_DWORD_MAX,
        )
        if type(self.outcome) is not AttemptOutcome or self.outcome not in (
            AttemptOutcome.SUCCEEDED,
            AttemptOutcome.FAILED,
        ):
            raise TickCoreError("attempt-result-outcome-invalid")
        if (exit_code == 0) is not (self.outcome is AttemptOutcome.SUCCEEDED):
            raise TickCoreError("attempt-result-exit-outcome-mismatch")
        _exact_int(self.observed_ns, "attempt-result-time-invalid")


@dataclass(frozen=True, slots=True)
class InProgressAttemptEvidence:
    """One recoverable launch/run state reconstructed from durable evidence.

    Phase-specific closed-schema rules prevent an executor from silently
    skipping a crash boundary.  Owner-written markers carry one owner token
    through assignment, resume, quiescence and the exact result.  A QUIESCENT
    prefix without a result is intentionally non-terminal.
    """

    ref: AttemptRef
    card_sha256: str
    phase: AttemptPhase
    owner_deadline_ns: int | None = None
    runner_started: RunnerStarted | None = None
    job_assigned: JobAssigned | None = None
    running: RunningEvidence | None = None
    snapshot: TaskSnapshot | None = None
    stop_pending: NonceStopPending | None = None
    quiescent: QuiescentEvidence | None = None
    result: ExactAttemptResult | None = None

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("attempt-ref-invalid")
        _digest(self.card_sha256)
        if type(self.phase) is not AttemptPhase or self.phase is AttemptPhase.PREPARED:
            raise TickCoreError("attempt-phase-invalid")
        if self.runner_started is not None:
            if type(self.runner_started) is not RunnerStarted:
                raise TickCoreError("runner-started-type-invalid")
            if self.runner_started.ref != self.ref:
                raise TickCoreError("runner-started-binding-mismatch")
        if self.job_assigned is not None:
            if type(self.job_assigned) is not JobAssigned:
                raise TickCoreError("job-assigned-type-invalid")
            if self.job_assigned.ref != self.ref:
                raise TickCoreError("job-assigned-binding-mismatch")
        if self.running is not None:
            if type(self.running) is not RunningEvidence:
                raise TickCoreError("running-type-invalid")
            if self.running.ref != self.ref:
                raise TickCoreError("running-binding-mismatch")
        if self.snapshot is not None and type(self.snapshot) is not TaskSnapshot:
            raise TickCoreError("snapshot-type-invalid")
        if self.stop_pending is not None:
            if type(self.stop_pending) is not NonceStopPending:
                raise TickCoreError("stop-pending-type-invalid")
            if self.stop_pending.ref != self.ref:
                raise TickCoreError("stop-pending-binding-mismatch")
        if self.quiescent is not None:
            if type(self.quiescent) is not QuiescentEvidence:
                raise TickCoreError("quiescent-type-invalid")
            if self.quiescent.ref != self.ref:
                raise TickCoreError("quiescent-binding-mismatch")
        if self.result is not None:
            if type(self.result) is not ExactAttemptResult:
                raise TickCoreError("attempt-result-type-invalid")
            if self.result.ref != self.ref:
                raise TickCoreError("attempt-result-binding-mismatch")

        owner_values = tuple(
            value.owner_token
            for value in (
                self.runner_started,
                self.job_assigned,
                self.running,
                self.stop_pending,
                self.quiescent,
                self.result,
            )
            if value is not None
        )
        if len(set(owner_values)) > 1:
            raise TickCoreError("owner-token-mismatch")

        if self.phase in (AttemptPhase.LAUNCH_INTENT, AttemptPhase.DISPATCH_READY):
            if self.owner_deadline_ns is not None or any(
                value is not None
                for value in (
                    self.runner_started,
                    self.job_assigned,
                    self.running,
                    self.snapshot,
                    self.stop_pending,
                    self.quiescent,
                    self.result,
                )
            ):
                raise TickCoreError("pre-dispatch-evidence-invalid")
        elif self.phase is AttemptPhase.RUN_REQUESTED:
            self._require_owner_deadline()
            if any(
                value is not None
                for value in (
                    self.runner_started,
                    self.job_assigned,
                    self.running,
                    self.snapshot,
                    self.stop_pending,
                    self.quiescent,
                    self.result,
                )
            ):
                raise TickCoreError("run-requested-evidence-invalid")
        elif self.phase is AttemptPhase.RUNNER_STARTED:
            self._require_owner_prefix(1)
        elif self.phase is AttemptPhase.JOB_ASSIGNED:
            self._require_owner_prefix(2)
        elif self.phase in (
            AttemptPhase.RUNNING,
            AttemptPhase.STOP_PENDING,
            AttemptPhase.QUIESCENT,
        ):
            self._require_owner_prefix(3)
            if self.snapshot is None:
                raise TickCoreError("running-evidence-incomplete")
            if self.snapshot.task_id != self.ref.task_id:
                raise TickCoreError("snapshot-task-binding-mismatch")
            if self.snapshot.attempt != self.ref.attempt:
                raise TickCoreError("snapshot-attempt-binding-mismatch")
            if self.phase in (AttemptPhase.RUNNING, AttemptPhase.STOP_PENDING):
                if self.snapshot.process_quiescent:
                    raise TickCoreError("quiescent-snapshot-without-marker")
                if self.quiescent is not None or self.result is not None:
                    raise TickCoreError("pre-quiescent-terminal-evidence-invalid")
            if self.phase is AttemptPhase.RUNNING and self.stop_pending is not None:
                raise TickCoreError("running-stop-pending-invalid")
            if self.phase is AttemptPhase.STOP_PENDING and self.stop_pending is None:
                raise TickCoreError("stop-pending-binding-mismatch")
            if self.phase is AttemptPhase.QUIESCENT:
                if (
                    self.quiescent is None
                    or self.snapshot.process_alive
                    or not self.snapshot.process_quiescent
                ):
                    raise TickCoreError("quiescent-evidence-incomplete")
        else:
            raise TickCoreError("attempt-phase-invalid")

        if self.result is not None and self.quiescent is None:
            raise TickCoreError("attempt-result-before-quiescent")
        self._validate_owner_timeline()

    def _require_owner_deadline(self) -> int:
        if self.owner_deadline_ns is None:
            raise TickCoreError("owner-deadline-missing")
        return _exact_int(self.owner_deadline_ns, "owner-deadline-invalid")

    def _require_owner_prefix(self, length: int) -> None:
        deadline = self._require_owner_deadline()
        prefix = (self.runner_started, self.job_assigned, self.running)
        if any(prefix[index] is None for index in range(length)) or any(
            prefix[index] is not None for index in range(length, len(prefix))
        ):
            raise TickCoreError("owner-prefix-invalid")
        if self.phase in (AttemptPhase.RUNNER_STARTED, AttemptPhase.JOB_ASSIGNED):
            if any(
                value is not None
                for value in (
                    self.snapshot,
                    self.stop_pending,
                    self.quiescent,
                    self.result,
                )
            ):
                raise TickCoreError("owner-prefix-extra-evidence")
        latest = (
            self.running.confirmed_ns
            if self.running is not None
            else self.job_assigned.assigned_ns
            if self.job_assigned is not None
            else self.runner_started.started_ns
        )
        if deadline < latest:
            raise TickCoreError("owner-deadline-before-phase")

    def _validate_owner_timeline(self) -> None:
        if self.runner_started is None:
            return
        times = [self.runner_started.started_ns]
        if self.job_assigned is not None:
            times.append(self.job_assigned.assigned_ns)
        if self.running is not None:
            times.append(self.running.confirmed_ns)
        if times != sorted(times):
            raise TickCoreError("owner-marker-time-order-invalid")
        if self.running is not None and self.snapshot is not None:
            if self.snapshot.attempt_started_ns > self.runner_started.started_ns:
                raise TickCoreError("runner-before-attempt-start")
        if self.stop_pending is not None and self.running is not None:
            if self.stop_pending.detected_ns < self.running.confirmed_ns:
                raise TickCoreError("stop-before-running")
        if self.quiescent is not None and self.running is not None:
            if self.quiescent.verified_ns < self.running.confirmed_ns:
                raise TickCoreError("quiescent-before-running")
        if self.quiescent is not None and self.stop_pending is not None:
            if self.quiescent.verified_ns < self.stop_pending.detected_ns:
                raise TickCoreError("quiescent-before-stop")
        if self.result is not None and self.quiescent is not None:
            if self.result.observed_ns < self.quiescent.verified_ns:
                raise TickCoreError("result-before-quiescent")


@dataclass(frozen=True, slots=True)
class UnreadableAttemptEvidence:
    ref: AttemptRef
    issue: EvidenceIssue

    def __post_init__(self) -> None:
        if type(self.ref) is not AttemptRef:
            raise TickCoreError("attempt-ref-invalid")
        if type(self.issue) is not EvidenceIssue:
            raise TickCoreError("evidence-issue-invalid")


AttemptEvidence: TypeAlias = InProgressAttemptEvidence | UnreadableAttemptEvidence


def _validate_command_identity(
    ref: AttemptRef,
    card_sha256: str,
    expected_phase: AttemptPhase,
    allowed_phases: tuple[AttemptPhase, ...],
) -> None:
    if type(ref) is not AttemptRef:
        raise TickCoreError("command-ref-invalid")
    _digest(card_sha256)
    if type(expected_phase) is not AttemptPhase or expected_phase not in allowed_phases:
        raise TickCoreError("command-expected-phase-invalid")


class AttemptBoundCommand:
    """Common explicit identity surface for queue/process adapters."""

    __slots__ = ()

    ref: AttemptRef
    card_sha256: str
    expected_phase: AttemptPhase

    @property
    def task_id(self) -> str:
        return self.ref.task_id

    @property
    def attempt(self) -> int:
        return self.ref.attempt

    @property
    def nonce(self) -> str:
        return self.ref.nonce


@dataclass(frozen=True, slots=True)
class WriteHalt:
    reason: HaltReason

    def __post_init__(self) -> None:
        if type(self.reason) is not HaltReason:
            raise TickCoreError("halt-reason-invalid")


@dataclass(frozen=True, slots=True)
class PersistLaunchIntent(AttemptBoundCommand):
    """Create an immutable nonce/card-bound launch intent idempotently.

    Success makes LAUNCH_INTENT reconstructible.  An existing byte-equivalent
    intent is success; any identity/digest conflict is a fail-closed error.
    """

    ref: AttemptRef
    card_sha256: str
    expected_phase: AttemptPhase = AttemptPhase.PREPARED

    def __post_init__(self) -> None:
        _validate_command_identity(
            self.ref, self.card_sha256, self.expected_phase, (AttemptPhase.PREPARED,)
        )


@dataclass(frozen=True, slots=True)
class ClaimPrepared(AttemptBoundCommand):
    """CAS this exact card/ref from queue; never claim by first-match lookup.

    Success makes DISPATCH_READY reconstructible.  A replay may accept only
    the same ref already in ``in_progress`` with the same digest; a different
    nonce, attempt, digest, or queue location is an ABA/conflict failure.
    """

    ref: AttemptRef
    card_sha256: str
    expected_phase: AttemptPhase = AttemptPhase.LAUNCH_INTENT

    def __post_init__(self) -> None:
        _validate_command_identity(
            self.ref,
            self.card_sha256,
            self.expected_phase,
            (AttemptPhase.LAUNCH_INTENT,),
        )


@dataclass(frozen=True, slots=True)
class DispatchAttempt(AttemptBoundCommand):
    """Idempotently request this exact attempt from the scheduler.

    From DISPATCH_READY, success makes RUN_REQUESTED reconstructible.  From
    RUN_REQUESTED, replay must target the same deterministic scheduler name
    and may never create a second runner for the attempt.
    """

    ref: AttemptRef
    card_sha256: str
    expected_phase: AttemptPhase

    def __post_init__(self) -> None:
        _validate_command_identity(
            self.ref,
            self.card_sha256,
            self.expected_phase,
            (AttemptPhase.DISPATCH_READY, AttemptPhase.RUN_REQUESTED),
        )


@dataclass(frozen=True, slots=True)
class PersistStopPending(AttemptBoundCommand):
    """Create the nonce-bound marker and make STOP_PENDING reconstructible."""

    ref: AttemptRef
    card_sha256: str
    pending: NonceStopPending
    expected_phase: AttemptPhase = AttemptPhase.RUNNING

    def __post_init__(self) -> None:
        _validate_command_identity(
            self.ref, self.card_sha256, self.expected_phase, (AttemptPhase.RUNNING,)
        )
        if type(self.pending) is not NonceStopPending or self.pending.ref != self.ref:
            raise TickCoreError("stop-pending-binding-mismatch")


@dataclass(frozen=True, slots=True)
class CompleteAttempt(AttemptBoundCommand):
    ref: AttemptRef
    card_sha256: str
    expected_phase: AttemptPhase

    def __post_init__(self) -> None:
        _validate_command_identity(
            self.ref,
            self.card_sha256,
            self.expected_phase,
            (AttemptPhase.QUIESCENT,),
        )


@dataclass(frozen=True, slots=True)
class FailAttempt(AttemptBoundCommand):
    """Use queue ``fail``; there is deliberately no requeue command."""

    ref: AttemptRef
    card_sha256: str
    expected_phase: AttemptPhase
    cause: Cause
    expected: ExpectedFailDisposition

    def __post_init__(self) -> None:
        _validate_command_identity(
            self.ref,
            self.card_sha256,
            self.expected_phase,
            (AttemptPhase.QUIESCENT,),
        )
        if type(self.cause) is not Cause:
            raise TickCoreError("fail-cause-invalid")
        if type(self.expected) is not ExpectedFailDisposition:
            raise TickCoreError("fail-disposition-invalid")


@dataclass(frozen=True, slots=True)
class BlockAttempt(AttemptBoundCommand):
    ref: AttemptRef
    card_sha256: str
    expected_phase: AttemptPhase
    cause: Cause

    def __post_init__(self) -> None:
        _validate_command_identity(
            self.ref,
            self.card_sha256,
            self.expected_phase,
            (AttemptPhase.QUIESCENT,),
        )
        if type(self.cause) is not Cause:
            raise TickCoreError("block-cause-invalid")


Command: TypeAlias = (
    WriteHalt
    | PersistLaunchIntent
    | ClaimPrepared
    | DispatchAttempt
    | PersistStopPending
    | CompleteAttempt
    | FailAttempt
    | BlockAttempt
)


@dataclass(frozen=True, slots=True)
class ReportNotice:
    code: ReportCode
    ref: AttemptRef | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not ReportCode:
            raise TickCoreError("report-code-invalid")
        if self.ref is not None and type(self.ref) is not AttemptRef:
            raise TickCoreError("report-ref-invalid")


@dataclass(frozen=True, slots=True)
class TickPlan:
    """Commands to execute in order, aborting after the first failed command."""

    now_ns: int
    state: PlanState
    commands: tuple[Command, ...]
    notices: tuple[ReportNotice, ...] = ()

    def __post_init__(self) -> None:
        _exact_int(self.now_ns, "now-ns-invalid")
        if type(self.state) is not PlanState:
            raise TickCoreError("plan-state-invalid")
        if type(self.commands) is not tuple:
            raise TickCoreError("commands-type-invalid")
        if type(self.notices) is not tuple or any(
            type(notice) is not ReportNotice for notice in self.notices
        ):
            raise TickCoreError("notices-type-invalid")

        command_types = (
            WriteHalt,
            PersistLaunchIntent,
            ClaimPrepared,
            DispatchAttempt,
            PersistStopPending,
            CompleteAttempt,
            FailAttempt,
            BlockAttempt,
        )
        if any(type(command) not in command_types for command in self.commands):
            raise TickCoreError("command-type-invalid")
        halts = [command for command in self.commands if type(command) is WriteHalt]
        if halts:
            if self.state is not PlanState.HALTED or len(self.commands) != 1:
                raise TickCoreError("halt-command-must-be-exclusive")
            return
        if self.state is PlanState.HALTED and self.commands:
            raise TickCoreError("halted-plan-command-invalid")

        task_ids: set[str] = set()
        prepared_count = 0
        for command in self.commands:
            if type(command) is WriteHalt:
                continue
            task_id = command.ref.task_id
            if task_id in task_ids:
                raise TickCoreError("multiple-commands-for-task")
            task_ids.add(task_id)
            if type(command) is PersistLaunchIntent:
                prepared_count += 1
        if prepared_count > 1:
            raise TickCoreError("multiple-new-launches")
        if prepared_count and len(self.commands) != 1:
            raise TickCoreError("new-launch-must-be-exclusive")

        durable_phases = {
            command.expected_phase
            for command in self.commands
            if isinstance(command, AttemptBoundCommand)
        }
        if len(durable_phases) > 1:
            raise TickCoreError("mixed-durable-phases")


class CommandRefusedError(RuntimeError):
    """An executor refused the exact command, normally after a failed CAS."""

    def __init__(self, command: Command) -> None:
        self.command = command
        super().__init__(f"command-refused:{type(command).__name__}")


@runtime_checkable
class CommandExecutor(Protocol):
    """Production side-effect boundary for a fully validated tick plan.

    ``execute`` must return the exact bool ``True`` only after the command is
    durably accepted (including idempotent replay of the same identity).
    ``False``, ``None`` and other values are fail-closed refusals.
    """

    def execute(self, command: Command) -> bool:
        """Execute one command without weakening any embedded CAS identity."""


def execute_tick_plan(plan: TickPlan, executor: CommandExecutor) -> None:
    """Execute ``plan`` in order and abort at the first error or refusal.

    Executor exceptions intentionally propagate unchanged.  In particular,
    this helper never reports success for a partial plan and never invokes a
    later command after an exception or a non-``True`` result.
    """

    if type(plan) is not TickPlan:
        raise TickCoreError("execute-plan-type-invalid")
    for command in plan.commands:
        accepted = executor.execute(command)
        if accepted is not True:
            raise CommandRefusedError(command)


@runtime_checkable
class IntegerNsClock(Protocol):
    def now_ns(self) -> int:
        """Return one exact integer-nanosecond timestamp for the entire tick."""


@runtime_checkable
class TickEvidenceAdapter(Protocol):
    """Read-only evidence boundary for future supervisor wiring.

    ``read_attempts`` must include orphaned LAUNCH_INTENT records as well as
    queue ``in_progress`` records so every crash boundary can be recovered.
    ``peek_prepared`` must prepare one exact card/ref and must already apply
    capacity policy; it may not imply or perform a claim.
    """

    def read_audit(self) -> AuditEvidence:
        """Return current full audit and durable HALT evidence."""

    def read_attempts(self) -> tuple[AttemptEvidence, ...]:
        """Return stable, nonce-bound recoverable attempts in all phases."""

    def peek_prepared(self) -> PreparedCandidate | None:
        """Return at most one exact candidate without mutating the queue."""


@runtime_checkable
class ReporterAdapter(Protocol):
    def report(self, notice: ReportNotice) -> None:
        """Best effort only; build_tick_plan deliberately never calls this."""


def _halt(now_ns: int, reason: HaltReason) -> TickPlan:
    return TickPlan(
        now_ns,
        PlanState.HALTED,
        (WriteHalt(reason),),
        (ReportNotice(ReportCode.HALT_PLANNED),),
    )


def _identity(evidence: InProgressAttemptEvidence) -> tuple[AttemptRef, str]:
    return evidence.ref, evidence.card_sha256


_RECONCILE_PHASE_PRIORITY = {
    # Finish or contain already-running work before advancing an earlier
    # launch crash boundary.  The selected tick remains homogeneous by its
    # exact durable source phase.
    AttemptPhase.QUIESCENT: 0,
    AttemptPhase.STOP_PENDING: 1,
    AttemptPhase.RUNNING: 2,
    AttemptPhase.JOB_ASSIGNED: 3,
    AttemptPhase.RUNNER_STARTED: 4,
    AttemptPhase.RUN_REQUESTED: 5,
    AttemptPhase.DISPATCH_READY: 6,
    AttemptPhase.LAUNCH_INTENT: 7,
}


def _terminal_command(
    evidence: InProgressAttemptEvidence,
    action: Action,
    cause: Cause,
) -> Command:
    snapshot = evidence.snapshot
    if (
        evidence.phase is not AttemptPhase.QUIESCENT
        or evidence.quiescent is None
        or evidence.result is None
        or snapshot is None
        or snapshot.process_alive
        or not snapshot.process_quiescent
    ):
        raise TickCoreError("terminal-without-quiescence")
    ref, digest = _identity(evidence)
    phase = evidence.phase
    if action is Action.RETRY_ATTEMPT:
        return FailAttempt(
            ref, digest, phase, cause, ExpectedFailDisposition.RETRY_QUEUE
        )
    if action is Action.FAIL:
        return FailAttempt(ref, digest, phase, cause, ExpectedFailDisposition.FAILED)
    if action is Action.BLOCK:
        return BlockAttempt(ref, digest, phase, cause)
    raise TickCoreError("terminal-policy-action-invalid")


def _plan_running(
    evidence: InProgressAttemptEvidence,
    *,
    now_ns: int,
) -> Command | None:
    if evidence.snapshot is None or evidence.running is None:
        raise TickCoreError("running-evidence-incomplete")
    snapshot = evidence.snapshot
    decision = decide_task(snapshot, now_ns=now_ns)
    ref, digest = _identity(evidence)

    if snapshot.process_alive:
        if decision.action is Action.NOOP:
            return None
        if decision.action is not Action.REQUEST_STOP:
            raise TickCoreError("live-policy-action-invalid")
        pending = NonceStopPending(
            ref, evidence.running.owner_token, decision.cause, now_ns
        )
        return PersistStopPending(ref, digest, pending)

    # The owner may be between primary exit and durable quiescence/result.
    # The coordinator has no Job handle and therefore has no safe command here.
    return None


def _plan_quiescent(
    evidence: InProgressAttemptEvidence,
    *,
    now_ns: int,
) -> Command | None:
    if evidence.snapshot is None or evidence.quiescent is None:
        raise TickCoreError("quiescent-evidence-incomplete")
    result = evidence.result
    if result is None:
        return None
    ref, digest = _identity(evidence)
    if evidence.stop_pending is not None:
        policy_pending = evidence.stop_pending.to_policy_pending(evidence.ref)
        decision = decide_after_stop(
            evidence.snapshot,
            pending=policy_pending,
            now_ns=now_ns,
        )
        return _terminal_command(evidence, decision.action, decision.cause)
    if result.outcome is AttemptOutcome.SUCCEEDED:
        return CompleteAttempt(ref, digest, AttemptPhase.QUIESCENT)
    decision = decide_task(evidence.snapshot, now_ns=now_ns)
    return _terminal_command(
        evidence, decision.action, Cause.PROCESS_EXITED
    )


def _owner_wait_incomplete(evidence: InProgressAttemptEvidence) -> bool:
    if evidence.phase not in (
        AttemptPhase.RUN_REQUESTED,
        AttemptPhase.RUNNER_STARTED,
        AttemptPhase.JOB_ASSIGNED,
        AttemptPhase.RUNNING,
        AttemptPhase.STOP_PENDING,
        AttemptPhase.QUIESCENT,
    ):
        return False
    return not (
        evidence.phase is AttemptPhase.QUIESCENT and evidence.result is not None
    )


def _owner_unresponsive(
    evidence: InProgressAttemptEvidence, *, now_ns: int
) -> bool:
    if not _owner_wait_incomplete(evidence):
        return False
    deadline = evidence.owner_deadline_ns
    if type(deadline) is not int or deadline < 0:
        raise TickCoreError("owner-deadline-invalid")
    return now_ns >= deadline


def _validate_marker_times(
    evidence: InProgressAttemptEvidence, *, now_ns: int
) -> None:
    values = tuple(
        value
        for value in (
            evidence.runner_started.started_ns
            if evidence.runner_started is not None
            else None,
            evidence.job_assigned.assigned_ns
            if evidence.job_assigned is not None
            else None,
            evidence.running.confirmed_ns
            if evidence.running is not None
            else None,
            evidence.stop_pending.detected_ns
            if evidence.stop_pending is not None
            else None,
            evidence.quiescent.verified_ns
            if evidence.quiescent is not None
            else None,
            evidence.result.observed_ns if evidence.result is not None else None,
        )
        if value is not None
    )
    if any(value > now_ns for value in values):
        raise TickCoreError("owner-marker-in-future")
    if evidence.owner_deadline_ns is not None:
        deadline = _exact_int(
            evidence.owner_deadline_ns,
            "owner-deadline-invalid",
        )
        if any(value > deadline for value in values):
            raise TickCoreError("owner-marker-after-deadline")


def _plan_attempt(
    evidence: InProgressAttemptEvidence,
    *,
    now_ns: int,
) -> Command | None:
    ref, digest = _identity(evidence)
    _validate_marker_times(evidence, now_ns=now_ns)
    if evidence.phase is AttemptPhase.LAUNCH_INTENT:
        return ClaimPrepared(ref, digest)
    if evidence.phase is AttemptPhase.DISPATCH_READY:
        return DispatchAttempt(ref, digest, AttemptPhase.DISPATCH_READY)
    if evidence.phase is AttemptPhase.RUN_REQUESTED:
        return DispatchAttempt(ref, digest, AttemptPhase.RUN_REQUESTED)
    if evidence.phase in (
        AttemptPhase.RUNNER_STARTED,
        AttemptPhase.JOB_ASSIGNED,
        AttemptPhase.STOP_PENDING,
    ):
        return None
    if evidence.phase is AttemptPhase.RUNNING:
        return _plan_running(evidence, now_ns=now_ns)
    if evidence.phase is AttemptPhase.QUIESCENT:
        return _plan_quiescent(evidence, now_ns=now_ns)
    raise TickCoreError("attempt-phase-unhandled")


def build_tick_plan(
    evidence_adapter: TickEvidenceAdapter,
    clock: IntegerNsClock,
) -> TickPlan:
    """Return an exact, replayable plan without executing any command."""

    try:
        now_ns = clock.now_ns()
    except Exception:
        return _halt(0, HaltReason.CLOCK_READ_FAILED)
    if type(now_ns) is not int or now_ns < 0:
        return _halt(0, HaltReason.CLOCK_INVALID)

    try:
        audit = evidence_adapter.read_audit()
    except Exception:
        return _halt(now_ns, HaltReason.AUDIT_READ_FAILED)
    if type(audit) is not AuditEvidence:
        return _halt(now_ns, HaltReason.AUDIT_INVALID)
    if audit.status is AuditStatus.FAIL:
        return _halt(now_ns, HaltReason.AUDIT_FAILED)
    if audit.halt_active:
        return TickPlan(
            now_ns,
            PlanState.HALTED,
            (),
            (ReportNotice(ReportCode.HALT_ACTIVE),),
        )

    try:
        attempts = evidence_adapter.read_attempts()
    except Exception:
        return _halt(now_ns, HaltReason.EVIDENCE_READ_FAILED)
    if type(attempts) is not tuple:
        return _halt(now_ns, HaltReason.EVIDENCE_INVALID)

    trusted: list[InProgressAttemptEvidence] = []
    task_ids: set[str] = set()
    for item in attempts:
        if type(item) is UnreadableAttemptEvidence:
            reason = (
                HaltReason.EVIDENCE_UNKNOWN
                if item.issue is EvidenceIssue.UNKNOWN
                else HaltReason.EVIDENCE_CORRUPT
            )
            return _halt(now_ns, reason)
        if type(item) is not InProgressAttemptEvidence:
            return _halt(now_ns, HaltReason.EVIDENCE_INVALID)
        if item.ref.task_id in task_ids:
            return _halt(now_ns, HaltReason.EVIDENCE_INVALID)
        task_ids.add(item.ref.task_id)
        trusted.append(item)

    try:
        for item in trusted:
            _validate_marker_times(item, now_ns=now_ns)
            if item.snapshot is not None:
                decide_task(item.snapshot, now_ns=now_ns)
        if any(_owner_unresponsive(item, now_ns=now_ns) for item in trusted):
            return _halt(now_ns, HaltReason.OWNER_UNRESPONSIVE)
    except (PolicyError, TickCoreError, TypeError, ValueError):
        return _halt(now_ns, HaltReason.EVIDENCE_INVALID)

    commands: list[Command] = []
    notices: list[ReportNotice] = []
    try:
        for item in sorted(trusted, key=lambda value: value.ref):
            command = _plan_attempt(item, now_ns=now_ns)
            if command is not None:
                commands.append(command)
                notices.append(ReportNotice(ReportCode.RECONCILE, item.ref))
    except (PolicyError, TickCoreError, TypeError, ValueError):
        return _halt(now_ns, HaltReason.EVIDENCE_INVALID)

    # Never prepare a new launch while any existing attempt needs an action.
    if commands:
        selected_phase = min(
            (command.expected_phase for command in commands),
            key=_RECONCILE_PHASE_PRIORITY.__getitem__,
        )
        selected = [
            (command, notice)
            for command, notice in zip(commands, notices, strict=True)
            if command.expected_phase is selected_phase
        ]
        return TickPlan(
            now_ns,
            PlanState.RUNNING,
            tuple(command for command, _notice in selected),
            tuple(notice for _command, notice in selected),
        )

    try:
        candidate = evidence_adapter.peek_prepared()
    except Exception:
        return _halt(now_ns, HaltReason.CANDIDATE_READ_FAILED)
    if candidate is None:
        return TickPlan(now_ns, PlanState.RUNNING, ())
    if type(candidate) is not PreparedCandidate:
        return _halt(now_ns, HaltReason.CANDIDATE_INVALID)
    if candidate.ref.task_id in task_ids:
        return _halt(now_ns, HaltReason.CANDIDATE_INVALID)

    command = PersistLaunchIntent(candidate.ref, candidate.card_sha256)
    return TickPlan(
        now_ns,
        PlanState.RUNNING,
        (command,),
        (ReportNotice(ReportCode.LAUNCH_PREPARED, candidate.ref),),
    )
