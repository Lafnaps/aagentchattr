from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import get_args
import unittest

import autonomy.tick_core as tick_core
from autonomy.supervisor import Cause, NANOSECONDS_PER_SECOND, TaskSnapshot
from autonomy.tick_core import (
    AttemptOutcome,
    AttemptPhase,
    AttemptRef,
    AuditEvidence,
    AuditStatus,
    BlockAttempt,
    ClaimPrepared,
    CommandRefusedError,
    CompleteAttempt,
    DispatchAttempt,
    EvidenceIssue,
    ExactAttemptResult,
    ExpectedFailDisposition,
    FailAttempt,
    HaltReason,
    InProgressAttemptEvidence,
    JobAssigned,
    NonceStopPending,
    PersistLaunchIntent,
    PersistStopPending,
    PlanState,
    PreparedCandidate,
    QuiescentEvidence,
    RunningEvidence,
    RunnerStarted,
    TickCoreError,
    TickPlan,
    UnreadableAttemptEvidence,
    WriteHalt,
    build_tick_plan,
    execute_tick_plan,
)


S = NANOSECONDS_PER_SECOND
NOW = 1_100 * S
DEADLINE = 1_200 * S
NONCE_A = "1" * 32
NONCE_B = "2" * 32
OWNER_A = "a" * 32
OWNER_B = "b" * 32
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
JOB_FLAGS = 0x00002000


def ref(task_id: str = "task-one", attempt: int = 1, nonce: str = NONCE_A):
    return AttemptRef(task_id, attempt, nonce)


def snapshot(attempt_ref: AttemptRef | None = None, **overrides):
    attempt_ref = attempt_ref or ref()
    values = {
        "task_id": attempt_ref.task_id,
        "attempt": attempt_ref.attempt,
        "max_attempts": 2,
        "restart_safe": True,
        "max_step_seconds": 3_600,
        "heartbeat_timeout_seconds": 120,
        "attempt_started_ns": 1_000 * S,
        "heartbeat_ns": 1_090 * S,
        "progress_ns": 1_060 * S,
        "process_alive": True,
        "process_quiescent": False,
    }
    values.update(overrides)
    return TaskSnapshot(**values)


def started(attempt_ref=None, token=OWNER_A, when=1_001 * S, pid=101):
    attempt_ref = attempt_ref or ref()
    return RunnerStarted(attempt_ref, token, pid, when)


def assigned(attempt_ref=None, token=OWNER_A, when=1_002 * S, pid=202, flags=JOB_FLAGS):
    attempt_ref = attempt_ref or ref()
    return JobAssigned(attempt_ref, token, pid, flags, when)


def running(attempt_ref=None, token=OWNER_A, when=1_003 * S):
    attempt_ref = attempt_ref or ref()
    return RunningEvidence(attempt_ref, token, when)


def pending(attempt_ref=None, token=OWNER_A, cause=Cause.HEARTBEAT_STALE, when=1_080 * S):
    attempt_ref = attempt_ref or ref()
    return NonceStopPending(attempt_ref, token, cause, when)


def quiet(attempt_ref=None, token=OWNER_A, when=1_095 * S):
    attempt_ref = attempt_ref or ref()
    return QuiescentEvidence(attempt_ref, token, when)


def exact_result(
    attempt_ref=None,
    token=OWNER_A,
    code=0,
    outcome=None,
    when=1_096 * S,
):
    attempt_ref = attempt_ref or ref()
    if outcome is None:
        outcome = AttemptOutcome.SUCCEEDED if code == 0 else AttemptOutcome.FAILED
    return ExactAttemptResult(attempt_ref, token, code, outcome, when)


def phase_evidence(
    phase: AttemptPhase,
    *,
    attempt_ref=None,
    digest=DIGEST_A,
    deadline=DEADLINE,
    owner_token=OWNER_A,
    stop=None,
    result=None,
    **snapshot_overrides,
):
    attempt_ref = attempt_ref or ref()
    if phase in (AttemptPhase.LAUNCH_INTENT, AttemptPhase.DISPATCH_READY):
        return InProgressAttemptEvidence(attempt_ref, digest, phase)
    values = {
        "ref": attempt_ref,
        "card_sha256": digest,
        "phase": phase,
        "owner_deadline_ns": deadline,
    }
    if phase is AttemptPhase.RUN_REQUESTED:
        return InProgressAttemptEvidence(**values)
    values["runner_started"] = started(attempt_ref, owner_token)
    if phase is AttemptPhase.RUNNER_STARTED:
        return InProgressAttemptEvidence(**values)
    values["job_assigned"] = assigned(attempt_ref, owner_token)
    if phase is AttemptPhase.JOB_ASSIGNED:
        return InProgressAttemptEvidence(**values)
    values["running"] = running(attempt_ref, owner_token)
    is_quiescent = phase is AttemptPhase.QUIESCENT
    values["snapshot"] = snapshot(
        attempt_ref,
        process_alive=(
            False if is_quiescent else snapshot_overrides.pop("process_alive", True)
        ),
        process_quiescent=(
            True
            if is_quiescent
            else snapshot_overrides.pop("process_quiescent", False)
        ),
        **snapshot_overrides,
    )
    if phase is AttemptPhase.RUNNING:
        return InProgressAttemptEvidence(**values)
    if phase is AttemptPhase.STOP_PENDING:
        values["stop_pending"] = stop or pending(attempt_ref, owner_token)
        return InProgressAttemptEvidence(**values)
    if phase is AttemptPhase.QUIESCENT:
        values["stop_pending"] = stop
        values["quiescent"] = quiet(attempt_ref, owner_token)
        values["result"] = result
        return InProgressAttemptEvidence(**values)
    raise AssertionError(phase)


class Clock:
    def __init__(self, value=NOW, raises=False):
        self.value = value
        self.raises = raises
        self.calls = 0

    def now_ns(self):
        self.calls += 1
        if self.raises:
            raise RuntimeError("clock")
        return self.value


class Adapter:
    def __init__(self, *, audit=None, attempts=(), candidate=None, raise_at=None):
        self.audit = audit or AuditEvidence(AuditStatus.PASS, False)
        self.attempts = attempts
        self.candidate = candidate
        self.raise_at = raise_at
        self.calls = []

    def read_audit(self):
        self.calls.append("audit")
        if self.raise_at == "audit":
            raise RuntimeError("audit")
        return self.audit

    def read_attempts(self):
        self.calls.append("attempts")
        if self.raise_at == "attempts":
            raise RuntimeError("attempts")
        return self.attempts

    def peek_prepared(self):
        self.calls.append("candidate")
        if self.raise_at == "candidate":
            raise RuntimeError("candidate")
        return self.candidate


def plan_for(evidence, now=NOW, candidate=None):
    return build_tick_plan(Adapter(attempts=(evidence,), candidate=candidate), Clock(now))


class LaunchAndOwnerBoundaryTests(unittest.TestCase):
    def test_prepared_emits_only_launch_intent(self):
        candidate = PreparedCandidate(ref(), DIGEST_A)
        plan = build_tick_plan(Adapter(candidate=candidate), Clock())
        self.assertEqual(plan.commands, (PersistLaunchIntent(ref(), DIGEST_A),))

    def test_launch_intent_claims_exact_card(self):
        self.assertEqual(
            plan_for(phase_evidence(AttemptPhase.LAUNCH_INTENT)).commands,
            (ClaimPrepared(ref(), DIGEST_A),),
        )

    def test_dispatch_ready_dispatches_once(self):
        self.assertEqual(
            plan_for(phase_evidence(AttemptPhase.DISPATCH_READY)).commands,
            (DispatchAttempt(ref(), DIGEST_A, AttemptPhase.DISPATCH_READY),),
        )

    def test_run_requested_replays_dispatch(self):
        expected = (DispatchAttempt(ref(), DIGEST_A, AttemptPhase.RUN_REQUESTED),)
        evidence = phase_evidence(AttemptPhase.RUN_REQUESTED)
        self.assertEqual(plan_for(evidence).commands, expected)
        self.assertEqual(plan_for(evidence).commands, expected)

    def test_runner_started_and_job_assigned_await_owner(self):
        for phase in (AttemptPhase.RUNNER_STARTED, AttemptPhase.JOB_ASSIGNED):
            with self.subTest(phase=phase):
                self.assertEqual(plan_for(phase_evidence(phase)).commands, ())

    def test_healthy_running_awaits_owner_and_policy(self):
        self.assertEqual(plan_for(phase_evidence(AttemptPhase.RUNNING)).commands, ())

    def test_coordinator_has_no_process_control_commands(self):
        for name in ("MarkRunning", "RequestStop", "VerifyQuiescence"):
            self.assertFalse(hasattr(tick_core, name), name)
        source = Path(tick_core.__file__).read_text(encoding="utf-8")
        for declaration in (
            "class MarkRunning",
            "class RequestStop",
            "class VerifyQuiescence",
        ):
            self.assertNotIn(declaration, source)
        command_names = {command_type.__name__ for command_type in get_args(tick_core.Command)}
        self.assertTrue(
            {"MarkRunning", "RequestStop", "VerifyQuiescence"}.isdisjoint(
                command_names
            )
        )
        for owner_marker in (started(), assigned(), running(), quiet()):
            with self.subTest(marker=type(owner_marker).__name__):
                with self.assertRaisesRegex(TickCoreError, "command-type-invalid"):
                    TickPlan(NOW, PlanState.RUNNING, (owner_marker,))

    def test_reconciliation_prevents_new_candidate(self):
        adapter = Adapter(
            attempts=(phase_evidence(AttemptPhase.LAUNCH_INTENT),),
            candidate=PreparedCandidate(ref("queued", 1, NONCE_B), DIGEST_B),
        )
        self.assertIs(type(build_tick_plan(adapter, Clock()).commands[0]), ClaimPrepared)
        self.assertEqual(adapter.calls, ["audit", "attempts"])

    def test_plans_are_deterministic(self):
        evidence = phase_evidence(AttemptPhase.RUN_REQUESTED)
        self.assertEqual(plan_for(evidence), plan_for(evidence))


class RunningAndTerminalTests(unittest.TestCase):
    def test_stale_heartbeat_only_persists_owner_bound_stop_pending(self):
        evidence = phase_evidence(
            AttemptPhase.RUNNING,
            heartbeat_ns=1_000 * S,
            progress_ns=1_090 * S,
            heartbeat_timeout_seconds=50,
        )
        plan = plan_for(evidence)
        self.assertEqual(len(plan.commands), 1)
        command = plan.commands[0]
        self.assertIs(type(command), PersistStopPending)
        self.assertEqual(command.pending.owner_token, OWNER_A)
        self.assertIs(command.pending.cause, Cause.HEARTBEAT_STALE)
        self.assertEqual(command.pending.detected_ns, NOW)

    def test_progress_stale_takes_precedence(self):
        evidence = phase_evidence(
            AttemptPhase.RUNNING,
            heartbeat_ns=1_000 * S,
            progress_ns=1_000 * S,
            max_step_seconds=50,
            heartbeat_timeout_seconds=50,
        )
        command = plan_for(evidence).commands[0]
        self.assertIs(command.pending.cause, Cause.PROGRESS_STALE)

    def test_dead_nonquiescent_running_awaits_owner(self):
        evidence = phase_evidence(AttemptPhase.RUNNING, process_alive=False)
        self.assertEqual(plan_for(evidence).commands, ())

    def test_stop_pending_never_requests_or_verifies_process(self):
        evidence = phase_evidence(AttemptPhase.STOP_PENDING)
        self.assertEqual(plan_for(evidence).commands, ())

    def test_quiescent_without_exact_result_is_nonterminal(self):
        evidence = phase_evidence(AttemptPhase.QUIESCENT)
        self.assertEqual(plan_for(evidence).commands, ())

    def test_exact_zero_result_completes_only_from_quiescent(self):
        evidence = phase_evidence(
            AttemptPhase.QUIESCENT,
            result=exact_result(),
        )
        self.assertEqual(
            plan_for(evidence).commands,
            (CompleteAttempt(ref(), DIGEST_A, AttemptPhase.QUIESCENT),),
        )

    def test_nonzero_result_retries_safe_first_attempt(self):
        evidence = phase_evidence(
            AttemptPhase.QUIESCENT,
            result=exact_result(code=7),
        )
        command = plan_for(evidence).commands[0]
        self.assertIs(type(command), FailAttempt)
        self.assertIs(command.expected, ExpectedFailDisposition.RETRY_QUEUE)
        self.assertIs(command.cause, Cause.PROCESS_EXITED)

    def test_nonzero_result_fails_second_attempt(self):
        attempt_ref = ref(attempt=2)
        evidence = phase_evidence(
            AttemptPhase.QUIESCENT,
            attempt_ref=attempt_ref,
            result=exact_result(attempt_ref, code=1),
        )
        command = plan_for(evidence).commands[0]
        self.assertIs(type(command), FailAttempt)
        self.assertIs(command.expected, ExpectedFailDisposition.FAILED)

    def test_progress_stop_is_authoritative_over_late_success(self):
        stop = pending(cause=Cause.PROGRESS_STALE)
        evidence = phase_evidence(
            AttemptPhase.QUIESCENT,
            stop=stop,
            result=exact_result(),
        )
        command = plan_for(evidence).commands[0]
        self.assertEqual(
            command,
            BlockAttempt(ref(), DIGEST_A, AttemptPhase.QUIESCENT, Cause.PROGRESS_STALE),
        )

    def test_heartbeat_stop_retries_despite_late_success(self):
        evidence = phase_evidence(
            AttemptPhase.QUIESCENT,
            stop=pending(cause=Cause.HEARTBEAT_STALE),
            result=exact_result(),
        )
        command = plan_for(evidence).commands[0]
        self.assertIs(type(command), FailAttempt)
        self.assertIs(command.expected, ExpectedFailDisposition.RETRY_QUEUE)
        self.assertIs(command.cause, Cause.HEARTBEAT_STALE)

    def test_unsigned_high_dword_is_exact_failure(self):
        result = exact_result(code=0xC0000005)
        self.assertEqual(result.exit_code, 0xC0000005)
        command = plan_for(
            phase_evidence(AttemptPhase.QUIESCENT, result=result)
        ).commands[0]
        self.assertIs(type(command), FailAttempt)


class EvidenceContractTests(unittest.TestCase):
    def test_owner_token_continuity_is_mandatory(self):
        with self.assertRaisesRegex(TickCoreError, "owner-token-mismatch"):
            InProgressAttemptEvidence(
                ref(),
                DIGEST_A,
                AttemptPhase.JOB_ASSIGNED,
                owner_deadline_ns=DEADLINE,
                runner_started=started(token=OWNER_A),
                job_assigned=assigned(token=OWNER_B),
            )

    def test_actor_ref_mismatch_is_rejected(self):
        other = ref("other-task", nonce=NONCE_B)
        with self.assertRaisesRegex(TickCoreError, "binding-mismatch"):
            InProgressAttemptEvidence(
                ref(),
                DIGEST_A,
                AttemptPhase.RUNNER_STARTED,
                owner_deadline_ns=DEADLINE,
                runner_started=started(other),
            )

    def test_marker_prefix_gaps_and_extras_are_rejected(self):
        with self.assertRaisesRegex(TickCoreError, "owner-prefix-invalid"):
            InProgressAttemptEvidence(
                ref(),
                DIGEST_A,
                AttemptPhase.JOB_ASSIGNED,
                owner_deadline_ns=DEADLINE,
                job_assigned=assigned(),
            )
        with self.assertRaisesRegex(TickCoreError, "owner-prefix-invalid"):
            InProgressAttemptEvidence(
                ref(),
                DIGEST_A,
                AttemptPhase.RUNNER_STARTED,
                owner_deadline_ns=DEADLINE,
                runner_started=started(),
                job_assigned=assigned(),
            )

    def test_run_requested_rejects_early_owner_marker(self):
        with self.assertRaisesRegex(TickCoreError, "run-requested-evidence-invalid"):
            InProgressAttemptEvidence(
                ref(),
                DIGEST_A,
                AttemptPhase.RUN_REQUESTED,
                owner_deadline_ns=DEADLINE,
                runner_started=started(),
            )

    def test_running_requires_full_owner_prefix(self):
        with self.assertRaisesRegex(TickCoreError, "owner-prefix-invalid"):
            InProgressAttemptEvidence(
                ref(),
                DIGEST_A,
                AttemptPhase.RUNNING,
                owner_deadline_ns=DEADLINE,
                runner_started=started(),
                running=running(),
                snapshot=snapshot(),
            )

    def test_quiescent_gap_is_rejected(self):
        base = phase_evidence(AttemptPhase.RUNNING)
        with self.assertRaisesRegex(TickCoreError, "quiescent-evidence-incomplete"):
            replace(
                base,
                phase=AttemptPhase.QUIESCENT,
                snapshot=snapshot(process_alive=False, process_quiescent=True),
            )

    def test_result_before_quiescent_is_rejected(self):
        base = phase_evidence(AttemptPhase.RUNNING)
        with self.assertRaisesRegex(TickCoreError, "pre-quiescent-terminal-evidence-invalid"):
            replace(base, result=exact_result())

    def test_result_publication_before_quiescence_time_is_rejected(self):
        with self.assertRaisesRegex(TickCoreError, "result-before-quiescent"):
            phase_evidence(
                AttemptPhase.QUIESCENT,
                result=exact_result(when=1_094 * S),
            )

    def test_stop_token_mismatch_is_rejected(self):
        with self.assertRaisesRegex(TickCoreError, "owner-token-mismatch"):
            phase_evidence(
                AttemptPhase.STOP_PENDING,
                stop=pending(token=OWNER_B),
            )

    def test_stop_ref_mismatch_is_rejected(self):
        other = ref("other-task", nonce=NONCE_B)
        with self.assertRaisesRegex(TickCoreError, "binding-mismatch"):
            phase_evidence(
                AttemptPhase.STOP_PENDING,
                stop=pending(attempt_ref=other),
            )

    def test_result_token_mismatch_is_rejected(self):
        with self.assertRaisesRegex(TickCoreError, "owner-token-mismatch"):
            phase_evidence(
                AttemptPhase.QUIESCENT,
                result=exact_result(token=OWNER_B),
            )

    def test_exact_result_requires_unsigned_dword_and_zero_equivalence(self):
        for code in (-1, 0x1_0000_0000, True):
            with self.subTest(code=code), self.assertRaises(TickCoreError):
                exact_result(code=code)
        with self.assertRaisesRegex(TickCoreError, "exit-outcome-mismatch"):
            exact_result(code=0, outcome=AttemptOutcome.FAILED)
        with self.assertRaisesRegex(TickCoreError, "exit-outcome-mismatch"):
            exact_result(code=1, outcome=AttemptOutcome.SUCCEEDED)
        with self.assertRaisesRegex(TickCoreError, "outcome-invalid"):
            exact_result(code=1, outcome="failed")

    def test_stop_cause_requires_exact_enum(self):
        with self.assertRaisesRegex(TickCoreError, "cause-invalid"):
            pending(cause="heartbeat_stale")

    def test_job_assignment_requires_kill_on_close_and_no_breakaway(self):
        with self.assertRaisesRegex(TickCoreError, "kill-on-close"):
            assigned(flags=0)
        with self.assertRaisesRegex(TickCoreError, "breakaway"):
            assigned(flags=JOB_FLAGS | 0x00000800)

    def test_marker_time_order_is_rejected(self):
        with self.assertRaisesRegex(TickCoreError, "time-order"):
            InProgressAttemptEvidence(
                ref(),
                DIGEST_A,
                AttemptPhase.JOB_ASSIGNED,
                owner_deadline_ns=DEADLINE,
                runner_started=started(when=1_010 * S),
                job_assigned=assigned(when=1_005 * S),
            )

    def test_future_marker_halts_fail_closed(self):
        evidence = phase_evidence(AttemptPhase.RUNNER_STARTED)
        evidence = replace(
            evidence,
            runner_started=started(when=NOW + 1),
            owner_deadline_ns=DEADLINE,
        )
        plan = plan_for(evidence)
        self.assertEqual(plan.state, PlanState.HALTED)
        self.assertEqual(plan.commands, (WriteHalt(HaltReason.EVIDENCE_INVALID),))

    def test_invalid_snapshot_precedes_owner_timeout_and_halts_as_evidence(self):
        evidence = phase_evidence(
            AttemptPhase.STOP_PENDING,
            deadline=NOW,
            heartbeat_ns=NOW + 1,
        )
        plan = plan_for(evidence)
        self.assertEqual(plan.state, PlanState.HALTED)
        self.assertEqual(plan.commands, (WriteHalt(HaltReason.EVIDENCE_INVALID),))


class OwnerTimeoutTests(unittest.TestCase):
    def test_every_incomplete_owner_phase_times_out_to_global_halt(self):
        phases = (
            AttemptPhase.RUN_REQUESTED,
            AttemptPhase.RUNNER_STARTED,
            AttemptPhase.JOB_ASSIGNED,
            AttemptPhase.RUNNING,
            AttemptPhase.STOP_PENDING,
            AttemptPhase.QUIESCENT,
        )
        for phase in phases:
            with self.subTest(phase=phase):
                evidence = phase_evidence(phase, deadline=NOW)
                plan = plan_for(evidence)
                self.assertEqual(plan.state, PlanState.HALTED)
                self.assertEqual(
                    plan.commands,
                    (WriteHalt(HaltReason.OWNER_UNRESPONSIVE),),
                )

    def test_timeout_never_becomes_retry(self):
        plan = plan_for(phase_evidence(AttemptPhase.STOP_PENDING, deadline=NOW))
        self.assertFalse(any(type(command) is FailAttempt for command in plan.commands))

    def test_full_quiescent_result_beats_expired_owner_deadline(self):
        evidence = phase_evidence(
            AttemptPhase.QUIESCENT,
            deadline=NOW - 1,
            result=exact_result(),
        )
        plan = plan_for(evidence)
        self.assertEqual(plan.state, PlanState.RUNNING)
        self.assertIs(type(plan.commands[0]), CompleteAttempt)

    def test_quiescent_and_result_at_deadline_are_allowed(self):
        at_deadline = 1_096 * S
        evidence = InProgressAttemptEvidence(
            ref(),
            DIGEST_A,
            AttemptPhase.QUIESCENT,
            owner_deadline_ns=at_deadline,
            runner_started=started(),
            job_assigned=assigned(),
            running=running(),
            snapshot=snapshot(process_alive=False, process_quiescent=True),
            quiescent=quiet(when=at_deadline),
            result=exact_result(when=at_deadline),
        )
        plan = plan_for(evidence)
        self.assertEqual(plan.state, PlanState.RUNNING)
        self.assertIs(type(plan.commands[0]), CompleteAttempt)

    def test_quiescent_after_deadline_halts_instead_of_completing(self):
        evidence = phase_evidence(
            AttemptPhase.QUIESCENT,
            deadline=1_094 * S,
            result=exact_result(),
        )
        plan = plan_for(evidence)
        self.assertEqual(plan.state, PlanState.HALTED)
        self.assertEqual(plan.commands, (WriteHalt(HaltReason.EVIDENCE_INVALID),))

    def test_result_after_deadline_halts_even_if_quiescence_was_timely(self):
        deadline = 1_095 * S
        evidence = InProgressAttemptEvidence(
            ref(),
            DIGEST_A,
            AttemptPhase.QUIESCENT,
            owner_deadline_ns=deadline,
            runner_started=started(),
            job_assigned=assigned(),
            running=running(),
            snapshot=snapshot(process_alive=False, process_quiescent=True),
            quiescent=quiet(when=deadline),
            result=exact_result(when=deadline + 1),
        )
        plan = plan_for(evidence)
        self.assertEqual(plan.state, PlanState.HALTED)
        self.assertEqual(plan.commands, (WriteHalt(HaltReason.EVIDENCE_INVALID),))

    def test_owner_deadline_is_required_and_cannot_precede_marker(self):
        with self.assertRaisesRegex(TickCoreError, "owner-deadline-missing"):
            InProgressAttemptEvidence(ref(), DIGEST_A, AttemptPhase.RUN_REQUESTED)
        with self.assertRaisesRegex(TickCoreError, "owner-deadline-before-phase"):
            InProgressAttemptEvidence(
                ref(),
                DIGEST_A,
                AttemptPhase.RUNNER_STARTED,
                owner_deadline_ns=1_000 * S,
                runner_started=started(),
            )


class FailClosedPlannerTests(unittest.TestCase):
    def test_clock_failures_halt_without_reading_adapter(self):
        adapter = Adapter()
        plan = build_tick_plan(adapter, Clock(raises=True))
        self.assertEqual(plan.commands, (WriteHalt(HaltReason.CLOCK_READ_FAILED),))
        self.assertEqual(adapter.calls, [])
        for invalid in (-1, True, 1.5):
            with self.subTest(invalid=invalid):
                self.assertEqual(
                    build_tick_plan(Adapter(), Clock(invalid)).commands[0].reason,
                    HaltReason.CLOCK_INVALID,
                )

    def test_audit_failure_and_active_halt_short_circuit(self):
        plan = build_tick_plan(
            Adapter(audit=AuditEvidence(AuditStatus.FAIL, False)), Clock()
        )
        self.assertEqual(plan.commands, (WriteHalt(HaltReason.AUDIT_FAILED),))
        adapter = Adapter(audit=AuditEvidence(AuditStatus.PASS, True))
        plan = build_tick_plan(adapter, Clock())
        self.assertEqual(plan.state, PlanState.HALTED)
        self.assertEqual(plan.commands, ())
        self.assertEqual(adapter.calls, ["audit"])

    def test_read_failures_halt(self):
        cases = {
            "audit": HaltReason.AUDIT_READ_FAILED,
            "attempts": HaltReason.EVIDENCE_READ_FAILED,
            "candidate": HaltReason.CANDIDATE_READ_FAILED,
        }
        for point, reason in cases.items():
            with self.subTest(point=point):
                plan = build_tick_plan(Adapter(raise_at=point), Clock())
                self.assertEqual(plan.commands, (WriteHalt(reason),))

    def test_unknown_and_corrupt_attempts_halt(self):
        for issue, reason in (
            (EvidenceIssue.UNKNOWN, HaltReason.EVIDENCE_UNKNOWN),
            (EvidenceIssue.CORRUPT, HaltReason.EVIDENCE_CORRUPT),
        ):
            evidence = UnreadableAttemptEvidence(ref(), issue)
            plan = build_tick_plan(Adapter(attempts=(evidence,)), Clock())
            self.assertEqual(plan.commands, (WriteHalt(reason),))

    def test_duplicate_task_attempt_evidence_halts(self):
        attempts = (
            phase_evidence(AttemptPhase.LAUNCH_INTENT),
            phase_evidence(
                AttemptPhase.DISPATCH_READY,
                attempt_ref=ref(attempt=2, nonce=NONCE_B),
            ),
        )
        plan = build_tick_plan(Adapter(attempts=attempts), Clock())
        self.assertEqual(plan.commands, (WriteHalt(HaltReason.EVIDENCE_INVALID),))

    def test_candidate_for_existing_task_halts(self):
        evidence = phase_evidence(AttemptPhase.RUNNER_STARTED)
        candidate = PreparedCandidate(ref(attempt=2, nonce=NONCE_B), DIGEST_B)
        plan = build_tick_plan(Adapter(attempts=(evidence,), candidate=candidate), Clock())
        self.assertEqual(plan.commands, (WriteHalt(HaltReason.CANDIDATE_INVALID),))

    def test_strict_identity_and_command_phases(self):
        with self.assertRaises(TickCoreError):
            AttemptRef("task-one", True, NONCE_A)
        with self.assertRaises(TickCoreError):
            PreparedCandidate(ref(), "bad")
        with self.assertRaisesRegex(TickCoreError, "expected-phase"):
            DispatchAttempt(ref(), DIGEST_A, AttemptPhase.RUNNING)
        with self.assertRaisesRegex(TickCoreError, "expected-phase"):
            CompleteAttempt(ref(), DIGEST_A, AttemptPhase.RUNNING)

    def test_tick_plan_rejects_mixed_phases_and_duplicate_tasks(self):
        with self.assertRaisesRegex(TickCoreError, "multiple-commands-for-task"):
            TickPlan(
                NOW,
                PlanState.RUNNING,
                (
                    ClaimPrepared(ref(), DIGEST_A),
                    DispatchAttempt(ref(), DIGEST_A, AttemptPhase.DISPATCH_READY),
                ),
            )
        with self.assertRaisesRegex(TickCoreError, "mixed-durable-phases"):
            TickPlan(
                NOW,
                PlanState.RUNNING,
                (
                    ClaimPrepared(ref("claim", nonce=NONCE_A), DIGEST_A),
                    DispatchAttempt(
                        ref("dispatch", nonce=NONCE_B),
                        DIGEST_B,
                        AttemptPhase.DISPATCH_READY,
                    ),
                ),
            )


class OrderedExecutorTests(unittest.TestCase):
    @staticmethod
    def claim_plan():
        attempts = tuple(
            phase_evidence(
                AttemptPhase.LAUNCH_INTENT,
                attempt_ref=ref(name, nonce=nonce),
                digest=digest,
            )
            for name, nonce, digest in (
                ("claim-c", "3" * 32, "c" * 64),
                ("claim-a", NONCE_A, DIGEST_A),
                ("claim-b", NONCE_B, DIGEST_B),
            )
        )
        return build_tick_plan(Adapter(attempts=attempts), Clock())

    def test_executor_aborts_on_first_exception(self):
        plan = self.claim_plan()

        class ExplodingExecutor:
            def __init__(self):
                self.calls = []

            def execute(self, command):
                self.calls.append(command)
                raise RuntimeError("injected")

        executor = ExplodingExecutor()
        with self.assertRaisesRegex(RuntimeError, "injected"):
            execute_tick_plan(plan, executor)
        self.assertEqual(executor.calls, [plan.commands[0]])

    def test_executor_aborts_on_exact_false_or_non_bool(self):
        plan = self.claim_plan()
        for refused in (False, None, 1):
            with self.subTest(refused=refused):
                class RefusingExecutor:
                    def __init__(self):
                        self.calls = []

                    def execute(self, command):
                        self.calls.append(command)
                        return refused

                executor = RefusingExecutor()
                with self.assertRaises(CommandRefusedError):
                    execute_tick_plan(plan, executor)
                self.assertEqual(executor.calls, [plan.commands[0]])

    def test_executor_runs_valid_plan_in_order(self):
        plan = self.claim_plan()

        class AcceptingExecutor:
            def __init__(self):
                self.calls = []

            def execute(self, command):
                self.calls.append(command)
                return True

        executor = AcceptingExecutor()
        execute_tick_plan(plan, executor)
        self.assertEqual(executor.calls, list(plan.commands))


if __name__ == "__main__":
    unittest.main()
