"""Pure policy engine for one autonomy supervisor tick.

This module deliberately does not inspect processes or mutate the queue.  It
turns an attested task/process snapshot into a small, closed decision.  The
Windows adapter and queue CLI integration execute that decision separately,
which keeps policy tests deterministic and makes fail-closed behaviour easy to
audit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re


NANOSECONDS_PER_SECOND = 1_000_000_000
TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class PolicyError(ValueError):
    """The supplied snapshot is unsafe or internally inconsistent."""


class Action(str, Enum):
    NOOP = "noop"
    REQUEST_STOP = "request_stop"
    RETRY_ATTEMPT = "retry_attempt"
    BLOCK = "block"
    FAIL = "fail"


class Cause(str, Enum):
    HEALTHY = "healthy"
    HEARTBEAT_STALE = "heartbeat_stale"
    PROGRESS_STALE = "progress_stale"
    PROCESS_EXITED = "process_exited"
    STOP_NOT_VERIFIED = "stop_not_verified"


@dataclass(frozen=True)
class TaskSnapshot:
    task_id: str
    attempt: int
    max_attempts: int
    restart_safe: bool
    max_step_seconds: int
    heartbeat_timeout_seconds: int
    attempt_started_ns: int
    heartbeat_ns: int | None
    progress_ns: int | None
    process_alive: bool
    process_quiescent: bool


@dataclass(frozen=True)
class Decision:
    action: Action
    cause: Cause


@dataclass(frozen=True)
class StopPending:
    """Durable binding written before a process-stop attempt begins."""

    task_id: str
    attempt: int
    cause: Cause
    detected_ns: int


def _validate(snapshot: TaskSnapshot, now_ns: int) -> None:
    if type(snapshot.task_id) is not str or not TASK_ID_RE.fullmatch(snapshot.task_id):
        raise PolicyError("task-id-empty")
    if type(snapshot.attempt) is not int or snapshot.attempt < 1:
        raise PolicyError("attempt-invalid")
    if type(snapshot.max_attempts) is not int or not 1 <= snapshot.max_attempts <= 2:
        raise PolicyError("max-attempts-invalid")
    if snapshot.attempt > snapshot.max_attempts:
        raise PolicyError("attempt-exceeds-max")
    if not isinstance(snapshot.restart_safe, bool):
        raise PolicyError("restart-safe-invalid")
    if (
        type(snapshot.max_step_seconds) is not int
        or not 1 <= snapshot.max_step_seconds <= 86_400
    ):
        raise PolicyError("max-step-seconds-invalid")
    if (
        type(snapshot.heartbeat_timeout_seconds) is not int
        or not 1 <= snapshot.heartbeat_timeout_seconds <= 3_600
    ):
        raise PolicyError("heartbeat-timeout-invalid")
    if type(now_ns) is not int or type(snapshot.attempt_started_ns) is not int:
        raise PolicyError("time-type-invalid")
    if now_ns < 0 or snapshot.attempt_started_ns < 0:
        raise PolicyError("time-invalid")
    if snapshot.attempt_started_ns > now_ns:
        raise PolicyError("attempt-start-in-future")
    for label, value in (
        ("heartbeat", snapshot.heartbeat_ns),
        ("progress", snapshot.progress_ns),
    ):
        if value is not None and type(value) is not int:
            raise PolicyError(f"{label}-time-type-invalid")
        if value is not None and (value < snapshot.attempt_started_ns or value > now_ns):
            raise PolicyError(f"{label}-time-invalid")
    if type(snapshot.process_alive) is not bool or type(snapshot.process_quiescent) is not bool:
        raise PolicyError("process-state-type-invalid")
    if snapshot.process_alive and snapshot.process_quiescent:
        raise PolicyError("live-process-cannot-be-quiescent")


def _terminal_after_failure(snapshot: TaskSnapshot) -> Action:
    if not snapshot.process_quiescent:
        return Action.BLOCK
    if not snapshot.restart_safe:
        return Action.BLOCK
    if snapshot.attempt >= snapshot.max_attempts:
        return Action.FAIL
    return Action.RETRY_ATTEMPT


def decide_task(snapshot: TaskSnapshot, *, now_ns: int) -> Decision:
    """Return the only allowed supervisor action for ``snapshot``.

    A live stale process is never transitioned immediately: the caller must
    first stop its contained process tree and prove quiescence.  If that proof
    fails, a follow-up snapshot with ``process_quiescent=False`` can only block.
    Progress timeout is intentionally stricter than a missing heartbeat: it is
    always blocked after a verified stop instead of being retried blindly.
    """

    _validate(snapshot, now_ns)
    heartbeat_base = (
        snapshot.heartbeat_ns
        if snapshot.heartbeat_ns is not None
        else snapshot.attempt_started_ns
    )
    progress_base = (
        snapshot.progress_ns
        if snapshot.progress_ns is not None
        else snapshot.attempt_started_ns
    )
    heartbeat_stale = (
        now_ns - heartbeat_base
        > snapshot.heartbeat_timeout_seconds * NANOSECONDS_PER_SECOND
    )
    progress_stale = (
        now_ns - progress_base
        > snapshot.max_step_seconds * NANOSECONDS_PER_SECOND
    )

    if snapshot.process_alive:
        # Progress overtime is the stricter condition.  If both clocks are
        # stale, retrying as a heartbeat failure would hide a looping worker.
        if progress_stale:
            return Decision(Action.REQUEST_STOP, Cause.PROGRESS_STALE)
        if heartbeat_stale:
            return Decision(Action.REQUEST_STOP, Cause.HEARTBEAT_STALE)
        return Decision(Action.NOOP, Cause.HEALTHY)

    if not snapshot.process_quiescent:
        return Decision(Action.BLOCK, Cause.STOP_NOT_VERIFIED)
    return Decision(
        _terminal_after_failure(snapshot),
        Cause.PROCESS_EXITED,
    )


def decide_after_stop(
    snapshot: TaskSnapshot,
    *,
    pending: StopPending,
    now_ns: int,
) -> Decision:
    """Finish a durable two-phase stop started by :func:`decide_task`.

    The caller must persist ``pending`` before attempting to stop the process
    tree.  Re-reading that marker after a crash prevents a progress
    timeout from being misclassified as a quiet exit and retried.
    """

    _validate(snapshot, now_ns)
    if type(pending) is not StopPending:
        raise PolicyError("stop-pending-type-invalid")
    if type(pending.task_id) is not str or not TASK_ID_RE.fullmatch(pending.task_id):
        raise PolicyError("stop-pending-task-id-invalid")
    if type(pending.attempt) is not int:
        raise PolicyError("stop-pending-attempt-invalid")
    if pending.task_id != snapshot.task_id or pending.attempt != snapshot.attempt:
        raise PolicyError("stop-pending-binding-mismatch")
    if type(pending.cause) is not Cause or pending.cause not in (
        Cause.HEARTBEAT_STALE,
        Cause.PROGRESS_STALE,
    ):
        raise PolicyError("original-stop-cause-invalid")
    if type(pending.detected_ns) is not int or not (
        snapshot.attempt_started_ns <= pending.detected_ns <= now_ns
    ):
        raise PolicyError("stop-pending-time-invalid")
    if snapshot.process_alive or not snapshot.process_quiescent:
        return Decision(Action.BLOCK, Cause.STOP_NOT_VERIFIED)
    if pending.cause is Cause.PROGRESS_STALE:
        return Decision(Action.BLOCK, Cause.PROGRESS_STALE)
    return Decision(_terminal_after_failure(snapshot), Cause.HEARTBEAT_STALE)
