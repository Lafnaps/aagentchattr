from __future__ import annotations

import unittest

from autonomy.supervisor import (
    Action,
    Cause,
    NANOSECONDS_PER_SECOND,
    PolicyError,
    StopPending,
    TaskSnapshot,
    decide_after_stop,
    decide_task,
)


S = NANOSECONDS_PER_SECOND


def snapshot(**overrides) -> TaskSnapshot:
    values = {
        "task_id": "task-one",
        "attempt": 1,
        "max_attempts": 2,
        "restart_safe": True,
        "max_step_seconds": 3600,
        "heartbeat_timeout_seconds": 120,
        "attempt_started_ns": 1_000 * S,
        "heartbeat_ns": 1_090 * S,
        "progress_ns": 1_060 * S,
        "process_alive": True,
        "process_quiescent": False,
    }
    values.update(overrides)
    return TaskSnapshot(**values)


class SupervisorPolicyTests(unittest.TestCase):
    def test_policy_table(self):
        cases = [
            (
                "healthy",
                snapshot(),
                1_100 * S,
                (Action.NOOP, Cause.HEALTHY),
            ),
            (
                "stale-heartbeat-safe",
                snapshot(heartbeat_ns=1_000 * S),
                1_121 * S,
                (Action.REQUEST_STOP, Cause.HEARTBEAT_STALE),
            ),
            (
                "stale-heartbeat-unsafe",
                snapshot(heartbeat_ns=1_000 * S, restart_safe=False),
                1_121 * S,
                (Action.REQUEST_STOP, Cause.HEARTBEAT_STALE),
            ),
            (
                "stale-progress",
                snapshot(
                    max_step_seconds=60,
                    heartbeat_ns=1_120 * S,
                    progress_ns=1_000 * S,
                ),
                1_121 * S,
                (Action.REQUEST_STOP, Cause.PROGRESS_STALE),
            ),
            (
                "quiet-exit-safe",
                snapshot(process_alive=False, process_quiescent=True),
                1_100 * S,
                (Action.RETRY_ATTEMPT, Cause.PROCESS_EXITED),
            ),
            (
                "quiet-exit-unsafe",
                snapshot(
                    restart_safe=False, process_alive=False, process_quiescent=True
                ),
                1_100 * S,
                (Action.BLOCK, Cause.PROCESS_EXITED),
            ),
            (
                "attempt-budget-exhausted",
                snapshot(
                    attempt=2, process_alive=False, process_quiescent=True
                ),
                1_100 * S,
                (Action.FAIL, Cause.PROCESS_EXITED),
            ),
            (
                "stop-not-verified",
                snapshot(process_alive=False, process_quiescent=False),
                1_100 * S,
                (Action.BLOCK, Cause.STOP_NOT_VERIFIED),
            ),
        ]
        for label, state, now_ns, expected in cases:
            with self.subTest(label):
                decision = decide_task(state, now_ns=now_ns)
                self.assertEqual(
                    (decision.action, decision.cause), expected
                )

    def test_threshold_is_strictly_greater_than_configured_age(self):
        at_boundary = decide_task(
            snapshot(heartbeat_ns=1_000 * S), now_ns=1_120 * S
        )
        after_boundary = decide_task(
            snapshot(heartbeat_ns=1_000 * S), now_ns=1_120 * S + 1
        )
        self.assertEqual(at_boundary.action, Action.NOOP)
        self.assertEqual(after_boundary.action, Action.REQUEST_STOP)

    def test_simultaneous_stale_clocks_block_after_stop(self):
        decision = decide_task(
            snapshot(
                heartbeat_ns=1_000 * S,
                progress_ns=1_000 * S,
                max_step_seconds=60,
            ),
            now_ns=1_121 * S,
        )
        self.assertEqual(decision.cause, Cause.PROGRESS_STALE)

    def test_two_phase_stop_preserves_original_cause(self):
        stopped = snapshot(process_alive=False, process_quiescent=True)
        progress_pending = StopPending(
            "task-one", 1, Cause.PROGRESS_STALE, 1_090 * S
        )
        heartbeat_pending = StopPending(
            "task-one", 1, Cause.HEARTBEAT_STALE, 1_090 * S
        )
        progress = decide_after_stop(
            stopped, pending=progress_pending, now_ns=1_100 * S
        )
        heartbeat = decide_after_stop(
            stopped, pending=heartbeat_pending, now_ns=1_100 * S
        )
        unverified = decide_after_stop(
            snapshot(process_alive=True, process_quiescent=False),
            pending=heartbeat_pending,
            now_ns=1_100 * S,
        )
        self.assertEqual((progress.action, progress.cause), (Action.BLOCK, Cause.PROGRESS_STALE))
        self.assertEqual((heartbeat.action, heartbeat.cause), (Action.RETRY_ATTEMPT, Cause.HEARTBEAT_STALE))
        self.assertEqual((unverified.action, unverified.cause), (Action.BLOCK, Cause.STOP_NOT_VERIFIED))

    def test_stop_pending_is_strictly_typed_and_bound(self):
        stopped = snapshot(process_alive=False, process_quiescent=True)
        bad_values = [
            StopPending("other-task", 1, Cause.HEARTBEAT_STALE, 1_090 * S),
            StopPending("task-one", 2, Cause.HEARTBEAT_STALE, 1_090 * S),
            StopPending("task-one", True, Cause.HEARTBEAT_STALE, 1_090 * S),
            StopPending("task-one", 1.0, Cause.HEARTBEAT_STALE, 1_090 * S),
            StopPending("task-one", 1, "progress_stale", 1_090 * S),
            StopPending("task-one", 1, None, 1_090 * S),
            StopPending("task-one", 1, Cause.HEALTHY, 1_090 * S),
            StopPending("task-one", 1, Cause.HEARTBEAT_STALE, 999 * S),
        ]
        for pending in bad_values:
            with self.subTest(pending=pending):
                with self.assertRaises(PolicyError):
                    decide_after_stop(stopped, pending=pending, now_ns=1_100 * S)

    def test_invalid_or_contradictory_snapshots_fail_closed(self):
        invalid = [
            snapshot(attempt=0),
            snapshot(attempt=3),
            snapshot(process_alive=True, process_quiescent=True),
            snapshot(heartbeat_ns=999 * S),
            snapshot(progress_ns=1_101 * S),
            snapshot(max_attempts=3),
            snapshot(process_alive=1),
            snapshot(heartbeat_ns=1.5),
            snapshot(task_id="../escape"),
            snapshot(task_id=1),
            snapshot(max_step_seconds=86_401),
            snapshot(heartbeat_timeout_seconds=3_601),
        ]
        for state in invalid:
            with self.subTest(state=state):
                with self.assertRaises(PolicyError):
                    decide_task(state, now_ns=1_100 * S)


if __name__ == "__main__":
    unittest.main()
