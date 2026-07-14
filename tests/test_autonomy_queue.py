"""Hermetic tests for autonomy/queue_cli.py (M0+M1).

Temp directories only: no live agentchattr data, processes, network, SVN, or
TradeStation paths. The parallel-claim and module-invocation tests use real
child processes (``python -m autonomy.queue_cli``) so the documented CLI
contract and the atomic-rename claim race are exercised across OS process
boundaries. Link-based escape tests skip only where the platform can create
neither a symlink nor an NTFS junction.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from autonomy import queue_cli  # noqa: E402


def run_cli(*argv: str):
    """Run the CLI in-process; asserts the stdout contract on every call:
    exactly one JSON object on stdout, nothing on stderr."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = queue_cli.main(list(argv))
    text = stdout.getvalue()
    lines = text.strip().splitlines()
    assert len(lines) == 1, f"stdout must be exactly one JSON object: {text!r}"
    assert stderr.getvalue() == "", f"stderr must be empty: {stderr.getvalue()!r}"
    return code, json.loads(lines[0])


def run_cli_subprocess(*argv: str):
    proc = subprocess.run(
        [sys.executable, "-m", "autonomy.queue_cli", *argv],
        capture_output=True, text=True, timeout=120, cwd=str(ROOT),
    )
    return proc


def sha256_upper(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def can_make_file_symlink(base: Path) -> bool:
    target = base / "symlink-probe-target.txt"
    target.write_bytes(b"probe")
    try:
        os.symlink(str(target), str(base / "symlink-probe-link.txt"))
    except (OSError, NotImplementedError):
        return False
    return True


def can_make_junction(base: Path) -> bool:
    if os.name != "nt":
        return False
    target = base / "junction-probe-target"
    target.mkdir()
    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J",
         str(base / "junction-probe-link"), str(target)],
        capture_output=True,
    )
    return proc.returncode == 0


class AutonomyQueueTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="autonomy-queue-test-")
        self.base = Path(self._tmp.name)
        self.root = str(self.base / "qroot")
        code, payload = run_cli("--root", self.root, "init")
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"])
        self.allowed = self.base / "allowed"
        self.allowed.mkdir()
        self.payload_file = self.allowed / "payload.txt"
        self.payload_file.write_bytes(b"night-autonomy payload\n")
        self.payload_sha = sha256_upper(self.payload_file.read_bytes())

    def tearDown(self):
        self._tmp.cleanup()

    # ------------------------------------------------------------- helpers

    def make_card(self, task_id: str, **overrides) -> dict:
        card = {
            "version": 1,
            "task_id": task_id,
            "profile": "claude-work",
            "model": "claude-fable-5",
            "allowed_root": str(self.allowed),
            "max_step_seconds": 600,
            "created_utc": "2026-07-13T12:00:00.000Z",
            "payload_relpath": "payload.txt",
            "payload_sha256": self.payload_sha,
        }
        card.update(overrides)
        return {key: value for key, value in card.items() if value is not ...}

    def write_card_file(self, card: dict, name: str | None = None) -> Path:
        source = self.base / (name or f"card-{card.get('task_id', 'x')}.json")
        source.write_text(json.dumps(card), encoding="ascii")
        return source

    def enqueue(self, card: dict, expect_code: int = 0):
        source = self.write_card_file(card)
        code, payload = run_cli(
            "--root", self.root, "enqueue", "--card", str(source)
        )
        self.assertEqual(code, expect_code, payload)
        return payload

    def claim(self, worker: str = "worker-a", profile: str = "claude-work",
              model: str = "claude-fable-5"):
        return run_cli(
            "--root", self.root, "claim", "--profile", profile,
            "--model", model, "--worker", worker,
        )

    def claim_expect(self, task_id: str) -> dict:
        code, payload = self.claim()
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["task_id"], task_id)
        return payload

    def claim_expect_empty(self) -> dict:
        code, payload = self.claim()
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "nothing-to-claim")
        self.assertIsNone(payload["claimed"])
        return payload

    def state_of(self, task_id: str, root: str | None = None) -> str | None:
        for state in queue_cli.STATES:
            if (Path(root or self.root) / state / f"{task_id}.json").is_file():
                return state
        return None

    def card_of(self, task_id: str) -> dict:
        state = self.state_of(task_id)
        raw = (Path(self.root) / state / f"{task_id}.json").read_text("utf-8")
        return json.loads(raw)

    def events_of(self, task_id: str) -> dict[str, bytes]:
        directory = Path(self.root) / "events" / task_id
        return {
            path.name: path.read_bytes()
            for path in sorted(directory.glob("*.json"))
        }

    def durable_snapshot(self, root: str | None = None) -> dict[str, bytes | None]:
        """Content/layout snapshot excluding tmp lock implementation detail."""
        base = Path(root or self.root)
        snapshot: dict[str, bytes | None] = {}
        for top in queue_cli.STATES + (
            "events", "attempts", queue_cli.EXACT_PROTOCOL_DIR,
        ):
            parent = base / top
            for path in sorted(parent.rglob("*")):
                relative = str(path.relative_to(base))
                snapshot[relative] = path.read_bytes() if path.is_file() else None
        return snapshot

    def audit(self, root: str | None = None):
        return run_cli("--root", root or self.root, "audit")

    def audit_kinds(self, root: str | None = None):
        code, payload = self.audit(root)
        return code, {gap["kind"] for gap in payload["gaps"]}, payload

    def peek_exact(self, task_id: str):
        return run_cli(
            "--root", self.root, "peek-exact", "--task-id", task_id,
        )

    def claim_exact(self, task_id: str, next_attempt: int, digest: str,
                    worker: str = "worker-a", profile: str = "claude-work",
                    model: str = "claude-fable-5"):
        return run_cli(
            "--root", self.root, "claim-exact", "--task-id", task_id,
            "--expected-next-attempt", str(next_attempt),
            "--expected-digest", digest, "--profile", profile,
            "--model", model, "--worker", worker,
        )

    def quarantine_exact_payload(
        self, task_id: str, worker: str = "worker-a"
    ):
        return run_cli(
            "--root", self.root, "quarantine-exact-payload",
            "--task-id", task_id, "--worker", worker,
        )

    def requeue_exact(self, task_id: str, attempt: int, digest: str,
                      worker: str = "worker-a"):
        return run_cli(
            "--root", self.root, "requeue-exact", "--task-id", task_id,
            "--expected-attempt", str(attempt),
            "--expected-digest", digest, "--worker", worker,
        )

    def enqueue_with_own_payload(self, task_id: str, **overrides) -> Path:
        """Enqueue with a task-private payload so drift stays isolated."""
        payload = self.allowed / f"{task_id}.txt"
        payload.write_bytes(f"payload for {task_id}\n".encode("ascii"))
        self.enqueue(self.make_card(
            task_id,
            payload_relpath=payload.name,
            payload_sha256=sha256_upper(payload.read_bytes()),
            **overrides,
        ))
        return payload

    def write_event(self, task_id: str, seq: int, transition: str,
                    attempt: int, from_state: str | None = None,
                    to_state: str | None = None, root: str | None = None):
        table_from, table_to = queue_cli.TRANSITIONS[transition]
        event = {
            "version": 1,
            "task_id": task_id,
            "seq": seq,
            "transition": transition,
            "from_state": from_state if from_state is not None else table_from,
            "to_state": to_state if to_state is not None else table_to,
            "attempt": attempt,
            "worker": "worker-x",
            "reason": "manual" if transition in queue_cli.BLOCK_TRANSITIONS else "",
            "recorded_utc": "2026-07-13T12:00:00.000Z",
        }
        events_dir = Path(root or self.root) / "events" / task_id
        events_dir.mkdir(parents=True, exist_ok=True)
        (events_dir / f"{seq:06d}.json").write_text(
            json.dumps(event), encoding="ascii"
        )

    # ------------------------------------------------------- CLI contract

    def test_module_invocation_contract(self):
        proc = run_cli_subprocess("--root", self.root, "audit")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, "")
        lines = proc.stdout.strip().splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertTrue(payload["ok"])

        # Argument errors also honor the one-JSON-object / exit-2 contract.
        for argv in (
            ("--root", self.root),                       # missing command
            ("--root", self.root, "unknown-verb"),       # unknown command
            ("--root", self.root, "claim"),              # missing options
        ):
            proc = run_cli_subprocess(*argv)
            self.assertEqual(proc.returncode, 2, argv)
            self.assertEqual(proc.stderr, "", argv)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["error"], "invalid-arguments")

    def test_malformed_json_and_utf8_are_always_single_json_failures(self):
        def exact(proc, code, error=None):
            self.assertEqual(proc.returncode, code, proc.stderr)
            self.assertEqual(proc.stderr, "")
            self.assertEqual(len(proc.stdout.strip().splitlines()), 1)
            payload = json.loads(proc.stdout)
            if error is not None:
                self.assertEqual(payload["error"], error)
            return payload

        source = self.base / "malformed-card.json"
        for raw, error in ((b"{", "malformed-json"),
                           (b'{"x":"\xff"}', "invalid-utf8")):
            with self.subTest(kind=error, command="enqueue"):
                source.write_bytes(raw)
                exact(
                    run_cli_subprocess(
                        "--root", self.root, "enqueue", "--card", str(source)
                    ),
                    2, error,
                )

        # Every command that reads a durable JSON object keeps the same
        # stdout/stderr boundary; no parser exception can become a traceback.
        command_cases = (
            ("in_progress", "complete", ("--worker", "worker-a")),
            ("in_progress", "fail", ("--worker", "worker-a")),
            ("in_progress", "block",
             ("--worker", "worker-a", "--reason", "manual")),
            ("blocked", "requeue", ("--worker", "worker-a")),
        )
        for index, (state, command, extra) in enumerate(command_cases):
            task_id = f"task-bad-{index}"
            path = Path(self.root) / state / f"{task_id}.json"
            path.write_bytes(b"{")
            with self.subTest(command=command):
                exact(
                    run_cli_subprocess(
                        "--root", self.root, command, "--task-id", task_id,
                        *extra,
                    ),
                    2, "malformed-json",
                )

        bad_claim = Path(self.root) / "queue" / "task-bad-claim.json"
        bad_claim.write_bytes(b"\xff")
        claim_payload = exact(
            run_cli_subprocess(
                "--root", self.root, "claim", "--profile", "claude-work",
                "--model", "claude-fable-5", "--worker", "worker-a",
            ),
            2, "nothing-to-claim",
        )
        self.assertIsNone(claim_payload["claimed"])
        self.assertEqual(self.state_of("task-bad-claim"), "blocked")

        audit_payload = exact(
            run_cli_subprocess("--root", self.root, "audit"), 3
        )
        self.assertEqual(audit_payload["audit"], "AUDIT_GAP")

        bad_root = self.base / "bad-marker-root"
        bad_root.mkdir()
        (bad_root / queue_cli.ROOT_MARKER).write_bytes(b"\xff")
        exact(
            run_cli_subprocess("--root", str(bad_root), "audit"),
            2, "root-marker-invalid",
        )
        exact(
            run_cli_subprocess("--root", str(bad_root), "init"),
            2, "root-marker-invalid",
        )

    def test_contract_documents_real_init_invocation(self):
        contract = json.loads(
            (ROOT / "autonomy" / "contract.json").read_text("utf-8")
        )
        self.assertEqual(contract["cli"]["commands"]["init"], "--root R init")

    def test_claim_with_no_eligible_work_is_documented_nonsuccess(self):
        payload = self.claim_expect_empty()
        self.assertEqual(payload, {
            "claimed": None, "error": "nothing-to-claim", "ok": False,
        })

    def test_init_is_idempotent_and_marker_is_strict_closed_schema(self):
        code, payload = run_cli("--root", self.root, "init")
        self.assertEqual(code, 0, payload)
        marker = Path(self.root) / "autonomy-root.json"
        for bad in (
            {"version": 1, "name": "agentchattr-autonomy-queue", "x": 1},
            {"version": True, "name": "agentchattr-autonomy-queue"},
            {"version": 1.0, "name": "agentchattr-autonomy-queue"},
            {"version": 1},
            {"version": 2, "name": "agentchattr-autonomy-queue"},
        ):
            marker.write_text(json.dumps(bad), encoding="ascii")
            code, payload = self.audit()
            self.assertEqual(code, 2, (bad, payload))
            self.assertEqual(payload["error"], "root-marker-invalid")
        code, payload = run_cli("--root", str(self.base / "no-marker"), "audit")
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "root-missing")
        (self.base / "bare").mkdir()
        code, payload = run_cli("--root", str(self.base / "bare"), "audit")
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "root-marker-missing")
        code, payload = run_cli("--root", "relative-root", "audit")
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "root-not-absolute")

    # -------------------------------------------------------- transitions

    def test_full_transition_matrix_with_clean_audit(self):
        self.enqueue(self.make_card("task-block"))
        self.enqueue(self.make_card("task-done"))
        payload = self.claim_expect("task-block")
        self.assertTrue(payload["attempt_dir"].endswith("a1"))
        self.assertEqual(payload["claimed"]["attempt"], 1)
        self.assertEqual(
            Path(payload["payload_path"]).read_bytes(),
            self.payload_file.read_bytes(),
        )
        code, payload = run_cli(
            "--root", self.root, "block", "--task-id", "task-block",
            "--worker", "worker-a", "--reason", "owner-gate",
        )
        self.assertEqual(code, 0, payload)
        self.assertEqual(self.state_of("task-block"), "blocked")

        self.claim_expect("task-done")
        code, payload = run_cli(
            "--root", self.root, "complete", "--task-id", "task-done",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 0, payload)
        self.assertEqual(self.state_of("task-done"), "done")

        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id", "task-block",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 0, payload)
        self.assertEqual(self.state_of("task-block"), "queue")
        self.assertEqual(self.card_of("task-block")["attempt"], 1)

        self.claim_expect("task-block")
        self.assertEqual(self.card_of("task-block")["attempt"], 2)
        self.assertTrue(
            (Path(self.root) / "attempts" / "task-block" / "a2").is_dir()
        )
        code, payload = run_cli(
            "--root", self.root, "complete", "--task-id", "task-block",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 0, payload)

        code, payload = self.audit()
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["gaps"], [])

        # Illegal transitions are refused fail-closed.
        code, payload = run_cli(
            "--root", self.root, "complete", "--task-id", "task-done",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "card-not-in-in_progress")

    def test_defaults_are_persisted_explicitly(self):
        self.enqueue(self.make_card("task-default"))
        stored = self.card_of("task-default")
        self.assertIs(stored["restart_safe"], False)
        self.assertEqual(stored["attempt"], 0)
        self.assertEqual(stored["max_attempts"], 2)

    def test_retry_then_final_failure_with_max_attempts_two(self):
        self.enqueue(self.make_card("task-retry", max_attempts=2))
        self.claim_expect("task-retry")
        code, payload = run_cli(
            "--root", self.root, "fail", "--task-id", "task-retry",
            "--worker", "worker-a", "--reason", "boom-1",
        )
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["state"], "queue")
        self.assertEqual(self.card_of("task-retry")["attempt"], 1)

        self.claim_expect("task-retry")
        self.assertEqual(self.card_of("task-retry")["attempt"], 2)
        code, payload = run_cli(
            "--root", self.root, "fail", "--task-id", "task-retry",
            "--worker", "worker-a", "--reason", "boom-2",
        )
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["state"], "failed")
        attempts = Path(self.root) / "attempts" / "task-retry"
        self.assertTrue((attempts / "a1").is_dir())
        self.assertTrue((attempts / "a2").is_dir())
        code, payload = self.audit()
        self.assertEqual(code, 0, payload)

        # One task identity may never escape its two-execution blast radius.
        before_events = self.events_of("task-retry")
        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id", "task-retry",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "max-attempts-exhausted")
        self.assertEqual(self.state_of("task-retry"), "failed")
        self.assertEqual(self.card_of("task-retry")["attempt"], 2)
        self.assertFalse((attempts / "a3").exists())
        self.assertEqual(self.events_of("task-retry"), before_events)
        code, payload = self.audit()
        self.assertEqual(code, 0, payload)

    def test_requeue_blocked_refuses_exhausted_attempt_budget(self):
        self.enqueue(self.make_card("task-blocked-once", max_attempts=1))
        self.claim_expect("task-blocked-once")
        code, payload = run_cli(
            "--root", self.root, "block", "--task-id", "task-blocked-once",
            "--worker", "worker-a", "--reason", "owner-gate",
        )
        self.assertEqual(code, 0, payload)
        before_events = self.events_of("task-blocked-once")
        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id", "task-blocked-once",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "max-attempts-exhausted")
        self.assertEqual(self.state_of("task-blocked-once"), "blocked")
        self.assertEqual(self.events_of("task-blocked-once"), before_events)

    def test_first_failure_is_final_with_max_attempts_one(self):
        self.enqueue(self.make_card("task-once", max_attempts=1))
        self.claim_expect("task-once")
        code, payload = run_cli(
            "--root", self.root, "fail", "--task-id", "task-once",
            "--worker", "worker-a", "--reason", "boom",
        )
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["state"], "failed")
        self.assertEqual(self.state_of("task-once"), "failed")
        code, payload = self.audit()
        self.assertEqual(code, 0, payload)

    def test_claim_refuses_legacy_exhausted_queue_without_side_effects(self):
        for max_attempts in (1, 2):
            with self.subTest(max_attempts=max_attempts):
                root = str(self.base / f"exhausted-{max_attempts}")
                code, payload = run_cli("--root", root, "init")
                self.assertEqual(code, 0, payload)
                task_id = f"task-exhausted-{max_attempts}"
                source = self.write_card_file(
                    self.make_card(task_id, max_attempts=max_attempts),
                    f"card-exhausted-{max_attempts}.json",
                )
                code, payload = run_cli(
                    "--root", root, "enqueue", "--card", str(source)
                )
                self.assertEqual(code, 0, payload)

                # Reach terminal failure through public commands. Then
                # reproduce the legacy operator requeue that used to be
                # accepted and looked clean to audit.
                for attempt in range(1, max_attempts + 1):
                    code, payload = run_cli(
                        "--root", root, "claim", "--profile", "claude-work",
                        "--model", "claude-fable-5", "--worker", "worker-a",
                    )
                    self.assertEqual(code, 0, payload)
                    code, payload = run_cli(
                        "--root", root, "fail", "--task-id", task_id,
                        "--worker", "worker-a", "--reason", f"fail-{attempt}",
                    )
                    self.assertEqual(code, 0, payload)
                failed = Path(root) / "failed" / f"{task_id}.json"
                queued = Path(root) / "queue" / f"{task_id}.json"
                os.rename(failed, queued)
                event_count = len(
                    list((Path(root) / "events" / task_id).iterdir())
                )
                self.write_event(
                    task_id, event_count + 1, "requeue-failed", max_attempts,
                    root=root,
                )

                code, kinds, audit_payload = self.audit_kinds(root)
                self.assertEqual(code, 3, audit_payload)
                self.assertEqual(kinds, {"attempt_budget_violation"})
                details = {
                    gap.get("detail") for gap in audit_payload["gaps"]
                }
                self.assertIn("exhausted-card-in-queue", details)
                self.assertIn("exhausted-requeue", details)

                before = self.durable_snapshot(root)
                proc = run_cli_subprocess(
                    "--root", root, "claim", "--profile", "claude-work",
                    "--model", "claude-fable-5", "--worker", "worker-b",
                )
                self.assertEqual(proc.returncode, 2, proc.stdout)
                self.assertEqual(proc.stderr, "")
                self.assertEqual(len(proc.stdout.strip().splitlines()), 1)
                self.assertEqual(
                    json.loads(proc.stdout),
                    {"error": "exact-evidence-invalid", "ok": False},
                )
                self.assertEqual(self.durable_snapshot(root), before)
                self.assertTrue(queued.is_file())
                self.assertFalse(
                    (
                        Path(root) / "attempts" / task_id
                        / f"a{max_attempts + 1}"
                    ).exists()
                )

    def test_audit_detects_card_and_history_above_attempt_budget(self):
        self.enqueue(self.make_card("task-over-budget", max_attempts=1))
        self.claim_expect("task-over-budget")
        code, payload = run_cli(
            "--root", self.root, "fail", "--task-id", "task-over-budget",
            "--worker", "worker-a", "--reason", "terminal",
        )
        self.assertEqual(code, 0, payload)

        # Reproduce a legacy exhausted requeue and its forbidden second
        # claim, while keeping state/card/events/attempt dirs mutually
        # consistent. The only audit failure is the budget invariant.
        card_path = Path(self.root) / "failed" / "task-over-budget.json"
        queue_path = Path(self.root) / "queue" / "task-over-budget.json"
        os.rename(card_path, queue_path)
        self.write_event("task-over-budget", 3, "requeue-failed", 1)
        progress_path = (
            Path(self.root) / "in_progress" / "task-over-budget.json"
        )
        os.rename(queue_path, progress_path)
        card = json.loads(progress_path.read_text("utf-8"))
        card["attempt"] = 2
        progress_path.write_text(json.dumps(card), encoding="ascii")
        (Path(self.root) / "attempts" / "task-over-budget" / "a2").mkdir()
        self.write_event("task-over-budget", 4, "claim", 2)

        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertEqual(kinds, {"attempt_budget_violation"})
        details = {gap.get("detail") for gap in payload["gaps"]}
        self.assertEqual(
            details,
            {
                "card-attempt-exceeds-max",
                "exhausted-requeue",
                "claim-exceeds-max",
            },
        )

    def test_requeue_only_from_blocked_or_failed(self):
        self.enqueue(self.make_card("task-rq"))
        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id", "task-rq",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "requeue-source-invalid")
        self.claim_expect("task-rq")
        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id", "task-rq",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "requeue-source-invalid")
        run_cli(
            "--root", self.root, "complete", "--task-id", "task-rq",
            "--worker", "worker-a",
        )
        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id", "task-rq",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "requeue-source-invalid")

    def test_block_requires_reason(self):
        self.enqueue(self.make_card("task-blk"))
        self.claim_expect("task-blk")
        code, payload = run_cli(
            "--root", self.root, "block", "--task-id", "task-blk",
            "--worker", "worker-a", "--reason", "",
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "block-reason-required")
        self.assertEqual(self.state_of("task-blk"), "in_progress")

    def test_claim_filters_profile_and_model_exactly(self):
        self.enqueue(self.make_card("task-other", profile="claude-test1"))
        self.claim_expect_empty()
        self.assertEqual(self.state_of("task-other"), "queue")
        code, payload = self.claim(profile="claude-test1", worker="worker-b")
        self.assertEqual(code, 0, payload)
        self.assertEqual(self.state_of("task-other"), "in_progress")

    # -------------------------------------------------- card strictness

    def test_max_attempts_accepts_only_exact_int_one_or_two(self):
        for bad in (True, False, 2.0, 1.0, 3, 0, -1, "2", None, 10):
            with self.subTest(bad=bad):
                payload = self.enqueue(
                    self.make_card("task-ma", max_attempts=bad), expect_code=2
                )
                self.assertEqual(payload["error"], "card-max-attempts")
                self.assertIsNone(self.state_of("task-ma"))
        for good, task in ((1, "task-ma1"), (2, "task-ma2")):
            payload = self.enqueue(self.make_card(task, max_attempts=good))
            self.assertTrue(payload["ok"])
            self.assertEqual(self.card_of(task)["max_attempts"], good)

    def test_card_type_strictness(self):
        cases = [
            ({"version": True}, "card-version"),
            ({"version": 1.0}, "card-version"),
            ({"restart_safe": 1}, "card-restart-safe"),
            ({"restart_safe": 0}, "card-restart-safe"),
            ({"max_step_seconds": 2.5}, "card-max-step-seconds"),
            ({"max_step_seconds": True}, "card-max-step-seconds"),
            ({"attempt": "0"}, "card-attempt"),
            ({"attempt": True}, "card-attempt"),
            ({"attempt": 1}, "enqueue-attempt-nonzero"),
            ({"created_utc": "2026-13-01T00:00:00.000Z"}, "card-created-utc"),
            ({"created_utc": "2026-07-13 12:00:00"}, "card-created-utc"),
            ({"created_utc": "2026-02-30T00:00:00.000Z"}, "card-created-utc"),
            ({"payload_sha256": self.payload_sha.lower()}, "card-payload-sha256"),
            ({"task_id": "UPPER"}, "invalid-task-id"),
            ({"task_id": "nul"}, "invalid-task-id"),
            ({"allowed_root": "relative\\path"}, "card-allowed-root"),
            ({"unexpected": 1}, "card-schema"),
        ]
        for overrides, expected_error in cases:
            with self.subTest(overrides=overrides):
                card = self.make_card("task-strict")
                card.update(overrides)
                payload = self.enqueue(card, expect_code=2)
                self.assertEqual(payload["error"], expected_error)
        card = self.make_card("task-strict")
        del card["payload_relpath"]
        payload = self.enqueue(card, expect_code=2)
        self.assertEqual(payload["error"], "card-schema")

    def test_duplicate_json_keys_rejected(self):
        card = self.make_card("task-dup")
        text = json.dumps(card)
        source = self.base / "dup-card.json"
        source.write_text(text[:-1] + ', "task_id": "task-dup"}', "ascii")
        code, payload = run_cli(
            "--root", self.root, "enqueue", "--card", str(source)
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"], "duplicate-json-key")
        self.assertIsNone(self.state_of("task-dup"))

    def test_enqueue_refuses_duplicates_and_residue(self):
        self.enqueue(self.make_card("task-e1"))
        payload = self.enqueue(self.make_card("task-e1"), expect_code=2)
        self.assertEqual(payload["error"], "task-already-exists")
        (Path(self.root) / "events" / "task-e2").mkdir(parents=True)
        payload = self.enqueue(self.make_card("task-e2"), expect_code=2)
        self.assertEqual(payload["error"], "task-residue-exists")
        (Path(self.root) / "attempts" / "task-e3" / "a1").mkdir(parents=True)
        payload = self.enqueue(self.make_card("task-e3"), expect_code=2)
        self.assertEqual(payload["error"], "task-residue-exists")

    # ---------------------------------------------------- payload safety

    def test_enqueue_validates_payload_hash_and_presence(self):
        payload = self.enqueue(
            self.make_card("task-badsha", payload_sha256="B" * 64),
            expect_code=2,
        )
        self.assertEqual(payload["error"], "payload-tampered")
        self.assertIsNone(self.state_of("task-badsha"))

        payload = self.enqueue(
            self.make_card("task-nofile", payload_relpath="missing.txt"),
            expect_code=2,
        )
        self.assertEqual(payload["error"], "payload-missing")

        directory = self.allowed / "somedir"
        directory.mkdir()
        payload = self.enqueue(
            self.make_card("task-dir", payload_relpath="somedir"),
            expect_code=2,
        )
        self.assertEqual(payload["error"], "payload-not-regular-file")

    def test_claim_revalidates_payload_and_quarantines_tamper(self):
        self.enqueue(self.make_card("task-tamper"))
        self.payload_file.write_bytes(b"tampered after enqueue\n")
        self.claim_expect_empty()
        self.assertEqual(self.state_of("task-tamper"), "blocked")
        self.assertFalse(
            (Path(self.root) / "attempts" / "task-tamper").exists()
        )
        events_dir = Path(self.root) / "events" / "task-tamper"
        events = sorted(events_dir.iterdir())
        self.assertEqual(len(events), 1)
        event = json.loads(events[0].read_text("utf-8"))
        self.assertEqual(event["transition"], "block-payload")
        self.assertEqual(event["reason"], "payload-tampered")
        code, payload = self.audit()
        self.assertEqual(code, 0, payload)

    def test_claim_quarantines_missing_payload(self):
        self.enqueue(self.make_card("task-gone"))
        self.payload_file.unlink()
        self.claim_expect_empty()
        self.assertEqual(self.state_of("task-gone"), "blocked")
        code, payload = self.audit()
        self.assertEqual(code, 0, payload)

    def test_payload_relpath_traversal_rejected(self):
        bad_relpaths = [
            "..", "../x", "..\\x", "a/../b", "a\\..\\b", ".", "",
            "/abs/path", "\\abs", "C:\\windows\\system32", "a//b", "a/./b",
            "a:b", "nul", "sub/nul.txt", "con.json", "a\x00b", "a?b",
        ]
        for bad in bad_relpaths:
            with self.subTest(relpath=bad):
                payload = self.enqueue(
                    self.make_card("task-trav", payload_relpath=bad),
                    expect_code=2,
                )
                self.assertEqual(payload["error"], "card-payload-relpath")
                self.assertIsNone(self.state_of("task-trav"))

    def test_payload_link_escape_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_bytes(b"outside the allowed root\n")
        secret_sha = sha256_upper(secret.read_bytes())
        probe_dir = self.base / "linkprobe"
        probe_dir.mkdir()
        symlink_ok = can_make_file_symlink(probe_dir)
        junction_ok = can_make_junction(probe_dir)
        if not symlink_ok and not junction_ok:
            self.skipTest("platform cannot create symlinks or junctions")

        if symlink_ok:
            os.symlink(str(secret), str(self.allowed / "sneaky.txt"))
            # The hash matches the link target, so rejection can only come
            # from the reparse-point guard, not from hash mismatch.
            payload = self.enqueue(
                self.make_card(
                    "task-slink", payload_relpath="sneaky.txt",
                    payload_sha256=secret_sha,
                ),
                expect_code=2,
            )
            self.assertEqual(payload["error"], "payload-reparse-point")

            # Swap-after-enqueue: a payload replaced by a symlink with
            # identical content must be quarantined at claim time.
            self.enqueue(self.make_card("task-swap"))
            content = self.payload_file.read_bytes()
            self.payload_file.unlink()
            copy_outside = outside / "swap.txt"
            copy_outside.write_bytes(content)
            os.symlink(str(copy_outside), str(self.payload_file))
            self.claim_expect_empty()
            self.assertEqual(self.state_of("task-swap"), "blocked")
            self.payload_file.unlink()
            self.payload_file.write_bytes(content)

        if junction_ok:
            inner = outside / "jpayload.txt"
            inner.write_bytes(b"reachable only through a junction\n")
            proc = subprocess.run(
                ["cmd", "/c", "mklink", "/J",
                 str(self.allowed / "jsub"), str(outside)],
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = self.enqueue(
                self.make_card(
                    "task-junc", payload_relpath="jsub/jpayload.txt",
                    payload_sha256=sha256_upper(inner.read_bytes()),
                ),
                expect_code=2,
            )
            self.assertEqual(payload["error"], "payload-reparse-point")

    def test_payload_size_limit_bounds_reads(self):
        big = self.allowed / "big.bin"
        with open(big, "wb") as stream:
            stream.write(b"\x00" * (queue_cli.PAYLOAD_MAX_BYTES + 1))
        payload = self.enqueue(
            self.make_card(
                "task-big", payload_relpath="big.bin",
                payload_sha256="C" * 64,
            ),
            expect_code=2,
        )
        self.assertEqual(payload["error"], "payload-too-large")

    # ------------------------------------------------- claim fail-closure

    def test_malformed_queue_card_is_quarantined_not_executed(self):
        broken = Path(self.root) / "queue" / "task-broken.json"
        broken.write_text('{"version": 1, "unexpected": true}', encoding="ascii")
        self.claim_expect_empty()
        self.assertEqual(self.state_of("task-broken"), "blocked")
        events_dir = Path(self.root) / "events" / "task-broken"
        events = sorted(events_dir.iterdir())
        self.assertEqual(len(events), 1)
        event = json.loads(events[0].read_text("utf-8"))
        self.assertEqual(event["transition"], "block-malformed")
        code, payload = self.audit()
        self.assertEqual(code, 0, payload)
        # A quarantined malformed card cannot be requeued.
        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id", "task-broken",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2)

    def test_preexisting_attempt_dir_fails_claim_closed(self):
        self.enqueue(self.make_card("task-adir"))
        (Path(self.root) / "attempts" / "task-adir" / "a1").mkdir(parents=True)
        before = self.durable_snapshot()
        code, payload = self.claim()
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        self.assertEqual(self.state_of("task-adir"), "queue")
        events_dir = Path(self.root) / "events" / "task-adir"
        self.assertFalse(events_dir.exists())
        # Existing evidence is never repaired/quarantined by a legacy claim;
        # the stray directory remains visible to audit.
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("extra_attempt_dir", kinds)

    def test_transition_rename_never_overwrites_existing_target(self):
        self.enqueue(self.make_card("task-crash"))
        queue_card = Path(self.root) / "queue" / "task-crash.json"
        stale = Path(self.root) / "in_progress" / "task-crash.json"
        stale_bytes = b'{"stale": "in-progress card from a crashed run"}\n'
        stale.write_bytes(stale_bytes)
        self.claim_expect_empty()
        self.assertEqual(stale.read_bytes(), stale_bytes)
        self.assertTrue(queue_card.is_file())
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("duplicate_states", kinds)

    # -------------------------------------------------------------- events

    def test_event_seq_is_exclusive_and_never_replaced(self):
        self.enqueue(self.make_card("task-seq"))
        self.claim_expect("task-seq")
        events_dir = Path(self.root) / "events" / "task-seq"
        self.assertTrue((events_dir / "000001.json").is_file())
        squatter = events_dir / "000002.json"
        squatter_bytes = b"junk-not-json"
        squatter.write_bytes(squatter_bytes)
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "complete", "--task-id", "task-seq",
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

        # Exercise the append primitive independently: the terminal command
        # correctly refuses corrupt evidence, while exclusive publication
        # itself must still skip and never overwrite the occupied sequence.
        os.rename(
            Path(self.root) / "in_progress" / "task-seq.json",
            Path(self.root) / "done" / "task-seq.json",
        )
        queue_cli._append_event(
            Path(self.root), "task-seq", "complete", 1, "worker-a"
        )
        # The squatting seq file was never replaced; the publisher skipped
        # past it with max(existing)+1 instead of len()+1.
        self.assertEqual(squatter.read_bytes(), squatter_bytes)
        published = json.loads((events_dir / "000003.json").read_text("utf-8"))
        self.assertEqual(published["transition"], "complete")
        self.assertEqual(published["seq"], 3)
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("malformed_event", kinds)

    # ------------------------------------------------------ parallel claim

    def test_parallel_claims_produce_exactly_one_owner(self):
        self.enqueue(self.make_card("task-race"))

        def spawn(_index):
            return run_cli_subprocess(
                "--root", self.root, "claim", "--profile", "claude-work",
                "--model", "claude-fable-5", "--worker", "worker-a",
            )

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(spawn, range(6)))
        winners = [item for item in results if item.returncode == 0]
        losers = [item for item in results if item.returncode == 2]
        self.assertEqual(
            len(winners), 1,
            [(item.returncode, item.stdout, item.stderr) for item in results],
        )
        self.assertEqual(len(winners) + len(losers), 6)
        for loser in losers:
            self.assertEqual(
                json.loads(loser.stdout)["error"], "nothing-to-claim"
            )
        self.assertEqual(self.state_of("task-race"), "in_progress")
        self.assertEqual(self.card_of("task-race")["attempt"], 1)
        events_dir = Path(self.root) / "events" / "task-race"
        self.assertEqual(
            [path.name for path in sorted(events_dir.iterdir())],
            ["000001.json"],
        )
        attempts = Path(self.root) / "attempts" / "task-race"
        self.assertEqual(
            [path.name for path in sorted(attempts.iterdir())], ["a1"]
        )
        code, payload = self.audit()
        self.assertEqual(code, 0, payload)

    def test_task_lock_prevents_transition_event_interleave(self):
        self.enqueue(self.make_card("task-locked"))
        self.claim_expect("task-locked")
        entered = threading.Event()
        release = threading.Event()
        original_append = queue_cli._append_event

        def delayed_append(root, task_id, transition, attempt, worker,
                           reason=""):
            if task_id == "task-locked" and transition == "fail-retry":
                entered.set()
                if not release.wait(10):
                    raise AssertionError("test did not release delayed event")
            return original_append(
                root, task_id, transition, attempt, worker, reason
            )

        with mock.patch.object(queue_cli, "_append_event", delayed_append):
            with ThreadPoolExecutor(max_workers=1) as pool:
                failed = pool.submit(
                    queue_cli.cmd_fail, self.root, "task-locked", "worker-a",
                    "retry",
                )
                self.assertTrue(entered.wait(5), "fail did not reach event gap")
                claimant = subprocess.Popen(
                    [
                        sys.executable, "-m", "autonomy.queue_cli",
                        "--root", self.root, "claim",
                        "--profile", "claude-work",
                        "--model", "claude-fable-5",
                        "--worker", "worker-b",
                    ],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    cwd=str(ROOT),
                )
                time.sleep(0.25)
                self.assertIsNone(
                    claimant.poll(),
                    "second transition escaped while fail event was delayed",
                )
                release.set()
                fail_code, fail_payload = failed.result(timeout=10)
                out, err = claimant.communicate(timeout=20)

        self.assertEqual(fail_code, 0, fail_payload)
        self.assertEqual(err, "")
        self.assertEqual(claimant.returncode, 0, out)
        claimed = json.loads(out)
        self.assertEqual(claimed["task_id"], "task-locked")
        events = [
            json.loads(path.read_text("utf-8"))
            for path in sorted(
                (Path(self.root) / "events" / "task-locked").iterdir()
            )
        ]
        self.assertEqual(
            [event["transition"] for event in events],
            ["claim", "fail-retry", "claim"],
        )
        self.assertEqual([event["seq"] for event in events], [1, 2, 3])
        code, payload = self.audit()
        self.assertEqual(code, 0, payload)

    # ---------------------------------------------------------- exact CAS

    def test_authority_digest_is_canonical_defaulted_and_attempt_independent(self):
        implicit = self.make_card("task-digest")
        explicit = self.make_card(
            "task-digest", restart_safe=False, attempt=0, max_attempts=2,
        )
        bumped = dict(explicit, attempt=2)
        digest = queue_cli.card_authority_digest(implicit)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        normalized = queue_cli._normalize_card(implicit)
        authority = {
            key: normalized[key] for key in sorted(normalized)
            if key != "attempt"
        }
        expected_bytes = json.dumps(
            authority, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.assertEqual(digest, hashlib.sha256(expected_bytes).hexdigest())
        self.assertEqual(digest, queue_cli.card_authority_digest(explicit))
        self.assertEqual(digest, queue_cli.card_authority_digest(bumped))
        self.assertNotEqual(
            digest,
            queue_cli.card_authority_digest(
                dict(explicit, max_step_seconds=601)
            ),
        )

    def test_exact_peek_and_list_verify_payload_without_mutation_or_nonce(self):
        self.enqueue(self.make_card("task-view-b"))
        self.enqueue(self.make_card("task-view-a", max_attempts=1))
        before = self.durable_snapshot()

        code, peek = self.peek_exact("task-view-a")
        self.assertEqual(code, 0, peek)
        item = peek["task"]
        self.assertEqual(item["current_attempt"], 0)
        self.assertEqual(item["next_attempt"], 1)
        self.assertIsNone(item["worker"])
        self.assertTrue(item["payload"]["verified"])
        self.assertNotIn("nonce", json.dumps(peek).lower())

        code, listed = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 0, listed)
        self.assertEqual(
            [task["task_id"] for task in listed["tasks"]],
            ["task-view-a", "task-view-b"],
        )
        self.assertNotIn("nonce", json.dumps(listed).lower())
        self.assertEqual(before, self.durable_snapshot())

        self.payload_file.write_bytes(b"changed after enqueue")
        changed = self.durable_snapshot()
        # peek-exact keeps the strict fail-closed gate for the executable
        # queue state; list-exact instead exposes the drifted entries
        # deterministically so one bad payload cannot hide healthy work.
        code, payload = self.peek_exact("task-view-a")
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "payload-tampered")
        self.assertEqual(changed, self.durable_snapshot())
        code, listed = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 0, listed)
        self.assertEqual(
            [task["task_id"] for task in listed["tasks"]],
            ["task-view-a", "task-view-b"],
        )
        for task in listed["tasks"]:
            self.assertFalse(task["payload"]["verified"])
            self.assertEqual(task["payload"]["error"], "payload-tampered")
            self.assertIsNone(task["payload"]["path"])
        self.assertNotIn("nonce", json.dumps(listed).lower())
        self.assertEqual(changed, self.durable_snapshot())

    def test_exact_in_progress_view_exposes_durable_claim_worker(self):
        task_id = "task-visible-owner"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        code, claimed = self.claim_exact(
            task_id, 1, digest, worker="worker-b"
        )
        self.assertEqual(code, 0, claimed)

        # A restarted coordinator need not possess the lost claim response to
        # identify the durable owner of this stranded in-progress attempt.
        code, view = self.peek_exact(task_id)
        self.assertEqual(code, 0, view)
        self.assertEqual(view["task"]["state"], "in_progress")
        self.assertEqual(view["task"]["worker"], "worker-b")
        self.assertEqual(view["task"]["digest"], digest)

    def test_exact_claim_rejects_stale_card_attempt_filters_and_digest_byte_stably(self):
        self.enqueue(self.make_card("task-cas"))
        code, peek = self.peek_exact("task-cas")
        self.assertEqual(code, 0, peek)
        digest = peek["task"]["digest"]

        cases = (
            (2, digest, "claude-work", "claude-fable-5",
             "exact-attempt-mismatch"),
            (1, "0" * 64, "claude-work", "claude-fable-5",
             "exact-digest-mismatch"),
            (1, digest, "claude-test2", "claude-fable-5",
             "exact-profile-mismatch"),
            (1, digest, "claude-work", "claude-opus-4.1",
             "exact-model-mismatch"),
        )
        for attempt, candidate_digest, profile, model, error in cases:
            with self.subTest(error=error):
                before = self.durable_snapshot()
                code, payload = self.claim_exact(
                    "task-cas", attempt, candidate_digest,
                    profile=profile, model=model,
                )
                self.assertEqual(code, 2, payload)
                self.assertEqual(payload["error"], error)
                self.assertEqual(before, self.durable_snapshot())

        # Authority changed after observation: an old digest cannot claim it.
        card_path = Path(self.root) / "queue" / "task-cas.json"
        card = json.loads(card_path.read_text("utf-8"))
        card["max_step_seconds"] = 601
        card_path.write_bytes(queue_cli._encode_json(card))
        before = self.durable_snapshot()
        code, payload = self.claim_exact("task-cas", 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-digest-mismatch")
        self.assertEqual(before, self.durable_snapshot())

    def test_exact_cli_invalid_cas_values_are_stable_single_json_refusals(self):
        self.enqueue(self.make_card("task-invalid-cas"))
        digest = self.peek_exact("task-invalid-cas")[1]["task"]["digest"]
        cases = (
            (("claim-exact", "--task-id", "task-invalid-cas",
              "--expected-next-attempt", "0", "--expected-digest", digest,
              "--profile", "claude-work", "--model", "claude-fable-5",
              "--worker", "worker-a"), "invalid-expected-attempt"),
            (("claim-exact", "--task-id", "task-invalid-cas",
              "--expected-next-attempt", "1", "--expected-digest",
              digest.upper(), "--profile", "claude-work", "--model",
              "claude-fable-5", "--worker", "worker-a"),
             "invalid-expected-digest"),
        )
        for argv, error in cases:
            with self.subTest(error=error):
                before = self.durable_snapshot()
                code, payload = run_cli("--root", self.root, *argv)
                self.assertEqual(code, 2, payload)
                self.assertEqual(payload, {"ok": False, "error": error})
                self.assertEqual(before, self.durable_snapshot())

        # argparse conversion failures stay at the closed CLI boundary too.
        proc = run_cli_subprocess(
            "--root", self.root, "claim-exact", "--task-id",
            "task-invalid-cas", "--expected-next-attempt", "not-an-int",
            "--expected-digest", digest, "--profile", "claude-work",
            "--model", "claude-fable-5", "--worker", "worker-a",
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, "")
        self.assertEqual(
            json.loads(proc.stdout),
            {"ok": False, "error": "invalid-arguments"},
        )

    def test_exact_claim_response_loss_replay_and_conflicting_worker(self):
        self.enqueue(self.make_card("task-replay"))
        digest = self.peek_exact("task-replay")[1]["task"]["digest"]
        code, first = self.claim_exact("task-replay", 1, digest)
        self.assertEqual(code, 0, first)
        self.assertFalse(first["replayed"])
        after_first = self.durable_snapshot()

        code, replay = self.claim_exact("task-replay", 1, digest)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(after_first, self.durable_snapshot())

        code, conflict = self.claim_exact(
            "task-replay", 1, digest, worker="worker-b"
        )
        self.assertEqual(code, 2, conflict)
        self.assertEqual(conflict["error"], "exact-worker-mismatch")
        self.assertEqual(after_first, self.durable_snapshot())

    def test_exact_claim_rejects_queue_topology_aba_with_stale_generation(self):
        self.enqueue(self.make_card("task-exact-aba", max_attempts=2))
        stale = self.peek_exact("task-exact-aba")[1]["task"]
        digest = stale["digest"]
        self.assertEqual(self.claim_exact("task-exact-aba", 1, digest)[0], 0)
        code, payload = run_cli(
            "--root", self.root, "fail-exact", "--task-id",
            "task-exact-aba", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
            "--disposition", "retry",
        )
        self.assertEqual(code, 0, payload)
        self.assertEqual(self.state_of("task-exact-aba"), "queue")

        # Topology is queue again (A -> in_progress -> A), but generation is
        # now 1. The old queue view's expected next attempt 1 is not reusable.
        before = self.durable_snapshot()
        code, refused = self.claim_exact(
            "task-exact-aba", stale["next_attempt"], digest
        )
        self.assertEqual(code, 2, refused)
        self.assertEqual(refused["error"], "exact-attempt-mismatch")
        self.assertEqual(before, self.durable_snapshot())
        fresh = self.peek_exact("task-exact-aba")[1]["task"]
        self.assertEqual(fresh["current_attempt"], 1)
        self.assertEqual(fresh["next_attempt"], 2)
        self.assertEqual(fresh["digest"], digest)

    def test_parallel_exact_claim_has_one_incarnation_and_safe_replays(self):
        self.enqueue(self.make_card("task-exact-race"))
        digest = self.peek_exact("task-exact-race")[1]["task"]["digest"]

        def spawn(worker):
            return run_cli_subprocess(
                "--root", self.root, "claim-exact", "--task-id",
                "task-exact-race", "--expected-next-attempt", "1",
                "--expected-digest", digest, "--profile", "claude-work",
                "--model", "claude-fable-5", "--worker", worker,
            )

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(spawn, ["worker-a"] * 6))
        self.assertTrue(all(item.returncode == 0 for item in results), results)
        payloads = [json.loads(item.stdout) for item in results]
        self.assertEqual(sum(not item["replayed"] for item in payloads), 1)
        self.assertEqual(
            sorted((Path(self.root) / "attempts" / "task-exact-race").iterdir()),
            [Path(self.root) / "attempts" / "task-exact-race" / "a1"],
        )
        self.assertEqual(len(self.events_of("task-exact-race")), 1)

    def test_exact_complete_replay_wrong_bindings_and_terminal_conflict(self):
        self.enqueue(self.make_card("task-exact-done"))
        digest = self.peek_exact("task-exact-done")[1]["task"]["digest"]
        self.assertEqual(self.claim_exact("task-exact-done", 1, digest)[0], 0)

        for legacy in (
            ("complete",),
            ("fail", "--reason", "legacy"),
            ("block", "--reason", "legacy"),
        ):
            before = self.durable_snapshot()
            code, payload = run_cli(
                "--root", self.root, *legacy, "--task-id",
                "task-exact-done", "--worker", "worker-a",
            )
            self.assertEqual(code, 2, payload)
            self.assertEqual(payload["error"], "exact-transition-required")
            self.assertEqual(before, self.durable_snapshot())

        for option, value, error in (
            ("--expected-attempt", "2", "exact-attempt-mismatch"),
            ("--expected-digest", "0" * 64, "exact-digest-mismatch"),
            ("--worker", "worker-b", "exact-worker-mismatch"),
        ):
            args = {
                "--expected-attempt": "1",
                "--expected-digest": digest,
                "--worker": "worker-a",
            }
            args[option] = value
            flat = [part for pair in args.items() for part in pair]
            before = self.durable_snapshot()
            code, payload = run_cli(
                "--root", self.root, "complete-exact", "--task-id",
                "task-exact-done", *flat,
            )
            self.assertEqual(code, 2, payload)
            self.assertEqual(payload["error"], error)
            self.assertEqual(before, self.durable_snapshot())

        complete = (
            "--root", self.root, "complete-exact", "--task-id",
            "task-exact-done", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
        )
        code, first = run_cli(*complete)
        self.assertEqual(code, 0, first)
        self.assertFalse(first["replayed"])
        terminal = self.durable_snapshot()
        code, replay = run_cli(*complete)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(terminal, self.durable_snapshot())

        code, conflict = run_cli(
            "--root", self.root, "block-exact", "--task-id",
            "task-exact-done", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
            "--reason", "different terminal",
        )
        self.assertEqual(code, 2, conflict)
        self.assertEqual(conflict["error"], "exact-state-conflict")
        self.assertEqual(terminal, self.durable_snapshot())

    def test_exact_fail_disposition_max1_and_max2_and_replays(self):
        # max=1: only final is admissible.
        self.enqueue(self.make_card("task-max1-exact", max_attempts=1))
        d1 = self.peek_exact("task-max1-exact")[1]["task"]["digest"]
        self.assertEqual(self.claim_exact("task-max1-exact", 1, d1)[0], 0)
        base = (
            "--root", self.root, "fail-exact", "--task-id",
            "task-max1-exact", "--expected-attempt", "1",
            "--expected-digest", d1, "--worker", "worker-a",
        )
        before = self.durable_snapshot()
        code, refused = run_cli(*base, "--disposition", "retry")
        self.assertEqual(code, 2, refused)
        self.assertEqual(refused["error"], "fail-disposition-mismatch")
        self.assertEqual(before, self.durable_snapshot())
        code, final = run_cli(*base, "--disposition", "final")
        self.assertEqual(code, 0, final)
        self.assertEqual(final["state"], "failed")
        code, replay = run_cli(*base, "--disposition", "final")
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        terminal = self.durable_snapshot()
        code, refused = run_cli(*base, "--disposition", "retry")
        self.assertEqual(code, 2, refused)
        self.assertEqual(refused["error"], "fail-disposition-mismatch")
        self.assertEqual(terminal, self.durable_snapshot())

        # max=2: retry is exact at a1, then final is exact at a2.
        self.enqueue(self.make_card("task-max2-exact", max_attempts=2))
        d2 = self.peek_exact("task-max2-exact")[1]["task"]["digest"]
        self.assertEqual(self.claim_exact("task-max2-exact", 1, d2)[0], 0)
        retry_args = (
            "--root", self.root, "fail-exact", "--task-id",
            "task-max2-exact", "--expected-attempt", "1",
            "--expected-digest", d2, "--worker", "worker-a",
            "--disposition", "retry",
        )
        self.assertEqual(run_cli(*retry_args)[0], 0)
        retry_snapshot = self.durable_snapshot()
        code, replay = run_cli(*retry_args)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(retry_snapshot, self.durable_snapshot())
        self.assertEqual(self.claim_exact("task-max2-exact", 2, d2)[0], 0)
        code, final = run_cli(
            "--root", self.root, "fail-exact", "--task-id",
            "task-max2-exact", "--expected-attempt", "2",
            "--expected-digest", d2, "--worker", "worker-a",
            "--disposition", "final",
        )
        self.assertEqual(code, 0, final)
        self.assertEqual(final["state"], "failed")

    def test_exact_block_replay_and_audit_card_authority_evidence(self):
        self.enqueue(self.make_card("task-exact-block"))
        digest = self.peek_exact("task-exact-block")[1]["task"]["digest"]
        self.assertEqual(self.claim_exact("task-exact-block", 1, digest)[0], 0)
        args = (
            "--root", self.root, "block-exact", "--task-id",
            "task-exact-block", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
            "--reason", "owner gate",
        )
        self.assertEqual(run_cli(*args)[0], 0)
        snapshot = self.durable_snapshot()
        conflicting_reason = list(args)
        conflicting_reason[-1] = "different reason"
        code, refused = run_cli(*conflicting_reason)
        self.assertEqual(code, 2, refused)
        self.assertEqual(refused["error"], "exact-reason-mismatch")
        self.assertEqual(snapshot, self.durable_snapshot())
        code, replay = run_cli(*args)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(snapshot, self.durable_snapshot())
        self.assertEqual(self.audit()[0], 0)

        card_path = Path(self.root) / "blocked" / "task-exact-block.json"
        original_card = card_path.read_bytes()
        card = json.loads(card_path.read_text("utf-8"))
        card["model"] = "claude-opus-4.1"
        card_path.write_bytes(queue_cli._encode_json(card))
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("card_authority_mismatch", kinds)

        card_path.write_bytes(original_card)
        event_path = (
            Path(self.root) / "events" / "task-exact-block" / "000002.json"
        )
        event = json.loads(event_path.read_text("utf-8"))
        event["worker"] = "worker-b"
        event_path.write_bytes(queue_cli._encode_json(event))
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("exact_transition_inconsistency", kinds)

    def test_exact_semantic_validator_rejects_illegal_event_prefix(self):
        self.enqueue(self.make_card("task-illegal-prefix"))
        digest = self.peek_exact("task-illegal-prefix")[1]["task"]["digest"]
        self.assertEqual(
            self.claim_exact("task-illegal-prefix", 1, digest)[0], 0
        )
        event_path = (
            Path(self.root) / "events" / "task-illegal-prefix" / "000001.json"
        )
        event = json.loads(event_path.read_text("utf-8"))
        event.update({
            "transition": "complete",
            "from_state": "in_progress",
            "to_state": "done",
        })
        event_path.write_bytes(queue_cli._encode_json(event))
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "complete-exact", "--task-id",
            "task-illegal-prefix", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

    def test_exact_semantic_validator_requires_complete_attempt_tree(self):
        for task_id, corrupt_to_file in (
            ("task-missing-a1", False),
            ("task-corrupt-a1", True),
        ):
            with self.subTest(task_id=task_id):
                self.enqueue(self.make_card(task_id, max_attempts=2))
                digest = self.peek_exact(task_id)[1]["task"]["digest"]
                self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 0)
                self.assertEqual(run_cli(
                    "--root", self.root, "fail-exact", "--task-id", task_id,
                    "--expected-attempt", "1", "--expected-digest", digest,
                    "--worker", "worker-a", "--disposition", "retry",
                )[0], 0)
                a1 = Path(self.root) / "attempts" / task_id / "a1"
                a1.rmdir()
                if corrupt_to_file:
                    a1.write_bytes(b"not-an-attempt-directory")
                before = self.durable_snapshot()
                code, payload = self.claim_exact(task_id, 2, digest)
                self.assertEqual(code, 2, payload)
                self.assertEqual(payload["error"], "exact-evidence-invalid")
                self.assertEqual(before, self.durable_snapshot())
                self.assertFalse(
                    (Path(self.root) / "attempts" / task_id / "a2").exists()
                )

    def test_legacy_terminal_fails_closed_on_missing_or_malformed_exact_claim(self):
        for task_id, replacement in (
            ("task-missing-exact-event", None),
            ("task-malformed-exact-event", b"{"),
        ):
            with self.subTest(task_id=task_id):
                self.enqueue(self.make_card(task_id))
                digest = self.peek_exact(task_id)[1]["task"]["digest"]
                self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 0)
                event_path = (
                    Path(self.root) / "events" / task_id / "000001.json"
                )
                if replacement is None:
                    event_path.unlink()
                else:
                    event_path.write_bytes(replacement)
                before = self.durable_snapshot()
                code, payload = run_cli(
                    "--root", self.root, "complete", "--task-id", task_id,
                    "--worker", "worker-a",
                )
                self.assertEqual(code, 2, payload)
                self.assertEqual(payload["error"], "exact-evidence-invalid")
                self.assertEqual(before, self.durable_snapshot())
                self.assertEqual(self.state_of(task_id), "in_progress")

    def test_legacy_terminal_tail_cannot_downgrade_exact_claim(self):
        self.enqueue(self.make_card("task-legacy-tail"))
        digest = self.peek_exact("task-legacy-tail")[1]["task"]["digest"]
        self.assertEqual(self.claim_exact("task-legacy-tail", 1, digest)[0], 0)
        os.rename(
            Path(self.root) / "in_progress" / "task-legacy-tail.json",
            Path(self.root) / "done" / "task-legacy-tail.json",
        )
        queue_cli._append_event(
            Path(self.root), "task-legacy-tail", "complete", 1, "worker-a"
        )
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "complete-exact", "--task-id",
            "task-legacy-tail", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

    def test_invalid_max1_fail_retry_history_cannot_replay_success(self):
        self.enqueue(self.make_card("task-invalid-max1-retry", max_attempts=1))
        digest = self.peek_exact("task-invalid-max1-retry")[1]["task"]["digest"]
        self.assertEqual(
            self.claim_exact("task-invalid-max1-retry", 1, digest)[0], 0
        )
        os.rename(
            Path(self.root) / "in_progress" / "task-invalid-max1-retry.json",
            Path(self.root) / "queue" / "task-invalid-max1-retry.json",
        )
        queue_cli._append_event(
            Path(self.root), "task-invalid-max1-retry", "fail-retry", 1,
            "worker-a", authority_digest=digest, attempt_dir="a1",
        )
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "fail-exact", "--task-id",
            "task-invalid-max1-retry", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
            "--disposition", "retry",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

    def test_exact_metadata_schema_distinguishes_preclaim_quarantine(self):
        disallowed = (
            "block-malformed", "requeue-blocked", "requeue-failed",
        )
        for transition in disallowed:
            from_state, to_state = queue_cli.TRANSITIONS[transition]
            event = {
                "version": 1,
                "task_id": "task-schema",
                "seq": 1,
                "transition": transition,
                "from_state": from_state,
                "to_state": to_state,
                "attempt": 1,
                "worker": "worker-a",
                "reason": "quarantine" if transition in queue_cli.BLOCK_TRANSITIONS else "",
                "recorded_utc": "2026-07-13T12:00:00.000Z",
                "authority_digest": "a" * 64,
                "attempt_dir": "a1",
            }
            self.assertEqual(
                queue_cli._event_error(event, "task-schema", 1),
                "exact-metadata-transition",
            )

        for transition in queue_cli.EXACT_PRECLAIM_QUARANTINE_TRANSITIONS:
            from_state, to_state = queue_cli.TRANSITIONS[transition]
            event = {
                "version": 1,
                "task_id": "task-schema",
                "seq": 1,
                "transition": transition,
                "from_state": from_state,
                "to_state": to_state,
                "attempt": 0,
                "worker": "worker-a",
                "reason": "exact preclaim quarantine",
                "recorded_utc": "2026-07-13T12:00:00.000Z",
                "authority_digest": "a" * 64,
                "attempt_dir": "a1",
            }
            self.assertIsNone(
                queue_cli._event_error(event, "task-schema", 1)
            )
            event["attempt_dir"] = "a0"
            self.assertEqual(
                queue_cli._event_error(event, "task-schema", 1),
                "attempt-dir",
            )

        self.enqueue(self.make_card("task-exact-requeue-metadata"))
        self.assertEqual(self.claim()[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "block", "--task-id",
            "task-exact-requeue-metadata", "--worker", "worker-a",
            "--reason", "operator review",
        )[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "requeue", "--task-id",
            "task-exact-requeue-metadata", "--worker", "worker-a",
        )[0], 0)
        digest = self.peek_exact(
            "task-exact-requeue-metadata"
        )[1]["task"]["digest"]
        event_path = (
            Path(self.root) / "events" / "task-exact-requeue-metadata"
            / "000003.json"
        )
        event = json.loads(event_path.read_text("utf-8"))
        event["authority_digest"] = digest
        event["attempt_dir"] = "a1"
        event_path.write_bytes(queue_cli._encode_json(event))
        before = self.durable_snapshot()
        code, payload = self.claim_exact(
            "task-exact-requeue-metadata", 2, digest
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("malformed_event", kinds)

    def test_exact_marker_prevents_stripped_event_downgrade_to_legacy(self):
        self.enqueue(self.make_card("task-strip-exact"))
        digest = self.peek_exact("task-strip-exact")[1]["task"]["digest"]
        self.assertEqual(self.claim_exact("task-strip-exact", 1, digest)[0], 0)
        marker = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
            / "task-strip-exact.json"
        )
        self.assertTrue(marker.is_file())
        event_path = (
            Path(self.root) / "events" / "task-strip-exact" / "000001.json"
        )
        event = json.loads(event_path.read_text("utf-8"))
        del event["authority_digest"]
        del event["attempt_dir"]
        event_path.write_bytes(queue_cli._encode_json(event))
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "complete", "--task-id",
            "task-strip-exact", "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

    def test_exact_marker_survives_claim_worker_rewrite(self):
        self.enqueue(self.make_card("task-worker-rewrite"))
        digest = self.peek_exact("task-worker-rewrite")[1]["task"]["digest"]
        self.assertEqual(
            self.claim_exact("task-worker-rewrite", 1, digest)[0], 0
        )
        event_path = (
            Path(self.root) / "events" / "task-worker-rewrite" / "000001.json"
        )
        event = json.loads(event_path.read_text("utf-8"))
        event["worker"] = "worker-b"
        event_path.write_bytes(queue_cli._encode_json(event))
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "complete", "--task-id",
            "task-worker-rewrite", "--worker", "worker-b",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-transition-required")
        self.assertEqual(before, self.durable_snapshot())
        code, payload = run_cli(
            "--root", self.root, "complete-exact", "--task-id",
            "task-worker-rewrite", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-worker-mismatch")
        self.assertEqual(before, self.durable_snapshot())

    def test_missing_a1_after_exact_retry_blocks_legacy_a2_claim(self):
        self.enqueue(self.make_card("task-legacy-a2", max_attempts=2))
        digest = self.peek_exact("task-legacy-a2")[1]["task"]["digest"]
        self.assertEqual(self.claim_exact("task-legacy-a2", 1, digest)[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "fail-exact", "--task-id", "task-legacy-a2",
            "--expected-attempt", "1", "--expected-digest", digest,
            "--worker", "worker-a", "--disposition", "retry",
        )[0], 0)
        (Path(self.root) / "attempts" / "task-legacy-a2" / "a1").rmdir()
        before = self.durable_snapshot()
        code, payload = self.claim()
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        self.assertFalse(
            (Path(self.root) / "attempts" / "task-legacy-a2" / "a2").exists()
        )

    def test_illegal_event_prefix_blocks_legacy_retry_claim(self):
        self.enqueue(self.make_card("task-legacy-illegal", max_attempts=2))
        self.assertEqual(self.claim()[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "fail", "--task-id", "task-legacy-illegal",
            "--worker", "worker-a", "--reason", "retry",
        )[0], 0)
        event_path = (
            Path(self.root) / "events" / "task-legacy-illegal" / "000001.json"
        )
        event = json.loads(event_path.read_text("utf-8"))
        event.update({
            "transition": "complete",
            "from_state": "in_progress",
            "to_state": "done",
        })
        event_path.write_bytes(queue_cli._encode_json(event))
        before = self.durable_snapshot()
        code, payload = self.claim()
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        self.assertFalse(
            (Path(self.root) / "attempts" / "task-legacy-illegal" / "a2").exists()
        )

    def test_exact_marker_publish_response_loss_is_idempotent(self):
        for task_id, loss_point in (
            ("task-marker-before", "before"),
            ("task-marker-after", "after"),
        ):
            with self.subTest(loss_point=loss_point):
                self.enqueue(self.make_card(task_id))
                digest = self.peek_exact(task_id)[1]["task"]["digest"]
                marker_path = (
                    Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
                    / f"{task_id}.json"
                )
                if loss_point == "before":
                    original_publish = queue_cli._publish_json_exclusive

                    def stop_publish(root, target, value):
                        if target == marker_path:
                            raise queue_cli.FatalIOError("synthetic-before-marker")
                        return original_publish(root, target, value)

                    patcher = mock.patch.object(
                        queue_cli, "_publish_json_exclusive", stop_publish
                    )
                else:
                    original_move = queue_cli._move_card

                    def stop_after_marker(root, moved_task, transition):
                        if moved_task == task_id and transition == "claim":
                            self.assertTrue(marker_path.is_file())
                            raise queue_cli.QueueError("synthetic-after-marker")
                        return original_move(root, moved_task, transition)

                    patcher = mock.patch.object(
                        queue_cli, "_move_card", stop_after_marker
                    )
                with patcher:
                    code, payload = self.claim_exact(task_id, 1, digest)
                self.assertIn(code, (2, 3), payload)
                self.assertEqual(self.state_of(task_id), "queue")
                self.assertEqual(marker_path.exists(), loss_point == "after")
                self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 0)
                self.assertEqual(self.state_of(task_id), "in_progress")

    def test_exact_payload_race_quarantine_is_canonical_after_response_loss(self):
        task_id = "task-exact-payload-quarantine"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        original_verify = queue_cli._verify_payload
        original_quarantine = queue_cli._quarantine_from_queue
        verify_calls = 0

        def fail_post_move(card):
            nonlocal verify_calls
            verify_calls += 1
            if verify_calls == 2:
                raise queue_cli.QueueError("payload-tampered")
            return original_verify(card)

        def lose_response(*args, **kwargs):
            result = original_quarantine(*args, **kwargs)
            if args[2] == "block-payload":
                raise queue_cli.FatalIOError("synthetic-response-loss")
            return result

        with mock.patch.object(queue_cli, "_verify_payload", fail_post_move), \
             mock.patch.object(
                 queue_cli, "_quarantine_from_queue", lose_response
             ):
            code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 3, payload)
        self.assertEqual(payload["error"], "synthetic-response-loss")
        self.assertEqual(self.state_of(task_id), "blocked")
        self.assertEqual(self.card_of(task_id)["attempt"], 0)
        event = json.loads(next(iter(self.events_of(task_id).values())))
        self.assertEqual(event["transition"], "block-payload")
        self.assertEqual(event["attempt"], 0)
        self.assertEqual(event["authority_digest"], digest)
        self.assertEqual(event["attempt_dir"], "a1")
        self.assertFalse((Path(self.root) / "attempts" / task_id / "a1").exists())
        self.assertEqual(self.audit()[0], 0)

        terminal = self.durable_snapshot()
        code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-state-conflict")
        self.assertEqual(terminal, self.durable_snapshot())

    def test_exact_attempt_dir_race_quarantine_binds_collision(self):
        task_id = "task-exact-attempt-quarantine"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        attempt_dir = Path(self.root) / "attempts" / task_id / "a1"
        original_mkdir = queue_cli.os.mkdir

        def collide(path, mode=0o777, *args, **kwargs):
            if Path(path) == attempt_dir:
                original_mkdir(path, mode, *args, **kwargs)
                raise FileExistsError(str(path))
            return original_mkdir(path, mode, *args, **kwargs)

        with mock.patch.object(queue_cli.os, "mkdir", collide):
            code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-attempt-dir-conflict")
        self.assertEqual(self.state_of(task_id), "blocked")
        self.assertEqual(self.card_of(task_id)["attempt"], 0)
        self.assertTrue(attempt_dir.is_dir())
        event = json.loads(next(iter(self.events_of(task_id).values())))
        self.assertEqual(event["transition"], "block-attempt-dir")
        self.assertEqual(event["attempt"], 0)
        self.assertEqual(event["authority_digest"], digest)
        self.assertEqual(event["attempt_dir"], "a1")
        self.assertEqual(self.audit()[0], 0)

        terminal = self.durable_snapshot()
        code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-state-conflict")
        self.assertEqual(terminal, self.durable_snapshot())

    def test_first_exact_a2_preclaim_quarantine_is_a_valid_boundary(self):
        task_id = "task-first-exact-a2-quarantine"
        self.enqueue(self.make_card(task_id, max_attempts=2))
        self.claim_expect(task_id)
        code, payload = run_cli(
            "--root", self.root, "fail", "--task-id", task_id,
            "--worker", "worker-a", "--reason", "retry",
        )
        self.assertEqual(code, 0, payload)
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        original_verify = queue_cli._verify_payload
        verify_calls = 0

        def fail_post_move(card):
            nonlocal verify_calls
            verify_calls += 1
            if verify_calls == 2:
                raise queue_cli.QueueError("payload-tampered")
            return original_verify(card)

        with mock.patch.object(queue_cli, "_verify_payload", fail_post_move):
            code, payload = self.claim_exact(task_id, 2, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-payload-changed")
        self.assertEqual(self.state_of(task_id), "blocked")
        self.assertEqual(self.card_of(task_id)["attempt"], 1)
        events = [
            json.loads(raw) for raw in self.events_of(task_id).values()
        ]
        self.assertEqual(events[-1]["transition"], "block-payload")
        self.assertEqual(events[-1]["attempt"], 1)
        self.assertEqual(events[-1]["attempt_dir"], "a2")
        marker = json.loads((
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR / f"{task_id}.json"
        ).read_text("utf-8"))
        self.assertEqual(marker["first_exact_attempt"], 2)
        self.assertEqual(self.audit()[0], 0)

    def test_legacy_quarantine_requeue_then_first_exact_a1_or_a2(self):
        original_payload = b"night-autonomy payload\n"
        for first_attempt in (1, 2):
            with self.subTest(first_attempt=first_attempt):
                task_id = f"task-legacy-boundary-a{first_attempt}"
                self.enqueue(self.make_card(task_id, max_attempts=2))
                if first_attempt == 2:
                    self.claim_expect(task_id)
                    code, payload = run_cli(
                        "--root", self.root, "fail", "--task-id", task_id,
                        "--worker", "worker-a", "--reason", "retry",
                    )
                    self.assertEqual(code, 0, payload)

                self.payload_file.write_bytes(b"legacy payload drift\n")
                self.claim_expect_empty()
                self.assertEqual(self.state_of(task_id), "blocked")
                self.payload_file.write_bytes(original_payload)
                code, payload = run_cli(
                    "--root", self.root, "requeue", "--task-id", task_id,
                    "--worker", "worker-a",
                )
                self.assertEqual(code, 0, payload)
                self.assertEqual(self.state_of(task_id), "queue")

                code, view = self.peek_exact(task_id)
                self.assertEqual(code, 0, view)
                digest = view["task"]["digest"]
                code, payload = self.claim_exact(
                    task_id, first_attempt, digest
                )
                self.assertEqual(code, 0, payload)
                code, payload = run_cli(
                    "--root", self.root, "complete-exact", "--task-id",
                    task_id, "--expected-attempt", str(first_attempt),
                    "--expected-digest", digest, "--worker", "worker-a",
                )
                self.assertEqual(code, 0, payload)

                marker = json.loads((
                    Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
                    / f"{task_id}.json"
                ).read_text("utf-8"))
                self.assertEqual(
                    marker["prior_event_seq"],
                    2 if first_attempt == 1 else 4,
                )
                self.assertEqual(
                    marker["first_exact_attempt"], first_attempt
                )
                self.assertEqual(self.audit()[0], 0)

    def test_exact_managed_queued_payload_drift_quarantines_on_response_loss(self):
        task_id = "task-queued-exact-payload-loss"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        with queue_cli._task_lock(Path(self.root), task_id):
            queue_cli._ensure_exact_protocol_marker(
                Path(self.root), task_id, digest, 1
            )
        self.payload_file.write_bytes(b"drift after exact admission\n")
        original_quarantine = queue_cli._quarantine_from_queue

        def lose_response(*args, **kwargs):
            result = original_quarantine(*args, **kwargs)
            self.assertTrue(result)
            raise queue_cli.FatalIOError("synthetic-response-loss")

        with mock.patch.object(
            queue_cli, "_quarantine_from_queue", lose_response
        ):
            code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 3, payload)
        self.assertEqual(payload["error"], "synthetic-response-loss")
        self.assertEqual(self.state_of(task_id), "blocked")
        event = json.loads(next(iter(self.events_of(task_id).values())))
        self.assertEqual(event["transition"], "block-payload")
        self.assertEqual(event["authority_digest"], digest)
        self.assertEqual(event["attempt_dir"], "a1")
        self.assertEqual(self.audit()[0], 0)

        terminal = self.durable_snapshot()
        code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-state-conflict")
        self.assertEqual(terminal, self.durable_snapshot())

    def test_restart_without_cached_digest_repairs_exact_payload_and_lists_healthy(self):
        drifted_id = "task-a-restart-drift"
        healthy_id = "task-b-healthy"
        self.enqueue(self.make_card(drifted_id))

        healthy_file = self.allowed / "healthy.txt"
        healthy_file.write_bytes(b"independent healthy payload\n")
        self.enqueue(self.make_card(
            healthy_id,
            payload_relpath=healthy_file.name,
            payload_sha256=sha256_upper(healthy_file.read_bytes()),
        ))

        # Coordinator A durably admits exact protocol, then loses the response
        # before the claim move.  Coordinator B starts with no cached digest.
        digest = self.peek_exact(drifted_id)[1]["task"]["digest"]
        original_move = queue_cli._move_card

        def lose_before_claim(root, task_id, transition):
            if task_id == drifted_id and transition == "claim":
                raise queue_cli.QueueError("synthetic-claim-response-loss")
            return original_move(root, task_id, transition)

        with mock.patch.object(queue_cli, "_move_card", lose_before_claim):
            code, payload = self.claim_exact(drifted_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "synthetic-claim-response-loss")
        del digest

        self.payload_file.write_bytes(b"drift after coordinator restart\n")
        code, audit = self.audit()
        self.assertEqual(code, 3, audit)
        drift_gaps = [
            gap for gap in audit["gaps"]
            if gap["task_id"] == drifted_id
            and gap["kind"] == "exact_payload_unavailable"
        ]
        self.assertEqual(len(drift_gaps), 1, audit)
        durable_digest = drift_gaps[0]["authority_digest"]
        self.assertRegex(durable_digest, r"^[0-9a-f]{64}$")
        self.assertEqual(drift_gaps[0]["next_attempt"], 1)

        refused, result = self.peek_exact(drifted_id)
        self.assertEqual(refused, 2, result)
        self.assertEqual(result["error"], "payload-tampered")
        code, listed = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 0, listed)
        by_id = {task["task_id"]: task for task in listed["tasks"]}
        self.assertEqual(set(by_id), {drifted_id, healthy_id})
        self.assertFalse(by_id[drifted_id]["payload"]["verified"])
        self.assertEqual(
            by_id[drifted_id]["payload"]["error"], "payload-tampered"
        )
        self.assertTrue(by_id[healthy_id]["payload"]["verified"])

        original_quarantine = queue_cli._quarantine_from_queue

        def lose_quarantine_response(*args, **kwargs):
            result = original_quarantine(*args, **kwargs)
            self.assertTrue(result)
            raise queue_cli.FatalIOError("synthetic-repair-response-loss")

        with mock.patch.object(
            queue_cli, "_quarantine_from_queue", lose_quarantine_response
        ):
            code, payload = self.quarantine_exact_payload(drifted_id)
        self.assertEqual(code, 3, payload)
        self.assertEqual(payload["error"], "synthetic-repair-response-loss")
        self.assertEqual(self.state_of(drifted_id), "blocked")

        code, replay = self.quarantine_exact_payload(drifted_id)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["digest"], durable_digest)
        self.assertFalse(replay["payload_verified"])
        event = json.loads(
            next(iter(self.events_of(drifted_id).values()))
        )
        self.assertEqual(event["transition"], "block-payload")
        self.assertEqual(event["authority_digest"], durable_digest)
        self.assertEqual(event["attempt_dir"], "a1")

        code, audit = self.audit()
        self.assertEqual(code, 0, audit)
        code, listed = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 0, listed)
        self.assertEqual(
            [task["task_id"] for task in listed["tasks"]], [healthy_id]
        )
        self.assertIsNone(listed["tasks"][0]["worker"])

    def test_exact_payload_quarantine_requires_drift_and_durable_protocol(self):
        healthy_id = "task-repair-healthy"
        self.enqueue(self.make_card(healthy_id))
        # A healthy marker-free queue card refuses BEFORE any exact
        # admission: no marker is published and nothing durable moves.
        before = self.durable_snapshot()
        code, payload = self.quarantine_exact_payload(healthy_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-payload-not-drifted")
        self.assertEqual(before, self.durable_snapshot())

        digest = self.peek_exact(healthy_id)[1]["task"]["digest"]
        with queue_cli._task_lock(Path(self.root), healthy_id):
            queue_cli._ensure_exact_protocol_marker(
                Path(self.root), healthy_id, digest, 1
            )
        before = self.durable_snapshot()
        code, payload = self.quarantine_exact_payload(healthy_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-payload-not-drifted")
        self.assertEqual(before, self.durable_snapshot())

    def test_exact_payload_quarantine_refuses_corrupt_history_without_mutation(self):
        task_id = "task-repair-corrupt-history"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        with queue_cli._task_lock(Path(self.root), task_id):
            queue_cli._ensure_exact_protocol_marker(
                Path(self.root), task_id, digest, 1
            )
        marker_path = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR / f"{task_id}.json"
        )
        marker = json.loads(marker_path.read_text("ascii"))
        marker["prior_event_seq"] = 1
        marker_path.write_bytes(queue_cli._encode_json(marker))
        self.payload_file.write_bytes(b"drift with corrupt history\n")

        before = self.durable_snapshot()
        code, payload = self.quarantine_exact_payload(task_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("exact_protocol_inconsistency", kinds)
        self.assertNotIn("exact_payload_unavailable", kinds)

    def test_marker_free_queued_payload_drift_is_exposed_and_healable(self):
        # Fix8 P1 (review Probe B/B2): a fresh queued card has no exact
        # marker until its first successful claim-exact.  If its payload
        # drifts first, that must never be simultaneously audit-clean,
        # unhealable through exact verbs, and a global list-exact
        # head-of-line blocker hiding healthy work.
        drifted_id = "a-marker-free-drift"
        healthy_id = "t-healthy"
        self.enqueue(self.make_card(drifted_id))
        healthy_file = self.enqueue_with_own_payload(healthy_id)
        card_digest = queue_cli.card_authority_digest(self.card_of(drifted_id))
        self.payload_file.write_bytes(b"marker-free drift\n")

        # Probe B2: a wrong-profile legacy poll neither claims nor
        # quarantines; without Fix8 this left the card wedging list-exact.
        code, payload = self.claim(profile="claude-test1")
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "nothing-to-claim")
        self.assertEqual(self.state_of(drifted_id), "queue")

        # audit is NOT clean: it reports the task-scoped repair evidence
        # with the authority digest of the durable enqueue-validated card.
        code, audit = self.audit()
        self.assertEqual(code, 3, audit)
        drift_gaps = [
            gap for gap in audit["gaps"]
            if gap["kind"] == "exact_payload_unavailable"
        ]
        self.assertEqual(len(drift_gaps), 1, audit)
        self.assertEqual(drift_gaps[0]["task_id"], drifted_id)
        self.assertEqual(drift_gaps[0]["authority_digest"], card_digest)
        self.assertEqual(drift_gaps[0]["next_attempt"], 1)
        self.assertEqual(
            [gap for gap in audit["gaps"] if gap["task_id"] == healthy_id],
            [],
        )

        # list-exact exposes the bad task without hiding the healthy one.
        code, listed = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 0, listed)
        by_id = {task["task_id"]: task for task in listed["tasks"]}
        self.assertEqual(set(by_id), {drifted_id, healthy_id})
        self.assertFalse(by_id[drifted_id]["payload"]["verified"])
        self.assertEqual(
            by_id[drifted_id]["payload"]["error"], "payload-tampered"
        )
        self.assertEqual(by_id[drifted_id]["digest"], card_digest)
        self.assertEqual(by_id[drifted_id]["next_attempt"], 1)
        self.assertTrue(by_id[healthy_id]["payload"]["verified"])
        self.assertEqual(
            Path(by_id[healthy_id]["payload"]["path"]).read_bytes(),
            healthy_file.read_bytes(),
        )
        # peek-exact stays strictly fail-closed for the executable state.
        code, payload = self.peek_exact(drifted_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "payload-tampered")

        # Targeted fail-closed quarantine from durable card evidence only.
        code, repaired = self.quarantine_exact_payload(
            drifted_id, worker="worker-q"
        )
        self.assertEqual(code, 0, repaired)
        self.assertFalse(repaired["replayed"])
        self.assertEqual(repaired["digest"], card_digest)
        self.assertEqual(self.state_of(drifted_id), "blocked")
        marker = json.loads((
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
            / f"{drifted_id}.json"
        ).read_text("utf-8"))
        self.assertEqual(marker["authority_digest"], card_digest)
        self.assertEqual(marker["first_exact_attempt"], 1)
        self.assertEqual(marker["prior_event_seq"], 0)
        event = json.loads(next(iter(self.events_of(drifted_id).values())))
        self.assertEqual(event["transition"], "block-payload")
        self.assertEqual(event["attempt"], 0)
        self.assertEqual(event["worker"], "worker-q")
        self.assertEqual(event["authority_digest"], card_digest)
        self.assertEqual(event["attempt_dir"], "a1")

        # Sound history is audit-clean again, the quarantined card is
        # inspectable, and healthy work stays claimable.
        code, audit = self.audit()
        self.assertEqual(code, 0, audit)
        code, view = self.peek_exact(drifted_id)
        self.assertEqual(code, 0, view)
        self.assertEqual(view["task"]["state"], "blocked")
        self.assertFalse(view["task"]["payload"]["verified"])
        self.assertEqual(
            view["task"]["payload"]["error"], "payload-tampered"
        )
        code, listed = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 0, listed)
        self.assertEqual(
            [task["task_id"] for task in listed["tasks"]], [healthy_id]
        )
        self.claim_expect(healthy_id)
        self.assertEqual(self.audit()[0], 0)

    def test_marker_free_quarantine_crash_windows_and_replay(self):
        task_id = "task-mf-crash"
        self.enqueue(self.make_card(task_id))
        card_digest = queue_cli.card_authority_digest(self.card_of(task_id))
        self.payload_file.write_bytes(b"marker-free drift\n")
        marker_path = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR / f"{task_id}.json"
        )
        original_move = queue_cli._move_card

        def crash_before_move(root, moved_task, transition):
            if moved_task == task_id and transition == "block-payload":
                self.assertTrue(marker_path.is_file())
                raise queue_cli.QueueError("synthetic-crash-before-move")
            return original_move(root, moved_task, transition)

        with mock.patch.object(queue_cli, "_move_card", crash_before_move):
            code, payload = self.quarantine_exact_payload(task_id)
        self.assertEqual(code, 3, payload)
        self.assertEqual(payload["error"], "exact-quarantine-failed")
        # The marker landed durably strictly before the move: the crash
        # leaves the admitted idempotent response-loss window, and audit
        # still points at the same repair with the same authority.
        self.assertEqual(self.state_of(task_id), "queue")
        code, audit = self.audit()
        self.assertEqual(code, 3, audit)
        gaps = [gap for gap in audit["gaps"] if gap["task_id"] == task_id]
        self.assertEqual(
            {gap["kind"] for gap in gaps}, {"exact_payload_unavailable"}
        )
        self.assertEqual(gaps[0]["authority_digest"], card_digest)

        # The retry heals through the now marker-governed durable path.
        code, repaired = self.quarantine_exact_payload(task_id)
        self.assertEqual(code, 0, repaired)
        self.assertFalse(repaired["replayed"])
        self.assertEqual(repaired["digest"], card_digest)
        self.assertEqual(self.state_of(task_id), "blocked")
        terminal = self.durable_snapshot()

        # Response-loss replay is idempotent and worker-bound.
        code, replay = self.quarantine_exact_payload(task_id)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(terminal, self.durable_snapshot())
        code, refused = self.quarantine_exact_payload(
            task_id, worker="worker-b"
        )
        self.assertEqual(code, 2, refused)
        self.assertEqual(refused["error"], "exact-worker-mismatch")
        self.assertEqual(terminal, self.durable_snapshot())
        self.assertEqual(self.audit()[0], 0)

    def test_marker_free_quarantine_is_targeted_and_refuses_corruption(self):
        corrupt_id = "task-mf-corrupt"
        drifted_id = "task-mf-repairable"
        self.enqueue(self.make_card(corrupt_id))
        self.enqueue(self.make_card(drifted_id))
        self.payload_file.write_bytes(b"drift for both\n")
        # Corrupt the NAMED task's evidence: a stray attempt directory that
        # no claim history explains.
        (Path(self.root) / "attempts" / corrupt_id / "a1").mkdir(parents=True)

        before = self.durable_snapshot()
        code, payload = self.quarantine_exact_payload(corrupt_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        # Corrupt queued history keeps the deliberate all-or-nothing
        # list-exact head-of-line refusal.
        code, payload = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")

        # Audit refuses to label the corrupt task as repairable drift while
        # still reporting the healable one precisely.
        code, audit = self.audit()
        self.assertEqual(code, 3, audit)
        corrupt_kinds = {
            gap["kind"] for gap in audit["gaps"]
            if gap["task_id"] == corrupt_id
        }
        self.assertIn("extra_attempt_dir", corrupt_kinds)
        self.assertNotIn("exact_payload_unavailable", corrupt_kinds)
        self.assertEqual(
            {
                gap["kind"] for gap in audit["gaps"]
                if gap["task_id"] == drifted_id
            },
            {"exact_payload_unavailable"},
        )

        # Unrelated corrupt history cannot block the targeted repair.
        code, repaired = self.quarantine_exact_payload(drifted_id)
        self.assertEqual(code, 0, repaired)
        self.assertEqual(self.state_of(drifted_id), "blocked")

    def test_requeue_exact_restores_blocked_task_within_budget(self):
        # Fix8 P2 (review Probe F): an exact task quarantined by a transient
        # payload flap with retry budget remaining gets a true exact
        # blocked -> queue transition once the payload is restored.
        task_id = "task-exact-requeue"
        original_payload = self.payload_file.read_bytes()
        self.enqueue(self.make_card(task_id, max_attempts=2))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "fail-exact", "--task-id", task_id,
            "--expected-attempt", "1", "--expected-digest", digest,
            "--worker", "worker-a", "--disposition", "retry",
        )[0], 0)
        self.payload_file.write_bytes(b"transient payload flap\n")
        code, payload = self.claim_exact(task_id, 2, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-payload-changed")
        self.assertEqual(self.state_of(task_id), "blocked")
        self.payload_file.write_bytes(original_payload)

        # Restored byte-for-byte: peek shows the healthy quarantined card.
        code, view = self.peek_exact(task_id)
        self.assertEqual(code, 0, view)
        self.assertEqual(view["task"]["state"], "blocked")
        self.assertTrue(view["task"]["payload"]["verified"])

        # Legacy requeue may never downgrade the exact protocol.
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id", task_id,
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-transition-required")
        self.assertEqual(before, self.durable_snapshot())

        # Wrong CAS bindings and wrong worker refuse without mutation.
        for attempt, candidate, worker, error in (
            (2, digest, "worker-a", "exact-attempt-mismatch"),
            (1, "0" * 64, "worker-a", "exact-digest-mismatch"),
            (1, digest, "worker-b", "exact-worker-mismatch"),
        ):
            with self.subTest(error=error):
                code, payload = self.requeue_exact(
                    task_id, attempt, candidate, worker=worker
                )
                self.assertEqual(code, 2, payload)
                self.assertEqual(payload["error"], error)
                self.assertEqual(before, self.durable_snapshot())

        code, requeued = self.requeue_exact(task_id, 1, digest)
        self.assertEqual(code, 0, requeued)
        self.assertFalse(requeued["replayed"])
        self.assertEqual(requeued["state"], "queue")
        self.assertEqual(requeued["attempt"], 1)
        self.assertEqual(requeued["next_attempt"], 2)
        self.assertEqual(self.state_of(task_id), "queue")
        self.assertEqual(self.card_of(task_id)["attempt"], 1)
        self.assertEqual(self.audit()[0], 0)

        # Response-loss replay is idempotent; a conflicting worker refuses.
        requeued_snapshot = self.durable_snapshot()
        code, replay = self.requeue_exact(task_id, 1, digest)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(requeued_snapshot, self.durable_snapshot())
        code, payload = self.requeue_exact(
            task_id, 1, digest, worker="worker-b"
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-worker-mismatch")
        self.assertEqual(requeued_snapshot, self.durable_snapshot())

        # The next exact claim uses the correct next attempt with
        # no-downgrade semantics intact (legacy claim still skips it).
        code, payload = self.claim()
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "nothing-to-claim")
        code, claimed = self.claim_exact(task_id, 2, digest)
        self.assertEqual(code, 0, claimed)
        self.assertEqual(claimed["attempt"], 2)
        self.assertFalse(claimed["replayed"])
        self.assertTrue(
            (Path(self.root) / "attempts" / task_id / "a2").is_dir()
        )
        self.assertEqual(run_cli(
            "--root", self.root, "complete-exact", "--task-id", task_id,
            "--expected-attempt", "2", "--expected-digest", digest,
            "--worker", "worker-a",
        )[0], 0)
        self.assertEqual(self.audit()[0], 0)

    def test_requeue_exact_after_marker_free_quarantine_full_cycle(self):
        task_id = "task-mf-requeue-cycle"
        original_payload = self.payload_file.read_bytes()
        self.enqueue(self.make_card(task_id))
        card_digest = queue_cli.card_authority_digest(self.card_of(task_id))
        self.payload_file.write_bytes(b"pre-claim drift\n")
        code, payload = self.quarantine_exact_payload(
            task_id, worker="worker-q"
        )
        self.assertEqual(code, 0, payload)
        self.payload_file.write_bytes(original_payload)

        # Ownership is the durable quarantine tail, not the caller's word.
        before = self.durable_snapshot()
        code, payload = self.requeue_exact(task_id, 0, card_digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-worker-mismatch")
        self.assertEqual(before, self.durable_snapshot())

        code, requeued = self.requeue_exact(
            task_id, 0, card_digest, worker="worker-q"
        )
        self.assertEqual(code, 0, requeued)
        self.assertEqual(requeued["attempt"], 0)
        self.assertEqual(requeued["next_attempt"], 1)
        self.assertEqual(self.state_of(task_id), "queue")
        self.assertEqual(self.card_of(task_id)["attempt"], 0)
        self.assertEqual(self.audit()[0], 0)
        code, listed = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 0, listed)
        self.assertEqual(listed["tasks"][0]["task_id"], task_id)
        self.assertTrue(listed["tasks"][0]["payload"]["verified"])

        code, claimed = self.claim_exact(task_id, 1, card_digest)
        self.assertEqual(code, 0, claimed)
        self.assertEqual(claimed["attempt"], 1)
        self.assertEqual(run_cli(
            "--root", self.root, "complete-exact", "--task-id", task_id,
            "--expected-attempt", "1", "--expected-digest", card_digest,
            "--worker", "worker-a",
        )[0], 0)
        self.assertEqual(self.audit()[0], 0)

    def test_requeue_exact_refusals_without_mutation(self):
        # Payload still drifted after quarantine: refuse, keep quarantine.
        drifted_id = "task-rqx-drifted"
        drifted_payload = self.enqueue_with_own_payload(drifted_id)
        drifted_digest = queue_cli.card_authority_digest(
            self.card_of(drifted_id)
        )
        drifted_payload.write_bytes(b"still drifted\n")
        self.assertEqual(self.quarantine_exact_payload(drifted_id)[0], 0)
        before = self.durable_snapshot()
        code, payload = self.requeue_exact(drifted_id, 0, drifted_digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-payload-not-restored")
        self.assertEqual(before, self.durable_snapshot())
        self.assertEqual(self.state_of(drifted_id), "blocked")

        # CLI boundary: bad CAS inputs are stable single-JSON refusals.
        code, payload = run_cli(
            "--root", self.root, "requeue-exact", "--task-id", drifted_id,
            "--expected-attempt", "-1", "--expected-digest", drifted_digest,
            "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "invalid-expected-attempt")

        # Exhausted budget can never be re-armed.
        spent_id = "task-rqx-exhausted"
        self.enqueue_with_own_payload(spent_id, max_attempts=1)
        spent_digest = self.peek_exact(spent_id)[1]["task"]["digest"]
        self.assertEqual(self.claim_exact(spent_id, 1, spent_digest)[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "block-exact", "--task-id", spent_id,
            "--expected-attempt", "1", "--expected-digest", spent_digest,
            "--worker", "worker-a", "--reason", "owner gate",
        )[0], 0)
        before = self.durable_snapshot()
        code, payload = self.requeue_exact(spent_id, 1, spent_digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "max-attempts-exhausted")
        self.assertEqual(before, self.durable_snapshot())

        # Wrong state (in_progress) refuses.
        running_id = "task-rqx-running"
        self.enqueue_with_own_payload(running_id)
        running_digest = self.peek_exact(running_id)[1]["task"]["digest"]
        self.assertEqual(
            self.claim_exact(running_id, 1, running_digest)[0], 0
        )
        before = self.durable_snapshot()
        code, payload = self.requeue_exact(running_id, 1, running_digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-state-conflict")
        self.assertEqual(before, self.durable_snapshot())

        # Marker-free blocked work stays on the legacy requeue verb.
        legacy_id = "task-rqx-legacy"
        legacy_payload = self.enqueue_with_own_payload(legacy_id)
        legacy_digest = queue_cli.card_authority_digest(
            self.card_of(legacy_id)
        )
        legacy_payload.write_bytes(b"legacy drift\n")
        self.claim_expect_empty()
        self.assertEqual(self.state_of(legacy_id), "blocked")
        before = self.durable_snapshot()
        code, payload = self.requeue_exact(legacy_id, 0, legacy_digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-missing")
        self.assertEqual(before, self.durable_snapshot())

        # Corrupt/noncanonical history refuses.
        corrupt_id = "task-rqx-corrupt"
        corrupt_payload = self.enqueue_with_own_payload(corrupt_id)
        corrupt_digest = queue_cli.card_authority_digest(
            self.card_of(corrupt_id)
        )
        corrupt_payload.write_bytes(b"corrupt drift\n")
        self.assertEqual(self.quarantine_exact_payload(corrupt_id)[0], 0)
        corrupt_payload.write_bytes(
            f"payload for {corrupt_id}\n".encode("ascii")
        )
        marker_path = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
            / f"{corrupt_id}.json"
        )
        marker = json.loads(marker_path.read_text("utf-8"))
        marker["prior_event_seq"] = 1
        marker_path.write_bytes(queue_cli._encode_json(marker))
        before = self.durable_snapshot()
        code, payload = self.requeue_exact(corrupt_id, 0, corrupt_digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

    def test_requeue_exact_crash_window_stays_visible_and_fail_closed(self):
        task_id = "task-rqx-crash"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "block-exact", "--task-id", task_id,
            "--expected-attempt", "1", "--expected-digest", digest,
            "--worker", "worker-a", "--reason", "transient",
        )[0], 0)
        original_append = queue_cli._append_event

        def crash_append(root, moved_task, transition, attempt, worker,
                         reason="", **kwargs):
            if moved_task == task_id and transition == "requeue-exact":
                raise queue_cli.FatalIOError("synthetic-event-crash")
            return original_append(
                root, moved_task, transition, attempt, worker, reason,
                **kwargs
            )

        with mock.patch.object(queue_cli, "_append_event", crash_append):
            code, payload = self.requeue_exact(task_id, 1, digest)
        self.assertEqual(code, 3, payload)
        self.assertEqual(payload["error"], "synthetic-event-crash")
        self.assertEqual(self.state_of(task_id), "queue")

        # The move-before-event window is a visible AUDIT_GAP and is never
        # silently repaired: the identical retry fails closed.
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("state_mismatch", kinds)
        before = self.durable_snapshot()
        code, payload = self.requeue_exact(task_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

    def test_requeue_exact_event_schema_binds_next_generation(self):
        event = {
            "version": 1,
            "task_id": "task-schema",
            "seq": 1,
            "transition": "requeue-exact",
            "from_state": "blocked",
            "to_state": "queue",
            "attempt": 0,
            "worker": "worker-a",
            "reason": "",
            "recorded_utc": "2026-07-13T12:00:00.000Z",
            "authority_digest": "a" * 64,
            "attempt_dir": "a1",
        }
        self.assertIsNone(queue_cli._event_error(event, "task-schema", 1))
        wrong_dir = dict(event, attempt_dir="a0")
        self.assertEqual(
            queue_cli._event_error(wrong_dir, "task-schema", 1),
            "attempt-dir",
        )
        current_generation = dict(event, attempt=1)
        self.assertEqual(
            queue_cli._event_error(current_generation, "task-schema", 1),
            "attempt-dir",
        )

        # A requeue-exact event stripped of its exact metadata is a
        # detectable downgrade, not a legacy transition.
        task_id = "task-rqx-stripped"
        original_payload = self.payload_file.read_bytes()
        self.enqueue(self.make_card(task_id))
        card_digest = queue_cli.card_authority_digest(self.card_of(task_id))
        self.payload_file.write_bytes(b"drift before strip\n")
        self.assertEqual(self.quarantine_exact_payload(task_id)[0], 0)
        self.payload_file.write_bytes(original_payload)
        self.assertEqual(self.requeue_exact(task_id, 0, card_digest)[0], 0)
        event_path = Path(self.root) / "events" / task_id / "000002.json"
        stripped = json.loads(event_path.read_text("utf-8"))
        del stripped["authority_digest"]
        del stripped["attempt_dir"]
        event_path.write_bytes(queue_cli._encode_json(stripped))
        before = self.durable_snapshot()
        code, payload = self.peek_exact(task_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("exact_transition_inconsistency", kinds)

    def test_requeue_exact_refuses_attempt_dir_quarantine_without_mutation(self):
        # Fix9 P1: an exact block-attempt-dir quarantine binds an immutable
        # collision directory that can never be removed or reused, so the
        # quarantine is terminal for the task identity: requeue-exact must
        # refuse instead of re-arming a claim that would collide forever.
        task_id = "task-rqx-attempt-dir"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        attempt_dir = Path(self.root) / "attempts" / task_id / "a1"
        original_mkdir = queue_cli.os.mkdir

        def collide(path, mode=0o777, *args, **kwargs):
            if Path(path) == attempt_dir:
                original_mkdir(path, mode, *args, **kwargs)
                raise FileExistsError(str(path))
            return original_mkdir(path, mode, *args, **kwargs)

        with mock.patch.object(queue_cli.os, "mkdir", collide):
            code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-attempt-dir-conflict")
        self.assertEqual(self.state_of(task_id), "blocked")
        self.assertEqual(self.audit()[0], 0)

        before = self.durable_snapshot()
        for worker in ("worker-a", "worker-b"):
            with self.subTest(worker=worker):
                code, payload = self.requeue_exact(
                    task_id, 0, digest, worker=worker
                )
                self.assertEqual(code, 2, payload)
                self.assertEqual(
                    payload["error"], "exact-attempt-dir-not-requeueable"
                )
                self.assertEqual(before, self.durable_snapshot())
                self.assertEqual(self.state_of(task_id), "blocked")
        # Audit stays consistent with the immutable quarantine evidence.
        self.assertEqual(self.audit()[0], 0)
        self.assertTrue(attempt_dir.is_dir())

    def test_forged_requeue_after_attempt_dir_quarantine_is_never_clean(self):
        # Fix9 P1: even a canonical-looking requeue-exact persisted after an
        # exact block-attempt-dir tail (the old false re-arm) is rejected by
        # the validator and reported by audit, so the quarantine -> requeue
        # -> collision loop can never look clean or consume the queue.
        task_id = "task-rqx-forged-loop"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        attempt_dir = Path(self.root) / "attempts" / task_id / "a1"
        original_mkdir = queue_cli.os.mkdir

        def collide(path, mode=0o777, *args, **kwargs):
            if Path(path) == attempt_dir:
                original_mkdir(path, mode, *args, **kwargs)
                raise FileExistsError(str(path))
            return original_mkdir(path, mode, *args, **kwargs)

        with mock.patch.object(queue_cli.os, "mkdir", collide):
            self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 2)
        self.assertEqual(self.state_of(task_id), "blocked")

        queue_cli._move_card(Path(self.root), task_id, "requeue-exact")
        queue_cli._append_event(
            Path(self.root), task_id, "requeue-exact", 0, "worker-a",
            authority_digest=digest, attempt_dir="a1",
        )

        before = self.durable_snapshot()
        for command in ("peek", "list", "claim", "requeue"):
            with self.subTest(command=command):
                if command == "peek":
                    code, payload = self.peek_exact(task_id)
                elif command == "list":
                    code, payload = run_cli(
                        "--root", self.root, "list-exact"
                    )
                elif command == "claim":
                    code, payload = self.claim_exact(task_id, 1, digest)
                else:
                    code, payload = self.requeue_exact(task_id, 0, digest)
                self.assertEqual(code, 2, payload)
                self.assertEqual(payload["error"], "exact-evidence-invalid")
                self.assertEqual(before, self.durable_snapshot())
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("exact_transition_inconsistency", kinds)
        details = {gap.get("detail") for gap in audit["gaps"]}
        self.assertIn("requeue-exact-after-attempt-dir-quarantine", details)

    def test_worker_forged_requeue_after_terminal_block_fails_closed(self):
        # Fix9 P2: rewriting only the worker field of the persisted
        # requeue-exact event after an exact terminal block breaks durable
        # owner continuity for every caller and can never audit clean.
        task_id = "task-rqx-worker-forge"
        self.enqueue(self.make_card(task_id, max_attempts=2))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "block-exact", "--task-id", task_id,
            "--expected-attempt", "1", "--expected-digest", digest,
            "--worker", "worker-a", "--reason", "operator gate",
        )[0], 0)

        # Canonical terminal-block requeue plus response-loss replay keep
        # succeeding for the original owner; other workers stay refused
        # without mutation.
        code, requeued = self.requeue_exact(task_id, 1, digest)
        self.assertEqual(code, 0, requeued)
        self.assertFalse(requeued["replayed"])
        canonical = self.durable_snapshot()
        code, replay = self.requeue_exact(task_id, 1, digest)
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(canonical, self.durable_snapshot())
        code, payload = self.requeue_exact(
            task_id, 1, digest, worker="worker-b"
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-worker-mismatch")
        self.assertEqual(canonical, self.durable_snapshot())
        self.assertEqual(self.audit()[0], 0)

        event_path = Path(self.root) / "events" / task_id / "000003.json"
        forged = json.loads(event_path.read_text("utf-8"))
        self.assertEqual(forged["transition"], "requeue-exact")
        forged["worker"] = "worker-b"
        event_path.write_bytes(queue_cli._encode_json(forged))

        before = self.durable_snapshot()
        for worker in ("worker-b", "worker-a"):
            with self.subTest(worker=worker):
                code, payload = self.requeue_exact(
                    task_id, 1, digest, worker=worker
                )
                self.assertEqual(code, 2, payload)
                self.assertEqual(payload["error"], "exact-evidence-invalid")
                self.assertEqual(before, self.durable_snapshot())
        code, payload = self.peek_exact(task_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        code, payload = run_cli("--root", self.root, "list-exact")
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        code, payload = self.claim_exact(task_id, 2, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("exact_transition_inconsistency", kinds)
        details = {gap.get("detail") for gap in audit["gaps"]}
        self.assertIn("requeue-exact-worker-mismatch", details)

    def test_worker_forged_requeue_after_payload_quarantine_fails_closed(self):
        # Fix9 P2: the same event-only worker forgery after an exact
        # block-payload restore/requeue cycle is rejected end to end.
        task_id = "task-rqx-worker-forge-payload"
        payload_file = self.enqueue_with_own_payload(task_id)
        original_payload = payload_file.read_bytes()
        digest = queue_cli.card_authority_digest(self.card_of(task_id))
        payload_file.write_bytes(b"pre-claim drift\n")
        self.assertEqual(
            self.quarantine_exact_payload(task_id, worker="worker-q")[0], 0
        )
        payload_file.write_bytes(original_payload)
        code, requeued = self.requeue_exact(
            task_id, 0, digest, worker="worker-q"
        )
        self.assertEqual(code, 0, requeued)
        canonical = self.durable_snapshot()
        code, replay = self.requeue_exact(
            task_id, 0, digest, worker="worker-q"
        )
        self.assertEqual(code, 0, replay)
        self.assertTrue(replay["replayed"])
        self.assertEqual(canonical, self.durable_snapshot())
        self.assertEqual(self.audit()[0], 0)

        event_path = Path(self.root) / "events" / task_id / "000002.json"
        forged = json.loads(event_path.read_text("utf-8"))
        self.assertEqual(forged["transition"], "requeue-exact")
        forged["worker"] = "worker-r"
        event_path.write_bytes(queue_cli._encode_json(forged))

        before = self.durable_snapshot()
        for worker in ("worker-r", "worker-q"):
            with self.subTest(worker=worker):
                code, payload = self.requeue_exact(
                    task_id, 0, digest, worker=worker
                )
                self.assertEqual(code, 2, payload)
                self.assertEqual(payload["error"], "exact-evidence-invalid")
                self.assertEqual(before, self.durable_snapshot())
        code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("exact_transition_inconsistency", kinds)
        details = {gap.get("detail") for gap in audit["gaps"]}
        self.assertIn("requeue-exact-worker-mismatch", details)

    def test_exhausted_exact_queue_card_refuses_as_evidence_invalid(self):
        # A durably exhausted card sitting in queue/ is corrupt history: the
        # exact claim refuses it as exact-evidence-invalid without mutation
        # and audit reports the budget violation.  (The legacy claim verb
        # keeps its own max-attempts-exhausted refusal for history-free
        # cards; requeue verbs keep it for legal blocked/failed cards.)
        task_id = "task-exhausted-exact-queue"
        self.enqueue(self.make_card(task_id, max_attempts=1))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "fail-exact", "--task-id", task_id,
            "--expected-attempt", "1", "--expected-digest", digest,
            "--worker", "worker-a", "--disposition", "final",
        )[0], 0)
        os.rename(
            Path(self.root) / "failed" / f"{task_id}.json",
            Path(self.root) / "queue" / f"{task_id}.json",
        )
        before = self.durable_snapshot()
        code, payload = self.claim_exact(task_id, 2, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("attempt_budget_violation", kinds)

    def test_forged_exact_quarantine_metadata_omission_is_rejected(self):
        task_id = "task-forged-exact-omission"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        with queue_cli._task_lock(Path(self.root), task_id):
            queue_cli._ensure_exact_protocol_marker(
                Path(self.root), task_id, digest, 1
            )
        self.payload_file.write_bytes(b"drift after exact admission\n")
        code, payload = self.claim_exact(task_id, 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-payload-changed")
        event_path = (
            Path(self.root) / "events" / task_id / "000001.json"
        )
        event = json.loads(event_path.read_text("utf-8"))
        del event["authority_digest"]
        del event["attempt_dir"]
        event_path.write_bytes(queue_cli._encode_json(event))

        before = self.durable_snapshot()
        code, payload = self.peek_exact(task_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("exact_protocol_inconsistency", kinds)

    def test_forged_legacy_requeue_after_exact_quarantine_is_rejected(self):
        task_id = "task-forged-exact-requeue"
        self.enqueue(self.make_card(task_id))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        with queue_cli._task_lock(Path(self.root), task_id):
            queue_cli._ensure_exact_protocol_marker(
                Path(self.root), task_id, digest, 1
            )
        self.payload_file.write_bytes(b"drift after exact admission\n")
        self.assertEqual(self.claim_exact(task_id, 1, digest)[0], 2)
        queue_cli._move_card(Path(self.root), task_id, "requeue-blocked")
        queue_cli._append_event(
            Path(self.root), task_id, "requeue-blocked", 0, "worker-x"
        )

        before = self.durable_snapshot()
        code, payload = self.peek_exact(task_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("exact_transition_inconsistency", kinds)

    def test_audit_rejects_first_exact_attempt_above_card_budget(self):
        task_id = "task-marker-over-budget"
        self.enqueue(self.make_card(task_id, max_attempts=1))
        digest = self.peek_exact(task_id)[1]["task"]["digest"]
        marker_path = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR / f"{task_id}.json"
        )
        marker_path.write_bytes(queue_cli._encode_json({
            "version": 1,
            "task_id": task_id,
            "authority_digest": digest,
            "first_exact_attempt": 2,
            "prior_event_seq": 0,
        }))
        code, payload = self.peek_exact(task_id)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        code, kinds, audit = self.audit_kinds()
        self.assertEqual(code, 3, audit)
        self.assertIn("exact_protocol_conflict", kinds)

    def test_legacy_claim_skips_valid_exact_queue_but_surfaces_corruption(self):
        exact_id = "task-a-exact-managed"
        legacy_id = "task-b-legacy"
        self.enqueue(self.make_card(exact_id))
        self.enqueue(self.make_card(legacy_id))
        digest = self.peek_exact(exact_id)[1]["task"]["digest"]
        with queue_cli._task_lock(Path(self.root), exact_id):
            queue_cli._ensure_exact_protocol_marker(
                Path(self.root), exact_id, digest, 1
            )

        code, payload = self.claim()
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["task_id"], legacy_id)
        self.assertEqual(self.state_of(exact_id), "queue")
        self.assertEqual(self.audit()[0], 0)
        self.claim_expect_empty()

        later_id = "task-c-legacy"
        self.enqueue(self.make_card(later_id))
        marker = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR / f"{exact_id}.json"
        )
        marker.write_bytes(b"{")
        before = self.durable_snapshot()
        code, payload = self.claim()
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        self.assertEqual(self.state_of(later_id), "queue")

    def test_exact_marker_first_admission_race_requires_exact_proposal(self):
        def prepare_legacy_a2(task_id: str) -> tuple[str, Path]:
            self.enqueue(self.make_card(task_id, max_attempts=2))
            self.assertEqual(self.claim()[0], 0)
            code, payload = run_cli(
                "--root", self.root, "fail", "--task-id", task_id,
                "--worker", "worker-a", "--reason", "retry",
            )
            self.assertEqual(code, 0, payload)
            digest = self.peek_exact(task_id)[1]["task"]["digest"]
            marker_path = (
                Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
                / f"{task_id}.json"
            )
            return digest, marker_path

        original_publish = queue_cli._publish_json_exclusive

        matching_id = "task-marker-race-matching"
        matching_digest, matching_path = prepare_legacy_a2(matching_id)

        def publish_matching_winner(root, target, value):
            if target == matching_path:
                original_publish(root, target, value)
                raise FileExistsError(str(target))
            return original_publish(root, target, value)

        with mock.patch.object(
            queue_cli, "_publish_json_exclusive", publish_matching_winner
        ):
            code, payload = self.claim_exact(matching_id, 2, matching_digest)
        self.assertEqual(code, 0, payload)
        self.assertEqual(self.state_of(matching_id), "in_progress")
        self.assertEqual(self.card_of(matching_id)["attempt"], 2)
        self.assertEqual(
            json.loads(matching_path.read_text("utf-8"))[
                "first_exact_attempt"
            ],
            2,
        )
        self.assertEqual(self.audit()[0], 0)

        task_id = "task-marker-race-conflict"
        digest, marker_path = prepare_legacy_a2(task_id)

        def publish_conflicting_winner(root, target, value):
            if target == marker_path:
                competing = dict(value, first_exact_attempt=1)
                original_publish(root, target, competing)
                raise FileExistsError(str(target))
            return original_publish(root, target, value)

        with mock.patch.object(
            queue_cli, "_publish_json_exclusive", publish_conflicting_winner
        ):
            code, payload = self.claim_exact(task_id, 2, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-protocol-conflict")
        self.assertEqual(self.state_of(task_id), "queue")
        self.assertEqual(self.card_of(task_id)["attempt"], 1)
        self.assertFalse(
            (Path(self.root) / "attempts" / task_id / "a2").exists()
        )
        self.assertEqual(len(self.events_of(task_id)), 2)
        self.assertEqual(
            json.loads(marker_path.read_text("utf-8"))["first_exact_attempt"],
            1,
        )

    def test_exact_marker_conflict_malformed_and_removal_fail_closed(self):
        # Conflicting but canonical marker before first exact admission.
        self.enqueue(self.make_card("task-marker-conflict"))
        conflict_path = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
            / "task-marker-conflict.json"
        )
        conflict_path.write_bytes(queue_cli._encode_json({
            "version": 1,
            "task_id": "task-marker-conflict",
            "authority_digest": "0" * 64,
            "first_exact_attempt": 1,
            "prior_event_seq": 0,
        }))
        digest = queue_cli.card_authority_digest(
            self.card_of("task-marker-conflict")
        )
        before = self.durable_snapshot()
        code, payload = self.claim_exact("task-marker-conflict", 1, digest)
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

        # Non-canonical/malformed marker also refuses without repair.
        self.enqueue(self.make_card("task-marker-malformed"))
        malformed_path = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
            / "task-marker-malformed.json"
        )
        malformed_path.write_bytes(b"{")
        before = self.durable_snapshot()
        code, payload = self.peek_exact("task-marker-malformed")
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())

        # Removing provenance after an exact claim cannot make it legacy.
        self.enqueue(self.make_card("task-marker-removed"))
        removed_digest = self.peek_exact(
            "task-marker-removed"
        )[1]["task"]["digest"]
        self.assertEqual(
            self.claim_exact("task-marker-removed", 1, removed_digest)[0], 0
        )
        removed_path = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR
            / "task-marker-removed.json"
        )
        removed_path.unlink()
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "complete-exact", "--task-id",
            "task-marker-removed", "--expected-attempt", "1",
            "--expected-digest", removed_digest, "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-evidence-invalid")
        self.assertEqual(before, self.durable_snapshot())
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("exact_protocol_missing", kinds)

    def test_authoritative_peek_and_list_reject_missing_attempt_dir(self):
        self.enqueue(self.make_card("task-view-missing-a1", max_attempts=2))
        digest = self.peek_exact("task-view-missing-a1")[1]["task"]["digest"]
        self.assertEqual(
            self.claim_exact("task-view-missing-a1", 1, digest)[0], 0
        )
        self.assertEqual(run_cli(
            "--root", self.root, "fail-exact", "--task-id",
            "task-view-missing-a1", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
            "--disposition", "retry",
        )[0], 0)
        (Path(self.root) / "attempts" / "task-view-missing-a1" / "a1").rmdir()
        before = self.durable_snapshot()
        for argv in (
            ("peek-exact", "--task-id", "task-view-missing-a1"),
            ("list-exact",),
        ):
            code, payload = run_cli("--root", self.root, *argv)
            self.assertEqual(code, 2, payload)
            self.assertEqual(payload["error"], "exact-evidence-invalid")
            self.assertEqual(before, self.durable_snapshot())

    def test_authoritative_peek_and_list_reject_illegal_history(self):
        self.enqueue(self.make_card("task-view-illegal", max_attempts=2))
        self.assertEqual(self.claim()[0], 0)
        self.assertEqual(run_cli(
            "--root", self.root, "fail", "--task-id", "task-view-illegal",
            "--worker", "worker-a", "--reason", "retry",
        )[0], 0)
        event_path = (
            Path(self.root) / "events" / "task-view-illegal" / "000001.json"
        )
        event = json.loads(event_path.read_text("utf-8"))
        event["from_state"] = "in_progress"
        event["to_state"] = "done"
        event["transition"] = "complete"
        event_path.write_bytes(queue_cli._encode_json(event))
        before = self.durable_snapshot()
        for argv in (
            ("peek-exact", "--task-id", "task-view-illegal"),
            ("list-exact",),
        ):
            code, payload = run_cli("--root", self.root, *argv)
            self.assertEqual(code, 2, payload)
            self.assertEqual(payload["error"], "exact-evidence-invalid")
            self.assertEqual(before, self.durable_snapshot())

    def test_audit_waits_for_exact_move_event_transaction(self):
        self.enqueue(self.make_card("task-audit-serialized"))
        digest = self.peek_exact("task-audit-serialized")[1]["task"]["digest"]
        entered = threading.Event()
        release = threading.Event()
        original_append = queue_cli._append_event

        def delayed_append(root, task_id, transition, attempt, worker,
                           reason="", **kwargs):
            if task_id == "task-audit-serialized" and transition == "claim":
                entered.set()
                if not release.wait(10):
                    raise AssertionError("test did not release exact event")
            return original_append(
                root, task_id, transition, attempt, worker, reason, **kwargs
            )

        with mock.patch.object(queue_cli, "_append_event", delayed_append):
            with ThreadPoolExecutor(max_workers=1) as pool:
                claimed = pool.submit(
                    queue_cli.cmd_claim_exact, self.root,
                    "task-audit-serialized", 1, digest, "claude-work",
                    "claude-fable-5", "worker-a",
                )
                self.assertTrue(entered.wait(5))
                auditor = subprocess.Popen(
                    [sys.executable, "-m", "autonomy.queue_cli", "--root",
                     self.root, "audit"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    cwd=str(ROOT),
                )
                time.sleep(0.25)
                self.assertIsNone(
                    auditor.poll(), "audit observed move-before-event window"
                )
                release.set()
                claim_code, claim_payload = claimed.result(timeout=10)
                out, err = auditor.communicate(timeout=20)
        self.assertEqual(claim_code, 0, claim_payload)
        self.assertEqual(auditor.returncode, 0, out)
        self.assertEqual(err, "")
        self.assertTrue(json.loads(out)["ok"])

    def test_exact_protocol_blocks_legacy_requeue(self):
        self.enqueue(self.make_card("task-exact-no-legacy-requeue"))
        digest = self.peek_exact(
            "task-exact-no-legacy-requeue"
        )[1]["task"]["digest"]
        self.assertEqual(
            self.claim_exact("task-exact-no-legacy-requeue", 1, digest)[0], 0
        )
        self.assertEqual(run_cli(
            "--root", self.root, "block-exact", "--task-id",
            "task-exact-no-legacy-requeue", "--expected-attempt", "1",
            "--expected-digest", digest, "--worker", "worker-a",
            "--reason", "owner gate",
        )[0], 0)
        before = self.durable_snapshot()
        code, payload = run_cli(
            "--root", self.root, "requeue", "--task-id",
            "task-exact-no-legacy-requeue", "--worker", "worker-a",
        )
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["error"], "exact-transition-required")
        self.assertEqual(before, self.durable_snapshot())

    def test_lock_release_after_failure_preserves_visible_crash_gap(self):
        self.enqueue(self.make_card("task-crash-lock"))
        self.claim_expect("task-crash-lock")
        original_append = queue_cli._append_event

        def crash_append(root, task_id, transition, attempt, worker, reason=""):
            if task_id == "task-crash-lock" and transition == "complete":
                raise queue_cli.FatalIOError("synthetic-event-crash")
            return original_append(
                root, task_id, transition, attempt, worker, reason
            )

        with mock.patch.object(queue_cli, "_append_event", crash_append):
            code, payload = run_cli(
                "--root", self.root, "complete", "--task-id",
                "task-crash-lock", "--worker", "worker-a",
            )
        self.assertEqual(code, 3, payload)
        self.assertEqual(self.state_of("task-crash-lock"), "done")
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("state_mismatch", kinds)

    # ---------------------------------------------------------------- audit

    def test_audit_detects_simulated_claim_crash_windows(self):
        # Window A: rename happened, nothing else did.
        self.enqueue(self.make_card("task-w1"))
        os.rename(
            Path(self.root) / "queue" / "task-w1.json",
            Path(self.root) / "in_progress" / "task-w1.json",
        )
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("state_mismatch", kinds)

        # Window B: a claimed task was moved onward without its event.
        code, payload = run_cli(
            "--root", self.root, "fail", "--task-id", "task-w1",
            "--worker", "worker-a", "--reason", "reset",
        )
        self.assertEqual(code, 2, payload)  # attempt 0 in in_progress is a
        self.assertEqual(payload["error"], "card-never-claimed")  # crash artifact
        os.rename(
            Path(self.root) / "in_progress" / "task-w1.json",
            Path(self.root) / "queue" / "task-w1.json",
        )
        self.enqueue(self.make_card("task-w2"))
        self.claim_expect("task-w1")
        os.rename(
            Path(self.root) / "in_progress" / "task-w1.json",
            Path(self.root) / "done" / "task-w1.json",
        )
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("state_mismatch", kinds)

        # Window C: attempt dir created ahead of the card rewrite.
        self.claim_expect("task-w2")
        (Path(self.root) / "attempts" / "task-w2" / "a2").mkdir()
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("extra_attempt_dir", kinds)

    def test_audit_collects_all_safe_claim_crash_diagnostics(self):
        self.enqueue(self.make_card("task-multi-gap"))
        queue_card = Path(self.root) / "queue" / "task-multi-gap.json"
        progress_card = (
            Path(self.root) / "in_progress" / "task-multi-gap.json"
        )
        os.rename(queue_card, progress_card)
        (Path(self.root) / "attempts" / "task-multi-gap" / "a1").mkdir(
            parents=True
        )
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("state_mismatch", kinds)
        self.assertIn("extra_attempt_dir", kinds)

        card = json.loads(progress_card.read_text("utf-8"))
        card["attempt"] = 1
        progress_card.write_text(json.dumps(card), encoding="ascii")
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("state_mismatch", kinds)
        self.assertIn("card_attempt_mismatch", kinds)
        self.assertIn("extra_attempt_dir", kinds)

    def test_audit_rejects_unicode_digit_event_names_and_timestamps(self):
        self.enqueue(self.make_card("task-ascii-event"))
        self.claim_expect("task-ascii-event")
        event_dir = Path(self.root) / "events" / "task-ascii-event"
        (event_dir / "000001.json").rename(event_dir / "٠٠٠٠٠١.json")
        code, kinds, payload = self.audit_kinds()
        self.assertEqual(code, 3, payload)
        self.assertIn("unexpected_entry", kinds)

        self.assertFalse(queue_cli._utc_valid("٢٠٢٦-٠٧-١٣T12:00:00.000Z"))

    def test_audit_rejects_reserved_exact_marker_before_lstat(self):
        reserved = (
            Path(self.root) / queue_cli.EXACT_PROTOCOL_DIR / "con.json"
        )
        reserved.write_bytes(b"{}")
        original_lstat = queue_cli.os.lstat

        def guarded_lstat(path, *args, **kwargs):
            if Path(path) == reserved:
                self.fail("reserved exact marker path was touched before screening")
            return original_lstat(path, *args, **kwargs)

        with mock.patch.object(queue_cli.os, "lstat", guarded_lstat):
            code, payload = self.audit()
        self.assertEqual(code, 3, payload)
        self.assertIn(
            (queue_cli.EXACT_PROTOCOL_DIR, "con.json"),
            {
                (gap.get("where"), gap.get("entry"))
                for gap in payload["gaps"]
                if gap["kind"] == "unexpected_entry"
            },
        )

    @unittest.skipUnless(os.name == "nt", "Windows reserved-name semantics")
    def test_audit_surfaces_windows_reserved_state_and_child_residue(self):
        queue_entry = Path(self.root) / "queue" / "con.json"
        events_entry = Path(self.root) / "events" / "prn"
        attempts_entry = Path(self.root) / "attempts" / "aux"

        def extended(path: Path) -> str:
            return "\\\\?\\" + str(path.resolve())

        extended_queue = extended(queue_entry)
        extended_events = extended(events_entry)
        extended_attempts = extended(attempts_entry)
        try:
            with open(extended_queue, "xb") as stream:
                stream.write(b"{}")
            os.mkdir(extended_events)
            os.mkdir(extended_attempts)

            code, payload = self.audit()
            self.assertEqual(code, 3, payload)
            unexpected = {
                (gap.get("where"), gap.get("entry"))
                for gap in payload["gaps"]
                if gap["kind"] == "unexpected_entry"
            }
            self.assertTrue({
                ("queue", "con.json"),
                ("events", "prn"),
                ("attempts", "aux"),
            }.issubset(unexpected), payload)
        finally:
            for operation, path in (
                (os.unlink, extended_queue),
                (os.rmdir, extended_events),
                (os.rmdir, extended_attempts),
            ):
                try:
                    operation(path)
                except FileNotFoundError:
                    pass

    def test_audit_gap_matrix(self):
        def fresh_root(tag: str) -> str:
            root = str(self.base / f"gap-{tag}")
            code, payload = run_cli("--root", root, "init")
            self.assertEqual(code, 0, payload)
            return root

        def enqueue_at(root: str, card: dict):
            source = self.write_card_file(card, f"gap-card-{card['task_id']}.json")
            code, payload = run_cli("--root", root, "enqueue", "--card", str(source))
            self.assertEqual(code, 0, payload)

        def claim_at(root: str):
            code, payload = run_cli(
                "--root", root, "claim", "--profile", "claude-work",
                "--model", "claude-fable-5", "--worker", "worker-a",
            )
            self.assertEqual(code, 0, payload)
            return payload

        def expect_gap(root: str, kind: str):
            code, payload = run_cli("--root", root, "audit")
            self.assertEqual(code, 3, (kind, payload))
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["audit"], "AUDIT_GAP")
            kinds = {gap["kind"] for gap in payload["gaps"]}
            self.assertIn(kind, kinds, payload)

        with self.subTest(gap="duplicate_states"):
            root = fresh_root("dup")
            enqueue_at(root, self.make_card("task-a"))
            shutil.copyfile(
                Path(root) / "queue" / "task-a.json",
                Path(root) / "done" / "task-a.json",
            )
            expect_gap(root, "duplicate_states")

        with self.subTest(gap="orphan_events"):
            root = fresh_root("oev")
            (Path(root) / "events" / "task-ghost").mkdir()
            expect_gap(root, "orphan_events")

        with self.subTest(gap="orphan_attempts"):
            root = fresh_root("oat")
            (Path(root) / "attempts" / "task-ghost" / "a1").mkdir(parents=True)
            expect_gap(root, "orphan_attempts")

        with self.subTest(gap="attempt_without_events"):
            root = fresh_root("awe")
            card = self.make_card("task-a")
            card["attempt"] = 1
            card["restart_safe"] = False
            card["max_attempts"] = 2
            (Path(root) / "queue" / "task-a.json").write_text(
                json.dumps(card), encoding="ascii"
            )
            expect_gap(root, "attempt_without_events")

        with self.subTest(gap="broken_seq"):
            root = fresh_root("seq")
            enqueue_at(root, self.make_card("task-a"))
            claim_at(root)
            code, payload = run_cli(
                "--root", root, "complete", "--task-id", "task-a",
                "--worker", "worker-a",
            )
            self.assertEqual(code, 0, payload)
            (Path(root) / "events" / "task-a" / "000001.json").unlink()
            expect_gap(root, "broken_seq")

        with self.subTest(gap="illegal_transition"):
            root = fresh_root("ill")
            enqueue_at(root, self.make_card("task-a"))
            # complete's table entry is in_progress->done, so from/to is
            # self-consistent but illegal from the replayed queue state.
            self.write_event("task-a", 1, "complete", 0, root=root)
            expect_gap(root, "illegal_transition")

        with self.subTest(gap="from_to_mismatch"):
            root = fresh_root("ftm")
            enqueue_at(root, self.make_card("task-a"))
            self.write_event(
                "task-a", 1, "claim", 1, to_state="done", root=root
            )
            expect_gap(root, "from_to_mismatch")

        with self.subTest(gap="attempt_mismatch"):
            root = fresh_root("atm")
            enqueue_at(root, self.make_card("task-a"))
            self.write_event("task-a", 1, "claim", 2, root=root)
            expect_gap(root, "attempt_mismatch")

        with self.subTest(gap="card_attempt_mismatch"):
            root = fresh_root("cam")
            enqueue_at(root, self.make_card("task-a"))
            claim_at(root)
            card_path = Path(root) / "in_progress" / "task-a.json"
            card = json.loads(card_path.read_text("utf-8"))
            card["attempt"] = 2
            card_path.write_text(json.dumps(card), encoding="ascii")
            expect_gap(root, "card_attempt_mismatch")

        with self.subTest(gap="missing_attempt_dir"):
            root = fresh_root("mad")
            enqueue_at(root, self.make_card("task-a"))
            claim_at(root)
            (Path(root) / "attempts" / "task-a" / "a1").rmdir()
            expect_gap(root, "missing_attempt_dir")

        with self.subTest(gap="extra_attempt_dir"):
            root = fresh_root("ead")
            enqueue_at(root, self.make_card("task-a"))
            claim_at(root)
            (Path(root) / "attempts" / "task-a" / "a5").mkdir()
            expect_gap(root, "extra_attempt_dir")

        with self.subTest(gap="malformed_event"):
            root = fresh_root("mev")
            enqueue_at(root, self.make_card("task-a"))
            claim_at(root)
            (Path(root) / "events" / "task-a" / "000001.json").write_text(
                "{}", encoding="ascii"
            )
            expect_gap(root, "malformed_event")

        with self.subTest(gap="malformed_card"):
            root = fresh_root("mca")
            (Path(root) / "queue" / "task-a.json").write_text(
                "not json at all", encoding="ascii"
            )
            expect_gap(root, "malformed_card")

        with self.subTest(gap="unexpected_entry"):
            root = fresh_root("uxe")
            (Path(root) / "queue" / "notes.txt").write_text("x", "ascii")
            expect_gap(root, "unexpected_entry")

    def test_audit_never_repairs(self):
        self.enqueue(self.make_card("task-frozen"))
        os.rename(
            Path(self.root) / "queue" / "task-frozen.json",
            Path(self.root) / "in_progress" / "task-frozen.json",
        )
        before = sorted(
            str(path.relative_to(self.root))
            for path in Path(self.root).rglob("*")
        )
        code, _payload = self.audit()
        self.assertEqual(code, 3)
        after = sorted(
            str(path.relative_to(self.root))
            for path in Path(self.root).rglob("*")
        )
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
