"""Hermetic tests for autonomy/local_supervisor.py (CODEX-3-S2 MVP).

Temporary queue roots and harmless fake child processes only: no live
queue, no real Claude launch, no product/SVN data, no services or
scheduler.  Fake children are real OS processes (``python -c``) started
through the private ``_spawn`` seam, so process lifecycle (concurrency,
timeout kill, HALT/deadline termination) is exercised for real while the
recorded argv/env/cwd prove the exact established Claude invocation.
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
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from autonomy import local_supervisor, queue_cli  # noqa: E402
from autonomy.supervisor_transaction import (  # noqa: E402
    HaltActive,
    TransactionCompleted,
)

HALT = HaltActive(halt=MappingProxyType({}))
OBSERVED = TransactionCompleted(result=None)

# Fake child behaviors keyed by the first prompt token ("MODE:<key> ...").
FAKE_BODIES = {
    "ok": (
        "import json, sys; sys.stdout.write(json.dumps({'ok': True}));"
        " sys.exit(0)"
    ),
    "slowok": (
        "import json, sys, time; time.sleep(1.0);"
        " sys.stdout.write(json.dumps({'ok': True})); sys.exit(0)"
    ),
    "exit1": (
        "import sys; sys.stderr.write('safeguard: task refused');"
        " sys.exit(1)"
    ),
    "badjson": "import sys; sys.stdout.write('not json'); sys.exit(0)",
    "empty": "import sys; sys.exit(0)",
    "sleep": "import time; time.sleep(120)",
}


def sha256_upper(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def quota_iso(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def quota_window(key: str, used: int, now_s: int) -> dict:
    identities = {
        "five_hour": ("session", "five_hour", "none", ""),
        "seven_day": ("weekly_all", "seven_day", "none", ""),
        "fable_week": ("weekly_scoped", "weekly_scoped", "model", "Fable"),
    }
    bucket, name, scope_type, scope = identities[key]
    return {
        "Bucket": bucket,
        "Window": name,
        "ScopeType": scope_type,
        "Scope": scope,
        "UsedPercent": used,
        "WindowDurationMinutes": None,
        "ResetsAtUnixSeconds": now_s + 3600,
        "Active": key == "fable_week",
        "CollectedAtUnixSeconds": now_s,
        "Source": "oauth",
        "Stale": False,
    }


def quota_account(
    cache_profile: str, now_s: int, *, five: int = 0, week: int = 0,
    fable: int = 0,
) -> dict:
    return {
        "Provider": "claude",
        "Profile": cache_profile,
        "Source": "oauth",
        "AuthValid": True,
        "CollectorSuccess": True,
        "FallbackActive": False,
        "LastSuccessTimestampSeconds": now_s,
        "Windows": [
            quota_window("five_hour", five, now_s),
            quota_window("seven_day", week, now_s),
            quota_window("fable_week", fable, now_s),
        ],
    }


class LocalSupervisorTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="local-supervisor-")
        self.base = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.root = str(self.base / "qroot")
        code, payload = queue_cli.cmd_init(self.root)
        self.assertEqual(code, 0, payload)
        self.allowed = self.base / "allowed"
        self.allowed.mkdir()
        self.workroot = self.base / "workroot"
        self.workroot.mkdir()
        self.home = self.base / "home"
        self.home.mkdir()
        self.quota_cache = self.base / "ai-quotas-state.json"
        self.write_quota_cache()
        env_patch = mock.patch.dict(
            os.environ, {"USERPROFILE": str(self.home)}
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.records: list[dict] = []
        self.addCleanup(self._kill_leftover_children)

    def _kill_leftover_children(self):
        for record in self.records:
            proc = record.get("proc")
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)

    # ------------------------------------------------------------- fixtures

    def payload_doc(self, task_id: str, profile: str, prompt: str,
                    **overrides) -> dict:
        doc = {
            "version": 1,
            "task_id": task_id,
            "profile": profile,
            "model": "claude-fable-5",
            "working_root": str(self.workroot),
            "timeout_seconds": 60,
            "prompt": prompt,
        }
        doc.update(overrides)
        return {key: value for key, value in doc.items() if value is not ...}

    def enqueue_task(self, task_id: str, profile: str, prompt: str = "",
                     *, model: str = "claude-fable-5", max_attempts: int = 2,
                     payload_bytes: bytes | None = None,
                     **payload_overrides) -> None:
        if payload_bytes is None:
            merged = {"model": model}
            merged.update(payload_overrides)
            payload_bytes = json.dumps(
                self.payload_doc(task_id, profile, prompt, **merged)
            ).encode("utf-8")
        payload_file = self.allowed / f"{task_id}.json"
        payload_file.write_bytes(payload_bytes)
        card = {
            "version": 1,
            "task_id": task_id,
            "profile": profile,
            "model": model,
            "allowed_root": str(self.allowed),
            "max_step_seconds": 600,
            "max_attempts": max_attempts,
            "created_utc": "2026-07-14T00:00:00.000Z",
            "payload_relpath": payload_file.name,
            "payload_sha256": sha256_upper(payload_bytes),
        }
        card_file = self.base / f"card-{task_id}.json"
        card_file.write_text(json.dumps(card), encoding="ascii")
        code, result = queue_cli.cmd_enqueue(self.root, str(card_file))
        self.assertEqual(code, 0, result)

    def state_of(self, task_id: str) -> str | None:
        for state in queue_cli.STATES:
            if (Path(self.root) / state / f"{task_id}.json").is_file():
                return state
        return None

    def events_of(self, task_id: str) -> list[dict]:
        directory = Path(self.root) / "events" / task_id
        return [
            json.loads((directory / name).read_text("utf-8"))
            for name in sorted(os.listdir(directory))
        ]

    def attempt_dir(self, task_id: str, attempt: int) -> Path:
        return Path(self.root) / "attempts" / task_id / f"a{attempt}"

    def write_quota_cache(self, usage=None, *, profiles=None) -> None:
        now_s = int(time.time())
        usage = usage or {}
        profiles = profiles or local_supervisor.PROFILES
        accounts = []
        for profile in profiles:
            values = usage.get(profile, {})
            accounts.append(quota_account(
                local_supervisor.CONFIG_DIR_NAMES[profile], now_s,
                five=values.get("five", 0),
                week=values.get("week", 0),
                fable=values.get("fable", 0),
            ))
        self.quota_cache.write_text(json.dumps({
            "SchemaVersion": 1,
            "GeneratedAt": quota_iso(now_s),
            "Accounts": accounts,
        }), encoding="utf-8")

    # ---------------------------------------------------------------- fakes

    def fake_spawn(self, argv, cwd, env, stdout, stderr):
        prompt = argv[-1]
        mode = prompt.split(None, 1)[0].split(":", 1)[1]
        profile = argv[argv.index("--name") + 1]
        live_profiles = [
            record["profile"] for record in self.records
            if record["proc"].poll() is None
        ]
        # Invariant under test: never two live children for one profile.
        self.assertNotIn(profile, live_profiles)
        proc = subprocess.Popen(
            [sys.executable, "-c", FAKE_BODIES[mode]],
            cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr,
        )
        self.records.append({
            "argv": list(argv), "cwd": cwd, "env": dict(env),
            "profile": profile, "prompt": prompt, "proc": proc,
            "live_profiles_at_spawn": live_profiles,
        })
        return proc

    def observe_until_queue_idle(self):
        def observe(root):
            for state in ("queue", "in_progress"):
                if any((Path(self.root) / state).glob("*.json")):
                    return OBSERVED
            return HALT
        return observe

    def observe_sequence(self, *outcomes):
        remaining = list(outcomes)

        def observe(root):
            if len(remaining) > 1:
                return remaining.pop(0)
            return remaining[0]
        return observe

    def run_supervisor(self, observe, *, duration=60, poll=0.02,
                       profiles=local_supervisor.PROFILES,
                       claude="claude-fake"):
        config = local_supervisor.SupervisorConfig(
            root=self.root, duration_seconds=duration, poll_seconds=poll,
            profiles=tuple(profiles), claude=claude,
            quota_cache=str(self.quota_cache),
        )
        output = io.StringIO()
        with mock.patch.object(
            local_supervisor, "observe_night_tick", observe
        ), mock.patch.object(
            local_supervisor, "_spawn", self.fake_spawn
        ), contextlib.redirect_stdout(output):
            rc = local_supervisor.LocalSupervisor(config).run()
        return rc, output.getvalue()


class HaltAndObservationTests(LocalSupervisorTestBase):
    def test_immediate_halt_performs_no_list_claim_or_launch(self):
        self.enqueue_task("task-a", "claude-test3", "MODE:ok run")
        with mock.patch.object(
            queue_cli, "cmd_list_exact"
        ) as list_spy, mock.patch.object(
            queue_cli, "cmd_claim_exact"
        ) as claim_spy:
            rc, log = self.run_supervisor(lambda root: HALT)
        self.assertEqual(rc, 0)
        list_spy.assert_not_called()
        claim_spy.assert_not_called()
        self.assertEqual(self.records, [])
        self.assertEqual(self.state_of("task-a"), "queue")
        self.assertIn("valid HALT observed", log)

    def test_observation_error_stops_nonzero_without_claiming(self):
        self.enqueue_task("task-a", "claude-test3", "MODE:ok run")

        def observe(root):
            raise RuntimeError("boom")

        rc, log = self.run_supervisor(observe)
        self.assertEqual(rc, 1)
        self.assertEqual(self.records, [])
        self.assertEqual(self.state_of("task-a"), "queue")
        self.assertIn("observation error", log)

    def test_halt_terminates_running_children_and_settles_failed(self):
        self.enqueue_task(
            "task-a", "claude-test3", "MODE:sleep run",
            max_attempts=1, timeout_seconds=3600,
        )
        rc, _ = self.run_supervisor(self.observe_sequence(OBSERVED, HALT))
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.records), 1)
        self.assertIsNotNone(self.records[0]["proc"].poll())
        self.assertEqual(self.state_of("task-a"), "failed")
        tail = self.events_of("task-a")[-1]
        self.assertEqual(tail["transition"], "fail-final")
        self.assertEqual(tail["reason"], "halt")


class SuccessPathTests(LocalSupervisorTestBase):
    def test_claim_and_successful_json_child_lead_to_done_and_logs(self):
        prompt = "MODE:ok do the night task"
        self.enqueue_task("task-a", "claude-test3", prompt)
        rc, _ = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        self.assertEqual(self.state_of("task-a"), "done")
        self.assertEqual(len(self.records), 1)
        record = self.records[0]
        self.assertEqual(record["argv"], [
            "claude-fake", "-p",
            "--model", "fable",
            "--fallback-model", "fable",
            "--name", "claude-test3",
            "--disallowedTools", "Agent",
            "--permission-mode", "bypassPermissions",
            "--dangerously-skip-permissions",
            "--output-format", "json",
            prompt,
        ])
        self.assertEqual(record["cwd"], str(self.workroot))
        self.assertEqual(
            record["env"]["CLAUDE_CONFIG_DIR"],
            os.path.join(str(self.home), ".claude-test3"),
        )
        self.assertEqual(
            record["env"]["CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK"], "1"
        )
        attempt_dir = self.attempt_dir("task-a", 1)
        stdout_bytes = (attempt_dir / "child-stdout.txt").read_bytes()
        self.assertEqual(json.loads(stdout_bytes), {"ok": True})
        self.assertTrue((attempt_dir / "child-stderr.txt").is_file())
        tail = self.events_of("task-a")[-1]
        self.assertEqual(tail["transition"], "complete")
        self.assertEqual(tail["worker"], "claude-test3")

    def test_opus_task_uses_exact_opus_without_cross_model_fallback(self):
        prompt = "MODE:ok do mechanical work"
        self.enqueue_task(
            "task-opus", "claude-test1", prompt,
            model="claude-opus-4-8",
        )
        rc, _ = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        self.assertEqual(self.state_of("task-opus"), "done")
        record = self.records[0]
        self.assertEqual(
            record["argv"][record["argv"].index("--model") + 1], "opus"
        )
        self.assertEqual(
            record["argv"][record["argv"].index("--fallback-model") + 1],
            "opus",
        )
        self.assertNotIn("fable", record["argv"])
        self.assertEqual(
            record["env"]["CLAUDE_CONFIG_DIR"],
            os.path.join(str(self.home), ".claude-test1"),
        )


class ConcurrencyAndCasTests(LocalSupervisorTestBase):
    def test_two_profiles_concurrent_never_two_children_per_profile(self):
        self.enqueue_task("a-work", "claude-work", "MODE:slowok one")
        self.enqueue_task("b-test2", "claude-test2", "MODE:slowok two")
        self.enqueue_task("c-work", "claude-work", "MODE:ok three")
        rc, _ = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        for task_id in ("a-work", "b-test2", "c-work"):
            self.assertEqual(self.state_of(task_id), "done")
        self.assertEqual(
            [record["profile"] for record in self.records],
            ["claude-work", "claude-test2", "claude-work"],
        )
        # Both profiles were live at once: when b-test2 spawned, a-work's
        # child (1s runtime) was still running.
        self.assertIn("claude-work", self.records[1]["live_profiles_at_spawn"])
        # One-child-per-profile: c-work spawned only after a-work's child
        # had finished (fake_spawn also asserts the invariant directly).
        self.assertNotIn(
            "claude-work", self.records[2]["live_profiles_at_spawn"]
        )

    def test_exact_cas_prevents_duplicate_execution(self):
        self.enqueue_task("task-a", "claude-test3", "MODE:ok run")
        real_list = queue_cli.cmd_list_exact
        hijacked = {"done": False}

        def racing_list(root_arg):
            code, listing = real_list(root_arg)
            if not hijacked["done"] and listing["tasks"]:
                hijacked["done"] = True
                task = listing["tasks"][0]
                queue_cli.cmd_claim_exact(
                    root_arg, task["task_id"], task["next_attempt"],
                    task["digest"], task["profile"], task["model"],
                    "other-worker",
                )
            return code, listing

        with mock.patch.object(queue_cli, "cmd_list_exact", racing_list):
            rc, log = self.run_supervisor(
                self.observe_sequence(OBSERVED, HALT)
            )
        self.assertEqual(rc, 0)
        self.assertEqual(self.records, [])
        self.assertEqual(self.state_of("task-a"), "in_progress")
        self.assertIn("claim skipped task-a", log)
        tail = self.events_of("task-a")[-1]
        self.assertEqual(tail["transition"], "claim")
        self.assertEqual(tail["worker"], "other-worker")

    def test_same_worker_replayed_claim_starts_no_child(self):
        # A second supervisor with the same profile (worker=profile) loses
        # the race between list and claim; the queue answers its identical
        # claim as response-loss replay.  It must not launch the attempt.
        self.enqueue_task("task-a", "claude-test3", "MODE:ok run")
        real_list = queue_cli.cmd_list_exact
        real_claim = queue_cli.cmd_claim_exact
        hijacked = {"done": False}
        replay_results = []

        def racing_list(root_arg):
            code, listing = real_list(root_arg)
            if not hijacked["done"] and listing["tasks"]:
                hijacked["done"] = True
                task = listing["tasks"][0]
                real_claim(
                    root_arg, task["task_id"], task["next_attempt"],
                    task["digest"], task["profile"], task["model"],
                    task["profile"],
                )
            return code, listing

        def claim_spy(*args):
            code, claim = real_claim(*args)
            replay_results.append(claim)
            return code, claim

        with mock.patch.object(
            queue_cli, "cmd_list_exact", racing_list
        ), mock.patch.object(queue_cli, "cmd_claim_exact", claim_spy):
            rc, log = self.run_supervisor(
                self.observe_sequence(OBSERVED, HALT)
            )
        self.assertEqual(rc, 0)
        # The supervisor did receive a successful replayed claim result.
        self.assertEqual(len(replay_results), 1)
        self.assertIs(replay_results[0]["replayed"], True)
        # ...but started no child and left the first claimant's single
        # attempt in progress, unsettled.
        self.assertEqual(self.records, [])
        self.assertIn("replayed claim skipped task-a", log)
        self.assertEqual(self.state_of("task-a"), "in_progress")
        events = self.events_of("task-a")
        self.assertEqual(
            [event["transition"] for event in events], ["claim"]
        )
        self.assertEqual(events[-1]["attempt"], 1)
        self.assertEqual(events[-1]["worker"], "claude-test3")


class FailureAndRetryTests(LocalSupervisorTestBase):
    def test_nonzero_failure_retries_once_byte_identical_then_final(self):
        prompt = "MODE:exit1 will trip the safeguard"
        self.enqueue_task("task-a", "claude-test3", prompt, max_attempts=2)
        rc, _ = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        self.assertEqual(self.state_of("task-a"), "failed")
        self.assertEqual(len(self.records), 2)
        self.assertEqual(self.records[0]["prompt"], prompt)
        self.assertEqual(self.records[0]["prompt"], self.records[1]["prompt"])
        self.assertEqual(self.records[0]["argv"], self.records[1]["argv"])
        transitions = [
            event["transition"] for event in self.events_of("task-a")
        ]
        self.assertEqual(
            transitions, ["claim", "fail-retry", "claim", "fail-final"]
        )
        for event in self.events_of("task-a"):
            if event["transition"].startswith("fail-"):
                self.assertEqual(event["reason"], "child-exit-1")

    def test_attempt_one_final_via_fail_disposition_mismatch(self):
        self.enqueue_task(
            "task-a", "claude-test3", "MODE:exit1 run", max_attempts=1,
        )
        real_fail = queue_cli.cmd_fail_exact
        calls = []

        def fail_spy(root_arg, task_id, attempt, digest, worker,
                     disposition, reason):
            try:
                result = real_fail(
                    root_arg, task_id, attempt, digest, worker,
                    disposition, reason,
                )
            except Exception as exc:
                calls.append((disposition, f"raised:{exc}"))
                raise
            calls.append((disposition, "ok"))
            return result

        with mock.patch.object(queue_cli, "cmd_fail_exact", fail_spy):
            rc, _ = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        self.assertEqual(self.state_of("task-a"), "failed")
        self.assertEqual(len(self.records), 1)
        self.assertEqual(
            calls,
            [("retry", "raised:fail-disposition-mismatch"), ("final", "ok")],
        )

    def test_child_timeout_kills_child_and_fails(self):
        self.enqueue_task(
            "task-a", "claude-test3", "MODE:sleep run",
            max_attempts=1, timeout_seconds=1,
        )
        rc, _ = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.records), 1)
        self.assertIsNotNone(self.records[0]["proc"].poll())
        self.assertEqual(self.state_of("task-a"), "failed")
        tail = self.events_of("task-a")[-1]
        self.assertEqual(tail["transition"], "fail-final")
        self.assertEqual(tail["reason"], "child-timeout")

    def test_malformed_exit_zero_output_fails(self):
        self.enqueue_task(
            "bad-json", "claude-work", "MODE:badjson run", max_attempts=1,
        )
        self.enqueue_task(
            "no-output", "claude-test2", "MODE:empty run", max_attempts=1,
        )
        rc, _ = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        for task_id in ("bad-json", "no-output"):
            self.assertEqual(self.state_of(task_id), "failed")
            tail = self.events_of(task_id)[-1]
            self.assertEqual(tail["transition"], "fail-final")
            self.assertEqual(tail["reason"], "child-output-not-json")

    def test_invalid_payloads_fail_without_any_launch(self):
        missing_key = self.payload_doc("no-prompt", "claude-work", "x")
        del missing_key["prompt"]
        self.enqueue_task(
            "no-prompt", "claude-work", max_attempts=1,
            payload_bytes=json.dumps(missing_key).encode("utf-8"),
        )
        self.enqueue_task(
            "bad-root", "claude-test2", "MODE:ok run", max_attempts=1,
            working_root=str(self.base / "does-not-exist"),
        )
        mismatched = self.payload_doc(
            "model-mismatch", "claude-test3", "MODE:ok run",
            model="claude-opus-4-8",
        )
        self.enqueue_task(
            "model-mismatch", "claude-test3", max_attempts=1,
            model="claude-fable-5",
            payload_bytes=json.dumps(mismatched).encode("utf-8"),
        )
        rc, _ = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        self.assertEqual(self.records, [])
        for task_id, fragment in (
            ("no-prompt", "payload-schema"),
            ("bad-root", "payload-working-root"),
            ("model-mismatch", "payload-model-mismatch"),
        ):
            self.assertEqual(self.state_of(task_id), "failed")
            tail = self.events_of(task_id)[-1]
            self.assertEqual(tail["transition"], "fail-final")
            self.assertIn(fragment, tail["reason"])
            self.assertTrue(tail["reason"].startswith("invalid-payload"))


class CapacityGateTests(LocalSupervisorTestBase):
    def test_unsupported_model_stays_queued_and_is_logged(self):
        self.enqueue_task(
            "task-unknown", "claude-test2", "MODE:ok run",
            model="claude-sonnet-5",
        )
        rc, log = self.run_supervisor(
            self.observe_sequence(OBSERVED, HALT)
        )
        self.assertEqual(rc, 0)
        self.assertEqual(self.state_of("task-unknown"), "queue")
        self.assertEqual(self.records, [])
        self.assertIn(
            "model skipped task-unknown: claude-sonnet-5", log
        )

    def test_denied_fable_stays_queued_while_opus_same_profile_runs(self):
        self.write_quota_cache({"claude-work": {"fable": 100}})
        self.enqueue_task("a-fable", "claude-work", "MODE:ok complex")
        self.enqueue_task(
            "b-opus", "claude-work", "MODE:ok mechanical",
            model="claude-opus-4-8",
        )

        def observe(root):
            return HALT if self.state_of("b-opus") == "done" else OBSERVED

        rc, log = self.run_supervisor(observe)
        self.assertEqual(rc, 0)
        self.assertEqual(self.state_of("a-fable"), "queue")
        self.assertEqual(self.state_of("b-opus"), "done")
        self.assertEqual([r["prompt"] for r in self.records], ["MODE:ok mechanical"])
        self.assertIn("quota denied a-fable: fable-exhausted", log)

    def test_missing_profile_evidence_skips_it_and_runs_other_profile(self):
        self.write_quota_cache(profiles=("claude", "claude-work"))
        self.enqueue_task("a-test3", "claude-test3", "MODE:ok skipped")
        self.enqueue_task("b-claude", "claude", "MODE:ok admitted")

        def observe(root):
            return HALT if self.state_of("b-claude") == "done" else OBSERVED

        rc, log = self.run_supervisor(observe)
        self.assertEqual(rc, 0)
        self.assertEqual(self.state_of("a-test3"), "queue")
        self.assertEqual(self.state_of("b-claude"), "done")
        self.assertEqual([r["profile"] for r in self.records], ["claude"])
        self.assertIn("quota skipped a-test3", log)

    def test_unavailable_cache_claims_nothing_then_recovers_next_round(self):
        self.enqueue_task("task-a", "claude-test2", "MODE:ok run")
        real_load = local_supervisor.quota_capacity.load_snapshot
        calls = {"count": 0}

        def flaky_load(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                raise local_supervisor.quota_capacity.QuotaEvidenceError(
                    "cache-stale"
                )
            return real_load(*args, **kwargs)

        with mock.patch.object(
            local_supervisor.quota_capacity, "load_snapshot", flaky_load
        ):
            rc, log = self.run_supervisor(self.observe_until_queue_idle())
        self.assertEqual(rc, 0)
        self.assertEqual(self.state_of("task-a"), "done")
        self.assertGreaterEqual(calls["count"], 2)
        self.assertEqual(len(self.records), 1)
        self.assertIn("quota unavailable", log)

    def test_one_snapshot_is_loaded_for_a_claim_round(self):
        self.enqueue_task("a", "claude", "MODE:sleep one")
        self.enqueue_task("b", "claude-test1", "MODE:sleep two")
        config = local_supervisor.SupervisorConfig(
            root=self.root,
            profiles=local_supervisor.PROFILES,
            claude="claude-fake",
            quota_cache=str(self.quota_cache),
        )
        supervisor = local_supervisor.LocalSupervisor(config)
        real_load = local_supervisor.quota_capacity.load_snapshot
        with mock.patch.object(
            local_supervisor.quota_capacity, "load_snapshot", wraps=real_load
        ) as load, mock.patch.object(
            local_supervisor, "_spawn", self.fake_spawn
        ):
            try:
                supervisor._claim_round()
                self.assertEqual(load.call_count, 1)
                self.assertEqual(len(self.records), 2)
            finally:
                supervisor._cleanup("test-cleanup")


class DeadlineTests(LocalSupervisorTestBase):
    def test_kill_resistant_child_keeps_profile_slot_occupied(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.wait.side_effect = subprocess.TimeoutExpired("fake", 30)
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        child = local_supervisor._Child(
            proc=proc,
            task_id="task-stuck",
            attempt=1,
            digest="0" * 64,
            profile="claude-test2",
            worker="claude-test2",
            deadline=0,
            stdout_path=self.base / "stuck-stdout.json",
            stdout_file=stdout,
            stderr_file=stderr,
        )
        supervisor = local_supervisor.LocalSupervisor(
            local_supervisor.SupervisorConfig(
                root=self.root,
                quota_cache=str(self.quota_cache),
            )
        )
        supervisor._children["claude-test2"] = child
        with mock.patch.object(supervisor, "_now", return_value=1):
            supervisor._reap()
        self.assertIs(supervisor._children["claude-test2"], child)
        proc.kill.assert_called_once_with()
        self.assertFalse(stdout.closed)
        self.assertFalse(stderr.closed)

    def test_deadline_terminates_children_and_settles_failed(self):
        self.enqueue_task(
            "task-a", "claude-test3", "MODE:sleep run",
            max_attempts=1, timeout_seconds=3600,
        )
        rc, _ = self.run_supervisor(lambda root: OBSERVED, duration=1)
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.records), 1)
        self.assertIsNotNone(self.records[0]["proc"].poll())
        self.assertEqual(self.state_of("task-a"), "failed")
        tail = self.events_of("task-a")[-1]
        self.assertEqual(tail["transition"], "fail-final")
        self.assertEqual(tail["reason"], "supervisor-deadline")


class CliParsingTests(unittest.TestCase):
    ABS_ROOT = str(Path(tempfile.gettempdir()) / "qroot")

    def parse(self, *argv):
        return local_supervisor.parse_args(list(argv))

    def parse_error(self, *argv):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                self.parse(*argv)
        self.assertEqual(ctx.exception.code, 2)

    def test_defaults(self):
        config = self.parse("--root", self.ABS_ROOT)
        self.assertEqual(config.root, self.ABS_ROOT)
        self.assertEqual(config.duration_seconds, 25200)
        self.assertGreater(config.poll_seconds, 0)
        self.assertEqual(config.profiles, local_supervisor.PROFILES)
        self.assertEqual(config.claude, "claude")
        self.assertTrue(os.path.isabs(config.quota_cache))

    def test_overrides_and_zero_poll(self):
        config = self.parse(
            "--root", self.ABS_ROOT, "--duration-seconds", "9",
            "--poll-seconds", "0", "--profiles", "claude-test3,claude-work",
            "--claude", r"C:\tools\claude.exe",
            "--quota-cache", r"C:\quota\state.json",
        )
        self.assertEqual(config.duration_seconds, 9)
        self.assertEqual(config.poll_seconds, 0.0)
        self.assertEqual(config.profiles, ("claude-test3", "claude-work"))
        self.assertEqual(config.claude, r"C:\tools\claude.exe")
        self.assertEqual(config.quota_cache, r"C:\quota\state.json")

    def test_rejections(self):
        self.parse_error("--root", "relative/root")
        self.parse_error("--root", self.ABS_ROOT, "--profiles", "claude-evil")
        self.parse_error(
            "--root", self.ABS_ROOT,
            "--profiles", "claude-work,claude-work",
        )
        self.parse_error("--root", self.ABS_ROOT, "--profiles", "")
        self.parse_error(
            "--root", self.ABS_ROOT, "--duration-seconds", "-1"
        )
        self.parse_error("--root", self.ABS_ROOT, "--poll-seconds", "-0.1")
        self.parse_error("--root", self.ABS_ROOT, "--claude", "")
        self.parse_error(
            "--root", self.ABS_ROOT, "--quota-cache", "relative/state.json"
        )


def _powershell() -> str | None:
    for name in ("powershell", "pwsh"):
        found = shutil.which(name)
        if found:
            return found
    return None


class LauncherTests(unittest.TestCase):
    LAUNCHER = ROOT / "windows" / "start-local-supervisor.ps1"

    @unittest.skipUnless(_powershell(), "PowerShell is not available")
    def test_launcher_parses(self):
        proc = subprocess.run(
            [
                _powershell(), "-NoProfile", "-NonInteractive", "-Command",
                "[void][scriptblock]::Create("
                f"(Get-Content -Raw '{self.LAUNCHER}'))",
            ],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    @unittest.skipUnless(
        os.name == "nt" and _powershell(),
        "Windows PowerShell launcher forwarding test",
    )
    def test_launcher_forwards_arguments_cwd_and_exit_code(self):
        with tempfile.TemporaryDirectory(prefix="launcher-") as tmp:
            base = Path(tmp)
            capture_args = base / "args.txt"
            capture_cwd = base / "cwd.txt"
            fake_bin = base / "bin"
            fake_bin.mkdir()
            (fake_bin / "python.bat").write_text(
                "@echo off\r\n"
                f"echo %* > \"{capture_args}\"\r\n"
                f"echo %CD% > \"{capture_cwd}\"\r\n"
                "exit /b 7\r\n",
                encoding="ascii",
            )
            env = dict(os.environ)
            env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
            proc = subprocess.run(
                [
                    _powershell(), "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-File", str(self.LAUNCHER),
                    "-Root", r"C:\night\qroot",
                    "-DurationSeconds", "9",
                    "-PollSeconds", "0",
                    "-Profiles", "claude-test3",
                    "-Claude", r"C:\tools\claude.exe",
                    "-QuotaCache", r"C:\quota\state.json",
                ],
                capture_output=True, text=True, timeout=120, env=env,
            )
            self.assertEqual(proc.returncode, 7, proc.stderr)
            forwarded = capture_args.read_text(encoding="ascii").strip()
            self.assertEqual(
                forwarded,
                "-B -m autonomy.local_supervisor"
                r" --root C:\night\qroot"
                " --duration-seconds 9 --poll-seconds 0"
                " --profiles claude-test3"
                r" --claude C:\tools\claude.exe"
                r" --quota-cache C:\quota\state.json",
            )
            invoked_cwd = capture_cwd.read_text(encoding="ascii").strip()
            self.assertEqual(
                os.path.normcase(os.path.realpath(invoked_cwd)),
                os.path.normcase(os.path.realpath(str(ROOT))),
            )


if __name__ == "__main__":
    unittest.main()
