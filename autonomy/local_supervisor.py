"""Trusted foreground local night supervisor (CODEX-3-S2 MVP).

One foreground process (``python -B -m autonomy.local_supervisor``) executes
the prepared night queue for up to seven hours.  Every queue mutation goes
through the accepted exact queue operations in :mod:`autonomy.queue_cli`
(list/claim/complete/fail); before every claim round the accepted S1
:func:`autonomy.night_tick.observe_night_tick` is consulted.  A valid HALT
stops claiming, terminates this process's children, settles their attempts
as failures, and exits normally; an observation error stops the supervisor
nonzero.

Scope is deliberately the owner-authorized MVP: all processes and payloads on
this machine are trusted.  There is no service, scheduler registration,
reboot recovery, sandboxing, policy engine, log rotation, model fallback, or
persistence/resume.  At most one active child per selected profile; the five
owner profiles use fixed config dirs under ``%USERPROFILE%``.  Exact Fable and
Opus task models are admitted only from fresh local quota evidence, and retries
reuse the byte-identical prompt, profile, and model.

Test seams are private module attributes: ``_spawn`` (child process
creation) and the imported ``observe_night_tick`` name.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from autonomy import queue_cli, quota_capacity
from autonomy.night_tick import observe_night_tick
from autonomy.supervisor_transaction import HaltActive

__all__ = ["SupervisorConfig", "LocalSupervisor", "parse_args", "main"]

PROFILES = (
    "claude", "claude-work", "claude-test1", "claude-test2", "claude-test3",
)
CONFIG_DIR_NAMES = {
    "claude": ".claude",
    "claude-work": ".claude-work",
    "claude-test1": ".claude-test1",
    "claude-test2": ".claude-test2",
    "claude-test3": ".claude-test3",
}
MODEL_ARGS = {
    "claude-fable-5": "fable",
    "claude-opus-4-8": "opus",
}
DEFAULT_QUOTA_CACHE = os.path.join(
    os.environ.get(
        "LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local")
    ),
    "AIQuotaExporter", "ai-quotas-state.json",
)
CAPACITY_POLICY = quota_capacity.QuotaPolicy(
    fable_reserve_pct=Decimal("0"),
    general_week_reserve_pct=Decimal("0"),
    five_hour_reserve_pct=Decimal("0"),
)
DEFAULT_DURATION_SECONDS = 25200
DEFAULT_POLL_SECONDS = 5.0
PAYLOAD_KEYS = frozenset(
    {
        "version", "task_id", "profile", "model", "working_root",
        "timeout_seconds", "prompt",
    }
)
# Bounds exist only to reject accidentally unusable input, not as policy.
MAX_TIMEOUT_SECONDS = 86400
MAX_PROMPT_CHARS = 30000
STDOUT_NAME = "child-stdout.txt"
STDERR_NAME = "child-stderr.txt"
_TERMINATE_WAIT_SECONDS = 30


class PayloadError(Exception):
    """The immutable payload is not one usable trusted task document."""


class LaunchError(Exception):
    """The child process could not be started."""


def _spawn(argv, cwd, env, stdout, stderr):
    """Private seam: start one noninteractive child, no shell interpolation."""
    return subprocess.Popen(
        argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=stdout, stderr=stderr, shell=False,
    )


def _child_argv(
    claude: str, profile: str, model: str, prompt: str,
) -> list[str]:
    """The established fixed invocation; same argv on retry by construction."""
    model_arg = MODEL_ARGS[model]
    return [
        claude, "-p",
        "--model", model_arg,
        "--fallback-model", model_arg,
        "--name", profile,
        "--disallowedTools", "Agent",
        "--permission-mode", "bypassPermissions",
        "--dangerously-skip-permissions",
        "--output-format", "json",
        prompt,
    ]


def _config_dir(profile: str) -> str:
    home = os.environ.get("USERPROFILE")
    if not home:
        raise LaunchError("userprofile-unset")
    return os.path.join(home, CONFIG_DIR_NAMES[profile])


def _reason(text: str) -> str:
    """Fit an arbitrary message into the queue's printable-ASCII reason."""
    printable = "".join(ch if " " <= ch <= "~" else "?" for ch in text)
    return printable[:256]


def _is_exact_int(value: object) -> bool:
    return type(value) is int


def _validate_payload(raw: bytes, claim: dict) -> dict:
    """Strict UTF-8 JSON payload with exactly the seven contract keys."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise PayloadError("payload-not-utf8") from None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        raise PayloadError("payload-not-json") from None
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_KEYS:
        raise PayloadError("payload-schema")
    if not _is_exact_int(payload["version"]) or payload["version"] != 1:
        raise PayloadError("payload-version")
    for key in ("task_id", "profile", "model"):
        if type(payload[key]) is not str or payload[key] != claim[key]:
            raise PayloadError(f"payload-{key}-mismatch")
    if payload["model"] not in MODEL_ARGS:
        raise PayloadError("payload-model-unsupported")
    working_root = payload["working_root"]
    if (
        type(working_root) is not str
        or not working_root
        or not os.path.isabs(working_root)
        or not os.path.isdir(working_root)
    ):
        raise PayloadError("payload-working-root")
    timeout = payload["timeout_seconds"]
    if not _is_exact_int(timeout) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise PayloadError("payload-timeout")
    prompt = payload["prompt"]
    if (
        type(prompt) is not str
        or not prompt.strip()
        or len(prompt) > MAX_PROMPT_CHARS
    ):
        raise PayloadError("payload-prompt")
    return payload


@dataclass
class _Child:
    proc: subprocess.Popen
    task_id: str
    attempt: int
    digest: str
    profile: str
    worker: str
    deadline: float
    stdout_path: Path
    stdout_file: object
    stderr_file: object


@dataclass(frozen=True)
class SupervisorConfig:
    root: str
    duration_seconds: int = DEFAULT_DURATION_SECONDS
    poll_seconds: float = DEFAULT_POLL_SECONDS
    profiles: tuple[str, ...] = PROFILES
    claude: str = "claude"
    quota_cache: str = DEFAULT_QUOTA_CACHE


class LocalSupervisor:
    """One trusted foreground supervisor: immediate tick, then poll."""

    def __init__(self, config: SupervisorConfig):
        self._config = config
        self._root = config.root
        self._children: dict[str, _Child] = {}
        self._deadline = 0.0
        self._settle_errors = 0

    # ------------------------------------------------------------- plumbing

    def _now(self) -> float:
        return time.monotonic()

    def _sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def _log(self, message: str) -> None:
        print(f"[local-supervisor] {message}", flush=True)

    # ------------------------------------------------------------ main loop

    def run(self) -> int:
        self._deadline = self._now() + self._config.duration_seconds
        rc = 0
        try:
            while True:
                self._reap()
                if self._now() >= self._deadline:
                    self._log("duration expired")
                    self._cleanup("supervisor-deadline")
                    break
                try:
                    outcome = observe_night_tick(self._root)
                except Exception as exc:
                    self._log(f"observation error: {type(exc).__name__}")
                    self._cleanup("observation-error")
                    rc = 1
                    break
                if type(outcome) is HaltActive:
                    self._log("valid HALT observed")
                    self._cleanup("halt")
                    break
                try:
                    self._claim_round()
                except Exception as exc:
                    self._log(f"queue error: {type(exc).__name__}: {exc}")
                    self._cleanup("supervisor-error")
                    rc = 1
                    break
                self._sleep(self._config.poll_seconds)
        except KeyboardInterrupt:
            self._log("interrupted")
            self._cleanup("keyboard-interrupt")
            rc = 1
        if self._settle_errors and rc == 0:
            rc = 1
        return rc

    # ---------------------------------------------------------- claim round

    def _claim_round(self) -> None:
        idle = [p for p in self._config.profiles if p not in self._children]
        if not idle:
            return
        _, listing = queue_cli.cmd_list_exact(self._root)
        try:
            snapshot = quota_capacity.load_snapshot(
                Path(self._config.quota_cache),
                now_s=int(time.time()),
                policy=CAPACITY_POLICY,
            )
        except (OSError, quota_capacity.QuotaEvidenceError) as exc:
            # The exporter may recover on the next poll. Existing children
            # keep running and no queue state is mutated without evidence.
            self._log(f"quota unavailable: {type(exc).__name__}: {exc}")
            return
        for task in listing["tasks"]:
            if not idle:
                break
            profile = task["profile"]
            if profile not in idle:
                continue
            if task["next_attempt"] is None or not task["payload"]["verified"]:
                continue
            if task["model"] not in MODEL_ARGS:
                self._log(
                    f"model skipped {task['task_id']}: {task['model']}"
                )
                continue
            try:
                capacity = quota_capacity.decide(
                    snapshot,
                    profile=profile,
                    model=task["model"],
                    policy=CAPACITY_POLICY,
                )
            except quota_capacity.QuotaEvidenceError as exc:
                self._log(
                    f"quota skipped {task['task_id']}: "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            if not capacity.allowed:
                self._log(
                    f"quota denied {task['task_id']}: {capacity.reason.value}; "
                    f"remaining={capacity.effective_remaining_pct}%"
                )
                continue
            try:
                _, claim = queue_cli.cmd_claim_exact(
                    self._root, task["task_id"], task["next_attempt"],
                    task["digest"], profile, task["model"], profile,
                )
            except queue_cli.QueueError as exc:
                # Exact CAS lost the race for this observed incarnation.
                self._log(f"claim skipped {task['task_id']}: {exc}")
                continue
            if claim["replayed"] is True:
                # A same-worker claim already holds this attempt; the queue
                # answered as response-loss replay.  Launching would run the
                # same attempt twice, so leave it to the original claimant.
                self._log(f"replayed claim skipped {task['task_id']}")
                continue
            if self._start_attempt(claim):
                idle.remove(profile)

    def _start_attempt(self, claim: dict) -> bool:
        task_id, attempt = claim["task_id"], claim["attempt"]
        try:
            raw = Path(claim["payload_path"]).read_bytes()
            payload = _validate_payload(raw, claim)
        except (OSError, PayloadError) as exc:
            self._log(f"invalid payload {task_id}: {exc}")
            self._settle_failure(
                task_id, attempt, claim["digest"], claim["profile"],
                _reason(f"invalid-payload: {exc}"),
            )
            return False
        try:
            child = self._launch(claim, payload)
        except (OSError, LaunchError) as exc:
            self._log(f"launch failed {task_id}: {exc}")
            self._settle_failure(
                task_id, attempt, claim["digest"], claim["profile"],
                _reason(f"launch-error: {exc}"),
            )
            return False
        self._children[claim["profile"]] = child
        self._log(f"started {task_id} attempt {attempt} as {claim['profile']}")
        return True

    def _launch(self, claim: dict, payload: dict) -> _Child:
        profile = claim["profile"]
        attempt_dir = Path(claim["attempt_dir"])
        argv = _child_argv(
            self._config.claude, profile, payload["model"], payload["prompt"]
        )
        env = dict(os.environ)
        env["CLAUDE_CONFIG_DIR"] = _config_dir(profile)
        env["CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK"] = "1"
        stdout_path = attempt_dir / STDOUT_NAME
        stdout_file = open(stdout_path, "wb")
        try:
            stderr_file = open(attempt_dir / STDERR_NAME, "wb")
        except OSError:
            stdout_file.close()
            raise
        try:
            proc = _spawn(
                argv, cwd=payload["working_root"], env=env,
                stdout=stdout_file, stderr=stderr_file,
            )
        except BaseException:
            stdout_file.close()
            stderr_file.close()
            raise
        return _Child(
            proc=proc,
            task_id=claim["task_id"],
            attempt=claim["attempt"],
            digest=claim["digest"],
            profile=profile,
            worker=profile,
            deadline=self._now() + payload["timeout_seconds"],
            stdout_path=stdout_path,
            stdout_file=stdout_file,
            stderr_file=stderr_file,
        )

    # ------------------------------------------------------------- settling

    def _reap(self) -> None:
        for profile, child in list(self._children.items()):
            returncode = child.proc.poll()
            if returncode is None:
                if self._now() >= child.deadline:
                    if self._terminate(child):
                        self._settle_child_failure(child, "child-timeout")
                        del self._children[profile]
                continue
            self._close_logs(child)
            if returncode == 0 and self._stdout_is_json(child):
                self._settle_complete(child)
            elif returncode == 0:
                self._settle_child_failure(child, "child-output-not-json")
            else:
                self._settle_child_failure(child, f"child-exit-{returncode}")
            del self._children[profile]

    def _cleanup(self, reason: str) -> None:
        # Children that already finished settle on their own results first;
        # everything still running is terminated and settled as `reason`.
        self._reap()
        for profile, child in list(self._children.items()):
            if self._terminate(child):
                self._settle_child_failure(child, reason)
                del self._children[profile]
            else:
                # Keep the slot occupied and the attempt in progress. A live
                # process must never overlap a retry for the same profile.
                self._settle_errors += 1
                self._log(f"live child left unsettled for {child.task_id}")

    def _terminate(self, child: _Child) -> bool:
        if child.proc.poll() is None:
            child.proc.kill()
        try:
            child.proc.wait(timeout=_TERMINATE_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            self._log(f"child for {child.task_id} did not exit after kill")
            return False
        self._close_logs(child)
        return True

    def _close_logs(self, child: _Child) -> None:
        for stream in (child.stdout_file, child.stderr_file):
            try:
                stream.close()
            except OSError:
                pass

    def _stdout_is_json(self, child: _Child) -> bool:
        try:
            raw = child.stdout_path.read_bytes()
        except OSError:
            return False
        if not raw.strip():
            return False
        try:
            json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, ValueError):
            return False
        return True

    def _settle_complete(self, child: _Child) -> None:
        try:
            queue_cli.cmd_complete_exact(
                self._root, child.task_id, child.attempt, child.digest,
                child.worker,
            )
            self._log(f"done {child.task_id} attempt {child.attempt}")
        except Exception as exc:
            self._settle_errors += 1
            self._log(f"settle error (complete) {child.task_id}: {exc}")

    def _settle_child_failure(self, child: _Child, reason: str) -> None:
        self._log(f"failed {child.task_id} attempt {child.attempt}: {reason}")
        self._settle_failure(
            child.task_id, child.attempt, child.digest, child.worker,
            _reason(reason),
        )

    def _settle_failure(
        self, task_id: str, attempt: int, digest: str, worker: str,
        reason: str,
    ) -> None:
        # Attempt 2 is final; attempt 1 tries retry and repeats the same
        # binding as final only on the exact fail-disposition-mismatch.
        disposition = "final" if attempt >= 2 else "retry"
        try:
            try:
                queue_cli.cmd_fail_exact(
                    self._root, task_id, attempt, digest, worker,
                    disposition, reason,
                )
            except queue_cli.QueueError as exc:
                if (
                    disposition == "retry"
                    and str(exc) == "fail-disposition-mismatch"
                ):
                    queue_cli.cmd_fail_exact(
                        self._root, task_id, attempt, digest, worker,
                        "final", reason,
                    )
                else:
                    raise
        except Exception as exc:
            self._settle_errors += 1
            self._log(f"settle error (fail) {task_id}: {exc}")


# ------------------------------------------------------------------ CLI


def parse_args(argv: list[str] | None = None) -> SupervisorConfig:
    parser = argparse.ArgumentParser(
        prog="python -B -m autonomy.local_supervisor",
        description="Trusted foreground local night supervisor (MVP).",
    )
    parser.add_argument("--root", required=True, help="absolute queue root")
    parser.add_argument(
        "--duration-seconds", type=int, default=DEFAULT_DURATION_SECONDS,
    )
    parser.add_argument(
        "--poll-seconds", type=float, default=DEFAULT_POLL_SECONDS,
    )
    parser.add_argument(
        "--profiles", default=",".join(PROFILES),
        help="comma-separated subset of exactly " + ",".join(PROFILES),
    )
    parser.add_argument(
        "--claude", default="claude", help="exact executable override",
    )
    parser.add_argument(
        "--quota-cache", default=DEFAULT_QUOTA_CACHE,
        help="absolute normalized AIQuotaExporter cache path",
    )
    options = parser.parse_args(argv)
    if not os.path.isabs(options.root):
        parser.error("--root must be an absolute path")
    if options.duration_seconds < 0:
        parser.error("--duration-seconds must be >= 0")
    if options.poll_seconds < 0:
        parser.error("--poll-seconds must be >= 0")
    profiles = tuple(options.profiles.split(","))
    if (
        not profiles
        or len(set(profiles)) != len(profiles)
        or any(profile not in PROFILES for profile in profiles)
    ):
        parser.error(
            "--profiles must be a non-repeating subset of "
            + ",".join(PROFILES)
        )
    if not options.claude:
        parser.error("--claude must not be empty")
    if not os.path.isabs(options.quota_cache):
        parser.error("--quota-cache must be an absolute path")
    return SupervisorConfig(
        root=options.root,
        duration_seconds=options.duration_seconds,
        poll_seconds=options.poll_seconds,
        profiles=profiles,
        claude=options.claude,
        quota_cache=options.quota_cache,
    )


def main(argv: list[str] | None = None) -> int:
    config = parse_args(argv)
    return LocalSupervisor(config).run()


if __name__ == "__main__":
    raise SystemExit(main())
