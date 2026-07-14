"""Liveness heartbeat for one night-autonomy claim attempt (M2).

The heartbeat is written by a *sidecar* — a small helper thread or process
owned by the worker supervisor — so it keeps updating even while the model or
a tool call is stuck.  It is pure liveness: it says "this attempt still has a
living owner", nothing about progress.  Task progress lives in
``progress.json`` (see checkpoint.py) and changes only on explicit request;
the heartbeat sidecar never touches it.

Two APIs:

- ``write_heartbeat`` / ``read_heartbeat`` -- one-shot, atomic
  (bound temp-in-same-dir + identity-preserving rename), fail-closed on read like every other
  M2 state document.
- ``HeartbeatLoop`` -- a small stoppable pump around a zero-argument beat
  callable (see ``bind_heartbeat``).  ``run()`` executes in the calling
  thread; ``start()`` is an optional convenience that runs it on a daemon
  thread.  A beat that raises is recorded and surfaces through ``failure``,
  ``raise_if_failed()`` and ``stop()`` — a dead background loop never looks
  like a normally stopped one, and observability does not depend on
  ``threading.excepthook``.  Nothing here spawns a process.

Not wired into wrapper.py or any live agentchattr process yet.
"""

from __future__ import annotations

import math
import os
import re
import threading

from .checkpoint import (
    SCHEMA_VERSION,
    CheckpointError,
    SchemaError,
    _open_attempt_binding,
    atomic_write_document,
    format_utc,
    guard_state_file,
    read_state_document,
    resolve_attempt_dir,
    validate_attempt,
    validate_task_id,
)

__all__ = [
    "HeartbeatFailure",
    "HEARTBEAT_FILENAME",
    "MAX_HEARTBEAT_BYTES",
    "MAX_PID",
    "MAX_INTERVAL_SECONDS",
    "validate_profile",
    "validate_model",
    "validate_pid",
    "write_heartbeat",
    "read_heartbeat",
    "bind_heartbeat",
    "HeartbeatLoop",
]

HEARTBEAT_FILENAME = "heartbeat.json"
MAX_HEARTBEAT_BYTES = 2048
MAX_PID = 2**31 - 1
MAX_INTERVAL_SECONDS = 3600.0

# Same shapes as contract.json's claim filters.
_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")

_HEARTBEAT_KEYS = ("version", "task_id", "attempt", "profile", "model", "pid", "updated_at")


class HeartbeatFailure(CheckpointError):
    """A heartbeat beat raised; the loop is dead and must not look healthy."""


def validate_profile(profile):
    if not isinstance(profile, str) or not _PROFILE_RE.fullmatch(profile):
        raise SchemaError(f"malformed profile: {profile!r}")
    return profile


def validate_model(model):
    if not isinstance(model, str) or not _MODEL_RE.fullmatch(model):
        raise SchemaError(f"malformed model: {model!r}")
    return model


def validate_pid(pid):
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise SchemaError(f"malformed pid: {pid!r}")
    if not 1 <= pid <= MAX_PID:
        raise SchemaError(f"pid out of range 1..{MAX_PID}: {pid!r}")
    return pid


def _check_heartbeat_fields(document, _attempt_dir_real):
    validate_profile(document["profile"])
    validate_model(document["model"])
    validate_pid(document["pid"])


def write_heartbeat(queue_root, attempt_dir, *, task_id, attempt, profile, model, pid=None, now=None):
    """One-shot atomic heartbeat write; ``pid`` defaults to the calling process."""
    task = validate_task_id(task_id)
    attempt_number = validate_attempt(attempt)
    profile_value = validate_profile(profile)
    model_value = validate_model(model)
    pid_value = validate_pid(os.getpid() if pid is None else pid)
    binding = _open_attempt_binding(
        queue_root, attempt_dir, task_id=task, attempt=attempt_number
    )
    try:
        document = {
            "version": SCHEMA_VERSION,
            "task_id": task,
            "attempt": attempt_number,
            "profile": profile_value,
            "model": model_value,
            "pid": pid_value,
            "updated_at": format_utc(now),
        }
        path = guard_state_file(
            binding.path, HEARTBEAT_FILENAME, _binding=binding
        )
        atomic_write_document(
            path, document, MAX_HEARTBEAT_BYTES, _binding=binding
        )
        return path
    finally:
        binding.close()


def read_heartbeat(queue_root, attempt_dir, *, task_id, attempt):
    return read_state_document(
        queue_root,
        attempt_dir,
        filename=HEARTBEAT_FILENAME,
        max_bytes=MAX_HEARTBEAT_BYTES,
        keys=_HEARTBEAT_KEYS,
        task_id=task_id,
        attempt=attempt,
        field_check=_check_heartbeat_fields,
    )


def bind_heartbeat(queue_root, attempt_dir, *, task_id, attempt, profile, model, pid=None):
    """Validate once, fail fast, and return a zero-argument beat callable.

    ``pid`` is resolved at bind time (the sidecar's own pid by default).  The
    returned callable re-validates paths on every beat, so a queue root or
    attempt dir swapped out from under a running loop still fails closed.
    """
    pid_value = validate_pid(os.getpid() if pid is None else pid)
    validate_task_id(task_id)
    validate_attempt(attempt)
    validate_profile(profile)
    validate_model(model)
    resolve_attempt_dir(queue_root, attempt_dir, task_id=task_id, attempt=attempt)

    def beat():
        return write_heartbeat(
            queue_root,
            attempt_dir,
            task_id=task_id,
            attempt=attempt,
            profile=profile,
            model=model,
            pid=pid_value,
        )

    return beat


class HeartbeatLoop:
    """Stoppable heartbeat pump: beat immediately, then once per interval.

    ``run()`` blocks the calling thread until a stop is requested and always
    performs at least one beat, so a supervisor sees liveness right away.  A
    beat that raises is recorded as ``failure`` and propagates out of
    ``run()`` — a dead pump must look dead, never silently healthy.  When the
    loop runs on the ``start()`` background thread, the recorded failure is
    surfaced by ``failure``, ``raise_if_failed()`` and ``stop()`` instead of
    being lost to ``threading.excepthook``.  The loop only ever invokes its
    beat callable; it cannot touch checkpoint or progress documents.
    """

    def __init__(self, beat, interval_seconds):
        if not callable(beat):
            raise SchemaError(f"beat must be callable: {beat!r}")
        if isinstance(interval_seconds, bool) or not isinstance(interval_seconds, (int, float)):
            raise SchemaError(f"interval_seconds must be a number: {interval_seconds!r}")
        interval = float(interval_seconds)
        if not math.isfinite(interval) or not 0 < interval <= MAX_INTERVAL_SECONDS:
            raise SchemaError(
                f"interval_seconds out of (0, {MAX_INTERVAL_SECONDS}]: {interval_seconds!r}"
            )
        self._beat = beat
        self._interval = interval
        self._stop = threading.Event()
        self._thread = None
        self._beats = 0
        self._failure = None
        self._failure_lock = threading.Lock()

    @property
    def beats(self):
        return self._beats

    @property
    def stop_requested(self):
        return self._stop.is_set()

    @property
    def failure(self):
        """The exception that killed the loop, or None while it is healthy."""
        with self._failure_lock:
            return self._failure

    def raise_if_failed(self):
        """Fail closed: re-raise a recorded beat failure as HeartbeatFailure."""
        with self._failure_lock:
            failure = self._failure
        if failure is not None:
            raise HeartbeatFailure(f"heartbeat loop died: {failure!r}") from failure

    def request_stop(self):
        self._stop.set()

    def run(self):
        """Pump until stopped; returns the number of beats performed.

        A raising beat is recorded (see ``failure``) before re-raising, so
        inline callers and background-thread health checks observe the same
        dead state.
        """
        try:
            while True:
                self._beat()
                self._beats += 1
                if self._stop.wait(self._interval):
                    return self._beats
        except BaseException as exc:
            with self._failure_lock:
                self._failure = exc
            raise

    def _run_in_background(self):
        try:
            self.run()
        except BaseException:
            # Already recorded by run(); swallowing here keeps observability
            # on failure/raise_if_failed()/stop() instead of threading.excepthook.
            pass

    def start(self):
        """run() on a daemon thread; refuses to (re)start a loop that died."""
        self.raise_if_failed()
        if self._thread is not None:
            raise RuntimeError("heartbeat loop already started")
        thread = threading.Thread(
            target=self._run_in_background, name="autonomy-heartbeat", daemon=True
        )
        self._thread = thread
        thread.start()
        return thread

    def stop(self, timeout=10.0):
        """Request stop and join; raises HeartbeatFailure when the loop died.

        Returns True only for a loop that stopped normally and healthy — a
        dead heartbeat thread never looks like a normal stopped loop.
        """
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)
        self.raise_if_failed()
        return thread is None or not thread.is_alive()
