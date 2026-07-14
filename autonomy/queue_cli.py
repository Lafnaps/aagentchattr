"""Durable fail-closed autonomy task queue (M0+M1).

One producer drops closed-schema task cards into ``queue/``; workers claim
them with this CLI. A state transition is a single same-volume no-overwrite
atomic rename between state directories, so a parallel claim has exactly one
winner and an existing target is never replaced. The audit event is published
with an exclusive-create strategy strictly AFTER the transition; a crash
between the two leaves a visible AUDIT_GAP instead of a silent repair.

Integration contract (fixed by the control plane):
  python -m autonomy.queue_cli --root <ROOT> <command> ...
  stdout: exactly one JSON object, always (success and failure alike)
  exit 0: success
  exit 2: validation error or transition conflict (fail-closed refusal);
          this includes ``claim`` finding no eligible work, reported as
          {"ok": false, "error": "nothing-to-claim", "claimed": null}
  exit 3: AUDIT_GAP found by ``audit``, or an unexpected I/O failure

Claim ordering and crash windows (all detected by ``audit``, none repaired):
  1. card schema is validated; malformed cards are quarantined
     queue -> blocked (``block-malformed``), never executed
  2. payload is verified (containment + SHA-256) BEFORE the claim rename;
     a bad payload is quarantined queue -> blocked (``block-payload``)
  3. the claim rename queue -> in_progress picks exactly one winner
  4. payload is RE-verified immediately after winning; on failure the move
     is rolled back and the card quarantined (a tampered payload therefore
     never survives into a successful claim)
  5. attempts/<task>/a<N> is created with exclusive ``os.mkdir``; a
     pre-existing dir rolls back and quarantines (``block-attempt-dir``)
  6. the card is rewritten with the incremented attempt
  7. the claim event is published
  A crash after 3 and before 6 leaves an in_progress card whose attempt and
  event chain disagree with replay truth (audit: ``state_mismatch``); after
  5 and before 6 an extra attempt dir (audit: ``extra_attempt_dir``); after
  6 and before 7 a card/event attempt divergence (audit:
  ``card_attempt_mismatch``). Consumers MUST treat this CLI's stdout as the
  only signal that a claim is executable; scanning in_progress/ directly is
  not part of the contract.

Stdlib only. Never touches live agentchattr data, processes, SVN, or any
TradeStation working copy: every state/events/attempts path is guarded
against symlink/junction/reparse escape, and the card payload is verified
against ``allowed_root`` containment plus its pinned SHA-256 both at enqueue
and immediately before a successful claim.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import hashlib
import json
import os
import re
import stat as stat_module
import sys
import time
from pathlib import Path

CONTRACT_VERSION = 1
ROOT_MARKER = "autonomy-root.json"
MARKER_NAME = "agentchattr-autonomy-queue"
EXACT_PROTOCOL_DIR = "exact"
STATES = ("queue", "in_progress", "done", "failed", "blocked")
TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
HEX64_RE = re.compile(r"^[0-9A-F]{64}$")
LOWER_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
WORKER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"\.[0-9]{3}Z$"
)
REASON_RE = re.compile(r"^[ -~]{0,256}$")
SAFE_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
CARD_FILE_RE = re.compile(r"^([a-z0-9][a-z0-9-]{0,63})\.json$")
EVENT_FILE_RE = re.compile(r"^([0-9]{6})\.json$")
ATTEMPT_DIR_RE = re.compile(r"^a[1-9][0-9]{0,5}$")
WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_AUDIT_OR_IO = 3

MAX_JSON_BYTES = 1 << 20        # cards, events, marker: bounded reads
PAYLOAD_MAX_BYTES = 4 << 20     # payload hash reads are bounded too
MAX_ATTEMPT_VALUE = 1_000_000
MAX_EVENT_SEQ = 999_999
AUDIT_EVENT_CAP = 4096
EVENT_PUBLISH_RETRIES = 64

CARD_KEYS = {
    "version", "task_id", "profile", "model", "allowed_root", "restart_safe",
    "max_step_seconds", "attempt", "max_attempts", "created_utc",
    "payload_relpath", "payload_sha256",
}
# Keys a producer may omit; readers apply these exact fail-closed defaults.
CARD_DEFAULTS = {"restart_safe": False, "attempt": 0, "max_attempts": 2}
EVENT_KEYS = {
    "version", "task_id", "seq", "transition", "from_state", "to_state",
    "attempt", "worker", "reason", "recorded_utc",
}
EXACT_EVENT_KEYS = {"authority_digest", "attempt_dir"}
EXACT_PROTOCOL_KEYS = {
    "version", "task_id", "authority_digest", "first_exact_attempt",
    "prior_event_seq",
}
EXACT_PRECLAIM_QUARANTINE_TRANSITIONS = frozenset(
    {"block-payload", "block-attempt-dir"}
)
EXACT_EVENT_TRANSITIONS = frozenset(
    {"claim", "complete", "fail-retry", "fail-final", "block", "requeue-exact"}
) | EXACT_PRECLAIM_QUARANTINE_TRANSITIONS
# Transitions whose exact metadata binds the attempted/re-armed NEXT
# generation directory a<attempt+1> instead of the current a<attempt>.
EXACT_NEXT_GENERATION_TRANSITIONS = (
    EXACT_PRECLAIM_QUARANTINE_TRANSITIONS | frozenset({"requeue-exact"})
)
TRANSITIONS = {
    "claim": ("queue", "in_progress"),
    "complete": ("in_progress", "done"),
    "fail-retry": ("in_progress", "queue"),
    "fail-final": ("in_progress", "failed"),
    "block": ("in_progress", "blocked"),
    "block-malformed": ("queue", "blocked"),
    "block-payload": ("queue", "blocked"),
    "block-attempt-dir": ("queue", "blocked"),
    "requeue-blocked": ("blocked", "queue"),
    "requeue-failed": ("failed", "queue"),
    "requeue-exact": ("blocked", "queue"),
}
BLOCK_TRANSITIONS = frozenset(
    {"block", "block-malformed", "block-payload", "block-attempt-dir"}
)
REPARSE_FLAG = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class QueueError(Exception):
    """Fail-closed refusal; message is a stable machine-readable code."""


class FatalIOError(Exception):
    """Unrecoverable I/O divergence; maps to exit 3."""


# --------------------------------------------------------------- primitives


def _utc_text() -> str:
    now = time.time()
    parts = time.gmtime(now)
    millis = int((now % 1) * 1000)
    return (
        f"{parts.tm_year:04d}-{parts.tm_mon:02d}-{parts.tm_mday:02d}"
        f"T{parts.tm_hour:02d}:{parts.tm_min:02d}:{parts.tm_sec:02d}"
        f".{millis:03d}Z"
    )


def _utc_valid(value: object) -> bool:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        return False
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _no_duplicate_pairs(pairs: list) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise QueueError("duplicate-json-key")
        result[key] = value
    return result


def _reject_constant(_value: str):
    raise QueueError("nonfinite-json-number")


def _read_json(path: Path) -> object:
    with open(path, "rb") as stream:
        raw = stream.read(MAX_JSON_BYTES)
        if stream.read(1):
            raise QueueError("file-too-large")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise QueueError("invalid-utf8") from None
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError:
        raise QueueError("malformed-json") from None


def _encode_json(value: dict) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _no_reparse_lstat(path: Path):
    """lstat that fails closed on any symlink/junction/reparse point.

    Returns None when the path does not exist (a component about to be
    created); every existing component must be a plain filesystem object.
    """
    try:
        probe = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat_module.S_ISLNK(probe.st_mode):
        raise QueueError("reparse-point-in-root-path")
    if getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG:
        raise QueueError("reparse-point-in-root-path")
    return probe


def _safe_path(root: Path, *parts: str) -> Path:
    """Build a path under root from vetted components, guarding each level.

    Components are names we construct ourselves (states, task ids, seq file
    names, attempt dirs); the regex makes separator or dot-dot injection
    structurally impossible, and the per-component lstat rejects any
    symlink/junction/reparse point already present on the walk.
    """
    path = root
    for part in parts:
        if not SAFE_COMPONENT_RE.fullmatch(part):
            raise QueueError("unsafe-path-component")
        path = path / part
        _no_reparse_lstat(path)
    return path


@contextlib.contextmanager
def _task_lock(root: Path, task_id: str):
    """Hold the cross-process exclusive lock for one task transaction.

    The fixed lock inode lives in ``tmp/`` (which is deliberately outside
    the audited durable truth).  Every state-changing command holds it from
    its first authoritative read through the state move, attempt mutation,
    and event publication.  A process crash releases the kernel lock but
    does not repair any files, so the documented move/event crash gap stays
    visible to ``audit``.
    """
    _validate_task_id(task_id)
    lock_path = _safe_path(root, "tmp", f"lock-{task_id}.lck")
    stream = open(lock_path, "a+b")
    locked = False
    try:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
            os.fsync(stream.fileno())
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        locked = True
        yield
    finally:
        if locked:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def _rename_no_overwrite(source: Path, target: Path) -> None:
    """Atomic same-volume move that never replaces an existing target.

    Windows os.rename refuses an existing target natively. On POSIX,
    os.rename overwrites, so link+unlink is used instead; a crash between
    the two leaves the card visible in BOTH directories, which audit
    reports as duplicate_states (never silently repaired).
    """
    if os.name == "nt":
        os.rename(source, target)
        return
    os.link(source, target)
    try:
        os.unlink(source)
    except FileNotFoundError:
        pass


def _tmp_file(root: Path, hint: str) -> Path:
    tmp_dir = _safe_path(root, "tmp")
    tmp_dir.mkdir(exist_ok=True)
    return tmp_dir / f"{hint}.{os.getpid()}.{time.time_ns()}.tmp"


def _write_tmp(root: Path, hint: str, data: bytes) -> Path:
    tmp = _tmp_file(root, hint)
    with open(tmp, "xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return tmp


def _publish_json_exclusive(root: Path, target: Path, value: dict) -> None:
    """Create target atomically; raises FileExistsError, never replaces."""
    tmp = _write_tmp(root, target.name, _encode_json(value))
    try:
        _rename_no_overwrite(tmp, target)
    except FileExistsError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _replace_json_atomic(root: Path, target: Path, value: dict) -> None:
    """Owned rewrite (in_progress card attempt bump): temp + os.replace."""
    tmp = _write_tmp(root, target.name, _encode_json(value))
    os.replace(tmp, target)


# ---------------------------------------------------------------- root/card


def _validate_marker(root: Path) -> None:
    marker = root / ROOT_MARKER
    probe = _no_reparse_lstat(marker)
    if probe is None:
        raise QueueError("root-marker-missing")
    if not stat_module.S_ISREG(probe.st_mode):
        raise QueueError("root-marker-invalid")
    try:
        data = _read_json(marker)
    except Exception:
        raise QueueError("root-marker-invalid") from None
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "name"}
        or not _is_int(data["version"])
        or data["version"] != CONTRACT_VERSION
        or not isinstance(data["name"], str)
        or data["name"] != MARKER_NAME
    ):
        raise QueueError("root-marker-invalid")


def _resolve_root(root_arg: str) -> Path:
    root = Path(root_arg)
    if not root.is_absolute():
        raise QueueError("root-not-absolute")
    root = Path(os.path.realpath(root))
    if not root.is_dir():
        raise QueueError("root-missing")
    _validate_marker(root)
    return root


def _validate_task_id(task_id: object) -> str:
    if (
        not isinstance(task_id, str)
        or not TASK_ID_RE.fullmatch(task_id)
        or task_id in WINDOWS_RESERVED
    ):
        raise QueueError("invalid-task-id")
    return task_id


def _validate_payload_relpath(value: object) -> str:
    """Syntactic fail-closed checks; containment/hash happen separately."""
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise QueueError("card-payload-relpath")
    for char in value:
        if char in '<>:"|?*' or ord(char) < 0x20 or ord(char) == 0x7F:
            raise QueueError("card-payload-relpath")
    if value.startswith(("/", "\\")) or Path(value).is_absolute():
        raise QueueError("card-payload-relpath")
    for segment in re.split(r"[\\/]", value):
        if segment in ("", ".", ".."):
            raise QueueError("card-payload-relpath")
        if segment.split(".")[0].lower() in WINDOWS_RESERVED:
            raise QueueError("card-payload-relpath")
    return value


def _normalize_card(value: object) -> dict:
    if not isinstance(value, dict):
        raise QueueError("card-not-object")
    card = dict(value)
    for key, default in CARD_DEFAULTS.items():
        if key not in card:
            card[key] = default
    if set(card) != CARD_KEYS:
        raise QueueError("card-schema")
    if not _is_int(card["version"]) or card["version"] != CONTRACT_VERSION:
        raise QueueError("card-version")
    _validate_task_id(card["task_id"])
    if not isinstance(card["profile"], str) or not NAME_RE.fullmatch(card["profile"]):
        raise QueueError("card-profile")
    if not isinstance(card["model"], str) or not MODEL_RE.fullmatch(card["model"]):
        raise QueueError("card-model")
    allowed_root = card["allowed_root"]
    if (
        not isinstance(allowed_root, str)
        or not allowed_root
        or len(allowed_root) > 1024
        or "\x00" in allowed_root
        or not Path(allowed_root).is_absolute()
    ):
        raise QueueError("card-allowed-root")
    if not isinstance(card["restart_safe"], bool):
        raise QueueError("card-restart-safe")
    if not _is_int(card["max_step_seconds"]) or not (
        1 <= card["max_step_seconds"] <= 86400
    ):
        raise QueueError("card-max-step-seconds")
    if not _is_int(card["attempt"]) or not (
        0 <= card["attempt"] <= MAX_ATTEMPT_VALUE
    ):
        raise QueueError("card-attempt")
    # Bounded blast radius: only exact int 1 or 2 is admissible; bool, float,
    # strings, and anything > 2 are rejected before any filesystem effect.
    if not _is_int(card["max_attempts"]) or card["max_attempts"] not in (1, 2):
        raise QueueError("card-max-attempts")
    if not _utc_valid(card["created_utc"]):
        raise QueueError("card-created-utc")
    _validate_payload_relpath(card["payload_relpath"])
    if not isinstance(card["payload_sha256"], str) or not HEX64_RE.fullmatch(
        card["payload_sha256"]
    ):
        raise QueueError("card-payload-sha256")
    return card


def card_authority_digest(value: object) -> str:
    """Return the canonical immutable card-authority SHA-256.

    Defaults are materialized by ``_normalize_card`` and every normalized
    field participates except ``attempt``.  Attempt is deliberately bound by
    a separate exact-CAS argument, so changing either the mutable generation
    or any authority field invalidates a previously observed queue view.
    """
    card = _normalize_card(value)
    authority = {key: card[key] for key in sorted(card) if key != "attempt"}
    canonical = json.dumps(
        authority, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _load_exact_protocol_marker(root: Path, task_id: str) -> dict | None:
    """Load one immutable canonical exact-protocol marker, or None.

    Canonical bytes are part of the evidence: alternate whitespace/order,
    duplicate keys, malformed UTF-8/JSON, and non-exact types all refuse.
    """
    path = _safe_path(root, EXACT_PROTOCOL_DIR, f"{task_id}.json")
    probe = _no_reparse_lstat(path)
    if probe is None:
        return None
    if not stat_module.S_ISREG(probe.st_mode):
        raise QueueError("exact-evidence-invalid")
    try:
        with open(path, "rb") as stream:
            raw = stream.read(MAX_JSON_BYTES)
            if stream.read(1):
                raise QueueError("exact-evidence-invalid")
        marker = _read_json(path)
    except (OSError, QueueError):
        raise QueueError("exact-evidence-invalid") from None
    if (
        not isinstance(marker, dict)
        or set(marker) != EXACT_PROTOCOL_KEYS
        or not _is_int(marker["version"])
        or marker["version"] != CONTRACT_VERSION
        or marker["task_id"] != task_id
        or not isinstance(marker["authority_digest"], str)
        or not LOWER_HEX64_RE.fullmatch(marker["authority_digest"])
        or not _is_int(marker["first_exact_attempt"])
        or marker["first_exact_attempt"] not in (1, 2)
        or not _is_int(marker["prior_event_seq"])
        or not (0 <= marker["prior_event_seq"] <= MAX_EVENT_SEQ)
        or _encode_json(marker) != raw
    ):
        raise QueueError("exact-evidence-invalid")
    return marker


def _ensure_exact_protocol_marker(
    root: Path, task_id: str, authority_digest: str, first_attempt: int,
) -> dict:
    """Exclusive first admission; idempotently validates response-loss retry."""
    marker = _load_exact_protocol_marker(root, task_id)
    if marker is None:
        # The immutable boundary prevents a later marker from retroactively
        # reinterpreting supported marker-free quarantine/requeue history as an
        # exact transition.  The task lock makes this a stable contiguous tail.
        prior_event_seq = len(_exact_events(root, task_id, allow_missing=True))
        proposed = {
            "version": CONTRACT_VERSION,
            "task_id": task_id,
            "authority_digest": authority_digest,
            "first_exact_attempt": first_attempt,
            "prior_event_seq": prior_event_seq,
        }
        target = _safe_path(root, EXACT_PROTOCOL_DIR, f"{task_id}.json")
        try:
            _publish_json_exclusive(root, target, proposed)
            marker = proposed
        except FileExistsError:
            marker = _load_exact_protocol_marker(root, task_id)
            if marker is None:
                raise QueueError("exact-evidence-invalid")
            # This branch means the marker was absent at our initial read but
            # another publisher won the first-admission race.  Accept only
            # the byte-equivalent semantic proposal from that same request;
            # the looser pre-existing-marker compatibility rule below is for
            # a marker that was already visible before this call (for example
            # exact a1 followed by an exact a2 retry), not for a race winner.
            if marker != proposed:
                raise QueueError("exact-protocol-conflict")
    if (
        marker["authority_digest"] != authority_digest
        or marker["first_exact_attempt"] > first_attempt
    ):
        raise QueueError("exact-protocol-conflict")
    return marker


def _validate_expected_attempt(value: object) -> int:
    if not _is_int(value) or not (1 <= value <= MAX_ATTEMPT_VALUE):
        raise QueueError("invalid-expected-attempt")
    return value


def _validate_expected_current_attempt(value: object) -> int:
    """CAS input naming the CURRENT generation, where 0 (never claimed,
    e.g. an exact pre-claim quarantine of fresh work) is legitimate."""
    if not _is_int(value) or not (0 <= value <= MAX_ATTEMPT_VALUE):
        raise QueueError("invalid-expected-attempt")
    return value


def _validate_expected_digest(value: object) -> str:
    if not isinstance(value, str) or not LOWER_HEX64_RE.fullmatch(value):
        raise QueueError("invalid-expected-digest")
    return value


def _verify_payload(card: dict) -> Path:
    """Fail-closed payload admission: containment, type, size, exact hash.

    Every component under allowed_root is lstat-checked so a symlink or
    junction ANYWHERE on the relative walk is rejected, not just on the
    final component; a realpath containment check then backstops the walk.
    """
    allowed_root = Path(os.path.realpath(card["allowed_root"]))
    try:
        root_probe = os.lstat(allowed_root)
    except OSError:
        raise QueueError("payload-allowed-root-missing") from None
    if not stat_module.S_ISDIR(root_probe.st_mode):
        raise QueueError("payload-allowed-root-missing")
    path = allowed_root
    probe = root_probe
    for segment in re.split(r"[\\/]", card["payload_relpath"]):
        path = path / segment
        try:
            probe = os.lstat(path)
        except FileNotFoundError:
            raise QueueError("payload-missing") from None
        except OSError:
            raise QueueError("payload-unreadable") from None
        if stat_module.S_ISLNK(probe.st_mode):
            raise QueueError("payload-reparse-point")
        if getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG:
            raise QueueError("payload-reparse-point")
    if not stat_module.S_ISREG(probe.st_mode):
        raise QueueError("payload-not-regular-file")
    if probe.st_size > PAYLOAD_MAX_BYTES:
        raise QueueError("payload-too-large")
    resolved = os.path.normcase(os.path.realpath(path))
    base = os.path.normcase(str(allowed_root)).rstrip(os.sep) + os.sep
    if not resolved.startswith(base):
        raise QueueError("payload-escapes-allowed-root")
    digest = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as stream:
            while True:
                chunk = stream.read(1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > PAYLOAD_MAX_BYTES:
                    raise QueueError("payload-too-large")
                digest.update(chunk)
    except OSError:
        raise QueueError("payload-unreadable") from None
    if digest.hexdigest().upper() != card["payload_sha256"]:
        raise QueueError("payload-tampered")
    return path


# ------------------------------------------------------------- state moves


def _find_state(root: Path, task_id: str) -> str | None:
    for state in STATES:
        path = _safe_path(root, state, f"{task_id}.json")
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        return state
    return None


def _move_card(root: Path, task_id: str, transition: str) -> None:
    """One atomic no-overwrite rename; the losing racer raises QueueError."""
    from_state, to_state = TRANSITIONS[transition]
    source = _safe_path(root, from_state, f"{task_id}.json")
    target = _safe_path(root, to_state, f"{task_id}.json")
    try:
        _rename_no_overwrite(source, target)
    except FileNotFoundError:
        raise QueueError("card-not-in-" + from_state) from None
    except FileExistsError:
        raise QueueError("transition-collision") from None
    except PermissionError:
        raise QueueError("transition-collision") from None


def _rollback_claim(root: Path, task_id: str) -> None:
    source = _safe_path(root, "in_progress", f"{task_id}.json")
    target = _safe_path(root, "queue", f"{task_id}.json")
    try:
        _rename_no_overwrite(source, target)
    except OSError:
        raise FatalIOError("claim-rollback-failed") from None


def _quarantine_from_queue(
    root: Path, task_id: str, transition: str, attempt: int, worker: str,
    reason: str, *, authority_digest: str | None = None,
    attempt_dir: str | None = None,
) -> bool:
    try:
        _move_card(root, task_id, transition)
    except QueueError:
        return False
    _append_event(
        root, task_id, transition, attempt, worker, reason=reason,
        authority_digest=authority_digest, attempt_dir=attempt_dir,
    )
    return True


# ------------------------------------------------------------------ events


def _next_seq(events_dir: Path) -> int:
    top = 0
    for name in os.listdir(events_dir):
        match = EVENT_FILE_RE.fullmatch(name)
        if match:
            top = max(top, int(match.group(1)))
    return top + 1


def _exact_attempt_dir(transition: str, attempt: int) -> str:
    """Return the attempt directory bound by exact event metadata.

    Claim/terminal events bind the already-created current attempt.  An exact
    pre-claim quarantine instead binds the attempted *next* generation: no
    claim was published and the card's durable attempt therefore stays put.
    For ``block-attempt-dir`` that next-generation directory is the immutable
    collision evidence; for ``block-payload`` its absence is intentional.
    ``requeue-exact`` likewise binds the re-armed next generation that the
    subsequent exact claim will create; the directory does not exist yet.
    """
    if transition in EXACT_NEXT_GENERATION_TRANSITIONS:
        return f"a{attempt + 1}"
    return f"a{attempt}"


def _append_event(
    root: Path, task_id: str, transition: str, attempt: int, worker: str,
    reason: str = "", *, authority_digest: str | None = None,
    attempt_dir: str | None = None,
) -> None:
    """Publish the audit event strictly AFTER the state transition.

    seq is max(existing)+1 and the file is created exclusively (temp +
    no-overwrite rename/link): an existing seq file can NEVER be replaced;
    a collision retries with a fresh scan and fails closed when exhausted.
    """
    from_state, to_state = TRANSITIONS[transition]
    events_dir = _safe_path(root, "events", task_id)
    events_dir.mkdir(exist_ok=True)
    for _ in range(EVENT_PUBLISH_RETRIES):
        seq = _next_seq(events_dir)
        if seq > MAX_EVENT_SEQ:
            raise FatalIOError("event-seq-overflow")
        event = {
            "version": CONTRACT_VERSION,
            "task_id": task_id,
            "seq": seq,
            "transition": transition,
            "from_state": from_state,
            "to_state": to_state,
            "attempt": attempt,
            "worker": worker,
            "reason": reason,
            "recorded_utc": _utc_text(),
        }
        if authority_digest is not None or attempt_dir is not None:
            if (
                authority_digest is None
                or attempt_dir is None
                or transition not in EXACT_EVENT_TRANSITIONS
                or not LOWER_HEX64_RE.fullmatch(authority_digest)
                or attempt_dir != _exact_attempt_dir(transition, attempt)
            ):
                raise FatalIOError("invalid-exact-event-metadata")
            event["authority_digest"] = authority_digest
            event["attempt_dir"] = attempt_dir
        try:
            _publish_json_exclusive(root, events_dir / f"{seq:06d}.json", event)
        except FileExistsError:
            continue
        return
    raise FatalIOError("event-publish-collision")


def _event_error(event: object, task_id: str, expected_seq: int) -> str | None:
    """Strict closed-schema event validation; returns a code or None."""
    if not isinstance(event, dict):
        return "not-object"
    event_keys = set(event)
    if event_keys not in (EVENT_KEYS, EVENT_KEYS | EXACT_EVENT_KEYS):
        return "keys"
    if not _is_int(event["version"]) or event["version"] != CONTRACT_VERSION:
        return "version"
    if event["task_id"] != task_id:
        return "task-id"
    if not _is_int(event["seq"]) or event["seq"] != expected_seq:
        return "seq"
    transition = event["transition"]
    if not isinstance(transition, str) or transition not in TRANSITIONS:
        return "transition"
    if not _is_int(event["attempt"]) or not (
        0 <= event["attempt"] <= MAX_ATTEMPT_VALUE
    ):
        return "attempt"
    if not isinstance(event["worker"], str) or not WORKER_RE.fullmatch(
        event["worker"]
    ):
        return "worker"
    reason = event["reason"]
    if not isinstance(reason, str) or not REASON_RE.fullmatch(reason):
        return "reason"
    if transition in BLOCK_TRANSITIONS and not reason:
        return "reason-required"
    if not _utc_valid(event["recorded_utc"]):
        return "recorded-utc"
    expect_from, expect_to = TRANSITIONS[transition]
    if event["from_state"] != expect_from or event["to_state"] != expect_to:
        return "from-to"
    if EXACT_EVENT_KEYS <= event_keys:
        if transition not in EXACT_EVENT_TRANSITIONS:
            return "exact-metadata-transition"
        if (
            not isinstance(event["authority_digest"], str)
            or not LOWER_HEX64_RE.fullmatch(event["authority_digest"])
        ):
            return "authority-digest"
        if (
            transition not in EXACT_NEXT_GENERATION_TRANSITIONS
            and event["attempt"] == 0
        ) or event["attempt_dir"] != _exact_attempt_dir(
            transition, event["attempt"]
        ):
            return "attempt-dir"
    return None


# ---------------------------------------------------------------- commands


def cmd_init(root_arg: str) -> tuple[int, dict]:
    root = Path(root_arg)
    if not root.is_absolute():
        raise QueueError("root-not-absolute")
    root.mkdir(parents=True, exist_ok=True)
    root = Path(os.path.realpath(root))
    for name in STATES + ("events", "attempts", EXACT_PROTOCOL_DIR, "tmp"):
        _safe_path(root, name).mkdir(exist_ok=True)
    marker = root / ROOT_MARKER
    if _no_reparse_lstat(marker) is None:
        try:
            _publish_json_exclusive(
                root, marker,
                {"version": CONTRACT_VERSION, "name": MARKER_NAME},
            )
        except FileExistsError:
            pass  # racing init: validated below like any existing marker
    _validate_marker(root)
    return EXIT_OK, {"ok": True, "root": str(root)}


def cmd_enqueue(root_arg: str, card_arg: str) -> tuple[int, dict]:
    root = _resolve_root(root_arg)
    card_source = Path(card_arg)
    if not card_source.is_absolute() or not card_source.is_file():
        raise QueueError("card-file-missing")
    card = _normalize_card(_read_json(card_source))
    if card["attempt"] != 0:
        raise QueueError("enqueue-attempt-nonzero")
    task_id = card["task_id"]
    # SHA-256 + containment are validated at enqueue as well as at claim:
    # a payload that is already missing or tampered never enters the queue.
    _verify_payload(card)
    with _task_lock(root, task_id):
        if _find_state(root, task_id) is not None:
            raise QueueError("task-already-exists")
        for residue in ("events", "attempts"):
            if _no_reparse_lstat(_safe_path(root, residue, task_id)) is not None:
                raise QueueError("task-residue-exists")
        if _no_reparse_lstat(
            _safe_path(root, EXACT_PROTOCOL_DIR, f"{task_id}.json")
        ) is not None:
            raise QueueError("task-residue-exists")
        try:
            _publish_json_exclusive(
                root, _safe_path(root, "queue", f"{task_id}.json"), card
            )
        except FileExistsError:
            raise QueueError("task-already-exists") from None
    return EXIT_OK, {"ok": True, "task_id": task_id, "state": "queue"}


def _exact_states(root: Path, task_id: str) -> list[str]:
    """Return every durable state containing task_id; never hide duplicates."""
    states: list[str] = []
    for state in STATES:
        path = _safe_path(root, state, f"{task_id}.json")
        probe = _no_reparse_lstat(path)
        if probe is None:
            continue
        if not stat_module.S_ISREG(probe.st_mode):
            raise QueueError("exact-card-not-regular")
        states.append(state)
    return states


def _load_exact_card(root: Path, task_id: str, state: str) -> dict:
    card = _normalize_card(
        _read_json(_safe_path(root, state, f"{task_id}.json"))
    )
    if card["task_id"] != task_id:
        raise QueueError("card-task-id-mismatch")
    return card


def _exact_view(
    card: dict,
    state: str,
    payload_path: Path | None,
    active_claim: dict | None,
    payload_error: str | None = None,
) -> dict:
    current = card["attempt"]
    next_attempt = (
        current + 1
        if state == "queue" and current < card["max_attempts"]
        else None
    )
    if state == "in_progress":
        if active_claim is None:
            raise QueueError("exact-evidence-invalid")
        worker = active_claim["worker"]
    else:
        if active_claim is not None:
            raise QueueError("exact-evidence-invalid")
        worker = None
    if payload_error is not None:
        payload_view = {
            "verified": False,
            "error": payload_error,
            "path": None,
            "sha256": card["payload_sha256"],
        }
    else:
        payload_view = {
            "verified": True,
            "path": str(payload_path),
            "sha256": card["payload_sha256"],
        }
    return {
        "task_id": card["task_id"],
        "state": state,
        "current_attempt": current,
        "next_attempt": next_attempt,
        "digest": card_authority_digest(card),
        "profile": card["profile"],
        "model": card["model"],
        "worker": worker,
        "payload": payload_view,
    }


def cmd_peek_exact(root_arg: str, task_id: str) -> tuple[int, dict]:
    """Read and verify one exact authority view without durable mutation.

    Executable states (queue, in_progress) keep the strict fail-closed
    payload gate: an unverifiable payload refuses the whole view so a peek
    can never advertise executable work it did not verify.  Non-executable
    states (blocked/done/failed) instead report the payload verification
    outcome inside the view, so an operator can inspect a card they just
    quarantined without the expected drift masking the durable evidence.
    """
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    with _task_lock(root, task_id):
        evidence = _validate_task_semantic_evidence(root, task_id)
        state = evidence["state"]
        card = evidence["card"]
        if state in ("queue", "in_progress"):
            payload_path = _verify_payload(card)
            view = _exact_view(
                card, state, payload_path, evidence["active_claim"]
            )
        else:
            try:
                payload_path = _verify_payload(card)
            except QueueError as drift:
                view = _exact_view(
                    card, state, None, evidence["active_claim"],
                    payload_error=str(drift),
                )
            else:
                view = _exact_view(
                    card, state, payload_path, evidence["active_claim"]
                )
    return EXIT_OK, {"ok": True, "task": view}


def cmd_list_exact(root_arg: str) -> tuple[int, dict]:
    """List individually locked, verified queue authorities, sorted by id.

    Corrupt task evidence (cards/events/attempts/markers) still fails the
    whole list closed: dispatch must not silently skip corrupt queued work.
    A payload-only failure on an otherwise semantically valid queue card is
    different: it is a per-task condition that audit reports as
    ``exact_payload_unavailable`` and the targeted quarantine command heals,
    so the entry is exposed deterministically with ``verified: false``
    instead of hiding every healthy task behind one drifted payload.
    """
    root = _resolve_root(root_arg)
    queue_dir = _safe_path(root, "queue")
    items: list[dict] = []
    for name in sorted(os.listdir(queue_dir)):
        match = CARD_FILE_RE.fullmatch(name)
        if not match or match.group(1) in WINDOWS_RESERVED:
            raise QueueError("exact-evidence-invalid")
        task_id = match.group(1)
        with _task_lock(root, task_id):
            evidence = _validate_task_semantic_evidence(root, task_id)
            if evidence["state"] != "queue":
                continue  # a valid task raced to another state before lock
            card = evidence["card"]
            try:
                payload_path = _verify_payload(card)
            except QueueError as drift:
                items.append(_exact_view(
                    card, "queue", None, None, payload_error=str(drift),
                ))
            else:
                items.append(_exact_view(card, "queue", payload_path, None))
    return EXIT_OK, {"ok": True, "tasks": items}


def _exact_events(
    root: Path, task_id: str, *, allow_missing: bool = False,
) -> list[dict]:
    """Load a syntactically valid contiguous event chain without repair."""
    directory = _safe_path(root, "events", task_id)
    probe = _no_reparse_lstat(directory)
    if probe is None:
        if allow_missing:
            return []
        raise QueueError("exact-evidence-missing")
    if not stat_module.S_ISDIR(probe.st_mode):
        raise QueueError("exact-evidence-invalid")
    names = sorted(os.listdir(directory))
    if len(names) > AUDIT_EVENT_CAP:
        raise QueueError("exact-evidence-invalid")
    events: list[dict] = []
    for seq, name in enumerate(names, 1):
        if name != f"{seq:06d}.json":
            raise QueueError("exact-evidence-invalid")
        try:
            event = _read_json(_safe_path(root, "events", task_id, name))
        except QueueError:
            raise QueueError("exact-evidence-invalid") from None
        if _event_error(event, task_id, seq) is not None:
            raise QueueError("exact-evidence-invalid")
        events.append(event)
    return events


def _validate_task_semantic_evidence(root: Path, task_id: str) -> dict:
    """Fail-closed one-task replay used before every exact state action.

    The caller holds ``_task_lock``.  This is deliberately stronger than a
    last-event lookup: it validates the complete chain, current state/card,
    attempt budget, exact ownership, and the entire immutable attempt-dir
    index.  It never creates, moves, rewrites, or repairs durable evidence.
    """
    try:
        states = _exact_states(root, task_id)
        if len(states) != 1:
            raise QueueError("exact-evidence-invalid")
        state = states[0]
        card = _load_exact_card(root, task_id, state)
        events = _exact_events(root, task_id, allow_missing=True)
        digest = card_authority_digest(card)
        marker = _load_exact_protocol_marker(root, task_id)
        first_exact_attempt = None
        prior_event_seq = None
        if marker is not None:
            if (
                marker["authority_digest"] != digest
                or marker["first_exact_attempt"] > card["max_attempts"]
                or marker["prior_event_seq"] > len(events)
            ):
                raise QueueError("exact-evidence-invalid")
            first_exact_attempt = marker["first_exact_attempt"]
            prior_event_seq = marker["prior_event_seq"]

        if card["attempt"] > card["max_attempts"]:
            raise QueueError("exact-evidence-invalid")
        if state == "queue" and card["attempt"] >= card["max_attempts"]:
            raise QueueError("exact-evidence-invalid")

        replay_state = "queue"
        replay_attempt = 0
        claims = 0
        active_claim = None
        exact_started = False
        exact_preclaim_quarantine = None
        prev_event = None
        if marker is not None and prior_event_seq == 0:
            if first_exact_attempt != 1:
                raise QueueError("exact-evidence-invalid")
        for event in events:
            transition = event["transition"]
            has_exact = EXACT_EVENT_KEYS <= set(event)
            after_exact_boundary = (
                marker is not None and event["seq"] > prior_event_seq
            )
            if event["from_state"] != replay_state:
                raise QueueError("exact-evidence-invalid")

            if transition == "claim":
                if event["attempt"] != replay_attempt + 1:
                    raise QueueError("exact-evidence-invalid")
                replay_attempt += 1
                claims += 1
                if replay_attempt > card["max_attempts"]:
                    raise QueueError("exact-evidence-invalid")
                exact_required = (
                    after_exact_boundary
                    and replay_attempt >= first_exact_attempt
                )
                if has_exact != exact_required:
                    raise QueueError("exact-evidence-invalid")
                if has_exact:
                    if event["authority_digest"] != digest:
                        raise QueueError("exact-evidence-invalid")
                    active_claim = {
                        "exact": True,
                        "worker": event["worker"],
                        "digest": event["authority_digest"],
                        "attempt": event["attempt"],
                    }
                else:
                    active_claim = {
                        "exact": False,
                        "worker": event["worker"],
                        "digest": None,
                        "attempt": event["attempt"],
                    }
            elif transition == "block-malformed":
                # Matches audit's quarantine exception: the attempt was not
                # knowable when the unreadable card was moved from queue.
                if has_exact:
                    raise QueueError("exact-evidence-invalid")
            else:
                if event["attempt"] != replay_attempt:
                    raise QueueError("exact-evidence-invalid")

            if transition in EXACT_PRECLAIM_QUARANTINE_TRANSITIONS:
                exact_required = (
                    after_exact_boundary
                    and replay_attempt + 1 >= first_exact_attempt
                )
                if has_exact != exact_required:
                    raise QueueError("exact-evidence-invalid")
                if has_exact:
                    if active_claim is not None:
                        raise QueueError("exact-evidence-invalid")
                    exact_preclaim_quarantine = event

            if transition == "requeue-exact":
                # Only the exact verb publishes this transition: it must be
                # marker-governed, after the boundary, carry exact metadata,
                # and never re-arm an exhausted budget.
                if (
                    marker is None
                    or not after_exact_boundary
                    or not has_exact
                    or replay_attempt >= card["max_attempts"]
                ):
                    raise QueueError("exact-evidence-invalid")
                # Durable owner continuity: the requeue worker must equal the
                # worker recorded on the immediately preceding exact blocked
                # tail, and only a terminal ``block`` or an exact
                # ``block-payload`` is a repairable predecessor.  An exact
                # ``block-attempt-dir`` binds an immutable collision
                # directory that a re-armed claim would hit forever, so it
                # can never precede a valid requeue.
                if (
                    prev_event is None
                    or not (EXACT_EVENT_KEYS <= set(prev_event))
                    or prev_event["transition"] not in ("block", "block-payload")
                    or event["worker"] != prev_event["worker"]
                ):
                    raise QueueError("exact-evidence-invalid")

            if transition in ("requeue-blocked", "requeue-failed"):
                # Once any exact transition has been published, legacy requeue
                # can no longer erase that protocol boundary.  Requeues that
                # occurred wholly before a later first exact admission remain
                # valid compatibility history.
                if exact_started:
                    raise QueueError("exact-evidence-invalid")

            if transition in ("fail-retry", "fail-final"):
                retryable = event["attempt"] < card["max_attempts"]
                if (transition == "fail-retry") != retryable:
                    raise QueueError("exact-evidence-invalid")
            if (
                transition in ("requeue-blocked", "requeue-failed")
                and replay_attempt >= card["max_attempts"]
            ):
                raise QueueError("exact-evidence-invalid")

            if has_exact:
                if (
                    marker is None
                    or not after_exact_boundary
                    or transition not in EXACT_EVENT_TRANSITIONS
                    or event["authority_digest"] != digest
                ):
                    raise QueueError("exact-evidence-invalid")
                exact_started = True

            if transition in ("complete", "fail-retry", "fail-final", "block"):
                if active_claim is None:
                    raise QueueError("exact-evidence-invalid")
                if has_exact:
                    if (
                        not active_claim["exact"]
                        or event["worker"] != active_claim["worker"]
                        or event["authority_digest"] != active_claim["digest"]
                        or event["attempt"] != active_claim["attempt"]
                    ):
                        raise QueueError("exact-evidence-invalid")
                elif active_claim["exact"]:
                    # An exact claim can never be downgraded by appending a
                    # legacy terminal event that drops its authority binding.
                    raise QueueError("exact-evidence-invalid")
                active_claim = None

            replay_state = event["to_state"]
            if marker is not None and event["seq"] == prior_event_seq:
                if (
                    replay_state != "queue"
                    or replay_attempt != first_exact_attempt - 1
                ):
                    raise QueueError("exact-evidence-invalid")
            prev_event = event

        if replay_state != state or replay_attempt != card["attempt"]:
            raise QueueError("exact-evidence-invalid")
        if state == "in_progress" and active_claim is None:
            raise QueueError("exact-evidence-invalid")
        if state != "in_progress" and active_claim is not None:
            raise QueueError("exact-evidence-invalid")
        if marker is not None:
            before_first = first_exact_attempt - 1
            if replay_attempt < before_first:
                raise QueueError("exact-evidence-invalid")
            exact_quarantined = (
                state == "blocked"
                and bool(events)
                and exact_preclaim_quarantine is events[-1]
            )
            if (
                replay_attempt == before_first
                and state != "queue"
                and not exact_quarantined
            ):
                # Only the response-loss window after marker publication and
                # before the first exact claim, or a canonical exact pre-claim
                # quarantine at that boundary, is valid here.
                raise QueueError("exact-evidence-invalid")

        expected_dirs = {f"a{i}" for i in range(1, claims + 1)}
        if (
            exact_preclaim_quarantine is not None
            and exact_preclaim_quarantine["transition"] == "block-attempt-dir"
        ):
            expected_dirs.add(exact_preclaim_quarantine["attempt_dir"])
        actual_dirs: set[str] = set()
        tree = _safe_path(root, "attempts", task_id)
        tree_probe = _no_reparse_lstat(tree)
        if tree_probe is not None:
            if not stat_module.S_ISDIR(tree_probe.st_mode):
                raise QueueError("exact-evidence-invalid")
            for name in sorted(os.listdir(tree)):
                probe = os.lstat(tree / name)
                if (
                    not ATTEMPT_DIR_RE.fullmatch(name)
                    or stat_module.S_ISLNK(probe.st_mode)
                    or getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG
                    or not stat_module.S_ISDIR(probe.st_mode)
                ):
                    raise QueueError("exact-evidence-invalid")
                actual_dirs.add(name)
        if actual_dirs != expected_dirs:
            raise QueueError("exact-evidence-invalid")

        return {
            "state": state,
            "card": card,
            "events": events,
            "active_claim": active_claim,
            "exact_marker": marker,
        }
    except QueueError as exc:
        if str(exc) == "exact-evidence-invalid":
            raise
        raise QueueError("exact-evidence-invalid") from None
    except OSError:
        raise QueueError("exact-evidence-invalid") from None


def _require_exact_event(
    root: Path, task_id: str, events: list[dict], transition: str,
    expected_attempt: int,
    expected_digest: str, worker: str, expected_reason: str | None = None,
) -> dict:
    if not events:
        raise QueueError("exact-evidence-missing")
    event = events[-1]
    if not (EXACT_EVENT_KEYS <= set(event)):
        raise QueueError("exact-evidence-missing")
    if event["transition"] != transition or event["attempt"] != expected_attempt:
        raise QueueError("exact-transition-conflict")
    if event["authority_digest"] != expected_digest:
        raise QueueError("exact-digest-mismatch")
    if event["worker"] != worker:
        raise QueueError("exact-worker-mismatch")
    if expected_reason is not None and event["reason"] != expected_reason:
        raise QueueError("exact-reason-mismatch")
    if event["attempt_dir"] != f"a{expected_attempt}":
        raise QueueError("exact-evidence-invalid")
    attempt_dir = _safe_path(
        root, "attempts", task_id, event["attempt_dir"]
    )
    probe = _no_reparse_lstat(attempt_dir)
    if probe is None or not stat_module.S_ISDIR(probe.st_mode):
        raise QueueError("exact-evidence-invalid")
    return event


def _task_has_history_evidence(root: Path, task_id: str) -> bool:
    marker = _load_exact_protocol_marker(root, task_id)
    if marker is not None:
        return True
    return any(
        _no_reparse_lstat(_safe_path(root, top, task_id)) is not None
        for top in ("events", "attempts")
    )


def _refuse_legacy_terminal_for_exact_claim(root: Path, task_id: str) -> None:
    """Keep the compatibility verbs from bypassing an exact claim owner.

    Legacy claims retain their legacy terminal behavior.  Once a claim has
    durable exact evidence, however, its terminal transition must use the
    corresponding exact verb so attempt/digest/worker cannot be discarded.
    Missing, malformed, semantically illegal, or incomplete evidence refuses
    the legacy terminal too; this helper never guesses or repairs evidence.
    """
    evidence = _validate_task_semantic_evidence(root, task_id)
    if evidence["state"] != "in_progress":
        raise QueueError("exact-evidence-invalid")
    if evidence["exact_marker"] is not None:
        raise QueueError("exact-transition-required")
    claim = evidence["active_claim"]
    if claim is None:
        raise QueueError("exact-evidence-invalid")
    if claim["exact"]:
        raise QueueError("exact-transition-required")


def _verify_exact_card(
    card: dict, expected_attempt: int, expected_digest: str,
    profile: str | None = None, model: str | None = None,
) -> None:
    if card["attempt"] != expected_attempt:
        raise QueueError("exact-attempt-mismatch")
    if card_authority_digest(card) != expected_digest:
        raise QueueError("exact-digest-mismatch")
    if profile is not None and card["profile"] != profile:
        raise QueueError("exact-profile-mismatch")
    if model is not None and card["model"] != model:
        raise QueueError("exact-model-mismatch")


def _exact_claim_result(
    card: dict, payload_path: Path, attempt_dir: Path, replayed: bool,
) -> tuple[int, dict]:
    return EXIT_OK, {
        "ok": True,
        "task_id": card["task_id"],
        "state": "in_progress",
        "attempt": card["attempt"],
        "digest": card_authority_digest(card),
        "profile": card["profile"],
        "model": card["model"],
        "payload_verified": True,
        "payload_path": str(payload_path),
        "attempt_dir": str(attempt_dir),
        "replayed": replayed,
    }


def cmd_claim_exact(
    root_arg: str, task_id: str, expected_next_attempt: int,
    expected_digest: str, profile: str, model: str, worker: str,
) -> tuple[int, dict]:
    """Claim exactly one observed card incarnation, or replay that claim."""
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    expected_next_attempt = _validate_expected_attempt(expected_next_attempt)
    expected_digest = _validate_expected_digest(expected_digest)
    if not isinstance(worker, str) or not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")
    if (
        not isinstance(profile, str)
        or not NAME_RE.fullmatch(profile)
        or not isinstance(model, str)
        or not MODEL_RE.fullmatch(model)
    ):
        raise QueueError("invalid-claim-filter")
    with _task_lock(root, task_id):
        evidence = _validate_task_semantic_evidence(root, task_id)
        state = evidence["state"]
        card = evidence["card"]
        if state == "in_progress":
            _verify_exact_card(
                card, expected_next_attempt, expected_digest, profile, model
            )
            payload_path = _verify_payload(card)
            _require_exact_event(
                root, task_id, evidence["events"], "claim",
                expected_next_attempt,
                expected_digest, worker,
            )
            attempt_dir = _safe_path(
                root, "attempts", task_id, f"a{expected_next_attempt}"
            )
            return _exact_claim_result(card, payload_path, attempt_dir, True)
        if state != "queue":
            raise QueueError("exact-state-conflict")

        # A durably exhausted queue card (attempt >= max_attempts) is corrupt
        # history and was already refused exact-evidence-invalid by the
        # semantic validator; audit reports it as attempt_budget_violation.
        if card["attempt"] + 1 != expected_next_attempt:
            raise QueueError("exact-attempt-mismatch")
        if card_authority_digest(card) != expected_digest:
            raise QueueError("exact-digest-mismatch")
        if card["profile"] != profile:
            raise QueueError("exact-profile-mismatch")
        if card["model"] != model:
            raise QueueError("exact-model-mismatch")
        try:
            payload_path = _verify_payload(card)
        except QueueError as exc:
            if evidence["exact_marker"] is None:
                raise
            # A marker can legitimately precede a response-loss retry or an
            # exact fail-retry.  If its payload drifts while back in queue, the
            # exact protocol must produce a canonical terminal quarantine;
            # leaving a clean-but-unclaimable queue card would wedge the poller.
            quarantined = _quarantine_from_queue(
                root, task_id, "block-payload", card["attempt"], worker,
                str(exc), authority_digest=expected_digest,
                attempt_dir=f"a{expected_next_attempt}",
            )
            if not quarantined:
                raise FatalIOError("exact-quarantine-failed")
            raise QueueError("exact-payload-changed") from None
        _ensure_exact_protocol_marker(
            root, task_id, expected_digest, expected_next_attempt
        )
        _move_card(root, task_id, "claim")
        try:
            _verify_payload(card)
        except QueueError as exc:
            _rollback_claim(root, task_id)
            quarantined = _quarantine_from_queue(
                root, task_id, "block-payload", card["attempt"], worker,
                str(exc), authority_digest=expected_digest,
                attempt_dir=f"a{expected_next_attempt}",
            )
            if not quarantined:
                raise FatalIOError("exact-quarantine-failed")
            raise QueueError("exact-payload-changed") from None
        attempt_dir = None
        try:
            attempts_parent = _safe_path(root, "attempts", task_id)
            attempts_parent.mkdir(exist_ok=True)
            attempt_dir = _safe_path(
                root, "attempts", task_id, f"a{expected_next_attempt}"
            )
            os.mkdir(attempt_dir)
        except FileExistsError:
            _rollback_claim(root, task_id)
            try:
                collision = (
                    _no_reparse_lstat(attempt_dir)
                    if attempt_dir is not None else None
                )
            except QueueError:
                collision = None
            if collision is None or not stat_module.S_ISDIR(collision.st_mode):
                # The exact quarantine schema can bind an immutable directory
                # collision.  A file/reparse/vanishing-path race is corruption,
                # not a canonical outcome, and must remain visibly fail-closed.
                raise FatalIOError("exact-attempt-dir-conflict-unsafe")
            quarantined = _quarantine_from_queue(
                root, task_id, "block-attempt-dir", card["attempt"], worker,
                "attempt-dir-exists", authority_digest=expected_digest,
                attempt_dir=f"a{expected_next_attempt}",
            )
            if not quarantined:
                raise FatalIOError("exact-quarantine-failed")
            raise QueueError("exact-attempt-dir-conflict") from None
        except QueueError:
            _rollback_claim(root, task_id)
            raise FatalIOError("exact-attempt-path-unsafe") from None
        card["attempt"] = expected_next_attempt
        _replace_json_atomic(
            root, _safe_path(root, "in_progress", f"{task_id}.json"), card
        )
        _append_event(
            root, task_id, "claim", expected_next_attempt, worker,
            authority_digest=expected_digest,
            attempt_dir=f"a{expected_next_attempt}",
        )
        return _exact_claim_result(card, payload_path, attempt_dir, False)


def _exact_payload_quarantine_result(
    task_id: str,
    card: dict,
    digest: str,
    worker: str,
    *,
    replayed: bool,
) -> tuple[int, dict]:
    return EXIT_OK, {
        "ok": True,
        "task_id": task_id,
        "state": "blocked",
        "attempt": card["attempt"],
        "digest": digest,
        "worker": worker,
        "payload_verified": False,
        "replayed": replayed,
    }


def cmd_quarantine_exact_payload(
    root_arg: str, task_id: str, worker: str,
) -> tuple[int, dict]:
    """Quarantine one stranded queued payload without cached CAS data.

    For a marker-governed task the immutable exact-protocol marker is the
    sole authority digest.  For a still marker-free queued card the durable
    normalized queue card itself — payload-verified at enqueue — is the only
    authority source, and exact admission (the marker) is published before
    the state move so a crash between the two leaves the admitted idempotent
    response-loss window, never a half-quarantined task.  In both cases the
    current card supplies only its already validated attempt generation; the
    bytes of the drifted/missing payload are never treated as authority.  An
    identical retry after response loss accepts the canonical durable
    ``block-payload`` tail without consulting the payload again.
    """
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    if not isinstance(worker, str) or not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")

    with _task_lock(root, task_id):
        evidence = _validate_task_semantic_evidence(root, task_id)
        state = evidence["state"]
        card = evidence["card"]
        marker = evidence["exact_marker"]
        if marker is not None:
            digest = marker["authority_digest"]
        elif state == "queue":
            digest = card_authority_digest(card)
        else:
            # A marker-free non-queue card was never exact-admitted and has
            # no durable exact quarantine tail to replay: legacy verbs own it.
            raise QueueError("exact-evidence-missing")

        if state == "blocked":
            events = evidence["events"]
            if not events:
                raise QueueError("exact-state-conflict")
            event = events[-1]
            expected_dir = f"a{card['attempt'] + 1}"
            if (
                event["transition"] != "block-payload"
                or not EXACT_EVENT_KEYS <= set(event)
                or event["attempt"] != card["attempt"]
                or event["authority_digest"] != digest
                or event["attempt_dir"] != expected_dir
            ):
                raise QueueError("exact-state-conflict")
            if event["worker"] != worker:
                raise QueueError("exact-worker-mismatch")
            return _exact_payload_quarantine_result(
                task_id, card, digest, worker, replayed=True
            )

        if state != "queue":
            raise QueueError("exact-state-conflict")
        try:
            _verify_payload(card)
        except QueueError as drift:
            reason = str(drift)
        else:
            raise QueueError("exact-payload-not-drifted")

        if marker is None:
            # Exact admission for the drifted marker-free card, published
            # under the same lock strictly before the state move.  The
            # digest above came from the durable validated queue card, so
            # the marker/event authority is reconstructed evidence, never a
            # caller-supplied or payload-derived value.
            _ensure_exact_protocol_marker(
                root, task_id, digest, card["attempt"] + 1
            )

        next_attempt = card["attempt"] + 1
        quarantined = _quarantine_from_queue(
            root,
            task_id,
            "block-payload",
            card["attempt"],
            worker,
            reason,
            authority_digest=digest,
            attempt_dir=f"a{next_attempt}",
        )
        if not quarantined:
            raise FatalIOError("exact-quarantine-failed")
        return _exact_payload_quarantine_result(
            task_id, card, digest, worker, replayed=False
        )


def _claim_candidate_locked(
    root: Path, name: str, task_id: str, profile: str, model: str, worker: str
) -> tuple[int, dict] | None:
    """Inspect and possibly claim one queue entry while its lock is held."""
    entry = _safe_path(root, "queue", name)
    try:
        probe = os.lstat(entry)
    except OSError:
        return None
    if (
        stat_module.S_ISLNK(probe.st_mode)
        or getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG
        or not stat_module.S_ISREG(probe.st_mode)
    ):
        return None
    has_history = _task_has_history_evidence(root, task_id)
    if has_history:
        evidence = _validate_task_semantic_evidence(root, task_id)
        if evidence["exact_marker"] is not None:
            # This is a valid task, but legacy claim is not its protocol.  Skip
            # it so a lexically earlier exact-managed card cannot starve later
            # legacy candidates.  Malformed/conflicting exact evidence still
            # raises from the loader/semantic validator above.
            return None
        if evidence["state"] != "queue":
            raise QueueError("exact-evidence-invalid")
        card = evidence["card"]
    else:
        try:
            card = _normalize_card(_read_json(entry))
            if card["task_id"] != task_id:
                raise QueueError("card-task-id-mismatch")
        except (FileNotFoundError, PermissionError):
            return None
        except QueueError:
            # A fresh malformed card is quarantined fail-closed. Once history
            # exists, the semantic validator above refuses instead of adding
            # a transition to already-corrupt evidence.
            _quarantine_from_queue(
                root, task_id, "block-malformed", 0, worker, "malformed-card"
            )
            return None
        except OSError:
            return None
    if card["profile"] != profile or card["model"] != model:
        return None
    if card["attempt"] >= card["max_attempts"]:
        # A legacy/corrupt queued card must never turn into a<N+1>. Refuse
        # before payload work, the state rename, attempt-dir creation, or an
        # event append. Audit reports the durable queue/history violation;
        # claim deliberately does not try to repair or quarantine it.
        raise QueueError("max-attempts-exhausted")
    try:
        # Payload containment + exact SHA-256 BEFORE the claim rename:
        # a bad payload never reaches in_progress or attempt creation.
        payload_path = _verify_payload(card)
    except QueueError as exc:
        _quarantine_from_queue(
            root, task_id, "block-payload", card["attempt"], worker,
            str(exc),
        )
        return None
    try:
        _move_card(root, task_id, "claim")
    except QueueError:
        return None
    # Owned now. Re-verify immediately so a payload swapped between the
    # pre-check and the rename still cannot survive into a claim.
    try:
        _verify_payload(card)
    except QueueError as exc:
        _rollback_claim(root, task_id)
        _quarantine_from_queue(
            root, task_id, "block-payload", card["attempt"], worker,
            str(exc),
        )
        return None
    new_attempt = card["attempt"] + 1
    try:
        attempts_parent = _safe_path(root, "attempts", task_id)
        attempts_parent.mkdir(exist_ok=True)
        attempt_dir = _safe_path(root, "attempts", task_id, f"a{new_attempt}")
        # Attempt dirs are immutable and never reused: exclusive create.
        os.mkdir(attempt_dir)
    except FileExistsError:
        _rollback_claim(root, task_id)
        _quarantine_from_queue(
            root, task_id, "block-attempt-dir", card["attempt"], worker,
            "attempt-dir-exists",
        )
        return None
    except QueueError:
        _rollback_claim(root, task_id)
        _quarantine_from_queue(
            root, task_id, "block-attempt-dir", card["attempt"], worker,
            "attempt-path-unsafe",
        )
        return None
    card["attempt"] = new_attempt
    _replace_json_atomic(root, _safe_path(root, "in_progress", name), card)
    _append_event(root, task_id, "claim", new_attempt, worker)
    return EXIT_OK, {
        "ok": True, "task_id": task_id, "claimed": card,
        "payload_path": str(payload_path), "attempt_dir": str(attempt_dir),
    }


def cmd_claim(
    root_arg: str, profile: str, model: str, worker: str
) -> tuple[int, dict]:
    root = _resolve_root(root_arg)
    if not isinstance(worker, str) or not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")
    if not NAME_RE.fullmatch(profile) or not MODEL_RE.fullmatch(model):
        raise QueueError("invalid-claim-filter")
    queue_dir = _safe_path(root, "queue")
    for name in sorted(os.listdir(queue_dir)):
        match = CARD_FILE_RE.fullmatch(name)
        if not match or match.group(1) in WINDOWS_RESERVED:
            continue  # foreign junk is skipped here and surfaced by audit
        task_id = match.group(1)
        with _task_lock(root, task_id):
            result = _claim_candidate_locked(
                root, name, task_id, profile, model, worker
            )
        if result is not None:
            return result
    return EXIT_VALIDATION, {
        "ok": False, "error": "nothing-to-claim", "claimed": None,
    }


def _load_in_progress(root: Path, task_id: str) -> dict:
    path = _safe_path(root, "in_progress", f"{task_id}.json")
    if _no_reparse_lstat(path) is None:
        raise QueueError("card-not-in-in_progress")
    card = _normalize_card(_read_json(path))
    if card["task_id"] != task_id:
        raise QueueError("card-task-id-mismatch")
    if card["attempt"] == 0:
        # A successful claim always bumps attempt before publishing its
        # stdout; attempt 0 in in_progress is a crash-window artifact and
        # must never be completed/failed/blocked as if it were claimed.
        raise QueueError("card-never-claimed")
    return card


def _validate_reason(reason: str, required: bool) -> str:
    if not isinstance(reason, str) or not REASON_RE.fullmatch(reason):
        raise QueueError("invalid-reason")
    if required and not reason:
        raise QueueError("block-reason-required")
    return reason


def cmd_complete(root_arg: str, task_id: str, worker: str) -> tuple[int, dict]:
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    if not isinstance(worker, str) or not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")
    with _task_lock(root, task_id):
        card = _load_in_progress(root, task_id)
        _refuse_legacy_terminal_for_exact_claim(root, task_id)
        _move_card(root, task_id, "complete")
        _append_event(root, task_id, "complete", card["attempt"], worker)
    return EXIT_OK, {"ok": True, "task_id": task_id, "state": "done"}


def cmd_fail(
    root_arg: str, task_id: str, worker: str, reason: str
) -> tuple[int, dict]:
    """Supervisor retry path: attempt < max_attempts requeues, else final."""
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    if not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")
    _validate_reason(reason, required=False)
    with _task_lock(root, task_id):
        card = _load_in_progress(root, task_id)
        _refuse_legacy_terminal_for_exact_claim(root, task_id)
        if card["attempt"] < card["max_attempts"]:
            transition, state = "fail-retry", "queue"
        else:
            transition, state = "fail-final", "failed"
        _move_card(root, task_id, transition)
        _append_event(root, task_id, transition, card["attempt"], worker, reason)
    return EXIT_OK, {"ok": True, "task_id": task_id, "state": state}


def cmd_block(
    root_arg: str, task_id: str, worker: str, reason: str
) -> tuple[int, dict]:
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    if not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")
    _validate_reason(reason, required=True)
    with _task_lock(root, task_id):
        card = _load_in_progress(root, task_id)
        _refuse_legacy_terminal_for_exact_claim(root, task_id)
        _move_card(root, task_id, "block")
        _append_event(root, task_id, "block", card["attempt"], worker, reason)
    return EXIT_OK, {"ok": True, "task_id": task_id, "state": "blocked"}


def cmd_requeue(root_arg: str, task_id: str, worker: str) -> tuple[int, dict]:
    """Operator path: blocked/failed -> queue while retry budget remains."""
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    if not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")
    with _task_lock(root, task_id):
        if _task_has_history_evidence(root, task_id):
            evidence = _validate_task_semantic_evidence(root, task_id)
            if evidence["exact_marker"] is not None:
                raise QueueError("exact-transition-required")
            state = evidence["state"]
            card = evidence["card"]
        else:
            state = _find_state(root, task_id)
            if state not in ("blocked", "failed"):
                raise QueueError("requeue-source-invalid")
            card = _normalize_card(
                _read_json(_safe_path(root, state, f"{task_id}.json"))
            )
            if card["task_id"] != task_id:
                raise QueueError("card-task-id-mismatch")
        if state == "blocked":
            transition = "requeue-blocked"
        elif state == "failed":
            transition = "requeue-failed"
        else:
            raise QueueError("requeue-source-invalid")
        if card["attempt"] >= card["max_attempts"]:
            # The global autonomy blast-radius is at most two executions for
            # one task identity.  A deliberate run after exhaustion must be a
            # newly enqueued task_id, never an implicit a<N+1> escape hatch.
            raise QueueError("max-attempts-exhausted")
        _move_card(root, task_id, transition)
        _append_event(root, task_id, transition, card["attempt"], worker)
    return EXIT_OK, {"ok": True, "task_id": task_id, "state": "queue"}


def cmd_requeue_exact(
    root_arg: str, task_id: str, expected_attempt: int,
    expected_digest: str, worker: str,
) -> tuple[int, dict]:
    """Exact operator path: blocked -> queue while retry budget remains.

    Authority and ownership are the durable exact blocked tail (a terminal
    ``block`` or an exact ``block-payload`` quarantine), never a caller
    assertion: the caller must present the current attempt, the authority
    digest bound by the immutable marker/card, and the worker recorded on
    that tail.  An exact ``block-attempt-dir`` tail is never repairable
    here: its immutable collision directory ``a<attempt+1>`` cannot be
    removed or reused, so a re-armed claim would collide forever; it
    refuses ``exact-attempt-dir-not-requeueable`` for every worker and the
    safe recovery is a new task_id.  The
    payload must re-verify byte-exactly before the card becomes claimable
    again; a still-drifted payload refuses without mutation.  The published
    event re-arms the next generation ``a<attempt+1>`` without consuming
    budget, in move-then-event order so a crash between the two stays a
    visible AUDIT_GAP.  An identical retry after response loss accepts only
    the matching canonical ``requeue-exact`` tail and does not reread the
    payload.  Marker-free blocked work stays on the legacy ``requeue`` verb;
    ``failed`` is deliberately unreachable here because an exact
    ``fail-final`` only ever happens with the budget already exhausted.
    """
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    expected_attempt = _validate_expected_current_attempt(expected_attempt)
    expected_digest = _validate_expected_digest(expected_digest)
    if not isinstance(worker, str) or not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")
    with _task_lock(root, task_id):
        evidence = _validate_task_semantic_evidence(root, task_id)
        state = evidence["state"]
        card = evidence["card"]
        if evidence["exact_marker"] is None:
            raise QueueError("exact-evidence-missing")
        _verify_exact_card(card, expected_attempt, expected_digest)
        if card["attempt"] >= card["max_attempts"]:
            raise QueueError("max-attempts-exhausted")
        events = evidence["events"]
        if not events:
            raise QueueError("exact-state-conflict")
        tail = events[-1]
        has_exact_tail = EXACT_EVENT_KEYS <= set(tail)

        if state == "queue":
            if (
                tail["transition"] != "requeue-exact"
                or not has_exact_tail
                or tail["attempt"] != expected_attempt
                or tail["authority_digest"] != expected_digest
            ):
                raise QueueError("exact-state-conflict")
            if tail["worker"] != worker:
                raise QueueError("exact-worker-mismatch")
            return EXIT_OK, {
                "ok": True, "task_id": task_id, "state": "queue",
                "attempt": expected_attempt,
                "next_attempt": expected_attempt + 1,
                "digest": expected_digest, "replayed": True,
            }
        if state != "blocked":
            raise QueueError("exact-state-conflict")

        if (
            not has_exact_tail
            or tail["to_state"] != "blocked"
            or tail["attempt"] != expected_attempt
            or tail["authority_digest"] != expected_digest
        ):
            raise QueueError("exact-state-conflict")
        if tail["transition"] == "block-attempt-dir":
            # The immutable collision directory a<attempt+1> can never be
            # removed or reused, so a re-armed exact claim would collide and
            # quarantine again forever.  This refusal binds every worker; the
            # safe recovery is a new task_id.
            raise QueueError("exact-attempt-dir-not-requeueable")
        if tail["worker"] != worker:
            raise QueueError("exact-worker-mismatch")
        try:
            _verify_payload(card)
        except QueueError:
            raise QueueError("exact-payload-not-restored") from None
        _move_card(root, task_id, "requeue-exact")
        _append_event(
            root, task_id, "requeue-exact", expected_attempt, worker,
            authority_digest=expected_digest,
            attempt_dir=f"a{expected_attempt + 1}",
        )
        return EXIT_OK, {
            "ok": True, "task_id": task_id, "state": "queue",
            "attempt": expected_attempt,
            "next_attempt": expected_attempt + 1,
            "digest": expected_digest, "replayed": False,
        }


def _exact_terminal_result(
    task_id: str, state: str, attempt: int, digest: str, replayed: bool,
) -> tuple[int, dict]:
    return EXIT_OK, {
        "ok": True, "task_id": task_id, "state": state,
        "attempt": attempt, "digest": digest, "replayed": replayed,
    }


def _exact_terminal(
    root_arg: str, task_id: str, expected_attempt: int,
    expected_digest: str, worker: str, transition: str, reason: str = "",
    expected_disposition: str | None = None,
) -> tuple[int, dict]:
    root = _resolve_root(root_arg)
    _validate_task_id(task_id)
    expected_attempt = _validate_expected_attempt(expected_attempt)
    expected_digest = _validate_expected_digest(expected_digest)
    if not isinstance(worker, str) or not WORKER_RE.fullmatch(worker):
        raise QueueError("invalid-worker")
    _validate_reason(reason, required=transition == "block")
    if expected_disposition is not None and expected_disposition not in (
        "retry", "final"
    ):
        raise QueueError("invalid-fail-disposition")

    if transition == "complete":
        exact_transition, target_state = "complete", "done"
    elif transition == "block":
        exact_transition, target_state = "block", "blocked"
    elif transition == "fail":
        if expected_disposition not in ("retry", "final"):
            raise QueueError("invalid-fail-disposition")
        exact_transition = "fail-" + expected_disposition
        target_state = "queue" if expected_disposition == "retry" else "failed"
    else:
        raise QueueError("unknown-exact-transition")

    with _task_lock(root, task_id):
        evidence = _validate_task_semantic_evidence(root, task_id)
        state = evidence["state"]
        card = evidence["card"]
        _verify_exact_card(card, expected_attempt, expected_digest)

        if transition == "fail":
            actual = (
                "retry" if card["attempt"] < card["max_attempts"] else "final"
            )
            if expected_disposition != actual:
                raise QueueError("fail-disposition-mismatch")

        if state == target_state:
            _require_exact_event(
                root, task_id, evidence["events"], exact_transition,
                expected_attempt,
                expected_digest, worker, reason,
            )
            return _exact_terminal_result(
                task_id, target_state, expected_attempt, expected_digest, True
            )
        if state != "in_progress":
            raise QueueError("exact-state-conflict")

        # Exact terminal ownership is the durable exact claim evidence, not a
        # caller assertion.  A legacy or differently-owned claim cannot be
        # completed through the exact API.
        _require_exact_event(
            root, task_id, evidence["events"], "claim", expected_attempt,
            expected_digest, worker,
        )
        _move_card(root, task_id, exact_transition)
        _append_event(
            root, task_id, exact_transition, expected_attempt, worker, reason,
            authority_digest=expected_digest,
            attempt_dir=f"a{expected_attempt}",
        )
        return _exact_terminal_result(
            task_id, target_state, expected_attempt, expected_digest, False
        )


def cmd_complete_exact(
    root_arg: str, task_id: str, expected_attempt: int,
    expected_digest: str, worker: str,
) -> tuple[int, dict]:
    return _exact_terminal(
        root_arg, task_id, expected_attempt, expected_digest, worker,
        "complete",
    )


def cmd_fail_exact(
    root_arg: str, task_id: str, expected_attempt: int,
    expected_digest: str, worker: str, disposition: str, reason: str,
) -> tuple[int, dict]:
    return _exact_terminal(
        root_arg, task_id, expected_attempt, expected_digest, worker, "fail",
        reason, disposition,
    )


def cmd_block_exact(
    root_arg: str, task_id: str, expected_attempt: int,
    expected_digest: str, worker: str, reason: str,
) -> tuple[int, dict]:
    return _exact_terminal(
        root_arg, task_id, expected_attempt, expected_digest, worker, "block",
        reason,
    )


# ------------------------------------------------------------------- audit


def _audit_scan_states(root: Path, gap) -> dict[str, list[str]]:
    seen: dict[str, list[str]] = {}
    for state in STATES:
        try:
            state_dir = _safe_path(root, state)
        except QueueError as exc:
            gap(None, "layout", where=state, detail=str(exc))
            continue
        if not state_dir.is_dir():
            gap(None, "layout", where=state, detail="missing-state-dir")
            continue
        for name in sorted(os.listdir(state_dir)):
            match = CARD_FILE_RE.fullmatch(name)
            if not match or match.group(1) in WINDOWS_RESERVED:
                gap(None, "unexpected_entry", where=state, entry=name)
                continue
            try:
                probe = os.lstat(state_dir / name)
            except OSError:
                gap(None, "unexpected_entry", where=state, entry=name)
                continue
            if (
                stat_module.S_ISLNK(probe.st_mode)
                or getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG
                or not stat_module.S_ISREG(probe.st_mode)
            ):
                gap(None, "unexpected_entry", where=state, entry=name)
                continue
            seen.setdefault(match.group(1), []).append(state)
    return seen


def _audit_scan_children(root: Path, kind: str, gap) -> dict[str, Path]:
    """Scan events/ or attempts/ for per-task dirs; junk becomes gaps."""
    result: dict[str, Path] = {}
    try:
        base = _safe_path(root, kind)
    except QueueError as exc:
        gap(None, "layout", where=kind, detail=str(exc))
        return result
    if not base.is_dir():
        gap(None, "layout", where=kind, detail="missing-dir")
        return result
    for name in sorted(os.listdir(base)):
        if not TASK_ID_RE.fullmatch(name) or name in WINDOWS_RESERVED:
            gap(None, "unexpected_entry", where=kind, entry=name)
            continue
        child = base / name
        try:
            probe = os.lstat(child)
        except OSError:
            gap(None, "unexpected_entry", where=kind, entry=name)
            continue
        if (
            stat_module.S_ISLNK(probe.st_mode)
            or getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG
            or not stat_module.S_ISDIR(probe.st_mode)
        ):
            gap(None, "unexpected_entry", where=kind, entry=name)
            continue
        result[name] = child
    return result


def _audit_scan_exact_markers(root: Path, gap) -> dict[str, Path]:
    result: dict[str, Path] = {}
    try:
        base = _safe_path(root, EXACT_PROTOCOL_DIR)
    except QueueError as exc:
        gap(None, "layout", where=EXACT_PROTOCOL_DIR, detail=str(exc))
        return result
    if not base.is_dir():
        gap(None, "layout", where=EXACT_PROTOCOL_DIR, detail="missing-dir")
        return result
    for name in sorted(os.listdir(base)):
        match = CARD_FILE_RE.fullmatch(name)
        # Reject lexical junk and Windows device aliases before touching the
        # path.  Even lstat("con.json") can address a device on Windows unless
        # the name is screened first.
        if not match or match.group(1) in WINDOWS_RESERVED:
            gap(None, "unexpected_entry", where=EXACT_PROTOCOL_DIR, entry=name)
            continue
        child = base / name
        try:
            probe = os.lstat(child)
        except OSError:
            probe = None
        if (
            probe is None
            or stat_module.S_ISLNK(probe.st_mode)
            or getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG
            or not stat_module.S_ISREG(probe.st_mode)
        ):
            gap(None, "unexpected_entry", where=EXACT_PROTOCOL_DIR, entry=name)
            continue
        result[match.group(1)] = child
    return result


def _discover_audit_task_ids(root: Path) -> set[str]:
    """Best-effort name discovery; authoritative scan happens after locks."""
    task_ids: set[str] = set()
    for top in STATES:
        try:
            names = os.listdir(_safe_path(root, top))
        except (OSError, QueueError):
            continue
        for name in names:
            match = CARD_FILE_RE.fullmatch(name)
            if match and match.group(1) not in WINDOWS_RESERVED:
                task_ids.add(match.group(1))
    for top in ("events", "attempts"):
        try:
            names = os.listdir(_safe_path(root, top))
        except (OSError, QueueError):
            continue
        for name in names:
            if TASK_ID_RE.fullmatch(name) and name not in WINDOWS_RESERVED:
                task_ids.add(name)
    try:
        names = os.listdir(_safe_path(root, EXACT_PROTOCOL_DIR))
    except (OSError, QueueError):
        names = []
    for name in names:
        match = CARD_FILE_RE.fullmatch(name)
        if match and match.group(1) not in WINDOWS_RESERVED:
            task_ids.add(match.group(1))
    return task_ids


def _audit_load_events(events_dir: Path | None, task_id: str, gap):
    """Load + strictly validate the per-task chain; None means gap emitted."""
    if events_dir is None:
        return []
    names = sorted(os.listdir(events_dir))
    if len(names) > AUDIT_EVENT_CAP:
        gap(task_id, "event_chain_too_long", count=len(names))
        return None
    events = []
    for index, name in enumerate(names):
        expected_seq = index + 1
        match = EVENT_FILE_RE.fullmatch(name)
        if not match:
            gap(task_id, "unexpected_entry", where="events", entry=name)
            return None
        if int(match.group(1)) != expected_seq:
            gap(
                task_id, "broken_seq",
                expected=expected_seq, found=int(match.group(1)),
            )
            return None
        path = events_dir / name
        try:
            probe = os.lstat(path)
        except OSError:
            gap(task_id, "malformed_event", seq=expected_seq)
            return None
        if (
            stat_module.S_ISLNK(probe.st_mode)
            or getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG
            or not stat_module.S_ISREG(probe.st_mode)
        ):
            gap(task_id, "malformed_event", seq=expected_seq)
            return None
        try:
            event = _read_json(path)
        except Exception:
            gap(task_id, "malformed_event", seq=expected_seq)
            return None
        error = _event_error(event, task_id, expected_seq)
        if error == "from-to":
            gap(task_id, "from_to_mismatch", seq=expected_seq)
            return None
        if error is not None:
            gap(task_id, "malformed_event", seq=expected_seq, detail=error)
            return None
        events.append(event)
    return events


def _cmd_audit_locked(root: Path, locked_ids: set[str]) -> tuple[int, dict]:
    """Semantic replay: events are the claimed history; the state dirs,
    card attempt, and attempt dirs are independently compared against the
    replayed truth. Any divergence is AUDIT_GAP / exit 3, NEVER repaired."""
    gaps: list[dict] = []

    def gap(task_id, kind, **extra):
        entry = {"task_id": task_id, "gap": "AUDIT_GAP", "kind": kind}
        entry.update(extra)
        gaps.append(entry)

    seen = _audit_scan_states(root, gap)
    event_dirs = _audit_scan_children(root, "events", gap)
    attempt_trees = _audit_scan_children(root, "attempts", gap)
    protocol_markers = _audit_scan_exact_markers(root, gap)
    seen = {key: value for key, value in seen.items() if key in locked_ids}
    event_dirs = {
        key: value for key, value in event_dirs.items() if key in locked_ids
    }
    attempt_trees = {
        key: value for key, value in attempt_trees.items() if key in locked_ids
    }
    protocol_markers = {
        key: value for key, value in protocol_markers.items()
        if key in locked_ids
    }
    for task_id in sorted(event_dirs):
        if task_id not in seen:
            gap(task_id, "orphan_events")
    for task_id in sorted(attempt_trees):
        if task_id not in seen:
            gap(task_id, "orphan_attempts")
    for task_id in sorted(protocol_markers):
        if task_id not in seen:
            gap(task_id, "orphan_exact_protocol")

    for task_id, states in sorted(seen.items()):
        task_gap_start = len(gaps)
        if len(states) > 1:
            gap(task_id, "duplicate_states", states=states)
            continue
        state = states[0]
        card = None
        card_error = None
        try:
            card = _normalize_card(
                _read_json(_safe_path(root, state, f"{task_id}.json"))
            )
            if card["task_id"] != task_id:
                raise QueueError("card-task-id-mismatch")
        except (QueueError, ValueError, UnicodeDecodeError) as exc:
            card_error = str(exc)

        protocol_marker = None
        protocol_boundary_valid = True
        if task_id in protocol_markers:
            try:
                protocol_marker = _load_exact_protocol_marker(root, task_id)
            except QueueError:
                gap(task_id, "malformed_exact_protocol")
            if protocol_marker is not None and card is not None:
                card_digest = card_authority_digest(card)
                if protocol_marker["authority_digest"] != card_digest:
                    gap(
                        task_id, "exact_protocol_conflict",
                        marker_digest=protocol_marker["authority_digest"],
                        card_digest=card_digest,
                    )

        events = _audit_load_events(event_dirs.get(task_id), task_id, gap)
        if events is None:
            continue

        if protocol_marker is not None:
            prior_event_seq = protocol_marker["prior_event_seq"]
            if prior_event_seq > len(events):
                gap(
                    task_id, "exact_protocol_inconsistency",
                    detail="prior-event-seq-exceeds-history",
                    prior_event_seq=prior_event_seq,
                    event_count=len(events),
                )
                protocol_boundary_valid = False
            if prior_event_seq == 0 and (
                protocol_marker["first_exact_attempt"] != 1
            ):
                gap(
                    task_id, "exact_protocol_inconsistency",
                    detail="empty-prefix-first-attempt",
                    first_exact_attempt=(
                        protocol_marker["first_exact_attempt"]
                    ),
                )
                protocol_boundary_valid = False
            if (
                card is not None
                and protocol_marker["first_exact_attempt"]
                > card["max_attempts"]
            ):
                gap(
                    task_id, "exact_protocol_conflict",
                    detail="first-exact-attempt-exceeds-max",
                    first_exact_attempt=(
                        protocol_marker["first_exact_attempt"]
                    ),
                    max_attempts=card["max_attempts"],
                )
                protocol_boundary_valid = False

        # attempt/max_attempts is intentionally not a card-schema relation:
        # old/crash-corrupted durable history must remain readable so audit
        # can diagnose it precisely instead of collapsing it to
        # ``malformed_card``. Equality is valid in terminal/blocked states,
        # but an exhausted card in queue would permit a forbidden next claim.
        if card is not None:
            if card["attempt"] > card["max_attempts"]:
                gap(
                    task_id, "attempt_budget_violation",
                    detail="card-attempt-exceeds-max",
                    attempt=card["attempt"],
                    max_attempts=card["max_attempts"],
                )
            if state == "queue" and card["attempt"] >= card["max_attempts"]:
                gap(
                    task_id, "attempt_budget_violation",
                    detail="exhausted-card-in-queue",
                    attempt=card["attempt"],
                    max_attempts=card["max_attempts"],
                )

        replay_state = "queue"
        replay_attempt = 0
        claims = 0
        exact_owner = None
        exact_authority = None
        exact_started = False
        exact_preclaim_quarantine = None
        quarantined_attempt_dirs: set[str] = set()
        prev_event = None
        broken = False
        for event in events:
            transition = event["transition"]
            has_exact_evidence = EXACT_EVENT_KEYS <= set(event)
            after_exact_boundary = (
                protocol_marker is not None
                and event["seq"] > protocol_marker["prior_event_seq"]
            )
            if event["from_state"] != replay_state:
                gap(
                    task_id, "illegal_transition", seq=event["seq"],
                    expected_from=replay_state,
                    event_from=event["from_state"],
                )
                broken = True
                break
            if transition == "claim":
                if event["attempt"] != replay_attempt + 1:
                    gap(
                        task_id, "attempt_mismatch", seq=event["seq"],
                        expected=replay_attempt + 1, found=event["attempt"],
                    )
                    broken = True
                    break
                replay_attempt += 1
                claims += 1
                if protocol_marker is None:
                    if has_exact_evidence:
                        gap(
                            task_id, "exact_protocol_missing",
                            seq=event["seq"],
                        )
                else:
                    exact_required = (
                        after_exact_boundary
                        and replay_attempt
                        >= protocol_marker["first_exact_attempt"]
                    )
                    if has_exact_evidence != exact_required:
                        gap(
                            task_id, "exact_protocol_inconsistency",
                            seq=event["seq"],
                        )
                if has_exact_evidence:
                    exact_owner = event["worker"]
                    exact_authority = event["authority_digest"]
                if (
                    card is not None
                    and replay_attempt > card["max_attempts"]
                ):
                    gap(
                        task_id, "attempt_budget_violation",
                        detail="claim-exceeds-max", seq=event["seq"],
                        attempt=replay_attempt,
                        max_attempts=card["max_attempts"],
                    )
            elif transition == "block-malformed":
                # The card was unreadable when quarantined, so its attempt
                # could not be known; the recorded 0 is not replay-checked.
                pass
            elif event["attempt"] != replay_attempt:
                gap(
                    task_id, "attempt_mismatch", seq=event["seq"],
                    expected=replay_attempt, found=event["attempt"],
                )
                broken = True
                break
            if transition in EXACT_PRECLAIM_QUARANTINE_TRANSITIONS:
                exact_required = (
                    protocol_marker is not None
                    and after_exact_boundary
                    and replay_attempt + 1
                    >= protocol_marker["first_exact_attempt"]
                )
                if has_exact_evidence != exact_required:
                    gap(
                        task_id, "exact_protocol_inconsistency",
                        seq=event["seq"],
                    )
                if has_exact_evidence:
                    if protocol_marker is None:
                        gap(
                            task_id, "exact_protocol_missing",
                            seq=event["seq"],
                        )
                    exact_preclaim_quarantine = event
                    if transition == "block-attempt-dir":
                        quarantined_attempt_dirs.add(event["attempt_dir"])
            if transition == "requeue-exact":
                if not has_exact_evidence:
                    gap(
                        task_id, "exact_transition_inconsistency",
                        seq=event["seq"],
                        detail="requeue-exact-missing-evidence",
                    )
                # Owner continuity binds the requeue to the immediately
                # preceding exact blocked tail; an immutable attempt-dir
                # collision quarantine is never a repairable predecessor.
                if (
                    prev_event is not None
                    and prev_event["transition"] == "block-attempt-dir"
                ):
                    gap(
                        task_id, "exact_transition_inconsistency",
                        seq=event["seq"],
                        detail="requeue-exact-after-attempt-dir-quarantine",
                    )
                elif (
                    prev_event is None
                    or not (EXACT_EVENT_KEYS <= set(prev_event))
                    or prev_event["transition"]
                    not in ("block", "block-payload")
                ):
                    gap(
                        task_id, "exact_transition_inconsistency",
                        seq=event["seq"],
                        detail="requeue-exact-invalid-predecessor",
                    )
                elif event["worker"] != prev_event["worker"]:
                    gap(
                        task_id, "exact_transition_inconsistency",
                        seq=event["seq"],
                        detail="requeue-exact-worker-mismatch",
                    )
            if (
                transition in ("requeue-blocked", "requeue-failed")
                and exact_started
            ):
                gap(
                    task_id, "exact_transition_inconsistency",
                    seq=event["seq"], detail="legacy-requeue-after-exact",
                )
            if card is not None and transition in ("fail-retry", "fail-final"):
                retryable = event["attempt"] < card["max_attempts"]
                if (transition == "fail-retry") != retryable:
                    gap(
                        task_id, "illegal_transition", seq=event["seq"],
                        detail="fail-policy",
                    )
                    broken = True
                    break
            if has_exact_evidence:
                if (
                    protocol_marker is None
                    and transition != "claim"
                    and transition
                    not in EXACT_PRECLAIM_QUARANTINE_TRANSITIONS
                ):
                    gap(
                        task_id, "exact_protocol_missing",
                        seq=event["seq"],
                    )
                elif not after_exact_boundary:
                    gap(
                        task_id, "exact_protocol_inconsistency",
                        seq=event["seq"],
                        detail="exact-metadata-before-boundary",
                    )
                if (
                    card is not None
                    and event["authority_digest"] != card_authority_digest(card)
                ):
                    gap(
                        task_id, "card_authority_mismatch", seq=event["seq"],
                        event_digest=event["authority_digest"],
                        card_digest=card_authority_digest(card),
                    )
                exact_started = True
            if transition in ("complete", "fail-retry", "fail-final", "block"):
                if exact_owner is not None and (
                    not has_exact_evidence
                    or event["worker"] != exact_owner
                    or event["authority_digest"] != exact_authority
                ):
                    gap(
                        task_id, "exact_transition_inconsistency",
                        seq=event["seq"],
                    )
                elif has_exact_evidence and exact_owner is None:
                    gap(
                        task_id, "exact_transition_inconsistency",
                        seq=event["seq"],
                    )
            if (
                card is not None
                and transition
                in ("requeue-blocked", "requeue-failed", "requeue-exact")
                and replay_attempt >= card["max_attempts"]
            ):
                gap(
                    task_id, "attempt_budget_violation",
                    detail="exhausted-requeue", seq=event["seq"],
                    attempt=replay_attempt,
                    max_attempts=card["max_attempts"],
                )
            replay_state = event["to_state"]
            if (
                protocol_marker is not None
                and event["seq"] == protocol_marker["prior_event_seq"]
                and (
                    replay_state != "queue"
                    or replay_attempt
                    != protocol_marker["first_exact_attempt"] - 1
                )
            ):
                gap(
                    task_id, "exact_protocol_inconsistency",
                    seq=event["seq"],
                    detail="invalid-prior-prefix-state",
                    replay_state=replay_state,
                    replay_attempt=replay_attempt,
                )
                protocol_boundary_valid = False
            if transition in ("complete", "fail-retry", "fail-final", "block"):
                exact_owner = None
                exact_authority = None
            prev_event = event
        if broken:
            continue

        if protocol_marker is not None and protocol_boundary_valid:
            before_first = protocol_marker["first_exact_attempt"] - 1
            exact_quarantined = (
                state == "blocked"
                and bool(events)
                and exact_preclaim_quarantine is events[-1]
            )
            if (
                replay_attempt < before_first
                or (
                    replay_attempt == before_first
                    and state != "queue"
                    and not exact_quarantined
                )
            ):
                gap(task_id, "exact_protocol_inconsistency")

        if card_error is not None:
            quarantined = (
                state == "blocked"
                and bool(events)
                and events[-1]["transition"] == "block-malformed"
            )
            if not quarantined:
                gap(task_id, "malformed_card", detail=card_error)
        if replay_state != state:
            gap(
                task_id, "state_mismatch", state=state, replayed=replay_state,
            )
        if card is not None:
            if not events and card["attempt"] != 0:
                gap(
                    task_id, "attempt_without_events",
                    card_attempt=card["attempt"],
                )
            if card["attempt"] != replay_attempt:
                gap(
                    task_id, "card_attempt_mismatch",
                    card_attempt=card["attempt"], replayed=replay_attempt,
                )

        expected_dirs = {f"a{i}" for i in range(1, claims + 1)}
        expected_dirs.update(quarantined_attempt_dirs)
        actual_dirs: set[str] = set()
        tree = attempt_trees.get(task_id)
        junk = False
        if tree is not None:
            for name in sorted(os.listdir(tree)):
                try:
                    probe = os.lstat(tree / name)
                except OSError:
                    probe = None
                if (
                    probe is None
                    or not ATTEMPT_DIR_RE.fullmatch(name)
                    or stat_module.S_ISLNK(probe.st_mode)
                    or getattr(probe, "st_file_attributes", 0) & REPARSE_FLAG
                    or not stat_module.S_ISDIR(probe.st_mode)
                ):
                    gap(task_id, "unexpected_entry", where="attempts", entry=name)
                    junk = True
                    break
                actual_dirs.add(name)
        if junk:
            continue
        missing = sorted(expected_dirs - actual_dirs)
        extra = sorted(actual_dirs - expected_dirs)
        if missing:
            gap(task_id, "missing_attempt_dir", dirs=missing)
        if extra:
            gap(task_id, "extra_attempt_dir", dirs=extra)

        # A queued card with an unreadable/drifted payload is structurally
        # self-consistent but cannot be claimed: peek and every claim path
        # quite correctly refuse to execute an unverified payload.  Keep
        # audit non-clean for BOTH marker-governed and still marker-free
        # queued cards and expose only the durable authority digest (the
        # immutable marker when present, otherwise the validated queue card
        # written at enqueue) plus the next generation needed by the targeted
        # quarantine command.  Do not label corrupt history as repairable.
        if (
            len(gaps) == task_gap_start
            and state == "queue"
            and card is not None
            and (
                protocol_marker is None
                or protocol_marker["authority_digest"]
                == card_authority_digest(card)
            )
        ):
            try:
                _verify_payload(card)
            except QueueError as drift:
                gap(
                    task_id,
                    "exact_payload_unavailable",
                    detail=str(drift),
                    authority_digest=(
                        protocol_marker["authority_digest"]
                        if protocol_marker is not None
                        else card_authority_digest(card)
                    ),
                    next_attempt=card["attempt"] + 1,
                )

    if gaps:
        return EXIT_AUDIT_OR_IO, {
            "ok": False, "audit": "AUDIT_GAP", "tasks": len(seen),
            "gaps": gaps,
        }
    return EXIT_OK, {"ok": True, "audit": "clean", "tasks": len(seen), "gaps": []}


def cmd_audit(root_arg: str) -> tuple[int, dict]:
    """Serialize with all tasks in one stable discovery snapshot."""
    root = _resolve_root(root_arg)
    for _ in range(8):
        task_ids = _discover_audit_task_ids(root)
        with contextlib.ExitStack() as stack:
            for task_id in sorted(task_ids):
                stack.enter_context(_task_lock(root, task_id))
            # A task first seen after the initial discovery belongs to a later
            # snapshot. Retry so the locked snapshot never mixes it with the
            # move-before-event window of an already discovered task.
            if not _discover_audit_task_ids(root).issubset(task_ids):
                continue
            return _cmd_audit_locked(root, task_ids)
    raise FatalIOError("audit-lock-convergence")


# --------------------------------------------------------------------- CLI


class _Parser(argparse.ArgumentParser):
    """argparse that fails closed: JSON on stdout + exit 2, never usage."""

    def error(self, message):
        raise QueueError("invalid-arguments")


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="python -m autonomy.queue_cli", add_help=False)
    parser.add_argument("--root", required=True)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", add_help=False)
    enqueue = commands.add_parser("enqueue", add_help=False)
    enqueue.add_argument("--card", required=True)
    claim = commands.add_parser("claim", add_help=False)
    claim.add_argument("--profile", required=True)
    claim.add_argument("--model", required=True)
    claim.add_argument("--worker", required=True)
    peek_exact = commands.add_parser("peek-exact", add_help=False)
    peek_exact.add_argument("--task-id", required=True)
    commands.add_parser("list-exact", add_help=False)
    claim_exact = commands.add_parser("claim-exact", add_help=False)
    claim_exact.add_argument("--task-id", required=True)
    claim_exact.add_argument("--expected-next-attempt", required=True, type=int)
    claim_exact.add_argument("--expected-digest", required=True)
    claim_exact.add_argument("--profile", required=True)
    claim_exact.add_argument("--model", required=True)
    claim_exact.add_argument("--worker", required=True)
    quarantine_exact_payload = commands.add_parser(
        "quarantine-exact-payload", add_help=False
    )
    quarantine_exact_payload.add_argument("--task-id", required=True)
    quarantine_exact_payload.add_argument("--worker", required=True)
    for name in ("complete", "requeue"):
        sub = commands.add_parser(name, add_help=False)
        sub.add_argument("--task-id", required=True)
        sub.add_argument("--worker", required=True)
    fail = commands.add_parser("fail", add_help=False)
    fail.add_argument("--task-id", required=True)
    fail.add_argument("--worker", required=True)
    fail.add_argument("--reason", default="")
    block = commands.add_parser("block", add_help=False)
    block.add_argument("--task-id", required=True)
    block.add_argument("--worker", required=True)
    block.add_argument("--reason", required=True)
    for name in ("complete-exact", "block-exact"):
        sub = commands.add_parser(name, add_help=False)
        sub.add_argument("--task-id", required=True)
        sub.add_argument("--expected-attempt", required=True, type=int)
        sub.add_argument("--expected-digest", required=True)
        sub.add_argument("--worker", required=True)
        if name == "block-exact":
            sub.add_argument("--reason", required=True)
    fail_exact = commands.add_parser("fail-exact", add_help=False)
    fail_exact.add_argument("--task-id", required=True)
    fail_exact.add_argument("--expected-attempt", required=True, type=int)
    fail_exact.add_argument("--expected-digest", required=True)
    fail_exact.add_argument("--worker", required=True)
    fail_exact.add_argument("--disposition", required=True)
    fail_exact.add_argument("--reason", default="")
    requeue_exact = commands.add_parser("requeue-exact", add_help=False)
    requeue_exact.add_argument("--task-id", required=True)
    requeue_exact.add_argument("--expected-attempt", required=True, type=int)
    requeue_exact.add_argument("--expected-digest", required=True)
    requeue_exact.add_argument("--worker", required=True)
    commands.add_parser("audit", add_help=False)
    return parser


def _dispatch(args: argparse.Namespace) -> tuple[int, dict]:
    if args.command == "init":
        return cmd_init(args.root)
    if args.command == "enqueue":
        return cmd_enqueue(args.root, args.card)
    if args.command == "claim":
        return cmd_claim(args.root, args.profile, args.model, args.worker)
    if args.command == "peek-exact":
        return cmd_peek_exact(args.root, args.task_id)
    if args.command == "list-exact":
        return cmd_list_exact(args.root)
    if args.command == "claim-exact":
        return cmd_claim_exact(
            args.root, args.task_id, args.expected_next_attempt,
            args.expected_digest, args.profile, args.model, args.worker,
        )
    if args.command == "quarantine-exact-payload":
        return cmd_quarantine_exact_payload(
            args.root, args.task_id, args.worker
        )
    if args.command == "complete":
        return cmd_complete(args.root, args.task_id, args.worker)
    if args.command == "fail":
        return cmd_fail(args.root, args.task_id, args.worker, args.reason)
    if args.command == "block":
        return cmd_block(args.root, args.task_id, args.worker, args.reason)
    if args.command == "complete-exact":
        return cmd_complete_exact(
            args.root, args.task_id, args.expected_attempt,
            args.expected_digest, args.worker,
        )
    if args.command == "fail-exact":
        return cmd_fail_exact(
            args.root, args.task_id, args.expected_attempt,
            args.expected_digest, args.worker, args.disposition, args.reason,
        )
    if args.command == "block-exact":
        return cmd_block_exact(
            args.root, args.task_id, args.expected_attempt,
            args.expected_digest, args.worker, args.reason,
        )
    if args.command == "requeue":
        return cmd_requeue(args.root, args.task_id, args.worker)
    if args.command == "requeue-exact":
        return cmd_requeue_exact(
            args.root, args.task_id, args.expected_attempt,
            args.expected_digest, args.worker,
        )
    if args.command == "audit":
        return cmd_audit(args.root)
    raise QueueError("unknown-command")


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build_parser().parse_args(argv)
        code, payload = _dispatch(args)
    except QueueError as exc:
        code, payload = EXIT_VALIDATION, {"ok": False, "error": str(exc)}
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Defensive boundary: _read_json translates these already, but no
        # malformed input path may ever escape as a traceback on stderr.
        code, payload = EXIT_VALIDATION, {
            "ok": False, "error": "malformed-json",
        }
    except FatalIOError as exc:
        code, payload = EXIT_AUDIT_OR_IO, {"ok": False, "error": str(exc)}
    except OSError as exc:
        code, payload = EXIT_AUDIT_OR_IO, {
            "ok": False, "error": "io-failure", "detail": type(exc).__name__,
        }
    print(json.dumps(payload, ensure_ascii=True, allow_nan=False, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
