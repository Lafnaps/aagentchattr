"""Fail-closed filesystem control primitives for the autonomy supervisor.

This module is deliberately independent from the live agentchattr service.  It
provides four small building blocks used by a future runner/supervisor:

* immutable, idempotent attempt markers published without overwriting;
* mutable, atomically replaced attempt status markers;
* a root-level immutable ``HALT`` marker;
* permanent, non-blocking Windows byte-range locks.

Every JSON document is canonical ASCII JSON with a closed schema.  Attempt
documents are bound to ``version``, ``task_id``, ``attempt`` and ``nonce``.
Paths are accepted only inside the queue root identified by
``autonomy-root.json``; lexical and resolved containment must agree and no
symlink, junction, or other reparse point is allowed in the protected path.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "SCHEMA_VERSION",
    "ROOT_MARKER",
    "ROOT_MARKER_NAME",
    "ROOT_MARKER_MAX_BYTES",
    "HALT_FILENAME",
    "SUPERVISOR_LOCK_FILENAME",
    "RUNNER_LOCK_FILENAME",
    "MAX_DOCUMENT_BYTES",
    "ControlStateError",
    "SchemaError",
    "PathSecurityError",
    "MarkerConflictError",
    "MissingMarkerError",
    "LockUnavailableError",
    "LockIntegrityError",
    "UnsupportedPlatformError",
    "MarkerPublication",
    "PermanentFileLock",
    "canonical_json_bytes",
    "create_once_marker",
    "read_once_marker",
    "write_mutable_marker",
    "read_mutable_marker",
    "create_halt",
    "read_halt",
    "halt_exists",
    "parse_halt_document",
    "acquire_permanent_lock",
]

SCHEMA_VERSION = 1
ROOT_MARKER = "autonomy-root.json"
ROOT_MARKER_NAME = "agentchattr-autonomy-queue"
ROOT_MARKER_MAX_BYTES = 1024
HALT_FILENAME = "HALT"
SUPERVISOR_LOCK_FILENAME = "supervisor.lock"
RUNNER_LOCK_FILENAME = "runner.lock"
MAX_DOCUMENT_BYTES = 2048
MAX_ATTEMPT = 1_000_000
MAX_GENERATION = 2**63 - 1

_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_FILENAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}\.json$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

_ONCE_KEYS = frozenset(
    {"version", "kind", "task_id", "attempt", "nonce", "created_utc"}
)
_MUTABLE_KEYS = frozenset(
    {
        "version",
        "kind",
        "task_id",
        "attempt",
        "nonce",
        "generation",
        "updated_utc",
    }
)
_HALT_KEYS = _ONCE_KEYS
_ROOT_MARKER_KEYS = frozenset({"version", "name"})
_ROOT_MARKER_CANONICAL_BYTES = b'{"name":"agentchattr-autonomy-queue","version":1}\n'
_LOCK_FILENAMES = frozenset({SUPERVISOR_LOCK_FILENAME, RUNNER_LOCK_FILENAME})


class ControlStateError(Exception):
    """Base class for every fail-closed refusal in this module."""


class SchemaError(ControlStateError):
    """A JSON document or a caller-supplied field violates its closed schema."""


class PathSecurityError(ControlStateError):
    """A protected path is ambiguous, escaping, linked, or not a regular file."""


class MarkerConflictError(ControlStateError):
    """An immutable marker already exists with different canonical bytes."""


class MissingMarkerError(ControlStateError):
    """A requested marker does not exist."""


class LockUnavailableError(ControlStateError):
    """Another process or handle already owns the requested permanent lock.

    This type is reserved for exact kernel lock contention.  Every other lock
    failure (corrupt residue, identity drift, unknown I/O or security errors)
    uses :class:`LockIntegrityError` so contention is never guessed.
    """


class LockIntegrityError(ControlStateError):
    """A permanent lock file is corrupt, swapped, unsafe, or failed unknowably."""


class UnsupportedPlatformError(ControlStateError):
    """The requested OS-specific primitive is not available on this host."""


@dataclass(frozen=True)
class MarkerPublication:
    """Result of an idempotent immutable publication."""

    path: Path
    created: bool


def _reject_constant(value: str) -> None:
    raise SchemaError(f"non-finite JSON number is forbidden: {value}")


def _pairs_to_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def canonical_json_bytes(document: Mapping[str, Any]) -> bytes:
    """Return the only accepted on-disk encoding for a JSON object."""

    if not isinstance(document, Mapping):
        raise SchemaError("control document must be a JSON object")
    try:
        text = json.dumps(
            dict(document),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"control document is not strict JSON: {exc}") from exc
    encoded = text.encode("ascii") + b"\n"
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise SchemaError(
            f"control document exceeds {MAX_DOCUMENT_BYTES} bytes: {len(encoded)}"
        )
    return encoded


def _strict_load(raw: bytes) -> dict[str, Any]:
    if not raw:
        raise SchemaError("empty control document")
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise SchemaError(
            f"control document exceeds {MAX_DOCUMENT_BYTES} bytes: {len(raw)}"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SchemaError("control document is not valid UTF-8") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_pairs_to_object,
            parse_constant=_reject_constant,
        )
    except SchemaError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise SchemaError(f"invalid control JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SchemaError("control document must be a JSON object")
    if canonical_json_bytes(document) != raw:
        raise SchemaError("control document is not in canonical byte representation")
    return document


def _validate_task_id(value: Any) -> str:
    if not isinstance(value, str) or not _TASK_ID_RE.fullmatch(value):
        raise SchemaError(f"invalid task_id: {value!r}")
    if value.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
        raise SchemaError(f"reserved Windows task_id: {value!r}")
    return value


def _validate_attempt(value: Any, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaError(f"attempt must be an integer: {value!r}")
    if not minimum <= value <= MAX_ATTEMPT:
        raise SchemaError(f"attempt out of range {minimum}..{MAX_ATTEMPT}: {value!r}")
    return value


def _validate_nonce(value: Any) -> str:
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise SchemaError("nonce must be exactly 32 lowercase hexadecimal characters")
    return value


def _validate_kind(value: Any) -> str:
    if not isinstance(value, str) or not _KIND_RE.fullmatch(value):
        raise SchemaError(f"invalid marker kind: {value!r}")
    return value


def _validate_filename(value: Any) -> str:
    if not isinstance(value, str) or not _FILENAME_RE.fullmatch(value):
        raise SchemaError(f"invalid attempt marker filename: {value!r}")
    return value


def _validate_utc(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise SchemaError(f"{field} must use yyyy-MM-ddTHH:mm:ss.fffZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise SchemaError(f"{field} is not a valid UTC timestamp: {value!r}") from exc
    if parsed.utcoffset() != timedelta(0):  # Defensive; replace() above is always UTC.
        raise SchemaError(f"{field} must be UTC")
    return value


def _utc_now() -> str:
    moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _validate_exact_keys(document: Mapping[str, Any], expected: frozenset[str]) -> None:
    actual = frozenset(document)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise SchemaError(f"closed schema mismatch; missing={missing}, extra={extra}")


def _validate_once(document: Mapping[str, Any]) -> None:
    _validate_exact_keys(document, _ONCE_KEYS)
    if type(document["version"]) is not int or document["version"] != SCHEMA_VERSION:
        raise SchemaError(f"version must be integer {SCHEMA_VERSION}")
    _validate_kind(document["kind"])
    _validate_task_id(document["task_id"])
    _validate_attempt(document["attempt"])
    _validate_nonce(document["nonce"])
    _validate_utc(document["created_utc"], "created_utc")


def _validate_mutable(document: Mapping[str, Any]) -> None:
    _validate_exact_keys(document, _MUTABLE_KEYS)
    if type(document["version"]) is not int or document["version"] != SCHEMA_VERSION:
        raise SchemaError(f"version must be integer {SCHEMA_VERSION}")
    _validate_kind(document["kind"])
    _validate_task_id(document["task_id"])
    _validate_attempt(document["attempt"])
    _validate_nonce(document["nonce"])
    generation = document["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise SchemaError(f"generation must be an integer: {generation!r}")
    if not 0 <= generation <= MAX_GENERATION:
        raise SchemaError(f"generation out of range: {generation!r}")
    _validate_utc(document["updated_utc"], "updated_utc")


def _validate_halt(document: Mapping[str, Any]) -> None:
    _validate_exact_keys(document, _HALT_KEYS)
    if type(document["version"]) is not int or document["version"] != SCHEMA_VERSION:
        raise SchemaError(f"version must be integer {SCHEMA_VERSION}")
    if document["kind"] != "halt":
        raise SchemaError("HALT kind must be 'halt'")
    if document["task_id"] != "root":
        raise SchemaError("HALT task_id must be 'root'")
    _validate_attempt(document["attempt"], allow_zero=True)
    if document["attempt"] != 0:
        raise SchemaError("HALT attempt must be 0")
    _validate_nonce(document["nonce"])
    _validate_utc(document["created_utc"], "created_utc")


def _is_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_FLAG)


def _reject_reparse(path: Path) -> None:
    if _is_reparse(path):
        raise PathSecurityError(f"symlink/junction/reparse point is forbidden: {path}")


def _norm(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _real_norm(path: Path) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _contained(child: str, parent: str, *, strict: bool) -> bool:
    try:
        common = os.path.commonpath([child, parent])
    except ValueError:
        return False
    if common != parent:
        return False
    return not strict or child != parent


def _require_regular(path: Path) -> None:
    _reject_reparse(path)
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        raise
    if not stat.S_ISREG(mode):
        raise PathSecurityError(f"expected a regular file: {path}")


def _resolve_queue_root(queue_root: os.PathLike[str] | str) -> Path:
    if not isinstance(queue_root, (str, os.PathLike)):
        raise PathSecurityError(f"queue root must be a path: {queue_root!r}")
    raw = Path(queue_root)
    if not raw.is_absolute():
        raise PathSecurityError(f"queue root must be absolute: {raw}")
    literal = Path(os.path.abspath(raw))
    if not literal.is_dir():
        raise PathSecurityError(f"queue root is not a directory: {literal}")
    _reject_reparse(literal)
    if _norm(literal) != _real_norm(literal):
        raise PathSecurityError(f"queue root traverses a reparse point: {literal}")
    marker = literal / ROOT_MARKER
    try:
        _require_regular(marker)
    except FileNotFoundError as exc:
        raise PathSecurityError(f"queue root has no {ROOT_MARKER}: {literal}") from exc
    _authenticate_root_marker(marker)
    return literal


def _authenticate_root_marker(marker: Path) -> None:
    """Accept only the exact canonical queue root marker document."""

    try:
        with marker.open("rb") as stream:
            raw = stream.read(ROOT_MARKER_MAX_BYTES + 1)
    except OSError as exc:
        raise PathSecurityError(f"queue root marker is unreadable: {marker}") from exc
    if len(raw) > ROOT_MARKER_MAX_BYTES:
        raise PathSecurityError(
            f"queue root marker exceeds {ROOT_MARKER_MAX_BYTES} bytes: {marker}"
        )
    try:
        document = _strict_load(raw)
    except SchemaError as exc:
        raise PathSecurityError(f"queue root marker is not canonical: {marker}") from exc
    if frozenset(document) != _ROOT_MARKER_KEYS:
        raise PathSecurityError(f"queue root marker schema is closed: {marker}")
    version = document["version"]
    if type(version) is not int or version != SCHEMA_VERSION:
        raise PathSecurityError(
            f"queue root marker version must be exactly integer {SCHEMA_VERSION}: {marker}"
        )
    if document["name"] != ROOT_MARKER_NAME:
        raise PathSecurityError(
            f"queue root marker name must be {ROOT_MARKER_NAME!r}: {marker}"
        )
    if raw != _ROOT_MARKER_CANONICAL_BYTES:
        raise PathSecurityError(
            f"queue root marker must equal the exact canonical bytes: {marker}"
        )


def _resolve_attempt_dir(
    queue_root: os.PathLike[str] | str,
    attempt_dir: os.PathLike[str] | str,
    *,
    task_id: str,
    attempt: int,
) -> tuple[Path, Path]:
    root = _resolve_queue_root(queue_root)
    task = _validate_task_id(task_id)
    attempt_number = _validate_attempt(attempt)
    if not isinstance(attempt_dir, (str, os.PathLike)):
        raise PathSecurityError(f"attempt dir must be a path: {attempt_dir!r}")
    supplied = Path(attempt_dir)
    if any(part == ".." for part in supplied.parts):
        raise PathSecurityError(f"attempt dir traversal is forbidden: {supplied}")
    if not supplied.is_absolute():
        supplied = root / supplied
    supplied = Path(os.path.abspath(supplied))
    expected = root / "attempts" / task / f"a{attempt_number}"
    root_literal = _norm(root)
    supplied_literal = _norm(supplied)
    if not _contained(supplied_literal, root_literal, strict=True):
        raise PathSecurityError(f"attempt dir escapes queue root: {supplied}")
    if supplied_literal != _norm(expected):
        raise PathSecurityError(
            f"attempt dir is not bound to task/attempt; expected {expected}, got {supplied}"
        )
    if not supplied.is_dir():
        raise PathSecurityError(f"attempt dir is not a directory: {supplied}")

    cursor = root
    for part in supplied.relative_to(root).parts:
        cursor = cursor / part
        _reject_reparse(cursor)
    real = _real_norm(supplied)
    root_real = _real_norm(root)
    if not _contained(real, root_real, strict=True) or real != supplied_literal:
        raise PathSecurityError(f"attempt dir resolves through/outside a reparse point: {supplied}")
    return root, supplied


def _guard_destination(directory: Path, filename: str) -> Path:
    path = directory / filename
    if path.exists() or _is_reparse(path):
        _require_regular(path)
    return path


def _read_raw(path: Path) -> bytes:
    try:
        _require_regular(path)
        with path.open("rb") as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    except FileNotFoundError as exc:
        raise MissingMarkerError(f"marker does not exist: {path}") from exc
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise SchemaError(f"marker exceeds {MAX_DOCUMENT_BYTES} bytes: {path}")
    return raw


def _write_temp(directory: Path, filename: str, payload: bytes) -> Path:
    fd, raw_path = tempfile.mkstemp(prefix=f".{filename}.", suffix=".tmp", dir=directory)
    path = Path(raw_path)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    return path


def _fsync_directory(directory: Path) -> None:
    """Best-effort directory durability where the host exposes directory fsync."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_once(path: Path, payload: bytes) -> MarkerPublication:
    temp_path = _write_temp(path.parent, path.name, payload)
    try:
        try:
            # Linking a fully fsync'd same-directory temp is atomic and never
            # overwrites an existing name on either Windows or POSIX.
            os.link(temp_path, path)
        except FileExistsError:
            existing = _read_raw(path)
            if existing != payload:
                raise MarkerConflictError(
                    f"immutable marker already exists with different bytes: {path}"
                )
            return MarkerPublication(path, False)
        _fsync_directory(path.parent)
        return MarkerPublication(path, True)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_replace(path: Path, payload: bytes) -> Path:
    temp_path = _write_temp(path.parent, path.name, payload)
    try:
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
        return path
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _require_binding(
    document: Mapping[str, Any], *, kind: str, task_id: str, attempt: int, nonce: str
) -> None:
    expected = {
        "kind": _validate_kind(kind),
        "task_id": _validate_task_id(task_id),
        "attempt": _validate_attempt(attempt),
        "nonce": _validate_nonce(nonce),
    }
    for key, value in expected.items():
        if document[key] != value:
            raise SchemaError(
                f"stored {key} mismatch: expected {value!r}, got {document[key]!r}"
            )


def create_once_marker(
    queue_root: os.PathLike[str] | str,
    attempt_dir: os.PathLike[str] | str,
    filename: str,
    *,
    kind: str,
    task_id: str,
    attempt: int,
    nonce: str,
    created_utc: str | None = None,
) -> MarkerPublication:
    """Publish an immutable attempt marker, or accept an exact prior publish."""

    name = _validate_filename(filename)
    document = {
        "version": SCHEMA_VERSION,
        "kind": _validate_kind(kind),
        "task_id": _validate_task_id(task_id),
        "attempt": _validate_attempt(attempt),
        "nonce": _validate_nonce(nonce),
        "created_utc": _validate_utc(created_utc or _utc_now(), "created_utc"),
    }
    _validate_once(document)
    _root, directory = _resolve_attempt_dir(
        queue_root, attempt_dir, task_id=task_id, attempt=attempt
    )
    path = _guard_destination(directory, name)
    return _publish_once(path, canonical_json_bytes(document))


def read_once_marker(
    queue_root: os.PathLike[str] | str,
    attempt_dir: os.PathLike[str] | str,
    filename: str,
    *,
    kind: str,
    task_id: str,
    attempt: int,
    nonce: str,
) -> dict[str, Any]:
    """Read a canonical immutable marker and verify its complete binding."""

    name = _validate_filename(filename)
    _root, directory = _resolve_attempt_dir(
        queue_root, attempt_dir, task_id=task_id, attempt=attempt
    )
    document = _strict_load(_read_raw(_guard_destination(directory, name)))
    _validate_once(document)
    _require_binding(
        document, kind=kind, task_id=task_id, attempt=attempt, nonce=nonce
    )
    return document


def write_mutable_marker(
    queue_root: os.PathLike[str] | str,
    attempt_dir: os.PathLike[str] | str,
    filename: str,
    *,
    kind: str,
    task_id: str,
    attempt: int,
    nonce: str,
    generation: int,
    updated_utc: str | None = None,
) -> Path:
    """Atomically replace a small heartbeat-like bound control document."""

    name = _validate_filename(filename)
    document = {
        "version": SCHEMA_VERSION,
        "kind": _validate_kind(kind),
        "task_id": _validate_task_id(task_id),
        "attempt": _validate_attempt(attempt),
        "nonce": _validate_nonce(nonce),
        "generation": generation,
        "updated_utc": _validate_utc(updated_utc or _utc_now(), "updated_utc"),
    }
    _validate_mutable(document)
    _root, directory = _resolve_attempt_dir(
        queue_root, attempt_dir, task_id=task_id, attempt=attempt
    )
    path = _guard_destination(directory, name)
    return _atomic_replace(path, canonical_json_bytes(document))


def read_mutable_marker(
    queue_root: os.PathLike[str] | str,
    attempt_dir: os.PathLike[str] | str,
    filename: str,
    *,
    kind: str,
    task_id: str,
    attempt: int,
    nonce: str,
) -> dict[str, Any]:
    name = _validate_filename(filename)
    _root, directory = _resolve_attempt_dir(
        queue_root, attempt_dir, task_id=task_id, attempt=attempt
    )
    document = _strict_load(_read_raw(_guard_destination(directory, name)))
    _validate_mutable(document)
    _require_binding(
        document, kind=kind, task_id=task_id, attempt=attempt, nonce=nonce
    )
    return document


def create_halt(
    queue_root: os.PathLike[str] | str,
    *,
    nonce: str,
    created_utc: str | None = None,
) -> MarkerPublication:
    """Create the immutable root HALT marker, idempotently for exact bytes."""

    root = _resolve_queue_root(queue_root)
    document = {
        "version": SCHEMA_VERSION,
        "kind": "halt",
        "task_id": "root",
        "attempt": 0,
        "nonce": _validate_nonce(nonce),
        "created_utc": _validate_utc(created_utc or _utc_now(), "created_utc"),
    }
    _validate_halt(document)
    path = _guard_destination(root, HALT_FILENAME)
    return _publish_once(path, canonical_json_bytes(document))


def read_halt(
    queue_root: os.PathLike[str] | str, *, nonce: str | None = None
) -> dict[str, Any]:
    root = _resolve_queue_root(queue_root)
    document = _strict_load(_read_raw(_guard_destination(root, HALT_FILENAME)))
    _validate_halt(document)
    if nonce is not None and document["nonce"] != _validate_nonce(nonce):
        raise SchemaError(
            f"stored HALT nonce mismatch: expected {nonce!r}, got {document['nonce']!r}"
        )
    return document


def halt_exists(queue_root: os.PathLike[str] | str) -> bool:
    """Return False only for absence; corruption or unsafe paths fail closed."""

    root = _resolve_queue_root(queue_root)
    path = root / HALT_FILENAME
    if not path.exists() and not _is_reparse(path):
        return False
    read_halt(root)
    return True


def parse_halt_document(raw: bytes) -> dict[str, Any]:
    """Strictly parse already-read HALT bytes against the closed HALT schema.

    This is the byte-level validation seam for callers that must read the
    durable HALT through their own hardened handle (opened-versus-named
    identity pinning) instead of through :func:`read_halt`'s path-based read.
    Every violation raises :class:`SchemaError`.
    """

    document = _strict_load(raw)
    _validate_halt(document)
    return document


# ---------------------------------------------------------------------------
# Private Win32 primitive layer for the permanent lock fence.
#
# The permanent lock protocol below never trusts a pathname after the moment a
# handle is open: every checkpoint revalidates type, reparse status, link
# count, size, exact bytes, kernel-final path, and opened-versus-named file
# identity through raw non-inheritable handles that are retained for the whole
# critical section.  ``CreateFileW`` handles are non-inheritable because no
# ``SECURITY_ATTRIBUTES`` is supplied.

if os.name == "nt":  # pragma: no branch - module must import on POSIX hosts
    import ctypes
    from ctypes import wintypes as _wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _INVALID_HANDLE_VALUE = _wintypes.HANDLE(-1).value

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", _wintypes.DWORD),
            ("OffsetHigh", _wintypes.DWORD),
            ("hEvent", _wintypes.HANDLE),
        ]

    class _FILE_STANDARD_INFO(ctypes.Structure):
        _fields_ = [
            ("AllocationSize", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("NumberOfLinks", _wintypes.DWORD),
            ("DeletePending", ctypes.c_byte),
            ("Directory", ctypes.c_byte),
        ]

    class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", _wintypes.DWORD),
            ("ReparseTag", _wintypes.DWORD),
        ]

    class _FILE_ID_INFO(ctypes.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes.c_ulonglong),
            ("FileId", ctypes.c_byte * 16),
        ]

    class _FILE_DISPOSITION_INFO(ctypes.Structure):
        _fields_ = [("DeleteFileFlag", ctypes.c_byte)]

    _kernel32.CreateFileW.restype = _wintypes.HANDLE
    _kernel32.CreateFileW.argtypes = [
        _wintypes.LPCWSTR,
        _wintypes.DWORD,
        _wintypes.DWORD,
        _wintypes.LPVOID,
        _wintypes.DWORD,
        _wintypes.DWORD,
        _wintypes.HANDLE,
    ]
    _kernel32.CloseHandle.restype = _wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [_wintypes.HANDLE]
    _kernel32.ReadFile.restype = _wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        _wintypes.HANDLE,
        _wintypes.LPVOID,
        _wintypes.DWORD,
        ctypes.POINTER(_wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.WriteFile.restype = _wintypes.BOOL
    _kernel32.WriteFile.argtypes = [
        _wintypes.HANDLE,
        _wintypes.LPCVOID,
        _wintypes.DWORD,
        ctypes.POINTER(_wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.FlushFileBuffers.restype = _wintypes.BOOL
    _kernel32.FlushFileBuffers.argtypes = [_wintypes.HANDLE]
    _kernel32.GetFileInformationByHandleEx.restype = _wintypes.BOOL
    _kernel32.GetFileInformationByHandleEx.argtypes = [
        _wintypes.HANDLE,
        ctypes.c_int,
        _wintypes.LPVOID,
        _wintypes.DWORD,
    ]
    _kernel32.SetFileInformationByHandle.restype = _wintypes.BOOL
    _kernel32.SetFileInformationByHandle.argtypes = [
        _wintypes.HANDLE,
        ctypes.c_int,
        _wintypes.LPVOID,
        _wintypes.DWORD,
    ]
    _kernel32.GetFinalPathNameByHandleW.restype = _wintypes.DWORD
    _kernel32.GetFinalPathNameByHandleW.argtypes = [
        _wintypes.HANDLE,
        _wintypes.LPWSTR,
        _wintypes.DWORD,
        _wintypes.DWORD,
    ]
    _kernel32.LockFileEx.restype = _wintypes.BOOL
    _kernel32.LockFileEx.argtypes = [
        _wintypes.HANDLE,
        _wintypes.DWORD,
        _wintypes.DWORD,
        _wintypes.DWORD,
        _wintypes.DWORD,
        ctypes.POINTER(_OVERLAPPED),
    ]
    _kernel32.UnlockFileEx.restype = _wintypes.BOOL
    _kernel32.UnlockFileEx.argtypes = [
        _wintypes.HANDLE,
        _wintypes.DWORD,
        _wintypes.DWORD,
        _wintypes.DWORD,
        ctypes.POINTER(_OVERLAPPED),
    ]
else:  # pragma: no cover - exercised only outside Windows
    ctypes = None  # type: ignore[assignment]
    _kernel32 = None
    _INVALID_HANDLE_VALUE = -1

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE_ACCESS = 0x00010000
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_LIST_DIRECTORY = 0x0001
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_FILE_SHARE_DELETE = 0x4
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_LOCKFILE_FAIL_IMMEDIATELY = 0x1
_LOCKFILE_EXCLUSIVE_LOCK = 0x2
_FILE_STANDARD_INFO_CLASS = 1
_FILE_RENAME_INFO_CLASS = 3
_FILE_DISPOSITION_INFO_CLASS = 4
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_ID_INFO_CLASS = 18
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_ERROR_SHARING_VIOLATION = 32
_ERROR_LOCK_VIOLATION = 33
_ERROR_FILE_EXISTS = 80
_ERROR_ALREADY_EXISTS = 183
_LOCK_EVIDENCE_OFFSET = 0
_LOCK_OWNERSHIP_OFFSET = 1
_PERMANENT_LOCK_BYTES = b"\0"
_PUBLICATION_LOSS_OPEN_ATTEMPTS = 200
_PUBLICATION_LOSS_OPEN_SLEEP_SECONDS = 0.005


@dataclass(frozen=True)
class _HandleFacts:
    """One consistent kernel snapshot of an open handle's file object."""

    attributes: int
    reparse_tag: int
    identity: tuple[int, bytes]
    link_count: int
    size: int
    delete_pending: bool
    is_directory: bool
    final_path: str


def _win_error(context: str) -> OSError:
    error = ctypes.WinError(ctypes.get_last_error())
    error.strerror = f"{context}: {error.strerror}"
    return error


def _integrity_failure(cause: OSError, message: str) -> LockIntegrityError:
    """Wrap a Win32 failure as fail-closed integrity while keeping its cause."""

    failure = LockIntegrityError(message)
    failure.__cause__ = cause
    return failure


def _finalize_local_handle(
    handle: int, primary: BaseException | None, context: str
) -> None:
    """Single close attempt for a handle still local to one helper.

    ``primary`` is the already-caught helper failure when one exists.  A
    close success simply returns, so the caller's still-active ``except``
    re-raises the same primary object with its original traceback via a bare
    ``raise``.  An ``OSError`` refusal from the kernel close - including
    WinError 33 - is typed as :class:`LockIntegrityError` with the original
    cause; paired with a primary it becomes one ordered
    ``BaseExceptionGroup([primary, typed_close])``.  Any other
    ``BaseException`` from the close is preserved unchanged and ordered after
    the primary when both exist.  Exactly one close attempt is ever made and
    a successful helper result can never be returned past a failed close.
    """

    try:
        _win_close(handle)
    except OSError as exc:
        typed = _integrity_failure(exc, context)
        if primary is not None:
            raise BaseExceptionGroup(
                "helper failure and local handle close both failed",
                [primary, typed],
            )
        raise typed
    except BaseException as exc:
        if primary is not None:
            raise BaseExceptionGroup(
                "helper failure and local handle close both failed",
                [primary, exc],
            )
        raise


def _win_create_file(
    path: os.PathLike[str] | str,
    access: int,
    share: int,
    disposition: int,
    flags: int,
) -> int:
    handle = _kernel32.CreateFileW(
        os.fspath(path), access, share, None, disposition, flags, None
    )
    if handle is None or handle == _INVALID_HANDLE_VALUE:
        raise _win_error(f"CreateFileW failed: {path}")
    return handle


def _win_close(handle: int) -> None:
    """Close ``handle`` and fail closed when the kernel refuses the close."""

    if not _kernel32.CloseHandle(handle):
        raise _win_error("CloseHandle failed")


def _win_read_exact(handle: int, offset: int, length: int) -> bytes:
    overlapped = _OVERLAPPED()
    overlapped.Offset = offset
    buffer = ctypes.create_string_buffer(length)
    transferred = _wintypes.DWORD(0)
    ok = _kernel32.ReadFile(
        handle, buffer, length, ctypes.byref(transferred), ctypes.byref(overlapped)
    )
    if not ok:
        raise _win_error(f"ReadFile failed at offset {offset}")
    if transferred.value != length:
        raise _win_error(f"ReadFile was short at offset {offset}")
    return buffer.raw[: transferred.value]


def _win_write_all(handle: int, payload: bytes, offset: int) -> None:
    overlapped = _OVERLAPPED()
    overlapped.Offset = offset
    transferred = _wintypes.DWORD(0)
    ok = _kernel32.WriteFile(
        handle, payload, len(payload), ctypes.byref(transferred), ctypes.byref(overlapped)
    )
    if not ok or transferred.value != len(payload):
        raise _win_error(f"WriteFile failed at offset {offset}")


def _win_flush(handle: int) -> None:
    if not _kernel32.FlushFileBuffers(handle):
        raise _win_error("FlushFileBuffers failed")


def _win_final_path(handle: int) -> str:
    size = 512
    for _attempt in range(4):
        buffer = ctypes.create_unicode_buffer(size)
        needed = _kernel32.GetFinalPathNameByHandleW(handle, buffer, size, 0)
        if needed == 0:
            raise _win_error("GetFinalPathNameByHandleW failed")
        if needed < size:
            return buffer.value
        size = needed + 2
    raise _win_error("GetFinalPathNameByHandleW did not converge")


def _handle_facts(handle: int) -> _HandleFacts:
    standard = _FILE_STANDARD_INFO()
    if not _kernel32.GetFileInformationByHandleEx(
        handle, _FILE_STANDARD_INFO_CLASS, ctypes.byref(standard), ctypes.sizeof(standard)
    ):
        raise _win_error("FileStandardInfo query failed")
    tag = _FILE_ATTRIBUTE_TAG_INFO()
    if not _kernel32.GetFileInformationByHandleEx(
        handle, _FILE_ATTRIBUTE_TAG_INFO_CLASS, ctypes.byref(tag), ctypes.sizeof(tag)
    ):
        raise _win_error("FileAttributeTagInfo query failed")
    identity = _FILE_ID_INFO()
    if not _kernel32.GetFileInformationByHandleEx(
        handle, _FILE_ID_INFO_CLASS, ctypes.byref(identity), ctypes.sizeof(identity)
    ):
        raise _win_error("FileIdInfo query failed")
    return _HandleFacts(
        attributes=tag.FileAttributes,
        reparse_tag=tag.ReparseTag,
        identity=(identity.VolumeSerialNumber, bytes(identity.FileId)),
        link_count=standard.NumberOfLinks,
        size=standard.EndOfFile,
        delete_pending=bool(standard.DeletePending),
        is_directory=bool(standard.Directory),
        final_path=_win_final_path(handle),
    )


def _probe_facts(path: os.PathLike[str] | str) -> _HandleFacts:
    """Snapshot the current NAME without data access or share interference.

    Attribute-only opens neither perform nor register data share checks, so
    this probe always observes the live name, even while a publisher retains
    an exclusive-by-sharing handle to the same file.  The probe handle is
    transient: it is finalized on success and failure alike, and a snapshot
    is never returned past a failed close.
    """

    handle = _win_create_file(
        path,
        _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
    )
    try:
        facts = _handle_facts(handle)
    except BaseException as primary:
        _finalize_local_handle(
            handle, primary, f"probe handle close failed: {path}"
        )
        raise
    _finalize_local_handle(handle, None, f"probe handle close failed: {path}")
    return facts


_DRIVE_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:\\")
_RENAME_COMPONENT_FORBIDDEN_CHARS = frozenset('<>:"/\\|?*') | frozenset(
    chr(code) for code in range(0x20)
)
_RENAME_RESERVED_DEVICE_BASENAMES = frozenset(
    {"con", "prn", "aux", "nul", "clock$", "conin$", "conout$"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


def _require_clean_rename_components(body: str, original: str) -> None:
    """Reject every unsafe UNC server/share/tail or drive-tail component.

    Beyond empty/`.`/`..`, each component must be free of U+0000..U+001F and
    the reserved punctuation ``< > : " / \\ | ? *``, must not end with a dot
    or space, and must not carry a case-insensitive DOS device basename
    (``CON``, ``PRN``, ``AUX``, ``NUL``, ``CLOCK$``, ``CONIN$``, ``CONOUT$``,
    ``COM1``-``COM9``, ``LPT1``-``LPT9``), including extension forms such as
    ``NUL.txt``.
    """

    for component in body.split("\\"):
        if component in ("", ".", ".."):
            raise PathSecurityError(
                f"rename target has an empty or relative component: {original!r}"
            )
        if any(
            character in _RENAME_COMPONENT_FORBIDDEN_CHARS
            for character in component
        ):
            raise PathSecurityError(
                f"rename target component contains a forbidden character: {original!r}"
            )
        if component[-1] in (".", " "):
            raise PathSecurityError(
                f"rename target component ends with a dot or space: {original!r}"
            )
        basename = component.split(".", 1)[0].rstrip(" ").lower()
        if basename in _RENAME_RESERVED_DEVICE_BASENAMES:
            raise PathSecurityError(
                f"rename target component is a reserved DOS device name: {original!r}"
            )


def _require_unc_rename_body(body: str, original: str) -> None:
    if len(body.split("\\")) < 3:
        raise PathSecurityError(f"malformed UNC rename target: {original!r}")
    _require_clean_rename_components(body, original)


def _require_drive_rename_body(body: str, original: str) -> None:
    if not _DRIVE_ABSOLUTE_RE.match(body):
        raise PathSecurityError(
            f"rename target must be drive-absolute or UNC: {original!r}"
        )
    remainder = body[3:]
    if not remainder:
        raise PathSecurityError(
            f"rename target must name a file under the volume root: {original!r}"
        )
    _require_clean_rename_components(remainder, original)


def _nt_rename_target(target: os.PathLike[str] | str) -> str:
    """Return the absolute NT object-namespace rename target for ``target``.

    Exactly four input families are accepted: drive-absolute
    (``C:\\q\\f`` -> ``\\??\\C:\\q\\f``), classic UNC (``\\\\server\\share\\q\\f``
    -> ``\\??\\UNC\\server\\share\\q\\f``), extended (``\\\\?\\C:\\q\\f`` ->
    ``\\??\\C:\\q\\f``), and extended UNC (``\\\\?\\UNC\\server\\share\\q\\f`` ->
    ``\\??\\UNC\\server\\share\\q\\f``).  Extended UNC is checked before generic
    extended paths.  Relative paths, embedded NUL, forward slashes, ``\\\\.\\``
    device paths, malformed UNC, and already-NT (``\\??\\``) forms are
    rejected, so the produced name is never blind-prefixed or double-prefixed.
    """

    text = os.fspath(target)
    if not isinstance(text, str) or not text:
        raise PathSecurityError(f"rename target must be a non-empty path: {target!r}")
    if "\x00" in text:
        raise PathSecurityError("rename target contains an embedded NUL")
    if "/" in text:
        raise PathSecurityError(
            f"rename target must use backslash separators: {text!r}"
        )
    if text.startswith("\\??\\"):
        raise PathSecurityError(
            f"rename target is already an NT-namespace name: {text!r}"
        )
    if text.startswith("\\\\?\\UNC\\"):
        body = text[len("\\\\?\\UNC\\"):]
        _require_unc_rename_body(body, text)
        return "\\??\\UNC\\" + body
    if text.startswith("\\\\?\\"):
        body = text[len("\\\\?\\"):]
        _require_drive_rename_body(body, text)
        return "\\??\\" + body
    if text.startswith("\\\\.") or text.startswith("\\\\?"):
        raise PathSecurityError(
            f"device or malformed extended rename target: {text!r}"
        )
    if text.startswith("\\\\"):
        body = text[2:]
        _require_unc_rename_body(body, text)
        return "\\??\\UNC\\" + body
    _require_drive_rename_body(text, text)
    return "\\??\\" + text


def _win_rename_no_replace(handle: int, target: os.PathLike[str] | str) -> None:
    """Publish the still-open file object onto ``target`` without overwrite.

    ``SetFileInformationByHandle`` with ``FileRenameInfo`` requires the target
    as an absolute NT object-namespace name when ``RootDirectory`` is NULL;
    :func:`_nt_rename_target` performs that conversion exactly and rejects
    every malformed input instead of blind-prefixing.  ``ReplaceIfExists``
    stays FALSE so the exact kernel collision decides the unique publication
    winner.
    """

    name = _nt_rename_target(target)

    class _FILE_RENAME_INFO(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", ctypes.c_byte),
            ("RootDirectory", _wintypes.HANDLE),
            ("FileNameLength", _wintypes.DWORD),
            ("FileName", ctypes.c_wchar * (len(name) + 1)),
        ]

    info = _FILE_RENAME_INFO()
    info.ReplaceIfExists = 0
    info.RootDirectory = None
    info.FileNameLength = len(name) * 2
    info.FileName = name
    if not _kernel32.SetFileInformationByHandle(
        handle, _FILE_RENAME_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise _win_error(f"FileRenameInfo publication failed: {target}")


def _win_dispose(handle: int) -> None:
    """Delete the file underlying ``handle`` through the handle itself."""

    info = _FILE_DISPOSITION_INFO()
    info.DeleteFileFlag = 1
    if not _kernel32.SetFileInformationByHandle(
        handle, _FILE_DISPOSITION_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise _win_error("FileDispositionInfo delete failed")


def _win_lock_exclusive(handle: int, offset: int) -> None:
    """Nonblocking exclusive LockFileEx over exactly one byte at ``offset``."""

    overlapped = _OVERLAPPED()
    overlapped.Offset = offset
    ok = _kernel32.LockFileEx(
        handle,
        _LOCKFILE_EXCLUSIVE_LOCK | _LOCKFILE_FAIL_IMMEDIATELY,
        0,
        1,
        0,
        ctypes.byref(overlapped),
    )
    if not ok:
        raise _win_error(f"LockFileEx failed at offset {offset}")


def _win_unlock(handle: int, offset: int) -> None:
    overlapped = _OVERLAPPED()
    overlapped.Offset = offset
    if not _kernel32.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped)):
        raise _win_error(f"UnlockFileEx failed at offset {offset}")


def _from_kernel_final_path(final_path: str) -> str:
    """Normalize ``\\\\?\\C:\\...`` and ``\\\\?\\UNC\\...`` to classic forms."""

    if final_path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + final_path[len("\\\\?\\UNC\\"):]
    if final_path.startswith("\\\\?\\"):
        return final_path[len("\\\\?\\"):]
    return final_path


def _expected_child_final(root_final: str, name: str) -> str:
    return root_final.rstrip("\\") + "\\" + name


def _facts_reparse(facts: _HandleFacts) -> bool:
    return bool(facts.attributes & _REPARSE_FLAG) or facts.reparse_tag != 0


def _lock_open_seam(path: Path) -> None:
    """Private test seam between named inspection and handle open."""

    return None


def _lock_publish_seam(path: Path) -> None:
    """Private test seam between temp preparation and no-replace publication."""

    return None


def _pre_unlock_seam(path: Path) -> None:
    """Private test seam before the final retained validation and unlock.

    The seam runs strictly before the true final retained-state validation,
    so any state it perturbs is still observed by that checkpoint; nothing
    caller-controlled runs between the final validation and the unlock.
    """

    return None


def _root_open_seam(path: Path) -> None:
    """Private test seam between root inspection and the retained root open."""

    return None


def _marker_open_seam(path: Path) -> None:
    """Private test seam between marker inspection and the retained open."""

    return None


def _open_root_handle(root: Path) -> tuple[int, str, tuple[int, bytes]]:
    """Open and validate the retained queue-root directory handle.

    The handle requests ``FILE_LIST_DIRECTORY`` (a share-registered access) and
    shares read/write but never delete, so the authenticated root directory can
    neither be renamed nor removed while the fence is held.
    """

    try:
        pre = _probe_facts(root)
    except OSError as exc:
        raise PathSecurityError(f"queue root is unopenable: {root}") from exc
    if _facts_reparse(pre) or not pre.is_directory:
        raise PathSecurityError(f"queue root must be a plain directory: {root}")
    _root_open_seam(root)
    try:
        handle = _win_create_file(
            root,
            _FILE_LIST_DIRECTORY,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
    except OSError as exc:
        raise PathSecurityError(f"queue root cannot be retained: {root}") from exc
    try:
        try:
            facts = _handle_facts(handle)
            named = _probe_facts(root)
        except OSError as exc:
            raise PathSecurityError(f"queue root is unverifiable: {root}") from exc
        if _facts_reparse(facts) or not facts.is_directory:
            raise PathSecurityError(f"queue root identity is unsafe: {root}")
        if facts.identity != pre.identity or named.identity != facts.identity:
            raise PathSecurityError(
                f"queue root opened/named identity mismatch: {root}"
            )
        if os.path.normcase(_from_kernel_final_path(facts.final_path)) != _norm(root):
            raise PathSecurityError(
                f"queue root kernel-final path diverges from its name: {root}"
            )
    except BaseException as primary:
        # Exceptional pre-transfer exit: this helper still owns the handle
        # and makes the single close attempt; a successful return transfers
        # the still-open handle and MUST NOT close it.
        _finalize_local_handle(
            handle, primary, f"queue root handle close failed: {root}"
        )
        raise
    return handle, facts.final_path, facts.identity


def _check_marker_facts(
    facts: _HandleFacts, expected_final: str | None, marker: Path, error: type
) -> None:
    if _facts_reparse(facts):
        raise error(f"queue root marker is a reparse point: {marker}")
    if facts.is_directory or facts.delete_pending:
        raise error(f"queue root marker is not a live regular file: {marker}")
    if facts.link_count != 1:
        raise error(f"queue root marker link count must be one: {marker}")
    if facts.size != len(_ROOT_MARKER_CANONICAL_BYTES):
        raise error(f"queue root marker size is not canonical: {marker}")
    if expected_final is not None and os.path.normcase(
        facts.final_path
    ) != os.path.normcase(expected_final):
        raise error(f"queue root marker kernel-final path diverges: {marker}")


def _open_marker_handle(root: Path, root_final: str) -> tuple[int, tuple[int, bytes]]:
    """Open and validate the retained root-marker handle (read, share-read).

    Without write or delete sharing, the canonical marker can be neither
    rewritten, renamed, nor deleted for as long as the handle is retained.
    """

    marker = root / ROOT_MARKER
    expected_final = _expected_child_final(root_final, ROOT_MARKER)
    try:
        pre = _probe_facts(marker)
    except OSError as exc:
        raise PathSecurityError(f"queue root marker is unopenable: {marker}") from exc
    _check_marker_facts(pre, None, marker, PathSecurityError)
    _marker_open_seam(marker)
    try:
        handle = _win_create_file(
            marker,
            _GENERIC_READ,
            _FILE_SHARE_READ,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
        )
    except OSError as exc:
        raise PathSecurityError(f"queue root marker cannot be retained: {marker}") from exc
    try:
        try:
            facts = _handle_facts(handle)
            raw = _win_read_exact(handle, 0, len(_ROOT_MARKER_CANONICAL_BYTES))
            named = _probe_facts(marker)
        except OSError as exc:
            raise PathSecurityError(
                f"queue root marker is unverifiable: {marker}"
            ) from exc
        _check_marker_facts(facts, expected_final, marker, PathSecurityError)
        if facts.identity != pre.identity or named.identity != facts.identity:
            raise PathSecurityError(
                f"queue root marker opened/named identity mismatch: {marker}"
            )
        if raw != _ROOT_MARKER_CANONICAL_BYTES:
            raise PathSecurityError(
                f"queue root marker bytes are not canonical: {marker}"
            )
    except BaseException as primary:
        # Exceptional pre-transfer exit: single close attempt here; a
        # successful return transfers the still-open handle unclosed.
        _finalize_local_handle(
            handle, primary, f"queue root marker handle close failed: {marker}"
        )
        raise
    return handle, facts.identity


def _revalidate_root_handle(
    handle: int, root: Path, root_final: str, identity: tuple[int, bytes]
) -> None:
    try:
        facts = _handle_facts(handle)
        named = _probe_facts(root)
    except OSError as exc:
        raise LockIntegrityError(f"queue root verification failed: {root}") from exc
    if (
        _facts_reparse(facts)
        or not facts.is_directory
        or facts.delete_pending
        or facts.identity != identity
        or named.identity != identity
        or os.path.normcase(facts.final_path) != os.path.normcase(root_final)
    ):
        raise LockIntegrityError(f"queue root changed while the fence was held: {root}")


def _revalidate_marker_handle(
    handle: int, root: Path, root_final: str, identity: tuple[int, bytes]
) -> None:
    marker = root / ROOT_MARKER
    expected_final = _expected_child_final(root_final, ROOT_MARKER)
    try:
        facts = _handle_facts(handle)
        raw = _win_read_exact(handle, 0, len(_ROOT_MARKER_CANONICAL_BYTES))
        named = _probe_facts(marker)
    except OSError as exc:
        raise LockIntegrityError(f"queue root marker verification failed: {marker}") from exc
    _check_marker_facts(facts, expected_final, marker, LockIntegrityError)
    if (
        facts.identity != identity
        or named.identity != identity
        or raw != _ROOT_MARKER_CANONICAL_BYTES
    ):
        raise LockIntegrityError(
            f"queue root marker changed while the fence was held: {marker}"
        )


def _validate_lock_handle(
    handle: int,
    root_final: str,
    path: Path,
    expected_identity: tuple[int, bytes] | None,
) -> tuple[int, bytes]:
    """Fully validate the lock file object behind ``handle`` at a checkpoint.

    The permanent evidence byte is byte zero and is read before (and entirely
    independently of) the offset-one ownership range, so evidence validation
    never conflicts with a legitimate owner's kernel lock.  A byte-zero read
    obstruction is an integrity failure, never proof of a valid owner.
    """

    expected_final = _expected_child_final(root_final, path.name)
    try:
        facts = _handle_facts(handle)
    except OSError as exc:
        raise LockIntegrityError(f"lock verification failed: {path}") from exc
    if _facts_reparse(facts):
        raise LockIntegrityError(f"lock file is a reparse point: {path}")
    if facts.is_directory or facts.delete_pending:
        raise LockIntegrityError(f"lock file is not a live regular file: {path}")
    if facts.link_count != 1:
        raise LockIntegrityError(f"lock file link count must be one: {path}")
    if facts.size != 1:
        raise LockIntegrityError(f"lock file must contain exactly one byte: {path}")
    if os.path.normcase(facts.final_path) != os.path.normcase(expected_final):
        raise LockIntegrityError(f"lock kernel-final path diverges from its name: {path}")
    try:
        evidence = _win_read_exact(handle, _LOCK_EVIDENCE_OFFSET, 1)
    except OSError as exc:
        raise LockIntegrityError(
            f"lock evidence byte is unreadable or obstructed: {path}"
        ) from exc
    if evidence != _PERMANENT_LOCK_BYTES:
        raise LockIntegrityError(f"lock content must be exactly one NUL byte: {path}")
    try:
        named = _probe_facts(path)
    except OSError as exc:
        raise LockIntegrityError(f"lock name is unverifiable: {path}") from exc
    if named.identity != facts.identity:
        raise LockIntegrityError(f"lock opened/named identity mismatch: {path}")
    if expected_identity is not None and facts.identity != expected_identity:
        raise LockIntegrityError(f"lock identity changed while held: {path}")
    return facts.identity


def _publish_permanent_lock(
    root: Path, root_final: str, path: Path
) -> tuple[str, tuple[int, bytes] | None]:
    """Publish the permanent one-NUL-byte lock file, or lose the exact race.

    A cryptographically unique same-directory temporary is created with Win32
    no-overwrite semantics, fully written, flushed, and validated while its
    high-access handle stays open; the very same file object is then published
    with a handle-based no-replace rename.  Only the exact kernel collision
    from that rename selects the loser.  No path-based unlink, repair, or
    foreign-orphan cleanup ever happens here.

    Finalization of the exact publisher handle is mandatory, ordered, and
    fail closed: when the temp was not renamed, it is deleted first through
    the same still-open handle (``FileDispositionInfo``), then the handle is
    closed; a disposition failure - including WinError 33 - is
    :class:`LockIntegrityError`, never contention and never a silently
    successful loss.  A successful rename never disposes the published
    target and closes only after the published object has been validated and
    its FileId captured.  No outcome escapes until the applicable
    finalization succeeded; a primary failure plus cleanup failures raises
    one ordered ``BaseExceptionGroup`` with the primary first, so nothing is
    masked.
    """

    temp_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    temp_path = root / temp_name
    try:
        handle = _win_create_file(
            temp_path,
            _GENERIC_READ | _GENERIC_WRITE | _DELETE_ACCESS,
            _FILE_SHARE_READ,
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL,
        )
    except OSError as exc:
        raise LockIntegrityError(
            f"lock publication temp cannot be created: {temp_path}"
        ) from exc
    primary: BaseException | None = None
    outcome: tuple[str, tuple[int, bytes] | None] | None = None
    renamed = False
    try:
        try:
            _win_write_all(handle, _PERMANENT_LOCK_BYTES, 0)
            _win_flush(handle)
            facts = _handle_facts(handle)
            named = _probe_facts(temp_path)
            evidence = _win_read_exact(handle, _LOCK_EVIDENCE_OFFSET, 1)
        except OSError as exc:
            raise LockIntegrityError(
                f"lock publication temp cannot be prepared: {temp_path}"
            ) from exc
        if (
            _facts_reparse(facts)
            or facts.is_directory
            or facts.delete_pending
            or facts.link_count != 1
            or facts.size != 1
            or evidence != _PERMANENT_LOCK_BYTES
            or named.identity != facts.identity
            or os.path.normcase(facts.final_path)
            != os.path.normcase(_expected_child_final(root_final, temp_name))
        ):
            raise LockIntegrityError(
                f"lock publication temp failed validation: {temp_path}"
            )
        _lock_publish_seam(path)
        collided = False
        try:
            _win_rename_no_replace(handle, path)
        except OSError as exc:
            if getattr(exc, "winerror", None) in (
                _ERROR_FILE_EXISTS,
                _ERROR_ALREADY_EXISTS,
            ):
                collided = True
            else:
                raise LockIntegrityError(f"lock publication failed: {path}") from exc
        if collided:
            outcome = ("lost", None)
        else:
            renamed = True
            try:
                post = _handle_facts(handle)
                post_evidence = _win_read_exact(handle, _LOCK_EVIDENCE_OFFSET, 1)
                named = _probe_facts(path)
            except OSError as exc:
                raise LockIntegrityError(
                    f"published lock failed validation: {path}"
                ) from exc
            if (
                _facts_reparse(post)
                or post.is_directory
                or post.delete_pending
                or post.link_count != 1
                or post.size != 1
                or post_evidence != _PERMANENT_LOCK_BYTES
                or named.identity != post.identity
                or os.path.normcase(post.final_path)
                != os.path.normcase(_expected_child_final(root_final, path.name))
            ):
                raise LockIntegrityError(f"published lock failed validation: {path}")
            outcome = ("won", post.identity)
    except BaseException as exc:
        primary = exc
    failures: list[BaseException] = []
    if primary is not None:
        failures.append(primary)
    if not renamed:
        try:
            _win_dispose(handle)
        except OSError as exc:
            failures.append(
                _integrity_failure(
                    exc, f"lock publication temp cannot be disposed: {temp_path}"
                )
            )
        except BaseException as exc:
            failures.append(exc)
    try:
        _win_close(handle)
    except OSError as exc:
        failures.append(
            _integrity_failure(exc, f"lock publisher handle close failed: {path}")
        )
    except BaseException as exc:
        failures.append(exc)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup("lock publication and cleanup failed", failures)
    return outcome


def _authenticate_published_lock(root_final: str, path: Path) -> tuple[int, bytes]:
    """Authenticate the winning target immediately after a publication loss.

    The winner's publisher handle shares reads, so this read-only probe (which
    itself requests read access and tolerates the winner's still-open write
    and delete grants in its share request) authenticates the published target
    even while the winner retains its high-access handle.  The share request
    grants nobody any new access; the probe handle is transient and is
    finalized on success and failure alike, so an authenticated identity is
    never returned past a failed close.
    """

    try:
        handle = _win_create_file(
            path,
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
        )
    except OSError as exc:
        raise LockIntegrityError(
            f"published lock cannot be authenticated after race loss: {path}"
        ) from exc
    try:
        identity = _validate_lock_handle(handle, root_final, path, None)
    except BaseException as primary:
        _finalize_local_handle(
            handle, primary, f"published lock probe close failed: {path}"
        )
        raise
    _finalize_local_handle(
        handle, None, f"published lock probe close failed: {path}"
    )
    return identity


def _open_lock_after_publication_loss(path: Path) -> int:
    """Bounded retained-handle open retry, only after an exact rename loss.

    The winner's high-access publisher handle briefly breaks bidirectional
    share compatibility for the low-access retained open; only that exact
    sharing violation is retried, and only within a fixed bound.
    """

    for _attempt in range(_PUBLICATION_LOSS_OPEN_ATTEMPTS):
        try:
            return _win_create_file(
                path,
                _GENERIC_READ,
                _FILE_SHARE_READ,
                _OPEN_EXISTING,
                _FILE_FLAG_OPEN_REPARSE_POINT,
            )
        except OSError as exc:
            if getattr(exc, "winerror", None) != _ERROR_SHARING_VIOLATION:
                raise LockIntegrityError(
                    f"lock file cannot be opened after race loss: {path}"
                ) from exc
        time.sleep(_PUBLICATION_LOSS_OPEN_SLEEP_SECONDS)
    raise LockIntegrityError(
        f"publication winner did not release its publisher handle: {path}"
    )


def _open_permanent_lock(
    root: Path, root_final: str, path: Path
) -> tuple[int, tuple[int, bytes], bool]:
    """Open (publishing on first use) the retained permanent lock handle.

    Returns ``(handle, identity, published)``.  Every unexpected open or share
    failure is an integrity failure; contention is decided later and only by
    the exact offset-one ``LockFileEx`` collision.
    """

    published = False
    anchor: tuple[int, bytes] | None = None
    loser = False
    try:
        pre = _probe_facts(path)
    except OSError as exc:
        if getattr(exc, "winerror", None) in (
            _ERROR_FILE_NOT_FOUND,
            _ERROR_PATH_NOT_FOUND,
        ):
            pre = None
        else:
            raise LockIntegrityError(f"lock file is uninspectable: {path}") from exc
    if pre is not None:
        if _facts_reparse(pre):
            raise PathSecurityError(f"lock file is a reparse point: {path}")
        if pre.is_directory:
            raise PathSecurityError(f"lock file is not a regular file: {path}")
        if pre.size != 1:
            raise LockIntegrityError(f"lock file must contain exactly one byte: {path}")
        if pre.link_count != 1:
            raise LockIntegrityError(f"lock file link count must be one: {path}")
        anchor = pre.identity
    else:
        outcome, won_identity = _publish_permanent_lock(root, root_final, path)
        if outcome == "won":
            published = True
            anchor = won_identity
        else:
            loser = True
            anchor = _authenticate_published_lock(root_final, path)
    _lock_open_seam(path)
    if loser:
        handle = _open_lock_after_publication_loss(path)
    else:
        try:
            handle = _win_create_file(
                path,
                _GENERIC_READ,
                _FILE_SHARE_READ,
                _OPEN_EXISTING,
                _FILE_FLAG_OPEN_REPARSE_POINT,
            )
        except OSError as exc:
            raise LockIntegrityError(f"lock file cannot be opened: {path}") from exc
    try:
        identity = _validate_lock_handle(handle, root_final, path, None)
        if anchor is not None and identity != anchor:
            raise LockIntegrityError(
                f"lock identity changed between inspection and open: {path}"
            )
    except BaseException as primary:
        # Exceptional pre-transfer exit: single close attempt here; a
        # successful return transfers the still-open handle unclosed.
        _finalize_local_handle(
            handle, primary, f"lock handle close failed after validation: {path}"
        )
        raise
    return handle, identity, published


class PermanentFileLock:
    """Lifetime-owned non-blocking one-byte Windows lock over a permanent file.

    The permanent file is exactly one NUL byte with link count one.  Byte zero
    is immutable evidence and is validated before ownership is ever claimed;
    ownership itself is a nonblocking exclusive ``LockFileEx`` range of exactly
    one byte at offset one, so only the kernel decides ownership and holder
    death releases the fence without stale-state guessing.  Exactly the
    ``ERROR_LOCK_VIOLATION`` (WinError 33) result of that one ``LockFileEx``
    call maps to :class:`LockUnavailableError`; every other failure anywhere in
    the protocol is fail-closed :class:`LockIntegrityError` (or a path/schema
    error before handles exist).

    Raw non-inheritable Win32 handles for the authenticated queue root
    directory, the canonical root marker, and the lock file are retained for
    the whole critical section.  None of the retained handles shares delete
    (and the file handles share no writes either), so the authenticated names
    cannot be renamed, rewritten, or deleted while the fence is held; a
    hardlink alias can still be created by design of Windows sharing, resolves
    to the same file identity and the same kernel lock, and is caught by the
    link-count checks if it persists to any validation checkpoint.  Validation
    of type, reparse status, link count, size, exact bytes, kernel-final path,
    and opened-versus-named identity runs at open, after acquisition, and
    immediately before unlock.

    All object use is pinned to the creating thread; ``__exit__`` validates
    the owner thread before touching any state, so a rejected cross-thread
    exit leaves the fence fully active.  ``close`` is idempotent on the owning
    thread.
    """

    def __init__(self, queue_root: os.PathLike[str] | str, filename: str):
        if filename not in _LOCK_FILENAMES:
            raise SchemaError(
                f"lock filename must be supervisor.lock or runner.lock: {filename!r}"
            )
        if _kernel32 is None:
            raise UnsupportedPlatformError("Win32 byte-range locks require Windows")
        root = _resolve_queue_root(queue_root)
        path = _guard_destination(root, filename)
        self.root = root
        self.path = path
        self._owner_thread = threading.get_ident()
        self._entered = False
        self._published = False
        self._root_handle: int | None = None
        self._marker_handle: int | None = None
        self._lock_handle: int | None = None
        self._root_final = ""
        self._root_identity: tuple[int, bytes] | None = None
        self._marker_identity: tuple[int, bytes] | None = None
        self._identity: tuple[int, bytes] | None = None
        locked = False
        try:
            root_handle, root_final, root_identity = _open_root_handle(root)
            self._root_handle = root_handle
            self._root_final = root_final
            self._root_identity = root_identity
            marker_handle, marker_identity = _open_marker_handle(root, root_final)
            self._marker_handle = marker_handle
            self._marker_identity = marker_identity
            lock_handle, identity, published = _open_permanent_lock(
                root, root_final, path
            )
            self._lock_handle = lock_handle
            self._identity = identity
            self._published = published
            try:
                _win_lock_exclusive(lock_handle, _LOCK_OWNERSHIP_OFFSET)
            except OSError as exc:
                if getattr(exc, "winerror", None) == _ERROR_LOCK_VIOLATION:
                    raise LockUnavailableError(
                        f"lock is already held: {path}"
                    ) from exc
                raise LockIntegrityError(
                    f"lock acquisition failed for a non-contention reason: {path}"
                ) from exc
            locked = True
            self._revalidate_retained()
        except BaseException as primary:
            rollback_failures = self._release_retained(unlock=locked, validate=False)
            if rollback_failures:
                raise BaseExceptionGroup(
                    "lock acquisition and rollback both failed",
                    [primary, *rollback_failures],
                )
            raise

    def _require_owner_thread(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise LockIntegrityError(
                f"cross-thread use of a permanent lock is forbidden: {self.path}"
            )

    def _revalidate_retained(self) -> None:
        _revalidate_root_handle(
            self._root_handle, self.root, self._root_final, self._root_identity
        )
        _revalidate_marker_handle(
            self._marker_handle, self.root, self._root_final, self._marker_identity
        )
        _validate_lock_handle(
            self._lock_handle, self._root_final, self.path, self._identity
        )

    def _release_retained(self, *, unlock: bool, validate: bool) -> list[BaseException]:
        """Attempt every release step without short-circuiting.

        The final retained-state revalidation (when requested) runs directly
        adjacent to the offset-one unlock; no seam, callback, or other
        caller-controlled operation occurs between them.  No failure prevents
        the remaining unlock/close attempts; unlock and close Win32 failures
        are normalized to :class:`LockIntegrityError` and every failure is
        collected in observation order.  All handle fields are cleared in a
        ``finally`` path, so the object is terminal after the attempts even
        when failures are reported.  A production ``CloseHandle`` failure is
        an integrity condition: the remaining release attempts still run and
        the Python fields are cleared, but the failure is reported because
        the kernel never confirmed releasing that handle.
        """

        failures: list[BaseException] = []
        lock_handle = self._lock_handle
        marker_handle = self._marker_handle
        root_handle = self._root_handle
        try:
            if validate:
                try:
                    self._revalidate_retained()
                except BaseException as exc:
                    failures.append(exc)
            if lock_handle is not None:
                if unlock:
                    try:
                        _win_unlock(lock_handle, _LOCK_OWNERSHIP_OFFSET)
                    except OSError as exc:
                        failures.append(
                            _integrity_failure(
                                exc, f"lock unlock failed: {self.path}"
                            )
                        )
                    except BaseException as exc:
                        failures.append(exc)
                try:
                    _win_close(lock_handle)
                except OSError as exc:
                    failures.append(
                        _integrity_failure(
                            exc, f"lock handle close failed: {self.path}"
                        )
                    )
                except BaseException as exc:
                    failures.append(exc)
            if marker_handle is not None:
                try:
                    _win_close(marker_handle)
                except OSError as exc:
                    failures.append(
                        _integrity_failure(
                            exc,
                            f"marker handle close failed: {self.root / ROOT_MARKER}",
                        )
                    )
                except BaseException as exc:
                    failures.append(exc)
            if root_handle is not None:
                try:
                    _win_close(root_handle)
                except OSError as exc:
                    failures.append(
                        _integrity_failure(
                            exc, f"root handle close failed: {self.root}"
                        )
                    )
                except BaseException as exc:
                    failures.append(exc)
        finally:
            self._lock_handle = None
            self._marker_handle = None
            self._root_handle = None
        return failures

    @property
    def closed(self) -> bool:
        return self._lock_handle is None

    def close(self) -> None:
        """Release the fence, attempting every release step exactly once.

        The private test seam runs first; the true final retained-state
        validation then runs directly before the offset-one unlock and the
        handle closes, so state perturbed at the seam is still caught by the
        final checkpoint.  No seam, checkpoint, unlock, or close failure
        prevents the remaining release attempts, and the object is closed
        afterwards either way.  A single failure propagates unchanged (typed
        integrity for Win32 unlock/close failures); multiple failures raise
        one ordered ``BaseExceptionGroup``.
        """

        self._require_owner_thread()
        if self._lock_handle is None:
            return
        failures: list[BaseException] = []
        try:
            _pre_unlock_seam(self.path)
        except BaseException as exc:
            failures.append(exc)
        failures.extend(self._release_retained(unlock=True, validate=True))
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("permanent lock release failed", failures)

    def __enter__(self) -> "PermanentFileLock":
        self._require_owner_thread()
        if self.closed:
            # Closed-object misuse is an integrity condition;
            # LockUnavailableError stays reserved for the exact offset-one
            # kernel contention result.
            raise LockIntegrityError("cannot re-enter a closed permanent lock")
        if self._entered:
            raise LockIntegrityError(
                "same-object re-entry of a permanent lock is forbidden"
            )
        self._entered = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._require_owner_thread()
        self._entered = False
        self.close()


def acquire_permanent_lock(
    queue_root: os.PathLike[str] | str, filename: str
) -> PermanentFileLock:
    return PermanentFileLock(queue_root, filename)
