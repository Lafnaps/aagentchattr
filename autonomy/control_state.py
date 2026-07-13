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
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

try:  # Import-safe on non-Windows hosts; lock construction still fails closed.
    import msvcrt  # type: ignore
except ImportError:  # pragma: no cover - exercised only outside Windows
    msvcrt = None

__all__ = [
    "SCHEMA_VERSION",
    "ROOT_MARKER",
    "HALT_FILENAME",
    "MAX_DOCUMENT_BYTES",
    "ControlStateError",
    "SchemaError",
    "PathSecurityError",
    "MarkerConflictError",
    "MissingMarkerError",
    "LockUnavailableError",
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
    "acquire_permanent_lock",
]

SCHEMA_VERSION = 1
ROOT_MARKER = "autonomy-root.json"
HALT_FILENAME = "HALT"
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
_LOCK_FILENAMES = frozenset({"supervisor.lock", "runner.lock"})


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
    """Another process or handle already owns the requested permanent lock."""


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
    return literal


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


class PermanentFileLock:
    """Lifetime-owned non-blocking one-byte Windows lock.

    The lock remains held until ``close`` (or context exit) closes its file
    descriptor.  ``close`` is idempotent.  No stale PID or timestamp is used as
    authority: only the kernel byte-range lock decides ownership.
    """

    def __init__(self, queue_root: os.PathLike[str] | str, filename: str):
        if msvcrt is None:
            raise UnsupportedPlatformError("msvcrt byte-range locks require Windows")
        if filename not in _LOCK_FILENAMES:
            raise SchemaError(
                f"lock filename must be supervisor.lock or runner.lock: {filename!r}"
            )
        root = _resolve_queue_root(queue_root)
        path = _guard_destination(root, filename)
        self.path = path
        self._stream = None
        stream = path.open("a+b", buffering=0)
        try:
            _reject_reparse(path)
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
                os.fsync(stream.fileno())
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise LockUnavailableError(f"lock is already held: {path}") from exc
        except BaseException:
            stream.close()
            raise
        self._stream = stream

    @property
    def closed(self) -> bool:
        return self._stream is None

    def close(self) -> None:
        stream = self._stream
        if stream is None:
            return
        self._stream = None
        try:
            stream.seek(0)
            if msvcrt is not None:
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            # Closing the descriptor is authoritative even if explicit unlock
            # reports that the OS has already released it.
            pass
        finally:
            stream.close()

    def __enter__(self) -> "PermanentFileLock":
        if self.closed:
            raise LockUnavailableError("cannot re-enter a closed permanent lock")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def acquire_permanent_lock(
    queue_root: os.PathLike[str] | str, filename: str
) -> PermanentFileLock:
    return PermanentFileLock(queue_root, filename)
