"""Fail-closed synthetic worker for autonomy admission tests only.

No scenario accepts a command, prompt, product path, or network target.  The
worker consumes a small pinned JSON payload, performs one bounded synthetic
action, and optionally publishes one immutable bound result.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

__all__ = [
    "CONFIG_ERROR_EXIT",
    "CRASH_EXIT",
    "FAIL_EXIT",
    "MAX_PAYLOAD_BYTES",
    "RESULT_FILENAME",
    "CanaryWorkerError",
    "PayloadError",
    "PathValidationError",
    "ResultConflictError",
    "load_payload",
    "publish_result",
    "run_canary",
    "main",
]

RESULT_FILENAME = "worker-result.json"
ROOT_MARKER = "autonomy-root.json"
MAX_PAYLOAD_BYTES = 1024
MAX_RESULT_BYTES = 2048
FAIL_EXIT = 20
CRASH_EXIT = 21
CONFIG_ERROR_EXIT = 64
SCHEMA_VERSION = 1

_TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9A-F]{64}$")
_SCENARIOS = frozenset({"success", "fail", "crash", "hang", "spawn-tree"})
_PAYLOAD_KEYS = frozenset({"version", "scenario", "duration_ms"})
_RESULT_COMMON_KEYS = frozenset(
    {"version", "kind", "task_id", "attempt", "nonce", "scenario", "outcome"}
)
_RESULT_TREE_KEYS = _RESULT_COMMON_KEYS | {"descendant_pids"}
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)
_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

_INTERNAL_PREFIX = "AGENTCHATTR_CANARY_"
_INTERNAL_TOKEN = _INTERNAL_PREFIX + "TOKEN"
_INTERNAL_LEVEL = _INTERNAL_PREFIX + "LEVEL"
_INTERNAL_DEADLINE = _INTERNAL_PREFIX + "DEADLINE_NS"
_INTERNAL_ATTEMPT_DIR = _INTERNAL_PREFIX + "ATTEMPT_DIR"
_INTERNAL_NONCE = _INTERNAL_PREFIX + "NONCE"
_INTERNAL_PYTHON = _INTERNAL_PREFIX + "PYTHON"
_INTERNAL_BOOTSTRAP = _INTERNAL_PREFIX + "BOOTSTRAP"
_INTERNAL_KEYS = frozenset(
    {
        _INTERNAL_TOKEN,
        _INTERNAL_LEVEL,
        _INTERNAL_DEADLINE,
        _INTERNAL_ATTEMPT_DIR,
        _INTERNAL_NONCE,
        _INTERNAL_PYTHON,
        _INTERNAL_BOOTSTRAP,
    }
)


class CanaryWorkerError(Exception):
    """Base class for every fail-closed canary refusal."""


class PayloadError(CanaryWorkerError):
    """The pinned payload violates its bounded closed schema."""


class PathValidationError(CanaryWorkerError):
    """A supplied path is remote, linked, escaping, or non-canonical."""


class ResultConflictError(CanaryWorkerError):
    """An immutable result slot already contains different bytes."""


def _pairs_to_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PayloadError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PayloadError(f"non-finite JSON number is forbidden: {value}")


def _canonical_json(document: Mapping[str, Any], *, limit: int) -> bytes:
    if not isinstance(document, Mapping):
        raise PayloadError("document must be a JSON object")
    try:
        encoded = (
            json.dumps(
                dict(document),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PayloadError(f"document is not strict JSON: {exc}") from exc
    if len(encoded) > limit:
        raise PayloadError(f"document exceeds {limit} bytes")
    return encoded


def _reject_remote_or_device(raw_text: str, *, field: str) -> None:
    windows_form = raw_text.replace("/", "\\")
    if windows_form.startswith("\\\\") or windows_form.startswith("\\?"):
        raise PathValidationError(f"{field} cannot be UNC/device path: {raw_text}")
    drive, _tail = os.path.splitdrive(raw_text)
    if drive.startswith(("\\", "//")):
        raise PathValidationError(f"{field} cannot use a remote drive: {raw_text}")


def _is_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_FLAG
    )


def _path_chain(path: Path) -> list[Path]:
    return [*reversed(path.parents), path]


def _normal(path: os.PathLike[str] | str) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _real_normal(path: os.PathLike[str] | str) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _contained(child: Path, parent: Path, *, strict: bool = True) -> bool:
    try:
        common = os.path.commonpath([_normal(child), _normal(parent)])
    except ValueError:
        return False
    if common != _normal(parent):
        return False
    return not strict or _normal(child) != _normal(parent)


def _validate_existing_path(
    raw_value: os.PathLike[str] | str, *, expect_directory: bool, field: str
) -> Path:
    if not isinstance(raw_value, (str, os.PathLike)):
        raise PathValidationError(f"{field} must be a path")
    raw_text = os.fspath(raw_value)
    if not isinstance(raw_text, str) or not raw_text:
        raise PathValidationError(f"{field} must be a non-empty text path")
    _reject_remote_or_device(raw_text, field=field)
    supplied = Path(raw_text)
    if not supplied.is_absolute():
        raise PathValidationError(f"{field} must be absolute: {supplied}")
    if any(part == ".." for part in supplied.parts):
        raise PathValidationError(f"{field} traversal is forbidden: {supplied}")
    canonical_text = os.path.abspath(os.path.normpath(raw_text))
    if os.path.normcase(raw_text) != os.path.normcase(canonical_text):
        raise PathValidationError(f"{field} is not exact canonical form: {supplied}")
    canonical = Path(canonical_text)
    try:
        resolved = canonical.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise PathValidationError(f"{field} does not exist: {canonical}") from exc
    if _normal(resolved) != _normal(canonical) or _real_normal(canonical) != _normal(canonical):
        raise PathValidationError(f"{field} resolves through an alias/link: {canonical}")
    for component in _path_chain(canonical):
        if _is_reparse(component):
            raise PathValidationError(
                f"{field} contains a symlink/junction/reparse point: {component}"
            )
    try:
        mode = os.lstat(canonical).st_mode
    except OSError as exc:
        raise PathValidationError(f"cannot inspect {field}: {canonical}") from exc
    correct_type = stat.S_ISDIR(mode) if expect_directory else stat.S_ISREG(mode)
    if not correct_type:
        expected = "directory" if expect_directory else "regular file"
        raise PathValidationError(f"{field} must be an existing {expected}: {canonical}")
    return canonical


def _validate_queue_root(raw: os.PathLike[str] | str) -> Path:
    root = _validate_existing_path(raw, expect_directory=True, field="queue_root")
    marker = _validate_existing_path(
        root / ROOT_MARKER, expect_directory=False, field="queue root marker"
    )
    if marker.parent != root:
        raise PathValidationError("queue root marker binding mismatch")
    return root


def _validate_task_id(value: Any) -> str:
    if not isinstance(value, str) or not _TASK_ID_RE.fullmatch(value):
        raise PayloadError(f"invalid task_id: {value!r}")
    if value.lower() in _WINDOWS_RESERVED:
        raise PayloadError(f"reserved Windows task_id: {value!r}")
    return value


def _validate_attempt(value: Any) -> int:
    if type(value) is not int or value not in (1, 2):
        raise PayloadError("attempt must be integer 1 or 2")
    return value


def _validate_nonce(value: Any) -> str:
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise PayloadError("nonce must be exactly 32 lowercase hexadecimal characters")
    return value


def _validate_expected_sha256(value: Any) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise PayloadError("expected_sha256 must be exactly 64 uppercase hex characters")
    return value


def _validate_attempt_dir(
    queue_root: os.PathLike[str] | str,
    attempt_dir: os.PathLike[str] | str,
    *,
    task_id: str,
    attempt: int,
) -> tuple[Path, Path]:
    root = _validate_queue_root(queue_root)
    task = _validate_task_id(task_id)
    number = _validate_attempt(attempt)
    directory = _validate_existing_path(
        attempt_dir, expect_directory=True, field="attempt_dir"
    )
    expected = root / "attempts" / task / f"a{number}"
    if _normal(directory) != _normal(expected):
        raise PathValidationError(
            f"attempt_dir binding mismatch; expected {expected}, got {directory}"
        )
    if not _contained(directory, root):
        raise PathValidationError("attempt_dir escapes queue_root")
    return root, directory


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read_stable_regular(path: Path, *, limit: int, field: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise PathValidationError(f"cannot stat {field}: {path}") from exc
    if _is_reparse(path) or not stat.S_ISREG(before.st_mode):
        raise PathValidationError(f"{field} is not a safe regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PathValidationError(f"cannot safely open {field}: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PathValidationError(f"opened {field} is not regular: {path}")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise PathValidationError(f"{field} disappeared while open: {path}") from exc
    if _identity(before) != _identity(opened) or _identity(after) != _identity(opened):
        raise PathValidationError(f"{field} identity/content metadata changed while read")
    if len(raw) > limit:
        raise PayloadError(f"{field} exceeds {limit} bytes")
    return raw


def _validate_payload(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise PayloadError("payload must be a JSON object")
    actual = frozenset(document)
    if actual != _PAYLOAD_KEYS:
        raise PayloadError(
            "closed payload schema mismatch; "
            f"missing={sorted(_PAYLOAD_KEYS - actual)}, extra={sorted(actual - _PAYLOAD_KEYS)}"
        )
    if type(document["version"]) is not int or document["version"] != SCHEMA_VERSION:
        raise PayloadError(f"version must be integer {SCHEMA_VERSION}")
    scenario = document["scenario"]
    if not isinstance(scenario, str) or scenario not in _SCENARIOS:
        raise PayloadError(f"invalid scenario: {scenario!r}")
    duration = document["duration_ms"]
    if type(duration) is not int or not 0 <= duration <= 30_000:
        raise PayloadError("duration_ms must be an integer in range 0..30000")
    if scenario in {"hang", "spawn-tree"} and duration < 1000:
        raise PayloadError(f"{scenario} duration_ms must be in range 1000..30000")
    return dict(document)


def load_payload(
    payload_path: os.PathLike[str] | str,
    *,
    allowed_root: os.PathLike[str] | str,
    expected_sha256: str,
) -> dict[str, Any]:
    """Open, identity-check, hash, and parse the pinned payload exactly once."""

    allowed = _validate_existing_path(
        allowed_root, expect_directory=True, field="allowed_root"
    )
    payload = _validate_existing_path(
        payload_path, expect_directory=False, field="payload"
    )
    if not _contained(payload, allowed) or not _contained(
        Path(os.path.realpath(payload)), Path(os.path.realpath(allowed))
    ):
        raise PathValidationError("payload must be a strict child of allowed_root")
    expected = _validate_expected_sha256(expected_sha256)
    raw = _read_stable_regular(payload, limit=MAX_PAYLOAD_BYTES, field="payload")
    actual = hashlib.sha256(raw).hexdigest().upper()
    if actual != expected:
        raise PayloadError(f"payload SHA256 mismatch: expected {expected}, got {actual}")
    if not raw:
        raise PayloadError("payload is empty")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PayloadError("payload is not valid UTF-8") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_pairs_to_object,
            parse_constant=_reject_constant,
        )
    except PayloadError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PayloadError(f"invalid payload JSON: {exc}") from exc
    return _validate_payload(document)


def _validate_result(document: Mapping[str, Any]) -> dict[str, Any]:
    scenario = document.get("scenario") if isinstance(document, Mapping) else None
    expected = _RESULT_TREE_KEYS if scenario == "spawn-tree" else _RESULT_COMMON_KEYS
    if not isinstance(document, Mapping) or frozenset(document) != expected:
        raise PayloadError("closed result schema mismatch")
    if type(document["version"]) is not int or document["version"] != 1:
        raise PayloadError("result version must be integer 1")
    if document["kind"] != "canary-worker-result":
        raise PayloadError("invalid result kind")
    _validate_task_id(document["task_id"])
    _validate_attempt(document["attempt"])
    _validate_nonce(document["nonce"])
    if scenario == "success":
        if document["outcome"] != "success":
            raise PayloadError("success scenario/result mismatch")
    elif scenario == "fail":
        if document["outcome"] != "failure":
            raise PayloadError("fail scenario/result mismatch")
    elif scenario == "spawn-tree":
        if document["outcome"] != "diagnostic":
            raise PayloadError("spawn-tree result must be diagnostic")
        pids = document["descendant_pids"]
        if (
            not isinstance(pids, list)
            or len(pids) != 2
            or any(type(pid) is not int or pid <= 0 for pid in pids)
            or pids[0] == pids[1]
        ):
            raise PayloadError("descendant_pids must be two distinct positive integers")
    else:
        raise PayloadError(f"scenario cannot publish a result: {scenario!r}")
    return dict(document)


def _read_existing_result(path: Path) -> bytes:
    try:
        return _read_stable_regular(path, limit=MAX_RESULT_BYTES, field="result")
    except CanaryWorkerError as exc:
        raise ResultConflictError(f"unsafe/conflicting existing result: {exc}") from exc


def _publish_bytes_once(path: Path, payload: bytes) -> bool:
    if path.exists() or _is_reparse(path):
        existing = _read_existing_result(path)
        if existing != payload:
            raise ResultConflictError(f"immutable result conflicts: {path}")
        return False
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            existing = _read_existing_result(path)
            if existing != payload:
                raise ResultConflictError(f"concurrent immutable result conflict: {path}")
            return False
        return True
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def publish_result(attempt_dir: Path, document: Mapping[str, Any]) -> bool:
    directory = _validate_existing_path(
        attempt_dir, expect_directory=True, field="attempt_dir"
    )
    return _publish_bytes_once(
        directory / RESULT_FILENAME,
        _canonical_json(_validate_result(document), limit=MAX_RESULT_BYTES),
    )


def _require_result_absent(attempt_dir: Path) -> None:
    path = attempt_dir / RESULT_FILENAME
    if path.exists() or _is_reparse(path):
        raise ResultConflictError(f"scenario requires an empty result slot: {path}")


def _make_result(
    *,
    task_id: str,
    attempt: int,
    nonce: str,
    scenario: str,
    outcome: str,
    descendant_pids: list[int] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "version": 1,
        "kind": "canary-worker-result",
        "task_id": _validate_task_id(task_id),
        "attempt": _validate_attempt(attempt),
        "nonce": _validate_nonce(nonce),
        "scenario": scenario,
        "outcome": outcome,
    }
    if descendant_pids is not None:
        result["descendant_pids"] = descendant_pids
    return _validate_result(result)


def _validated_python_and_bootstrap() -> tuple[Path, Path]:
    # On Windows a venv ``python.exe`` can be a redirector which exits after
    # starting the base interpreter, making Popen.pid cease to identify the
    # worker.  Pin the real base image so the published child PID is the exact
    # process created by Popen and can be proven/contained.
    python_image = getattr(sys, "_base_executable", None) or sys.executable
    python = _validate_existing_path(
        os.path.abspath(python_image), expect_directory=False, field="python executable"
    )
    bootstrap = _validate_existing_path(
        os.path.abspath(__file__), expect_directory=False, field="canary bootstrap"
    )
    return python, bootstrap


def _internal_command(python: Path, bootstrap: Path) -> list[str]:
    return [os.fspath(python), "-I", "-S", os.fspath(bootstrap)]


def _minimal_environment(
    *,
    token: str,
    level: int,
    deadline_ns: int,
    attempt_dir: Path,
    nonce: str,
    python: Path,
    bootstrap: Path,
) -> dict[str, str]:
    environment: dict[str, str] = {}
    for key in ("SystemRoot", "WINDIR", "COMSPEC"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment.update(
        {
            _INTERNAL_TOKEN: token,
            _INTERNAL_LEVEL: str(level),
            _INTERNAL_DEADLINE: str(deadline_ns),
            _INTERNAL_ATTEMPT_DIR: os.fspath(attempt_dir),
            _INTERNAL_NONCE: nonce,
            _INTERNAL_PYTHON: os.fspath(python),
            _INTERNAL_BOOTSTRAP: os.fspath(bootstrap),
        }
    )
    return environment


def _spawn_report_path(attempt_dir: Path, nonce: str) -> Path:
    return attempt_dir / f".canary-spawn-{_validate_nonce(nonce)}.json"


def _publish_spawn_report(
    attempt_dir: Path, *, token: str, nonce: str, descendant_pids: list[int]
) -> None:
    if not _NONCE_RE.fullmatch(token):
        raise PayloadError("invalid private token")
    document = {
        "version": 1,
        "token": token,
        "nonce": _validate_nonce(nonce),
        "descendant_pids": descendant_pids,
    }
    _publish_bytes_once(
        _spawn_report_path(attempt_dir, nonce),
        _canonical_json(document, limit=MAX_RESULT_BYTES),
    )


def _read_spawn_report(
    attempt_dir: Path,
    *,
    token: str,
    nonce: str,
    child_pid: int,
    deadline_ns: int,
) -> list[int]:
    path = _spawn_report_path(attempt_dir, nonce)
    while time.monotonic_ns() < deadline_ns:
        if path.exists() or _is_reparse(path):
            raw = _read_existing_result(path)
            try:
                document = json.loads(
                    raw.decode("ascii"),
                    object_pairs_hook=_pairs_to_object,
                    parse_constant=_reject_constant,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, PayloadError) as exc:
                raise ResultConflictError("invalid private PID report") from exc
            expected = {"version", "token", "nonce", "descendant_pids"}
            if (
                not isinstance(document, dict)
                or set(document) != expected
                or document["version"] != 1
                or document["token"] != token
                or document["nonce"] != nonce
                or _canonical_json(document, limit=MAX_RESULT_BYTES) != raw
            ):
                raise ResultConflictError("private PID report binding mismatch")
            pids = document["descendant_pids"]
            if (
                not isinstance(pids, list)
                or len(pids) != 2
                or any(type(pid) is not int or pid <= 0 for pid in pids)
                or pids[0] != child_pid
                or pids[0] == pids[1]
            ):
                raise ResultConflictError(
                    f"private PID report child binding mismatch: expected {child_pid}, got {pids!r}"
                )
            return pids
        time.sleep(0.01)
    raise CanaryWorkerError("single wall deadline elapsed before PID report")


def _process_image(pid: int) -> Path | None:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            raise CanaryWorkerError(f"cannot open descendant PID {pid} for image proof")
        try:
            capacity = ctypes.c_ulong(32768)
            buffer = ctypes.create_unicode_buffer(capacity.value)
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(capacity)):
                raise CanaryWorkerError(f"cannot query descendant PID {pid} image")
            return Path(buffer.value)
        finally:
            kernel32.CloseHandle(handle)
    proc_link = Path(f"/proc/{pid}/exe")
    if proc_link.exists():
        return Path(os.path.realpath(proc_link))
    return None


def _verify_process_image(pid: int, expected_python: Path) -> None:
    actual = _process_image(pid)
    if actual is not None and _real_normal(actual) != _real_normal(expected_python):
        raise CanaryWorkerError(
            f"descendant image mismatch for PID {pid}: expected {expected_python}, got {actual}"
        )


def _require_current_job() -> None:
    if os.name != "nt":
        raise CanaryWorkerError("spawn-tree requires Windows Job containment")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.IsProcessInJob.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    kernel32.IsProcessInJob.restype = ctypes.c_int
    in_job = ctypes.c_int()
    if not kernel32.IsProcessInJob(kernel32.GetCurrentProcess(), None, ctypes.byref(in_job)):
        raise CanaryWorkerError("cannot prove current process Job membership")
    if not in_job.value:
        raise CanaryWorkerError("--contained-by-job asserted outside a Windows Job")


def _sleep_until(deadline_ns: int) -> None:
    remaining = deadline_ns - time.monotonic_ns()
    if remaining > 0:
        time.sleep(remaining / 1_000_000_000)


def _finish_process(process: subprocess.Popen[bytes], deadline_ns: int) -> None:
    remaining = max(0.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)
    try:
        process.wait(timeout=remaining + 2.0)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)


def _run_spawn_tree(
    *,
    task_id: str,
    attempt: int,
    nonce: str,
    attempt_dir: Path,
    deadline_ns: int,
) -> int:
    _require_current_job()
    python, bootstrap = _validated_python_and_bootstrap()
    token = os.urandom(16).hex()
    report_path = _spawn_report_path(attempt_dir, nonce)
    if report_path.exists() or _is_reparse(report_path):
        raise ResultConflictError(f"private PID report already exists: {report_path}")
    child = subprocess.Popen(
        _internal_command(python, bootstrap),
        cwd=bootstrap.parent.parent,
        env=_minimal_environment(
            token=token,
            level=1,
            deadline_ns=deadline_ns,
            attempt_dir=attempt_dir,
            nonce=nonce,
            python=python,
            bootstrap=bootstrap,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        _verify_process_image(child.pid, python)
        pids = _read_spawn_report(
            attempt_dir,
            token=token,
            nonce=nonce,
            child_pid=child.pid,
            deadline_ns=deadline_ns,
        )
        _verify_process_image(pids[1], python)
        try:
            report_path.unlink()
        except FileNotFoundError as exc:
            raise ResultConflictError("private PID report disappeared") from exc
        publish_result(
            attempt_dir,
            _make_result(
                task_id=task_id,
                attempt=attempt,
                nonce=nonce,
                scenario="spawn-tree",
                outcome="diagnostic",
                descendant_pids=pids,
            ),
        )
        _sleep_until(deadline_ns)
        _finish_process(child, deadline_ns)
        if child.returncode != 0:
            raise CanaryWorkerError(f"descendant helper exit: {child.returncode}")
        return 0
    finally:
        try:
            report_path.unlink()
        except FileNotFoundError:
            pass
        _finish_process(child, deadline_ns)


def _parse_internal_environment() -> tuple[str, int, int, Path, str, Path, Path]:
    if not _INTERNAL_KEYS.issubset(os.environ):
        raise CanaryWorkerError("incomplete private descendant environment")
    if any(key.startswith(_INTERNAL_PREFIX) and key not in _INTERNAL_KEYS for key in os.environ):
        raise CanaryWorkerError("unknown private descendant environment field")
    token = os.environ[_INTERNAL_TOKEN]
    nonce = _validate_nonce(os.environ[_INTERNAL_NONCE])
    if not _NONCE_RE.fullmatch(token):
        raise CanaryWorkerError("invalid private token")
    try:
        level = int(os.environ[_INTERNAL_LEVEL], 10)
        deadline_ns = int(os.environ[_INTERNAL_DEADLINE], 10)
    except ValueError as exc:
        raise CanaryWorkerError("invalid private numeric environment") from exc
    if str(level) != os.environ[_INTERNAL_LEVEL] or level not in (1, 2):
        raise CanaryWorkerError("private level must be 1 or 2")
    if str(deadline_ns) != os.environ[_INTERNAL_DEADLINE]:
        raise CanaryWorkerError("private deadline is not canonical")
    now = time.monotonic_ns()
    if deadline_ns < now - 5_000_000_000 or deadline_ns > now + 31_000_000_000:
        raise CanaryWorkerError("private deadline is outside bounded wall window")
    attempt_dir = _validate_existing_path(
        os.environ[_INTERNAL_ATTEMPT_DIR],
        expect_directory=True,
        field="private attempt_dir",
    )
    python = _validate_existing_path(
        os.environ[_INTERNAL_PYTHON], expect_directory=False, field="private python"
    )
    bootstrap = _validate_existing_path(
        os.environ[_INTERNAL_BOOTSTRAP], expect_directory=False, field="private bootstrap"
    )
    actual_python, actual_bootstrap = _validated_python_and_bootstrap()
    if _normal(python) != _normal(actual_python) or _normal(bootstrap) != _normal(actual_bootstrap):
        raise CanaryWorkerError("private executable/bootstrap binding mismatch")
    return token, level, deadline_ns, attempt_dir, nonce, python, bootstrap


def _run_internal() -> int:
    # The private environment is only a binding between descendants; it is not
    # an authority to create them.  Refuse the private entry point itself unless
    # this process can positively prove that it already belongs to a Windows
    # Job.  This must remain the first operation so a forged environment cannot
    # reach either Popen or the private PID report outside containment.
    _require_current_job()
    token, level, deadline_ns, attempt_dir, nonce, python, bootstrap = (
        _parse_internal_environment()
    )
    if level == 2:
        _sleep_until(deadline_ns)
        return 0
    grandchild = subprocess.Popen(
        _internal_command(python, bootstrap),
        cwd=bootstrap.parent.parent,
        env=_minimal_environment(
            token=token,
            level=2,
            deadline_ns=deadline_ns,
            attempt_dir=attempt_dir,
            nonce=nonce,
            python=python,
            bootstrap=bootstrap,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        _verify_process_image(grandchild.pid, python)
        _publish_spawn_report(
            attempt_dir,
            token=token,
            nonce=nonce,
            descendant_pids=[os.getpid(), grandchild.pid],
        )
        _sleep_until(deadline_ns)
        _finish_process(grandchild, deadline_ns)
        if grandchild.returncode != 0:
            raise CanaryWorkerError(f"grandchild helper exit: {grandchild.returncode}")
        return 0
    finally:
        _finish_process(grandchild, deadline_ns)


def run_canary(
    *,
    queue_root: os.PathLike[str] | str,
    allowed_root: os.PathLike[str] | str,
    payload_path: os.PathLike[str] | str,
    expected_sha256: str,
    attempt_dir: os.PathLike[str] | str,
    task_id: str,
    attempt: int,
    nonce: str,
    contained_by_job: bool = False,
) -> int:
    task = _validate_task_id(task_id)
    number = _validate_attempt(attempt)
    bound_nonce = _validate_nonce(nonce)
    _root, directory = _validate_attempt_dir(
        queue_root, attempt_dir, task_id=task, attempt=number
    )
    if type(contained_by_job) is not bool:
        raise PayloadError("contained_by_job must be bool")

    # This identity-stable open and hash is deliberately the final admission
    # operation immediately before dispatching the selected synthetic action.
    payload = load_payload(
        payload_path,
        allowed_root=allowed_root,
        expected_sha256=expected_sha256,
    )
    scenario = payload["scenario"]
    duration_ms = payload["duration_ms"]
    if scenario == "success":
        publish_result(
            directory,
            _make_result(
                task_id=task,
                attempt=number,
                nonce=bound_nonce,
                scenario=scenario,
                outcome="success",
            ),
        )
        return 0
    if scenario == "fail":
        publish_result(
            directory,
            _make_result(
                task_id=task,
                attempt=number,
                nonce=bound_nonce,
                scenario=scenario,
                outcome="failure",
            ),
        )
        return FAIL_EXIT
    if scenario == "crash":
        _require_result_absent(directory)
        return CRASH_EXIT
    if scenario == "hang":
        _require_result_absent(directory)
        deadline_ns = time.monotonic_ns() + duration_ms * 1_000_000
        _sleep_until(deadline_ns)
        return 0
    if scenario == "spawn-tree":
        _require_result_absent(directory)
        if not contained_by_job:
            raise CanaryWorkerError("spawn-tree requires explicit --contained-by-job")
        deadline_ns = time.monotonic_ns() + duration_ms * 1_000_000
        return _run_spawn_tree(
            task_id=task,
            attempt=number,
            nonce=bound_nonce,
            attempt_dir=directory,
            deadline_ns=deadline_ns,
        )
    raise AssertionError(f"validated scenario is not implemented: {scenario}")


def _attempt_argument(value: str) -> int:
    if value not in {"1", "2"}:
        raise argparse.ArgumentTypeError("attempt must be exactly 1 or 2")
    return int(value)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a bounded synthetic autonomy canary")
    parser.add_argument("--queue-root", required=True)
    parser.add_argument("--allowed-root", required=True)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--attempt-dir", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--attempt", required=True, type=_attempt_argument)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--contained-by-job", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if _INTERNAL_TOKEN in os.environ:
        try:
            return _run_internal()
        except (CanaryWorkerError, OSError) as exc:
            print(f"canary internal error: {exc}", file=sys.stderr)
            return CONFIG_ERROR_EXIT
    arguments = _build_parser().parse_args(argv)
    try:
        return run_canary(
            queue_root=arguments.queue_root,
            allowed_root=arguments.allowed_root,
            payload_path=arguments.payload,
            expected_sha256=arguments.expected_sha256,
            attempt_dir=arguments.attempt_dir,
            task_id=arguments.task_id,
            attempt=arguments.attempt,
            nonce=arguments.nonce,
            contained_by_job=arguments.contained_by_job,
        )
    except (CanaryWorkerError, OSError) as exc:
        print(f"canary error: {exc}", file=sys.stderr)
        return CONFIG_ERROR_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
