"""Fail-closed Windows Task Scheduler boundary for autonomy runners.

Each attempt has two immutable durable authority files in its exact attempt
directory: ``task-spec.json`` and ``runner-task.xml``.  Their bytes bind the
identity, trust roots, file identities, SHA-256 pins, dependency manifest and
the complete Task Scheduler launch contract.  The task-spec's exact digest is
passed independently to the bootstrap and is part of the unique task name.

Launching is one atomic Task Scheduler operation: a new task containing one
``RegistrationTrigger`` is registered with ``/Create``.  There is no query/run
gap and no overwrite flag.  The verified XML is held under a Windows
read-sharing-only handle until ``schtasks`` returns, so the scheduler consumes
the exact bytes which passed validation.

Production resolves ``schtasks.exe`` through ``GetSystemDirectoryW``.  Tests
may inject a different binary only through explicitly test-only arguments and
a SHA-256 pin.  There is no shell and no interpretation of localized output.
Every nonzero mutating command is a fail-closed error.

M4 adds the exact observation/replay boundary.  ``TaskObservation`` classifies
one deterministic task name as ABSENT, PRESENT_EXACT, PRESENT_CONFLICT or
UNKNOWN by comparing a deterministic semantic projection of the registered
definition against this attempt's durable XML contract.  ``schtasks`` cannot
distinguish "no such task" from any other failure without parsing localized
text, so absence is trusted only from the narrow read-only COM adapter's exact
not-found HRESULTs — never from a nonzero or localized CLI result.
``ensure_registered`` and ``ensure_absent`` are the idempotent replay entry
points: a matching existing task is success, a conflicting or differently
bound same-name task fails closed, and a create/delete response loss is
resolved only by a fresh exact inspection.  Every ambiguity fails closed.

Dependency-manifest Python is trusted code.  The static closure scanner and the
bootstrap's private finder bind ordinary imports to reviewed, pinned bytes; they
are integrity/determinism controls and defence-in-depth lint, not an in-process
sandbox against hostile admitted Python.
"""

from __future__ import annotations

import ast
import contextlib
import ctypes
import hashlib
import json
import keyword
import os
import re
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, ContextManager, Final, Mapping, Sequence

__all__ = [
    "TASK_FOLDER",
    "TASK_TIMEOUT",
    "SchedulerError",
    "PathValidationError",
    "TaskIdentity",
    "RunnerPaths",
    "TaskPresence",
    "TaskObservation",
    "TaskProbe",
    "TaskProbeStatus",
    "build_task_name",
    "build_runner_arguments",
    "build_task_xml",
    "TaskSchedulerAdapter",
]

TASK_FOLDER: Final[str] = r"\agentchattr-autonomy-v1"
TASK_TIMEOUT: Final[str] = "PT8H"
SPEC_PREFIX_HEX: Final[int] = 64
_TASK_NS: Final[str] = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_REPARSE_FLAG: Final[int] = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_PROFILE_RE: Final[re.Pattern[str]] = _TASK_ID_RE
_MODEL_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_NONCE_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_SID_RE: Final[re.Pattern[str]] = re.compile(r"^S-1-(?:[0-9]+-)*[0-9]+$")
_TASK_NAME_RE: Final[re.Pattern[str]] = re.compile(
    re.escape(TASK_FOLDER)
    + r"\\(?P<task_id>[a-z0-9][a-z0-9-]{0,63})"
    + r"-a(?P<attempt>[12])-(?P<nonce>[0-9a-f]{32})"
    + rf"-(?P<spec>[0-9a-f]{{{SPEC_PREFIX_HEX}}})$"
)
_WINDOWS_RESERVED: Final[frozenset[str]] = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)
_MAX_MANIFEST_BYTES: Final[int] = 1024 * 1024
_MAX_DURABLE_BYTES: Final[int] = 1024 * 1024
_XML_DECL_ENCODING_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<prefix>(?:^|[ \t\r\n])encoding[ \t\r\n]*=[ \t\r\n]*)"
    r"(?P<quote>['\"])(?P<value>[A-Za-z][A-Za-z0-9._-]*)(?P=quote)"
)
_REQUIRED_DEPENDENCY_PATHS: Final[frozenset[str]] = frozenset(
    {
        "autonomy/__init__.py",
        "autonomy/runner.py",
        "autonomy/supervisor_tick.py",
    }
)

_SECURITY_SETTINGS: Final[dict[str, str]] = {
    "MultipleInstancesPolicy": "IgnoreNew",
    "DisallowStartIfOnBatteries": "false",
    "StopIfGoingOnBatteries": "false",
    "AllowHardTerminate": "true",
    "StartWhenAvailable": "false",
    "RunOnlyIfNetworkAvailable": "false",
    "AllowStartOnDemand": "false",
    "Enabled": "true",
    "Hidden": "true",
    "RunOnlyIfIdle": "false",
    "WakeToRun": "false",
    "ExecutionTimeLimit": TASK_TIMEOUT,
    "Priority": "7",
}
_IDLE_SETTINGS: Final[dict[str, str]] = {
    "StopOnIdleEnd": "false",
    "RestartOnIdle": "false",
}


class SchedulerError(RuntimeError):
    """Stable, output-free failure at the scheduler trust boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PathValidationError(SchedulerError):
    """A path, pin, manifest or immutable file failed validation."""


class TaskPresence(str, Enum):
    PRESENT = "present"
    UNKNOWN = "unknown"


class TaskObservation(str, Enum):
    """Typed exact observation of one deterministic task name.

    ``PRESENT_EXACT`` means the registered definition's semantic projection is
    byte-for-byte semantically identical to this attempt's durable contract.
    ``ABSENT`` is produced only from a trustworthy native not-found signal.
    Every parse, name, principal, action, trigger, settings, argument or
    identity ambiguity is ``PRESENT_CONFLICT`` or ``UNKNOWN``, never exact and
    never absent.
    """

    ABSENT = "absent"
    PRESENT_EXACT = "present-exact"
    PRESENT_CONFLICT = "present-conflict"
    UNKNOWN = "unknown"


class TaskProbeStatus(str, Enum):
    """Raw presence signal produced by the narrow query port."""

    ABSENT = "absent"
    PRESENT = "present"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TaskProbe:
    """Raw query-port result: presence plus the registered definition.

    ``ABSENT`` may come only from an exact native not-found signal (the COM
    adapter's ``HRESULT`` 0x80070002/0x80070003), never from a nonzero or
    localized CLI result.  ``xml`` carries the registered definition bytes of
    a ``PRESENT`` task; ``None`` means the definition could not be read, which
    callers must treat as a conflict, never as exact or absent.
    """

    status: TaskProbeStatus
    xml: bytes | None = None


_CREATE_RESPONSE_LOSS: Final[frozenset[str]] = frozenset(
    {"schtasks-create-nonzero", "schtasks-timeout", "schtasks-exec-failed"}
)
_DELETE_RESPONSE_LOSS: Final[frozenset[str]] = frozenset(
    {"schtasks-delete-nonzero", "schtasks-timeout", "schtasks-exec-failed"}
)


def _validate_task_id(value: object) -> str:
    if not isinstance(value, str) or not _TASK_ID_RE.fullmatch(value):
        raise SchedulerError("task-id-invalid")
    if value.lower() in _WINDOWS_RESERVED:
        raise SchedulerError("task-id-reserved")
    return value


def _validate_attempt(value: object) -> int:
    if type(value) is not int or value not in (1, 2):
        raise SchedulerError("attempt-invalid")
    return value


def _validate_nonce(value: object) -> str:
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise SchedulerError("nonce-invalid")
    return value


def _validate_profile(value: object) -> str:
    if not isinstance(value, str) or not _PROFILE_RE.fullmatch(value):
        raise SchedulerError("profile-invalid")
    if value.lower() in _WINDOWS_RESERVED:
        raise SchedulerError("profile-reserved")
    return value


def _validate_model(value: object) -> str:
    if not isinstance(value, str) or not _MODEL_RE.fullmatch(value):
        raise SchedulerError("model-invalid")
    if ".." in value or value.endswith("."):
        raise SchedulerError("model-invalid")
    return value


def _validate_sha256(value: object) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise PathValidationError("sha256-invalid")
    return value


def _validate_principal_sid(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 184
        or _SID_RE.fullmatch(value) is None
    ):
        raise SchedulerError("principal-sid-invalid")
    return value


def _current_user_sid() -> str:
    """Return the exact process-token user SID without invoking a shell."""

    if os.name != "nt":
        raise SchedulerError("principal-query-unsupported-platform")
    try:
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        open_process_token = advapi32.OpenProcessToken
        open_process_token.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        open_process_token.restype = wintypes.BOOL

        get_token_information = advapi32.GetTokenInformation
        get_token_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_token_information.restype = wintypes.BOOL

        convert_sid = advapi32.ConvertSidToStringSidW
        convert_sid.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
        convert_sid.restype = wintypes.BOOL

        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        local_free = kernel32.LocalFree
        local_free.argtypes = [wintypes.HLOCAL]
        local_free.restype = wintypes.HLOCAL
        get_current_process = kernel32.GetCurrentProcess
        get_current_process.restype = wintypes.HANDLE

        token = wintypes.HANDLE()
        if not open_process_token(get_current_process(), 0x0008, ctypes.byref(token)):
            raise OSError
        try:
            needed = wintypes.DWORD()
            get_token_information(token, 1, None, 0, ctypes.byref(needed))
            if needed.value == 0:
                raise OSError
            buffer = ctypes.create_string_buffer(needed.value)
            if not get_token_information(
                token,
                1,
                ctypes.cast(buffer, wintypes.LPVOID),
                needed,
                ctypes.byref(needed),
            ):
                raise OSError
            sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            if not sid_pointer:
                raise OSError
            sid_text = wintypes.LPWSTR()
            if not convert_sid(sid_pointer, ctypes.byref(sid_text)):
                raise OSError
            try:
                sid = sid_text.value
            finally:
                local_free(ctypes.cast(sid_text, wintypes.HLOCAL))
        finally:
            close_handle(token)
    except (AttributeError, OSError, TypeError, ValueError):
        raise SchedulerError("principal-query-failed") from None
    return _validate_principal_sid(sid)


@dataclass(frozen=True)
class TaskIdentity:
    task_id: str
    attempt: int
    nonce: str
    profile: str
    model: str

    def __post_init__(self) -> None:
        _validate_task_id(self.task_id)
        _validate_attempt(self.attempt)
        _validate_nonce(self.nonce)
        _validate_profile(self.profile)
        _validate_model(self.model)


def build_task_name(
    task_id: str, attempt: int, nonce: str, spec_sha256: str
) -> str:
    task = _validate_task_id(task_id)
    number = _validate_attempt(attempt)
    token = _validate_nonce(nonce)
    spec_hash = _validate_sha256(spec_sha256)
    return (
        f"{TASK_FOLDER}\\{task}-a{number}-{token}-"
        f"{spec_hash[:SPEC_PREFIX_HEX]}"
    )


def _validate_task_name(value: object) -> str:
    if not isinstance(value, str) or _TASK_NAME_RE.fullmatch(value) is None:
        raise SchedulerError("task-name-invalid")
    match = _TASK_NAME_RE.fullmatch(value)
    assert match is not None
    _validate_task_id(match.group("task_id"))
    return value


def _contains_dotdot(path: Path) -> bool:
    return any(part == ".." for part in path.parts)


def _is_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        raise PathValidationError("path-inspection-failed") from None
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_FLAG
    )


def _reject_reparse_components(path: Path) -> None:
    for component in list(reversed(path.parents)) + [path]:
        if not component.exists():
            raise PathValidationError("path-missing")
        if _is_reparse(component):
            raise PathValidationError("path-reparse-forbidden")


def _validated_existing_path(
    value: os.PathLike[str] | str,
    *,
    kind: str,
    executable_name: str | None = None,
) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise PathValidationError("path-invalid")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw:
        raise PathValidationError("path-invalid")
    windows = raw.replace("/", "\\")
    if windows.startswith("\\\\") or windows.startswith("\\??\\"):
        raise PathValidationError("path-unc-device-forbidden")
    drive, tail = os.path.splitdrive(windows)
    if os.name == "nt" and (
        not re.fullmatch(r"[A-Za-z]:", drive) or ":" in tail
    ):
        raise PathValidationError("path-device-forbidden")
    supplied = Path(value)
    if not supplied.is_absolute():
        raise PathValidationError("path-not-absolute")
    if _contains_dotdot(supplied):
        raise PathValidationError("path-traversal-forbidden")
    literal = Path(os.path.abspath(raw))
    if not literal.exists():
        raise PathValidationError("path-missing")
    _reject_reparse_components(literal)
    try:
        mode = os.lstat(literal).st_mode
    except OSError:
        raise PathValidationError("path-inspection-failed") from None
    if kind == "file" and not stat.S_ISREG(mode):
        raise PathValidationError("path-not-file")
    if kind == "directory" and not stat.S_ISDIR(mode):
        raise PathValidationError("path-not-directory")
    if executable_name is not None and literal.name.lower() != executable_name:
        raise PathValidationError("executable-name-invalid")
    if os.path.normcase(os.path.realpath(literal)) != os.path.normcase(
        os.path.abspath(literal)
    ):
        raise PathValidationError("path-resolution-ambiguous")
    return literal


def _same_path(left: Path, right: Path) -> bool:
    return (
        os.path.normcase(os.path.abspath(left))
        == os.path.normcase(os.path.abspath(right))
        and os.path.normcase(os.path.realpath(left))
        == os.path.normcase(os.path.realpath(right))
    )


def _is_contained(child: Path, parent: Path, *, strict: bool = True) -> bool:
    child_text = os.path.normcase(os.path.abspath(child))
    parent_text = os.path.normcase(os.path.abspath(parent))
    try:
        common = os.path.commonpath([child_text, parent_text])
    except ValueError:
        return False
    return common == parent_text and (not strict or child_text != parent_text)


def _require_containment(child: Path, parent: Path, code: str) -> None:
    if not _is_contained(child, parent):
        raise PathValidationError(code)
    if not _is_contained(Path(os.path.realpath(child)), Path(os.path.realpath(parent))):
        raise PathValidationError(code)


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int

    def mapping(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
        }


def _stat_identity(path: Path) -> _FileIdentity:
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        raise PathValidationError("file-stat-failed") from None
    if not stat.S_ISREG(info.st_mode):
        raise PathValidationError("path-not-file")
    return _FileIdentity(
        int(info.st_dev), int(info.st_ino), int(info.st_size), int(info.st_mtime_ns)
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        raise PathValidationError("file-read-failed") from None
    return digest.hexdigest()


@dataclass(frozen=True)
class _PinnedFile:
    path: Path
    sha256: str
    identity: _FileIdentity

    @classmethod
    def capture(cls, path: Path, expected_sha256: str) -> "_PinnedFile":
        expected = _validate_sha256(expected_sha256)
        before = _stat_identity(path)
        actual = _hash_file(path)
        after = _stat_identity(path)
        if before != after:
            raise PathValidationError("file-changed-during-hash")
        if actual != expected:
            raise PathValidationError("file-hash-mismatch")
        return cls(path, expected, before)

    @classmethod
    def capture_current(cls, path: Path) -> "_PinnedFile":
        before = _stat_identity(path)
        actual = _hash_file(path)
        after = _stat_identity(path)
        if before != after:
            raise PathValidationError("file-changed-during-hash")
        return cls(path, actual, before)

    def verify(self) -> None:
        before = _stat_identity(self.path)
        if before != self.identity:
            raise PathValidationError("file-identity-mismatch")
        actual = _hash_file(self.path)
        after = _stat_identity(self.path)
        if before != after:
            raise PathValidationError("file-changed-during-hash")
        if actual != self.sha256:
            raise PathValidationError("file-hash-mismatch")

    def mapping(self) -> dict[str, Any]:
        return {
            "path": os.fspath(self.path),
            "sha256": self.sha256,
            "identity": self.identity.mapping(),
        }


def _reject_constant(value: str) -> None:
    raise PathValidationError("json-constant-forbidden")


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PathValidationError("json-duplicate-key")
        result[key] = value
    return result


def _read_bounded(path: Path, limit: int, code: str) -> bytes:
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError:
        raise PathValidationError(code) from None
    if len(raw) > limit:
        raise PathValidationError("file-too-large")
    return raw


def _dependency_module(relative: str) -> tuple[str, bool]:
    parts = PurePosixPath(relative).parts
    if (
        len(parts) < 2
        or parts[0] != "autonomy"
        or not parts[-1].endswith(".py")
    ):
        raise PathValidationError("manifest-entry-not-python-module")
    leaf = parts[-1][:-3]
    package = leaf == "__init__"
    module_parts = parts[:-1] if package else (*parts[:-1], leaf)
    if not module_parts or any(
        not part.isascii()
        or not part.isidentifier()
        or keyword.iskeyword(part)
        for part in module_parts
    ):
        raise PathValidationError("manifest-module-invalid")
    return ".".join(module_parts), package


_DYNAMIC_IMPORT_MODULE_ROOTS: Final[frozenset[str]] = frozenset(
    {"builtins", "importlib", "pkgutil", "runpy", "zipimport"}
)
_DYNAMIC_CAPABILITY_NAMES: Final[frozenset[str]] = frozenset(
    {
        "__builtins__",
        "__import__",
        "__loader__",
        "__spec__",
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "locals",
        "vars",
    }
)
_DYNAMIC_ATTRIBUTE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "__import__",
        "exec_module",
        "find_loader",
        "find_spec",
        "import_module",
        "iter_modules",
        "load_module",
        "module_from_spec",
        "run_module",
        "run_path",
        "spec_from_file_location",
        "walk_packages",
    }
)
_DYNAMIC_SUBSCRIPT_KEYS: Final[frozenset[str]] = frozenset(
    _DYNAMIC_CAPABILITY_NAMES | _DYNAMIC_ATTRIBUTE_NAMES | {"modules"}
)


class _AutonomyImportScanner(ast.NodeVisitor):
    """Build the static pinned-module closure and reject obvious ambiguity.

    This is intentionally not a Python capability sandbox.  All accepted source
    is trusted and reviewed; these conservative checks catch accidental dynamic
    imports that would defeat deterministic ordinary-import closure.
    """

    def __init__(
        self,
        modules: Mapping[str, tuple[str, "_PinnedFile"]],
        packages: frozenset[str],
    ) -> None:
        self._modules = modules
        self._packages = packages
        self.required: set[str] = set()

    def scan(self, tree: ast.AST) -> set[str]:
        self.visit(tree)
        return self.required

    @staticmethod
    def _reject_dynamic() -> None:
        raise PathValidationError("manifest-dynamic-import-forbidden")

    def _require(self, module: str) -> None:
        if module not in self._modules:
            raise PathValidationError("manifest-import-missing")
        parts = module.split(".")
        for index in range(1, len(parts)):
            parent = ".".join(parts[:index])
            if parent not in self._packages:
                raise PathValidationError("manifest-package-missing")
            self.required.add(parent)
        self.required.add(module)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name.split(".", 1)[0] in _DYNAMIC_IMPORT_MODULE_ROOTS:
                self._reject_dynamic()
            if alias.name == "autonomy" or alias.name.startswith("autonomy."):
                self._require(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            raise PathValidationError("manifest-relative-import-forbidden")
        module = node.module
        if module is None:
            raise PathValidationError("manifest-import-ambiguous")
        if module.split(".", 1)[0] in _DYNAMIC_IMPORT_MODULE_ROOTS:
            self._reject_dynamic()
        if module == "sys" and any(alias.name == "modules" for alias in node.names):
            self._reject_dynamic()
        if module != "autonomy" and not module.startswith("autonomy."):
            return
        self._require(module)
        for alias in node.names:
            if alias.name == "*":
                raise PathValidationError("manifest-import-ambiguous")
            candidate = f"{module}.{alias.name}"
            if candidate in self._modules:
                self._require(candidate)
            elif module in self._packages:
                # A name imported from a package could be either a submodule or
                # a runtime-created attribute.  The closed manifest may not
                # guess which one was intended.
                raise PathValidationError("manifest-import-ambiguous")

    def visit_Name(self, node: ast.Name) -> None:
        # Reject the capability at its first reference, not merely when it is
        # called.  This closes source-order-independent aliases such as
        # ``load = __import__`` and ``run = eval``.
        if node.id in _DYNAMIC_CAPABILITY_NAMES:
            self._reject_dynamic()

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _DYNAMIC_ATTRIBUTE_NAMES or node.attr == "__dict__":
            self._reject_dynamic()
        # ``sys.modules`` is a dynamic import/cache escape even when ``sys``
        # was bound under an alias.  Conservatively reject every ``.modules``
        # attribute rather than attempting incomplete name-flow inference.
        if node.attr == "modules":
            self._reject_dynamic()
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        key = node.slice
        if isinstance(key, ast.Constant) and key.value in _DYNAMIC_SUBSCRIPT_KEYS:
            self._reject_dynamic()
        self.generic_visit(node)


def _verify_dependency_closure(
    dependencies: Sequence[tuple[str, "_PinnedFile"]],
) -> None:
    by_module: dict[str, tuple[str, _PinnedFile]] = {}
    packages: set[str] = set()
    for relative, pin in dependencies:
        module, package = _dependency_module(relative)
        if module in by_module:
            raise PathValidationError("manifest-module-duplicate")
        by_module[module] = (relative, pin)
        if package:
            packages.add(module)

    paths = {relative for relative, _ in dependencies}
    if not _REQUIRED_DEPENDENCY_PATHS.issubset(paths):
        raise PathValidationError("manifest-required-entry-missing")

    required_modules = {
        "autonomy",
        "autonomy.runner",
        "autonomy.supervisor_tick",
    }
    pending = list(sorted(required_modules))
    visited: set[str] = set()
    package_set = frozenset(packages)
    while pending:
        module = pending.pop()
        if module in visited:
            continue
        entry = by_module.get(module)
        if entry is None:
            raise PathValidationError("manifest-import-missing")
        relative, pin = entry
        try:
            before = _stat_identity(pin.path)
            if before != pin.identity:
                raise PathValidationError("file-identity-mismatch")
            raw = _read_bounded(pin.path, _MAX_DURABLE_BYTES, "manifest-source-read-failed")
            after = _stat_identity(pin.path)
            if before != after:
                raise PathValidationError("file-changed-during-hash")
            if hashlib.sha256(raw).hexdigest() != pin.sha256:
                raise PathValidationError("file-hash-mismatch")
            source = raw.decode("utf-8-sig", errors="strict")
            tree = ast.parse(source, filename=relative, mode="exec")
        except PathValidationError:
            raise
        except (UnicodeDecodeError, SyntaxError, ValueError, TypeError):
            raise PathValidationError("manifest-source-invalid") from None
        scanner = _AutonomyImportScanner(by_module, package_set)
        scanner.scan(tree)
        visited.add(module)
        pending.extend(sorted(scanner.required - visited))

    if visited != set(by_module):
        raise PathValidationError("manifest-entry-not-required")


def _parse_dependency_manifest(
    manifest: Path, repo: Path
) -> tuple[tuple[str, _PinnedFile], ...]:
    raw = _read_bounded(manifest, _MAX_MANIFEST_BYTES, "manifest-read-failed")
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_pairs_object,
            parse_constant=_reject_constant,
        )
    except PathValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise PathValidationError("manifest-json-invalid") from None
    if not isinstance(document, dict) or set(document) != {"version", "dependencies"}:
        raise PathValidationError("manifest-schema-invalid")
    if type(document["version"]) is not int or document["version"] != 1:
        raise PathValidationError("manifest-schema-invalid")
    dependencies = document["dependencies"]
    if not isinstance(dependencies, list) or not dependencies:
        raise PathValidationError("manifest-schema-invalid")

    seen: set[str] = set()
    pinned: list[tuple[str, _PinnedFile]] = []
    for entry in dependencies:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise PathValidationError("manifest-schema-invalid")
        relative = entry["path"]
        if not isinstance(relative, str) or not relative or len(relative) > 240:
            raise PathValidationError("manifest-path-invalid")
        if "\\" in relative or ":" in relative or "\x00" in relative:
            raise PathValidationError("manifest-path-invalid")
        pure = PurePosixPath(relative)
        parts = pure.parts
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in parts):
            raise PathValidationError("manifest-traversal-forbidden")
        if pure.as_posix() != relative:
            raise PathValidationError("manifest-path-invalid")
        for part in parts:
            if (
                part.rstrip(" .") != part
                or part.split(".", 1)[0].lower() in _WINDOWS_RESERVED
            ):
                raise PathValidationError("manifest-path-invalid")
        duplicate_key = relative.casefold()
        if duplicate_key in seen:
            raise PathValidationError("manifest-duplicate-path")
        seen.add(duplicate_key)
        path = _validated_existing_path(repo.joinpath(*parts), kind="file")
        _require_containment(path, repo, "dependency-outside-repo")
        pinned.append((relative, _PinnedFile.capture(path, entry["sha256"])))
    result = tuple(sorted(pinned, key=lambda item: item[0].casefold()))
    _verify_dependency_closure(result)
    return result


@dataclass(frozen=True, init=False)
class RunnerPaths:
    approved_repo_root: Path
    python: Path
    repo: Path
    root: Path
    config: Path
    bootstrap: Path
    dependency_manifest: Path
    _python_pin: _PinnedFile
    _config_pin: _PinnedFile
    _bootstrap_pin: _PinnedFile
    _manifest_pin: _PinnedFile
    _dependencies: tuple[tuple[str, _PinnedFile], ...]

    @classmethod
    def validate(
        cls,
        *,
        approved_repo_root: os.PathLike[str] | str,
        python: os.PathLike[str] | str,
        repo: os.PathLike[str] | str,
        root: os.PathLike[str] | str,
        config: os.PathLike[str] | str,
        dependency_manifest: os.PathLike[str] | str,
        python_sha256: str,
        config_sha256: str,
        bootstrap_sha256: str,
        dependency_manifest_sha256: str,
    ) -> "RunnerPaths":
        approved = _validated_existing_path(approved_repo_root, kind="directory")
        repo_path = _validated_existing_path(repo, kind="directory")
        if not _same_path(approved, repo_path):
            raise PathValidationError("repo-not-approved")
        root_path = _validated_existing_path(root, kind="directory")
        config_path = _validated_existing_path(config, kind="file")
        manifest_path = _validated_existing_path(dependency_manifest, kind="file")
        python_path = _validated_existing_path(
            python, kind="file", executable_name="python.exe"
        )
        bootstrap = _validated_existing_path(
            repo_path / "autonomy" / "runner_bootstrap.py", kind="file"
        )
        _require_containment(root_path, repo_path, "root-outside-repo")
        _require_containment(config_path, root_path, "config-outside-root")
        _require_containment(manifest_path, root_path, "manifest-outside-root")
        if not _same_path(
            python_path, repo_path / ".venv" / "Scripts" / "python.exe"
        ):
            raise PathValidationError("python-not-approved-venv")

        python_pin = _PinnedFile.capture(python_path, python_sha256)
        config_pin = _PinnedFile.capture(config_path, config_sha256)
        bootstrap_pin = _PinnedFile.capture(bootstrap, bootstrap_sha256)
        manifest_pin = _PinnedFile.capture(manifest_path, dependency_manifest_sha256)
        dependencies = _parse_dependency_manifest(manifest_path, repo_path)
        manifest_pin.verify()

        instance = object.__new__(cls)
        for field, value in (
            ("approved_repo_root", approved),
            ("python", python_path),
            ("repo", repo_path),
            ("root", root_path),
            ("config", config_path),
            ("bootstrap", bootstrap),
            ("dependency_manifest", manifest_path),
            ("_python_pin", python_pin),
            ("_config_pin", config_pin),
            ("_bootstrap_pin", bootstrap_pin),
            ("_manifest_pin", manifest_pin),
            ("_dependencies", dependencies),
        ):
            object.__setattr__(instance, field, value)
        return instance

    def revalidate(self) -> None:
        # Re-run every path/reparse/containment check, then identity+hash pins.
        approved = _validated_existing_path(self.approved_repo_root, kind="directory")
        repo = _validated_existing_path(self.repo, kind="directory")
        root = _validated_existing_path(self.root, kind="directory")
        config = _validated_existing_path(self.config, kind="file")
        manifest = _validated_existing_path(self.dependency_manifest, kind="file")
        python = _validated_existing_path(
            self.python, kind="file", executable_name="python.exe"
        )
        bootstrap = _validated_existing_path(self.bootstrap, kind="file")
        if not _same_path(approved, repo):
            raise PathValidationError("repo-not-approved")
        _require_containment(root, repo, "root-outside-repo")
        _require_containment(config, root, "config-outside-root")
        _require_containment(manifest, root, "manifest-outside-root")
        if not _same_path(python, repo / ".venv" / "Scripts" / "python.exe"):
            raise PathValidationError("python-not-approved-venv")
        if not _same_path(bootstrap, repo / "autonomy" / "runner_bootstrap.py"):
            raise PathValidationError("bootstrap-path-changed")
        self._python_pin.verify()
        self._config_pin.verify()
        self._bootstrap_pin.verify()
        self._manifest_pin.verify()
        for _, pin in self._dependencies:
            _validated_existing_path(pin.path, kind="file")
            _require_containment(pin.path, repo, "dependency-outside-repo")
            pin.verify()


def _attempt_dir(identity: TaskIdentity, paths: RunnerPaths) -> Path:
    expected = paths.root / "attempts" / identity.task_id / f"a{identity.attempt}"
    directory = _validated_existing_path(expected, kind="directory")
    _require_containment(directory, paths.root, "attempt-outside-root")
    return directory


def _runner_argument_base(
    identity: TaskIdentity, paths: RunnerPaths, spec_path: Path
) -> tuple[str, ...]:
    return (
        "-I",
        "-S",
        os.fspath(paths.bootstrap),
        "--root",
        os.fspath(paths.root),
        "--task-id",
        identity.task_id,
        "--attempt",
        str(identity.attempt),
        "--nonce",
        identity.nonce,
        "--profile",
        identity.profile,
        "--model",
        identity.model,
        "--config",
        os.fspath(paths.config),
        "--dependency-manifest",
        os.fspath(paths.dependency_manifest),
        "--task-spec",
        os.fspath(spec_path),
    )


def _runner_arguments(
    identity: TaskIdentity,
    paths: RunnerPaths,
    spec_path: Path,
    spec_sha256: str,
) -> tuple[str, ...]:
    return (
        *_runner_argument_base(identity, paths, spec_path),
        "--task-spec-sha256",
        _validate_sha256(spec_sha256),
    )


def build_runner_arguments(identity: TaskIdentity, paths: RunnerPaths) -> tuple[str, ...]:
    if not isinstance(identity, TaskIdentity) or not isinstance(paths, RunnerPaths):
        raise SchedulerError("runner-spec-invalid")
    return _expected_task(identity, paths).arguments


def _canonical_json(document: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                dict(document),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise SchedulerError("task-spec-serialization-failed") from None


def _spec_document(
    identity: TaskIdentity,
    paths: RunnerPaths,
    attempt: Path,
    principal_sid: str,
) -> dict[str, Any]:
    spec_path = attempt / "task-spec.json"
    return {
        "version": 1,
        "identity": {
            "task_id": identity.task_id,
            "attempt": identity.attempt,
            "nonce": identity.nonce,
            "profile": identity.profile,
            "model": identity.model,
        },
        "paths": {
            "approved_repo_root": os.fspath(paths.approved_repo_root),
            "repo": os.fspath(paths.repo),
            "root": os.fspath(paths.root),
            "attempt": os.fspath(attempt),
            "config": os.fspath(paths.config),
            "bootstrap": os.fspath(paths.bootstrap),
            "dependency_manifest": os.fspath(paths.dependency_manifest),
            "task_spec": os.fspath(spec_path),
            "task_xml": os.fspath(attempt / "runner-task.xml"),
        },
        "pins": {
            "python": paths._python_pin.mapping(),
            "config": paths._config_pin.mapping(),
            "bootstrap": paths._bootstrap_pin.mapping(),
            "dependency_manifest": paths._manifest_pin.mapping(),
            "dependencies": [
                {"relative_path": relative, **pin.mapping()}
                for relative, pin in paths._dependencies
            ],
        },
        "launch": {
            "command": os.fspath(paths.python),
            # The exact spec digest cannot be embedded in the bytes it hashes.
            # XML appends --task-spec-sha256 to this otherwise-complete argv.
            "arguments_before_task_spec_sha256": list(
                _runner_argument_base(identity, paths, spec_path)
            ),
            "task_spec_sha256_argument": "--task-spec-sha256",
            "working_directory": os.fspath(paths.repo),
        },
        "scheduler_policy": {
            "folder": TASK_FOLDER,
            "principal_user_sid": principal_sid,
            "logon_type": "InteractiveToken",
            "run_level": "LeastPrivilege",
            "settings": dict(_SECURITY_SETTINGS),
            "idle_settings": dict(_IDLE_SETTINGS),
            "triggers": [
                {"type": "RegistrationTrigger", "enabled": True}
            ],
        },
    }


def _child(
    parent: ET.Element, tag: str, text: str | None = None, **attrs: str
) -> ET.Element:
    node = ET.SubElement(parent, f"{{{_TASK_NS}}}{tag}", attrs)
    if text is not None:
        node.text = text
    return node


def _task_xml(
    *,
    task_name: str,
    principal_sid: str,
    command: str,
    arguments: Sequence[str],
    cwd: str,
) -> str:
    ET.register_namespace("", _TASK_NS)
    task = ET.Element(f"{{{_TASK_NS}}}Task", {"version": "1.2"})
    registration = _child(task, "RegistrationInfo")
    _child(registration, "URI", task_name)
    triggers = _child(task, "Triggers")
    registration_trigger = _child(triggers, "RegistrationTrigger")
    _child(registration_trigger, "Enabled", "true")
    principals = _child(task, "Principals")
    principal = _child(principals, "Principal", None, id="Author")
    _child(principal, "UserId", _validate_principal_sid(principal_sid))
    _child(principal, "LogonType", "InteractiveToken")
    _child(principal, "RunLevel", "LeastPrivilege")
    settings = _child(task, "Settings")
    for key, value in _SECURITY_SETTINGS.items():
        if key == "AllowStartOnDemand":
            idle = _child(settings, "IdleSettings")
            for idle_key, idle_value in _IDLE_SETTINGS.items():
                _child(idle, idle_key, idle_value)
        _child(settings, key, value)
    actions = _child(task, "Actions", None, Context="Author")
    execute = _child(actions, "Exec")
    _child(execute, "Command", command)
    _child(execute, "Arguments", subprocess.list2cmdline(list(arguments)))
    _child(execute, "WorkingDirectory", cwd)
    body = ET.tostring(task, encoding="unicode", short_empty_elements=True)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body


@dataclass(frozen=True)
class _ExpectedTask:
    name: str
    spec_path: Path
    xml_path: Path
    spec_bytes: bytes
    spec_sha256: str
    xml_bytes: bytes
    principal_sid: str
    arguments: tuple[str, ...]


def _expected_task(identity: TaskIdentity, paths: RunnerPaths) -> _ExpectedTask:
    paths.revalidate()
    attempt = _attempt_dir(identity, paths)
    principal_sid = _current_user_sid()
    spec_bytes = _canonical_json(
        _spec_document(identity, paths, attempt, principal_sid)
    )
    spec_sha = hashlib.sha256(spec_bytes).hexdigest()
    name = build_task_name(identity.task_id, identity.attempt, identity.nonce, spec_sha)
    args = _runner_arguments(
        identity, paths, attempt / "task-spec.json", spec_sha
    )
    xml = _task_xml(
        task_name=name,
        principal_sid=principal_sid,
        command=os.fspath(paths.python),
        arguments=args,
        cwd=os.fspath(paths.repo),
    )
    xml_bytes = xml.encode("utf-8")
    if _xml_fingerprint(xml_bytes) != (
        name,
        principal_sid,
        os.fspath(paths.python),
        subprocess.list2cmdline(list(args)),
        os.fspath(paths.repo),
    ):
        raise SchedulerError("task-xml-invalid")
    return _ExpectedTask(
        name,
        attempt / "task-spec.json",
        attempt / "runner-task.xml",
        spec_bytes,
        spec_sha,
        xml_bytes,
        principal_sid,
        args,
    )


def build_task_xml(identity: TaskIdentity, paths: RunnerPaths) -> str:
    if not isinstance(identity, TaskIdentity) or not isinstance(paths, RunnerPaths):
        raise SchedulerError("task-spec-invalid")
    return _expected_task(identity, paths).xml_bytes.decode("utf-8")


def _read_existing_exact(path: Path, expected: bytes, conflict_code: str) -> None:
    validated = _validated_existing_path(path, kind="file")
    raw = _read_bounded(validated, _MAX_DURABLE_BYTES, "durable-read-failed")
    if raw != expected:
        raise SchedulerError(conflict_code)


def _publish_or_match(path: Path, expected: bytes, conflict_code: str) -> _PinnedFile:
    if len(expected) > _MAX_DURABLE_BYTES:
        raise SchedulerError("durable-file-too-large")
    if path.exists() or _is_reparse_if_present(path):
        _read_existing_exact(path, expected, conflict_code)
        return _PinnedFile.capture(path, hashlib.sha256(expected).hexdigest())
    try:
        fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    except OSError:
        raise SchedulerError("durable-temp-create-failed") from None
    temp = Path(raw_temp)
    primary = False
    try:
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            raise SchedulerError("durable-temp-write-failed") from None
        try:
            os.link(temp, path)
        except FileExistsError:
            _read_existing_exact(path, expected, conflict_code)
        except OSError:
            raise SchedulerError("durable-publish-failed") from None
    except BaseException:
        primary = True
        raise
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            if not primary:
                raise SchedulerError("durable-temp-cleanup-failed") from None
    return _PinnedFile.capture(path, hashlib.sha256(expected).hexdigest())


def _is_reparse_if_present(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        raise PathValidationError("path-inspection-failed") from None
    return _is_reparse(path)


def _require_durable_match_if_present(expected: _ExpectedTask) -> None:
    """Fail closed when a surviving durable authority file disagrees.

    Teardown never creates missing durable files; it only refuses to proceed
    when an existing ``task-spec.json`` or ``runner-task.xml`` differs from
    this attempt's computed contract, so a differently bound registration can
    never be targeted for deletion.
    """

    for path, blob, code in (
        (expected.spec_path, expected.spec_bytes, "durable-spec-conflict"),
        (expected.xml_path, expected.xml_bytes, "durable-xml-conflict"),
    ):
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            raise PathValidationError("path-inspection-failed") from None
        _read_existing_exact(path, blob, code)


@dataclass(frozen=True)
class _DurableTask:
    expected: _ExpectedTask
    paths: RunnerPaths
    spec_pin: _PinnedFile
    xml_pin: _PinnedFile

    def verify_for_create(self, locked_xml: BinaryIO) -> None:
        # This is the final local-file validation before Create.  XML is read
        # through the handle whose sharing mode remains in force for Create.
        self.paths.revalidate()
        self.spec_pin.verify()
        _verify_locked_xml(locked_xml, self.xml_pin, self.expected, self.paths)


def _publish_task(expected: _ExpectedTask, paths: RunnerPaths) -> _DurableTask:
    spec_pin = _publish_or_match(
        expected.spec_path, expected.spec_bytes, "durable-spec-conflict"
    )
    xml_pin = _publish_or_match(
        expected.xml_path, expected.xml_bytes, "durable-xml-conflict"
    )
    return _DurableTask(expected, paths, spec_pin, xml_pin)


def _identity_from_stat(info: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        int(info.st_dev), int(info.st_ino), int(info.st_size), int(info.st_mtime_ns)
    )


def _verify_locked_xml(
    stream: BinaryIO,
    pin: _PinnedFile,
    expected: _ExpectedTask,
    paths: RunnerPaths,
) -> None:
    try:
        descriptor = stream.fileno()
        before = _identity_from_stat(os.fstat(descriptor))
        if before != pin.identity:
            raise PathValidationError("file-identity-mismatch")
        stream.seek(0)
        digest = hashlib.sha256()
        total = 0
        while chunk := stream.read(1024 * 1024):
            if not isinstance(chunk, bytes):
                raise PathValidationError("locked-file-read-failed")
            total += len(chunk)
            if total > _MAX_DURABLE_BYTES:
                raise PathValidationError("file-too-large")
            digest.update(chunk)
        after = _identity_from_stat(os.fstat(descriptor))
    except SchedulerError:
        raise
    except (OSError, AttributeError, TypeError, ValueError):
        raise PathValidationError("locked-file-read-failed") from None
    if before != after:
        raise PathValidationError("file-changed-during-hash")
    if digest.hexdigest() != pin.sha256:
        raise PathValidationError("file-hash-mismatch")

    # The open handle and pathname must still identify the published file.
    validated = _validated_existing_path(pin.path, kind="file")
    if _stat_identity(validated) != before:
        raise PathValidationError("file-identity-mismatch")
    try:
        stream.seek(0)
        raw = stream.read(_MAX_DURABLE_BYTES + 1)
    except (OSError, AttributeError, TypeError, ValueError):
        raise PathValidationError("locked-file-read-failed") from None
    if not isinstance(raw, bytes) or len(raw) > _MAX_DURABLE_BYTES:
        raise PathValidationError("locked-file-read-failed")
    # Byte pinning is authoritative; fingerprinting independently rejects a
    # malformed local authority file and, in particular, any ignored UserId.
    if _xml_fingerprint(raw) != (
        expected.name,
        expected.principal_sid,
        os.fspath(paths.python),
        subprocess.list2cmdline(list(expected.arguments)),
        os.fspath(paths.repo),
    ):
        raise SchedulerError("task-xml-mismatch")


@contextlib.contextmanager
def _lock_xml_readonly(path: Path) -> Any:
    """Open *path* with read sharing only, denying write/delete/replace."""

    if os.name != "nt":
        raise SchedulerError("xml-lock-unsupported-platform")
    try:
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        handle = create_file(
            os.fspath(path),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ only
            None,
            3,  # OPEN_EXISTING
            0x00000080 | 0x00200000,  # NORMAL | OPEN_REPARSE_POINT
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle is None or int(handle) == invalid:
            raise OSError
        try:
            descriptor = msvcrt.open_osfhandle(
                int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
        except (OSError, OverflowError):
            close_handle(handle)
            raise
        # Ownership of the Windows handle moved to the CRT descriptor.
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            yield stream
    except SchedulerError:
        raise
    except (AttributeError, OSError, TypeError, ValueError, OverflowError):
        raise SchedulerError("xml-lock-failed") from None


def _get_system_directory() -> Path:
    if os.name != "nt":
        raise PathValidationError("unsupported-platform")
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        function = kernel32.GetSystemDirectoryW
        function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        function.restype = ctypes.c_uint
        size = 32768
        buffer = ctypes.create_unicode_buffer(size)
        result = int(function(buffer, size))
    except (AttributeError, OSError, TypeError, ValueError):
        raise PathValidationError("system-directory-query-failed") from None
    if result == 0 or result >= size or not buffer.value:
        raise PathValidationError("system-directory-query-failed")
    return Path(buffer.value)


def _q(tag: str) -> str:
    return f"{{{_TASK_NS}}}{tag}"


def _one(parent: ET.Element, tag: str) -> ET.Element:
    nodes = parent.findall(_q(tag))
    if len(nodes) != 1:
        raise SchedulerError("task-xml-invalid")
    return nodes[0]


def _text(parent: ET.Element, tag: str) -> str:
    node = _one(parent, tag)
    if node.text is None or list(node):
        raise SchedulerError("task-xml-invalid")
    return node.text


def _exact_children(parent: ET.Element, tags: Sequence[str]) -> None:
    if [child.tag for child in parent] != [_q(tag) for tag in tags]:
        raise SchedulerError("task-xml-invalid")


def _no_attributes(*nodes: ET.Element) -> None:
    if any(node.attrib for node in nodes):
        raise SchedulerError("task-xml-invalid")


def _no_mixed_text(*nodes: ET.Element) -> None:
    for node in nodes:
        if node.text is not None and node.text.strip():
            raise SchedulerError("task-xml-invalid")
        if any(child.tail is not None and child.tail.strip() for child in node):
            raise SchedulerError("task-xml-invalid")


def _xml_fingerprint(raw: bytes) -> tuple[Any, ...]:
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError, UnicodeError):
        raise SchedulerError("task-xml-invalid") from None
    if root.tag != _q("Task") or root.attrib != {"version": "1.2"}:
        raise SchedulerError("task-xml-invalid")
    if root.tail is not None and root.tail.strip():
        raise SchedulerError("task-xml-invalid")
    _exact_children(
        root, ["RegistrationInfo", "Triggers", "Principals", "Settings", "Actions"]
    )
    registration = _one(root, "RegistrationInfo")
    _no_attributes(registration)
    _no_mixed_text(root, registration)
    _exact_children(registration, ["URI"])
    uri = _text(registration, "URI")
    uri_node = _one(registration, "URI")
    _no_attributes(uri_node)

    triggers = _one(root, "Triggers")
    _no_attributes(triggers)
    _no_mixed_text(triggers)
    _exact_children(triggers, ["RegistrationTrigger"])
    trigger = _one(triggers, "RegistrationTrigger")
    _no_attributes(trigger)
    _no_mixed_text(trigger)
    _exact_children(trigger, ["Enabled"])
    enabled_node = _one(trigger, "Enabled")
    _no_attributes(enabled_node)
    if _text(trigger, "Enabled") != "true":
        raise SchedulerError("task-xml-invalid")

    principals = _one(root, "Principals")
    _no_attributes(principals)
    _no_mixed_text(principals)
    _exact_children(principals, ["Principal"])
    principal = _one(principals, "Principal")
    if principal.attrib != {"id": "Author"}:
        raise SchedulerError("task-xml-invalid")
    _no_mixed_text(principal)
    _exact_children(principal, ["UserId", "LogonType", "RunLevel"])
    try:
        user_sid = _validate_principal_sid(_text(principal, "UserId"))
    except SchedulerError:
        raise SchedulerError("task-xml-invalid") from None
    logon = _text(principal, "LogonType")
    run_level = _text(principal, "RunLevel")
    _no_attributes(
        _one(principal, "UserId"),
        _one(principal, "LogonType"),
        _one(principal, "RunLevel"),
    )
    if logon != "InteractiveToken" or run_level != "LeastPrivilege":
        raise SchedulerError("task-xml-invalid")

    settings_node = _one(root, "Settings")
    _no_attributes(settings_node)
    _no_mixed_text(settings_node)
    setting_tags: list[str] = []
    for key in _SECURITY_SETTINGS:
        if key == "AllowStartOnDemand":
            setting_tags.append("IdleSettings")
        setting_tags.append(key)
    _exact_children(settings_node, setting_tags)
    for key, expected_value in _SECURITY_SETTINGS.items():
        node = _one(settings_node, key)
        _no_attributes(node)
        if _text(settings_node, key) != expected_value:
            raise SchedulerError("task-xml-invalid")
    idle = _one(settings_node, "IdleSettings")
    _no_attributes(idle)
    _no_mixed_text(idle)
    _exact_children(idle, list(_IDLE_SETTINGS))
    for key, expected_value in _IDLE_SETTINGS.items():
        node = _one(idle, key)
        _no_attributes(node)
        if _text(idle, key) != expected_value:
            raise SchedulerError("task-xml-invalid")

    actions = _one(root, "Actions")
    if actions.attrib != {"Context": "Author"}:
        raise SchedulerError("task-xml-invalid")
    _no_mixed_text(actions)
    _exact_children(actions, ["Exec"])
    execute = _one(actions, "Exec")
    _no_attributes(execute)
    _no_mixed_text(execute)
    _exact_children(execute, ["Command", "Arguments", "WorkingDirectory"])
    command = _text(execute, "Command")
    arguments = _text(execute, "Arguments")
    cwd = _text(execute, "WorkingDirectory")
    _no_attributes(
        _one(execute, "Command"),
        _one(execute, "Arguments"),
        _one(execute, "WorkingDirectory"),
    )
    return uri, user_sid, command, arguments, cwd


# --------------------------------------------------------------------------- #
# Deterministic semantic projection of a registered task definition.          #
# --------------------------------------------------------------------------- #

_PROJECTION_TASK_CHILDREN: Final[frozenset[str]] = frozenset(
    {"RegistrationInfo", "Triggers", "Principals", "Settings", "Actions"}
)
# Registration metadata the store may stamp; carries no launch authority.
_PROJECTION_REGISTRATION_METADATA: Final[frozenset[str]] = frozenset(
    {"Date", "Author"}
)
_PROJECTION_IDLE_CHILDREN: Final[frozenset[str]] = frozenset(
    {"StopOnIdleEnd", "RestartOnIdle", "Duration", "WaitTimeout"}
)
# Deprecated, scheduler-managed idle timings with no launch authority.
_PROJECTION_IDLE_IGNORED: Final[frozenset[str]] = frozenset(
    {"Duration", "WaitTimeout"}
)
_BOOLEAN_SETTING_KEYS: Final[frozenset[str]] = frozenset(
    key for key, value in _SECURITY_SETTINGS.items() if value in ("true", "false")
)
_XML_BOOLEAN_CANONICAL: Final[dict[str, str]] = {
    "true": "true",
    "1": "true",
    "false": "false",
    "0": "false",
}


def _projection_require(condition: bool) -> None:
    if not condition:
        raise SchedulerError("task-xml-unprojectable")


def _projection_local(node: ET.Element) -> str:
    tag = node.tag
    if not isinstance(tag, str):
        raise SchedulerError("task-xml-unprojectable")
    prefix = f"{{{_TASK_NS}}}"
    _projection_require(tag.startswith(prefix))
    return tag[len(prefix):]


def _projection_no_mixed(node: ET.Element) -> None:
    if node.text is not None and node.text.strip():
        raise SchedulerError("task-xml-unprojectable")
    for child in node:
        if child.tail is not None and child.tail.strip():
            raise SchedulerError("task-xml-unprojectable")


def _projection_text(node: ET.Element) -> str:
    _projection_require(not node.attrib and len(node) == 0)
    return node.text or ""


def _projection_boolean(value: str) -> str:
    canonical = _XML_BOOLEAN_CANONICAL.get(value)
    if canonical is None:
        raise SchedulerError("task-xml-unprojectable")
    return canonical


def _semantic_projection(raw: bytes) -> tuple[Any, ...]:
    """Project definition bytes onto the exact semantic launch contract.

    The projection is deterministic and absorbs only provably semantics-free
    store normalization: element/attribute order, XML escaping and prefixing,
    the XML Schema boolean spellings, registration metadata (Date/Author),
    the deprecated idle timings, and the documented schema defaults for
    trigger ``Enabled``, principal ``RunLevel``, action ``Context`` and empty
    ``Arguments``/``WorkingDirectory``.  Localized text never participates.
    Every construct outside the closed contract raises
    ``task-xml-unprojectable``; callers map that to CONFLICT, never to exact
    and never to absent.
    """

    if type(raw) is not bytes or not raw or len(raw) > _MAX_DURABLE_BYTES:
        raise SchedulerError("task-xml-unprojectable")
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise SchedulerError("task-xml-unprojectable")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError, UnicodeError):
        raise SchedulerError("task-xml-unprojectable") from None
    _projection_require(root.tag == _q("Task"))
    _projection_require(set(root.attrib) <= {"version"})
    _projection_require(root.tail is None or not root.tail.strip())
    _projection_no_mixed(root)

    sections: dict[str, ET.Element] = {}
    for child in root:
        tag = _projection_local(child)
        _projection_require(tag in _PROJECTION_TASK_CHILDREN and tag not in sections)
        sections[tag] = child

    uri: str | None = None
    info = sections.get("RegistrationInfo")
    if info is not None:
        _projection_require(not info.attrib)
        _projection_no_mixed(info)
        seen_info: set[str] = set()
        for child in info:
            tag = _projection_local(child)
            _projection_require(tag not in seen_info)
            seen_info.add(tag)
            if tag == "URI":
                uri = _projection_text(child)
            elif tag in _PROJECTION_REGISTRATION_METADATA:
                _projection_text(child)
            else:
                raise SchedulerError("task-xml-unprojectable")

    triggers: list[tuple[str, str]] = []
    node = sections.get("Triggers")
    if node is not None:
        _projection_require(not node.attrib)
        _projection_no_mixed(node)
        for child in node:
            _projection_require(_projection_local(child) == "RegistrationTrigger")
            _projection_require(not child.attrib)
            _projection_no_mixed(child)
            enabled = "true"
            seen_trigger: set[str] = set()
            for element in child:
                tag = _projection_local(element)
                _projection_require(tag == "Enabled" and tag not in seen_trigger)
                seen_trigger.add(tag)
                enabled = _projection_boolean(_projection_text(element))
            triggers.append(("RegistrationTrigger", enabled))

    principals = sections.get("Principals")
    if principals is None:
        raise SchedulerError("task-xml-unprojectable")
    _projection_require(not principals.attrib)
    _projection_no_mixed(principals)
    principal_nodes = list(principals)
    _projection_require(len(principal_nodes) == 1)
    principal = principal_nodes[0]
    _projection_require(_projection_local(principal) == "Principal")
    _projection_require(set(principal.attrib) <= {"id"})
    _projection_no_mixed(principal)
    fields: dict[str, str] = {}
    for element in principal:
        tag = _projection_local(element)
        _projection_require(
            tag in ("UserId", "LogonType", "RunLevel") and tag not in fields
        )
        fields[tag] = _projection_text(element)
    _projection_require("UserId" in fields and "LogonType" in fields)
    user_sid = fields["UserId"]
    _projection_require(
        len(user_sid) <= 184 and _SID_RE.fullmatch(user_sid) is not None
    )
    principal_projection = (
        principal.attrib.get("id"),
        user_sid,
        fields["LogonType"],
        fields.get("RunLevel", "LeastPrivilege"),
    )

    settings: dict[str, str] = {}
    idle: dict[str, str] = {}
    node = sections.get("Settings")
    if node is not None:
        _projection_require(not node.attrib)
        _projection_no_mixed(node)
        idle_present = False
        for element in node:
            tag = _projection_local(element)
            if tag == "IdleSettings":
                _projection_require(not idle_present)
                idle_present = True
                _projection_require(not element.attrib)
                _projection_no_mixed(element)
                seen_idle: set[str] = set()
                for idle_element in element:
                    idle_tag = _projection_local(idle_element)
                    _projection_require(
                        idle_tag in _PROJECTION_IDLE_CHILDREN
                        and idle_tag not in seen_idle
                    )
                    seen_idle.add(idle_tag)
                    value = _projection_text(idle_element)
                    if idle_tag not in _PROJECTION_IDLE_IGNORED:
                        idle[idle_tag] = _projection_boolean(value)
                continue
            _projection_require(tag not in settings)
            value = _projection_text(element)
            if tag in _BOOLEAN_SETTING_KEYS:
                value = _projection_boolean(value)
            settings[tag] = value

    actions: list[tuple[str, str, str]] = []
    context = "Author"
    node = sections.get("Actions")
    if node is not None:
        _projection_require(set(node.attrib) <= {"Context"})
        context = node.attrib.get("Context", "Author")
        _projection_no_mixed(node)
        for element in node:
            _projection_require(_projection_local(element) == "Exec")
            _projection_require(not element.attrib)
            _projection_no_mixed(element)
            parts: dict[str, str] = {}
            for exec_child in element:
                tag = _projection_local(exec_child)
                _projection_require(
                    tag in ("Command", "Arguments", "WorkingDirectory")
                    and tag not in parts
                )
                parts[tag] = _projection_text(exec_child)
            _projection_require("Command" in parts)
            actions.append(
                (
                    parts["Command"],
                    parts.get("Arguments", ""),
                    parts.get("WorkingDirectory", ""),
                )
            )

    return (
        ("version", root.attrib.get("version")),
        ("uri", uri),
        ("triggers", tuple(sorted(triggers))),
        ("principal", principal_projection),
        ("context", context),
        ("settings", tuple(sorted(settings.items()))),
        ("idle", tuple(sorted(idle.items()))),
        ("actions", tuple(actions)),
    )


def _encode_bstr_task_xml(text: str) -> bytes:
    """Re-encode Task Scheduler's decoded BSTR without lying about encoding.

    ``IRegisteredTask::get_Xml`` returns a Unicode BSTR.  The service normally
    leaves an ``encoding="UTF-16"`` declaration in that text.  Once the BSTR
    has been decoded, emitting UTF-8 bytes verbatim would make the declaration
    contradict the byte stream and every valid task would fail XML parsing.

    Only the encoding pseudo-attribute inside an initial XML declaration is
    rewritten.  No XML is parsed or serialized here: unsupported constructs
    such as DTDs, entities, foreign nodes and attributes remain byte-visible
    for the closed semantic projection to reject.
    """

    if type(text) is not str or not text:
        raise SchedulerError("task-xml-unreadable")
    declaration_start = 1 if text.startswith("\ufeff") else 0
    if text.startswith("<?xml", declaration_start):
        declaration_end = text.find("?>", declaration_start + 5)
        if declaration_end < 0:
            raise SchedulerError("task-xml-unreadable")
        declaration = text[declaration_start : declaration_end + 2]
        matches = tuple(_XML_DECL_ENCODING_RE.finditer(declaration))
        if len(matches) > 1:
            raise SchedulerError("task-xml-unreadable")
        if matches:
            match = matches[0]
            quote = match.group("quote")
            replacement = f"{match.group('prefix')}{quote}UTF-8{quote}"
            declaration = (
                declaration[: match.start()]
                + replacement
                + declaration[match.end() :]
            )
            text = (
                text[:declaration_start]
                + declaration
                + text[declaration_end + 2 :]
            )
    try:
        raw = text.encode("utf-8", errors="strict")
    except UnicodeError:
        raise SchedulerError("task-xml-unreadable") from None
    if len(raw) > _MAX_DURABLE_BYTES:
        raise SchedulerError("task-xml-unreadable")
    return raw


# --------------------------------------------------------------------------- #
# Narrow read-only COM adapter: the defensible Windows absence signal.        #
# --------------------------------------------------------------------------- #

_CLSID_TASK_SCHEDULER: Final[str] = "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}"
_IID_ITASK_SERVICE: Final[str] = "{2FABA4C7-4DA9-4013-9697-20CC3FD40F85}"
_CLSCTX_INPROC_SERVER: Final[int] = 0x1
# taskschd.h vtable slots (IUnknown 0-2, IDispatch 3-6, interface methods 7+).
_VT_IUNKNOWN_RELEASE: Final[int] = 2
_VT_ITASKSERVICE_GET_FOLDER: Final[int] = 7
_VT_ITASKSERVICE_CONNECT: Final[int] = 10
_VT_ITASKFOLDER_GET_TASK: Final[int] = 13
_VT_IREGISTEREDTASK_GET_XML: Final[int] = 20
# HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND): the only
# signals ever mapped to ABSENT.
_HR_NOT_FOUND: Final[frozenset[int]] = frozenset({0x80070002, 0x80070003})
_VARIANT_PAYLOAD_BYTES: Final[int] = 16 if ctypes.sizeof(ctypes.c_void_p) == 8 else 8


class _ComGuid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _ComVariant(ctypes.Structure):
    # Only ever passed zeroed (VT_EMPTY), so the union layout is irrelevant;
    # the total by-value size must match the platform VARIANT.
    _fields_ = [
        ("vt", ctypes.c_ushort),
        ("reserved1", ctypes.c_ushort),
        ("reserved2", ctypes.c_ushort),
        ("reserved3", ctypes.c_ushort),
        ("payload", ctypes.c_ubyte * _VARIANT_PAYLOAD_BYTES),
    ]


class _ComTaskQueryPort:
    """Narrow read-only Task Scheduler observation via the native COM API.

    ``schtasks.exe`` reports every query failure as a localized message with
    an undifferentiated nonzero exit, so it has no defensible absence signal.
    ``ITaskFolder::GetTask`` returns exact, unlocalized not-found HRESULTs;
    only those become ABSENT.  Every other failure — COM init, connect,
    marshalling, unreadable definition — is UNKNOWN or an unreadable-PRESENT,
    never ABSENT.  The port performs no mutation: only ``Connect``,
    ``GetFolder``, ``GetTask`` and ``get_Xml`` are ever invoked.
    """

    def __call__(self, task_name: str) -> TaskProbe:
        name = _validate_task_name(task_name)
        if os.name != "nt":
            return TaskProbe(TaskProbeStatus.UNKNOWN)
        try:
            return self._probe_windows(name)
        except SchedulerError:
            raise
        except Exception:
            return TaskProbe(TaskProbeStatus.UNKNOWN)

    @staticmethod
    def _method(interface: int, index: int, *argtypes: Any) -> Any:
        vtable = ctypes.cast(
            ctypes.c_void_p(interface),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
        ).contents
        entry = vtable[index]
        if not entry:
            raise SchedulerError("task-probe-failed")
        prototype = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)
        return prototype(entry)

    @classmethod
    def _release(cls, interface: int | None) -> None:
        if not interface:
            return
        try:
            cls._method(interface, _VT_IUNKNOWN_RELEASE)(interface)
        except Exception:
            pass

    def _probe_windows(self, name: str) -> TaskProbe:
        unknown = TaskProbe(TaskProbeStatus.UNKNOWN)
        unreadable = TaskProbe(TaskProbeStatus.PRESENT, None)
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        oleaut32 = ctypes.WinDLL("oleaut32", use_last_error=True)

        co_initialize = ole32.CoInitializeEx
        co_initialize.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        co_initialize.restype = ctypes.c_long
        co_uninitialize = ole32.CoUninitialize
        co_uninitialize.argtypes = []
        co_uninitialize.restype = None
        clsid_from_string = ole32.CLSIDFromString
        clsid_from_string.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_ComGuid)]
        clsid_from_string.restype = ctypes.c_long
        co_create = ole32.CoCreateInstance
        co_create.argtypes = [
            ctypes.POINTER(_ComGuid),
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.POINTER(_ComGuid),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        co_create.restype = ctypes.c_long
        alloc_string = oleaut32.SysAllocString
        alloc_string.argtypes = [ctypes.c_wchar_p]
        alloc_string.restype = ctypes.c_void_p
        free_string = oleaut32.SysFreeString
        free_string.argtypes = [ctypes.c_void_p]
        free_string.restype = None
        string_len = oleaut32.SysStringLen
        string_len.argtypes = [ctypes.c_void_p]
        string_len.restype = ctypes.c_uint

        # S_OK / S_FALSE own an init; RPC_E_CHANGED_MODE means COM is already
        # usable on this thread but must not be uninitialized here.
        initialized = co_initialize(None, 0) in (0, 1)
        try:
            class_id = _ComGuid()
            interface_id = _ComGuid()
            if clsid_from_string(_CLSID_TASK_SCHEDULER, ctypes.byref(class_id)) != 0:
                return unknown
            if clsid_from_string(_IID_ITASK_SERVICE, ctypes.byref(interface_id)) != 0:
                return unknown
            service = ctypes.c_void_p()
            created = co_create(
                ctypes.byref(class_id),
                None,
                _CLSCTX_INPROC_SERVER,
                ctypes.byref(interface_id),
                ctypes.byref(service),
            )
            if created != 0 or not service.value:
                return unknown
            try:
                empty = _ComVariant()
                connect = self._method(
                    service.value,
                    _VT_ITASKSERVICE_CONNECT,
                    _ComVariant,
                    _ComVariant,
                    _ComVariant,
                    _ComVariant,
                )
                if connect(service, empty, empty, empty, empty) != 0:
                    return unknown
                folder = ctypes.c_void_p()
                root = alloc_string("\\")
                if not root:
                    return unknown
                try:
                    get_folder = self._method(
                        service.value,
                        _VT_ITASKSERVICE_GET_FOLDER,
                        ctypes.c_void_p,
                        ctypes.POINTER(ctypes.c_void_p),
                    )
                    result = get_folder(service, root, ctypes.byref(folder))
                finally:
                    free_string(root)
                if result != 0 or not folder.value:
                    return unknown
                try:
                    task = ctypes.c_void_p()
                    path = alloc_string(name)
                    if not path:
                        return unknown
                    try:
                        get_task = self._method(
                            folder.value,
                            _VT_ITASKFOLDER_GET_TASK,
                            ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_void_p),
                        )
                        result = get_task(folder, path, ctypes.byref(task))
                    finally:
                        free_string(path)
                    if (result & 0xFFFFFFFF) in _HR_NOT_FOUND:
                        return TaskProbe(TaskProbeStatus.ABSENT)
                    if result != 0 or not task.value:
                        return unknown
                    try:
                        xml_string = ctypes.c_void_p()
                        get_xml = self._method(
                            task.value,
                            _VT_IREGISTEREDTASK_GET_XML,
                            ctypes.POINTER(ctypes.c_void_p),
                        )
                        if (
                            get_xml(task, ctypes.byref(xml_string)) != 0
                            or not xml_string.value
                        ):
                            return unreadable
                        try:
                            length = int(string_len(xml_string))
                            if length <= 0 or length > _MAX_DURABLE_BYTES:
                                return unreadable
                            text = ctypes.wstring_at(xml_string.value, length)
                        finally:
                            free_string(xml_string)
                        try:
                            raw = _encode_bstr_task_xml(text)
                        except SchedulerError:
                            return unreadable
                        return TaskProbe(TaskProbeStatus.PRESENT, raw)
                    finally:
                        self._release(task.value)
                finally:
                    self._release(folder.value)
            finally:
                self._release(service.value)
        finally:
            if initialized:
                co_uninitialize()


class TaskSchedulerAdapter:
    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        test_only_schtasks_path: os.PathLike[str] | str | None = None,
        test_only_schtasks_sha256: str | None = None,
        test_only_xml_locker: Callable[[Path], ContextManager[BinaryIO]] | None = None,
        test_only_query_port: Callable[[str], TaskProbe] | None = None,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise SchedulerError("timeout-invalid")
        if not 0 < timeout_seconds <= 300:
            raise SchedulerError("timeout-invalid")
        if (test_only_schtasks_path is None) != (test_only_schtasks_sha256 is None):
            raise SchedulerError("test-schtasks-pin-required")
        if test_only_xml_locker is not None and test_only_schtasks_path is None:
            raise SchedulerError("test-xml-locker-forbidden")
        if test_only_xml_locker is not None and not callable(test_only_xml_locker):
            raise SchedulerError("test-xml-locker-invalid")
        if test_only_query_port is not None and test_only_schtasks_path is None:
            raise SchedulerError("test-query-port-forbidden")
        if test_only_query_port is not None and not callable(test_only_query_port):
            raise SchedulerError("test-query-port-invalid")
        if test_only_schtasks_path is None:
            system_directory = _validated_existing_path(
                _get_system_directory(), kind="directory"
            )
            schtasks = _validated_existing_path(
                system_directory / "schtasks.exe",
                kind="file",
                executable_name="schtasks.exe",
            )
            schtasks_pin = _PinnedFile.capture_current(schtasks)
        else:
            schtasks = _validated_existing_path(
                test_only_schtasks_path,
                kind="file",
                executable_name="schtasks.exe",
            )
            schtasks_pin = _PinnedFile.capture(schtasks, test_only_schtasks_sha256)
        self._schtasks = schtasks
        self._schtasks_pin = schtasks_pin
        self._timeout = float(timeout_seconds)
        self._xml_locker = test_only_xml_locker or _lock_xml_readonly
        # A hermetic test adapter never falls back to the live COM service:
        # without an injected port the exact-observation surface fails closed.
        if test_only_schtasks_path is None:
            self._query_port: Callable[[str], TaskProbe] | None = _ComTaskQueryPort()
        else:
            self._query_port = test_only_query_port

    @property
    def executable(self) -> Path:
        return self._schtasks

    def _invoke(
        self,
        arguments: Sequence[str],
        *,
        preflight: object | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        _validated_existing_path(
            self._schtasks, kind="file", executable_name="schtasks.exe"
        )
        self._schtasks_pin.verify()
        if preflight is not None:
            if not callable(preflight):
                raise SchedulerError("preflight-invalid")
            try:
                preflight()
            except SchedulerError:
                raise
            except BaseException:
                raise SchedulerError("preflight-failed") from None
        try:
            result = subprocess.run(
                [os.fspath(self._schtasks), *arguments],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SchedulerError("schtasks-timeout") from None
        except OSError:
            raise SchedulerError("schtasks-exec-failed") from None
        if type(result.returncode) is not int:
            raise SchedulerError("schtasks-result-invalid")
        return result

    def register(self, identity: TaskIdentity, paths: RunnerPaths) -> str:
        if not isinstance(identity, TaskIdentity) or not isinstance(paths, RunnerPaths):
            raise SchedulerError("task-spec-invalid")
        expected = _expected_task(identity, paths)
        durable = _publish_task(expected, paths)
        self._create(expected, durable)
        return expected.name

    def _create(self, expected: _ExpectedTask, durable: _DurableTask) -> None:
        try:
            manager = self._xml_locker(expected.xml_path)
            with manager as locked_xml:
                outcome = self._invoke(
                    (
                        "/Create",
                        "/TN",
                        expected.name,
                        "/XML",
                        os.fspath(expected.xml_path),
                    ),
                    preflight=lambda: durable.verify_for_create(locked_xml),
                )
        except SchedulerError:
            raise
        except (OSError, AttributeError, TypeError, ValueError):
            raise SchedulerError("xml-lock-failed") from None
        if outcome.returncode != 0:
            raise SchedulerError("schtasks-create-nonzero")

    def query(self, task_name: str) -> TaskPresence:
        name = _validate_task_name(task_name)
        outcome = self._invoke(("/Query", "/TN", name))
        return TaskPresence.PRESENT if outcome.returncode == 0 else TaskPresence.UNKNOWN

    def delete(self, task_name: str) -> None:
        name = _validate_task_name(task_name)
        outcome = self._invoke(("/Delete", "/TN", name, "/F"))
        if outcome.returncode != 0:
            raise SchedulerError("schtasks-delete-nonzero")

    # ---- M4 exact observation and idempotent replay ---- #

    def _require_query_port(self) -> Callable[[str], TaskProbe]:
        if self._query_port is None:
            raise SchedulerError("query-port-unavailable")
        return self._query_port

    def _probe(self, task_name: str) -> TaskProbe:
        port = self._require_query_port()
        try:
            probe = port(task_name)
        except SchedulerError:
            raise
        except Exception:
            raise SchedulerError("task-probe-failed") from None
        if type(probe) is not TaskProbe or not isinstance(
            probe.status, TaskProbeStatus
        ):
            raise SchedulerError("probe-result-invalid")
        if probe.status is TaskProbeStatus.PRESENT:
            if probe.xml is not None and type(probe.xml) is not bytes:
                raise SchedulerError("probe-result-invalid")
        elif probe.xml is not None:
            raise SchedulerError("probe-result-invalid")
        return probe

    def _observe(self, expected: _ExpectedTask) -> TaskObservation:
        try:
            wanted = _semantic_projection(expected.xml_bytes)
        except SchedulerError:
            raise SchedulerError("task-xml-invalid") from None
        probe = self._probe(expected.name)
        if probe.status is TaskProbeStatus.UNKNOWN:
            return TaskObservation.UNKNOWN
        if probe.status is TaskProbeStatus.ABSENT:
            return TaskObservation.ABSENT
        if probe.xml is None:
            return TaskObservation.PRESENT_CONFLICT
        try:
            observed = _semantic_projection(probe.xml)
        except SchedulerError:
            return TaskObservation.PRESENT_CONFLICT
        if observed != wanted:
            return TaskObservation.PRESENT_CONFLICT
        return TaskObservation.PRESENT_EXACT

    def observe_exact(
        self, identity: TaskIdentity, paths: RunnerPaths
    ) -> TaskObservation:
        """Classify this attempt's deterministic task name, fail-closed.

        PRESENT_EXACT is returned only when the registered definition's
        semantic projection equals the durable contract computed from the
        revalidated pinned inputs.  ABSENT comes only from the port's exact
        native not-found signal.  Everything ambiguous is UNKNOWN or
        PRESENT_CONFLICT.
        """

        if not isinstance(identity, TaskIdentity) or not isinstance(paths, RunnerPaths):
            raise SchedulerError("task-spec-invalid")
        self._require_query_port()
        expected = _expected_task(identity, paths)
        return self._observe(expected)

    def ensure_registered(self, identity: TaskIdentity, paths: RunnerPaths) -> str:
        """Idempotently converge on this attempt's exact registered task.

        A matching already-existing task is success without any mutation.  A
        conflicting same-name task fails closed.  A create response loss
        (nonzero, timeout, spawn failure) is resolved only by a fresh exact
        inspection; a definite create success must also confirm exact.
        """

        if not isinstance(identity, TaskIdentity) or not isinstance(paths, RunnerPaths):
            raise SchedulerError("task-spec-invalid")
        self._require_query_port()
        expected = _expected_task(identity, paths)
        durable = _publish_task(expected, paths)
        observation = self._observe(expected)
        if observation is TaskObservation.PRESENT_EXACT:
            return expected.name
        if observation is TaskObservation.PRESENT_CONFLICT:
            raise SchedulerError("task-conflict")
        if observation is TaskObservation.UNKNOWN:
            raise SchedulerError("task-observation-unknown")
        try:
            self._create(expected, durable)
        except SchedulerError as error:
            if error.code not in _CREATE_RESPONSE_LOSS:
                raise
            recovered = self._observe(expected)
            if recovered is TaskObservation.PRESENT_EXACT:
                return expected.name
            if recovered is TaskObservation.PRESENT_CONFLICT:
                raise SchedulerError("task-conflict") from None
            raise
        confirmation = self._observe(expected)
        if confirmation is TaskObservation.PRESENT_EXACT:
            return expected.name
        if confirmation is TaskObservation.PRESENT_CONFLICT:
            raise SchedulerError("task-conflict")
        raise SchedulerError("task-create-unconfirmed")

    def ensure_absent(self, identity: TaskIdentity, paths: RunnerPaths) -> None:
        """Idempotently converge on trustworthy absence of this exact task.

        Success requires an exact ABSENT observation.  Only a PRESENT_EXACT
        task is ever deleted; a conflicting or differently bound same-name
        task fails closed untouched.  A delete response loss is resolved only
        by reinspection, and a definite delete success must still observe
        ABSENT.
        """

        if not isinstance(identity, TaskIdentity) or not isinstance(paths, RunnerPaths):
            raise SchedulerError("task-spec-invalid")
        self._require_query_port()
        expected = _expected_task(identity, paths)
        _require_durable_match_if_present(expected)
        observation = self._observe(expected)
        if observation is TaskObservation.ABSENT:
            return
        if observation is TaskObservation.PRESENT_CONFLICT:
            raise SchedulerError("task-conflict")
        if observation is TaskObservation.UNKNOWN:
            raise SchedulerError("task-observation-unknown")
        failure: SchedulerError | None = None
        try:
            outcome = self._invoke(("/Delete", "/TN", expected.name, "/F"))
            if outcome.returncode != 0:
                failure = SchedulerError("schtasks-delete-nonzero")
        except SchedulerError as error:
            if error.code not in _DELETE_RESPONSE_LOSS:
                raise
            failure = error
        final = self._observe(expected)
        if final is TaskObservation.ABSENT:
            return
        if failure is not None:
            raise failure
        if final is TaskObservation.PRESENT_CONFLICT:
            raise SchedulerError("task-conflict")
        if final is TaskObservation.PRESENT_EXACT:
            raise SchedulerError("task-delete-unconfirmed")
        raise SchedulerError("task-observation-unknown")
