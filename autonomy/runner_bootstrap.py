"""Pinned, fail-closed bootstrap boundary for the isolated night-autonomy MVP.

The Windows Task Scheduler launches exactly one command (see
``autonomy.scheduler``)::

    <repo>\\.venv\\Scripts\\python.exe -I -S <repo>\\autonomy\\runner_bootstrap.py
        --root R --task-id T --attempt N --nonce X --profile P --model M
        --config C --dependency-manifest D --task-spec S --task-spec-sha256 H

This module runs as ``__main__`` under ``-I -S`` (isolated, no site).  It is the
sole trust gate between the scheduler's immutable authority files and the
autonomy runner:

* It parses a *closed* argv schema before anything else is trusted.
* It validates every path *lexically* (exact absolute, no dot/dup/UNC/device/
  8.3/reparse aliases) and requires argv paths to equal the task-spec paths
  byte-for-byte, not merely realpath-equal.
* It reads ``task-spec.json`` through an identity-stable, deny-delete handle and
  refuses to trust its JSON until the file's SHA-256 equals the exact digest
  carried independently in argv.
* It re-validates the running interpreter, this bootstrap, the config, the
  dependency manifest and every dependency against the task-spec's path +
  SHA-256 + file identity, holding each handle open (no ``FILE_SHARE_DELETE``
  on Windows; ``O_NOFOLLOW`` + fstat on POSIX) so a swap/delete/reparse race
  cannot retarget validation or later execution.
* It loads manifest-listed, trusted ``autonomy.*`` modules from the
  already-verified bytes through a private in-memory finder/loader, after
  stripping the repo/cwd from ``sys.path`` and purging pre-loaded ``autonomy``
  modules.  Ordinary imports cannot fall back to an unlisted filesystem module.
  This gives integrity and deterministic imports; it is deliberately not a
  sandbox against hostile Python already admitted to the manifest.
* The private loader injects a fresh one-shot handoff into ``autonomy.runner``
  before executing its verified bytes.  This catches accidental direct use and
  replay; it is not cryptographic provenance against in-process Python.
* It then invokes the runner with a private immutable context.  The statically
  required ``autonomy.supervisor_tick`` is readiness-only until concrete
  orchestration receives separate admission.  ``autonomy.boot_clock`` is
  likewise a statically required pinned dependency root and must be pinned as
  exactly the file ``autonomy/boot_clock.py``; it is a producer-only,
  unintegrated component that nothing here consumes yet.

Every bootstrap-owned failure is a stable nonzero exit with one bounded ASCII
JSON diagnostic on stderr, empty stdout, and no traceback.  Validation itself
has no disk side effects.  Once trusted manifest code starts, that code is part
of the TCB and cannot be made side-effect-free by a Python import hook.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.machinery
import json
import keyword
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

# --------------------------------------------------------------------------- #
# Constants (a small, self-contained mirror of the scheduler's contract).      #
# --------------------------------------------------------------------------- #

_EXIT_FAILCLOSED: int = 2

TASK_FOLDER = r"\agentchattr-autonomy-v1"
TASK_TIMEOUT = "PT8H"

_MAX_PATH_LEN = 4096
_MAX_SPEC_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_DURABLE_BYTES = 1024 * 1024
_MAX_EXE_BYTES = 256 * 1024 * 1024

_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_PROFILE_RE = _TASK_ID_RE
_MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ATTEMPT_RE = re.compile(r"^[12]$")
_SID_RE = re.compile(r"^S-1-(?:[0-9]+-)*[0-9]+$")
_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

_FLAGS = (
    "--root",
    "--task-id",
    "--attempt",
    "--nonce",
    "--profile",
    "--model",
    "--config",
    "--dependency-manifest",
    "--task-spec",
    "--task-spec-sha256",
)

# The scheduler's launch policy, duplicated here so the bootstrap can bind every
# ``scheduler_policy`` field emitted into task-spec.json without importing (and
# thereby trusting) any un-pinned autonomy module.
_SECURITY_SETTINGS = {
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
_IDLE_SETTINGS = {
    "StopOnIdleEnd": "false",
    "RestartOnIdle": "false",
}
_EXPECTED_TRIGGERS = [{"type": "RegistrationTrigger", "enabled": True}]


class _BootstrapError(Exception):
    """A fail-closed refusal carrying a stable, ASCII, kebab-case code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


# --------------------------------------------------------------------------- #
# Windows primitives (share-mode handle + final-path verification).            #
# --------------------------------------------------------------------------- #

if os.name == "nt":  # pragma: no branch - platform specific
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE

    _GetFinalPathNameByHandleW = _kernel32.GetFinalPathNameByHandleW
    _GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _GetFinalPathNameByHandleW.restype = wintypes.DWORD

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    _INVALID_HANDLE = ctypes.c_void_p(-1).value
    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080


def _current_user_sid() -> str:
    """Return the exact process-token user SID (Windows), shell-free."""

    if os.name != "nt":
        raise _BootstrapError("sid-unsupported-platform")
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
        raise _BootstrapError("sid-query-failed") from None
    if not isinstance(sid, str) or len(sid) > 184 or _SID_RE.fullmatch(sid) is None:
        raise _BootstrapError("sid-invalid")
    return sid


# --------------------------------------------------------------------------- #
# Strict lexical path validation.                                             #
# --------------------------------------------------------------------------- #


def _strict_lexical(raw: object) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_PATH_LEN:
        raise _BootstrapError("path-invalid")
    if "\x00" in raw or any(ord(ch) < 0x20 for ch in raw):
        raise _BootstrapError("path-invalid")
    if os.name == "nt":
        return _strict_lexical_windows(raw)
    return _strict_lexical_posix(raw)


def _strict_lexical_windows(raw: str) -> str:
    if "/" in raw:
        raise _BootstrapError("path-separator-invalid")
    if raw[:2] == "\\\\":
        raise _BootstrapError("path-unc-or-device")
    drive, tail = os.path.splitdrive(raw)
    if re.fullmatch(r"[A-Za-z]:", drive) is None:
        raise _BootstrapError("path-not-drive-absolute")
    if ":" in tail:
        raise _BootstrapError("path-colon-in-body")
    if not tail.startswith("\\"):
        raise _BootstrapError("path-not-absolute")
    components = tail.split("\\")
    body = components[1:]
    if not body:
        raise _BootstrapError("path-bare-root")
    for comp in body:
        if comp == "":
            raise _BootstrapError("path-empty-component")
        if comp in (".", ".."):
            raise _BootstrapError("path-dot-segment")
        if comp.rstrip(" .") != comp:
            raise _BootstrapError("path-trailing-space-or-dot")
        if comp.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
            raise _BootstrapError("path-reserved-name")
    if os.path.normpath(raw) != raw:
        raise _BootstrapError("path-not-canonical")
    return raw


def _strict_lexical_posix(raw: str) -> str:
    if not raw.startswith("/"):
        raise _BootstrapError("path-not-absolute")
    for comp in raw.split("/")[1:]:
        if comp in ("", ".", ".."):
            raise _BootstrapError("path-invalid-component")
    if os.path.normpath(raw) != raw:
        raise _BootstrapError("path-not-canonical")
    return raw


def _is_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        raise _BootstrapError("path-inspection-failed") from None
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_FLAG
    )


def _reject_reparse_components(path_str: str) -> None:
    path = Path(path_str)
    for component in list(reversed(path.parents)) + [path]:
        if not component.exists():
            raise _BootstrapError("path-missing")
        if _is_reparse(component):
            raise _BootstrapError("path-reparse-forbidden")


def _resolve_existing(raw: object, kind: str) -> str:
    """Strict-lexical-validate *raw*, confirm it exists, is not aliased and
    is of the requested *kind* (``"file"``/``"dir"``).  Returns the exact
    (unchanged) string on success."""

    canonical = _strict_lexical(raw)
    _reject_reparse_components(canonical)
    if os.path.normcase(os.path.realpath(canonical)) != os.path.normcase(
        os.path.abspath(canonical)
    ):
        raise _BootstrapError("path-resolution-ambiguous")
    try:
        mode = os.lstat(canonical).st_mode
    except OSError:
        raise _BootstrapError("path-inspection-failed") from None
    if kind == "file" and not stat.S_ISREG(mode):
        raise _BootstrapError("path-not-file")
    if kind == "dir" and not stat.S_ISDIR(mode):
        raise _BootstrapError("path-not-directory")
    return canonical


def _contained(child: str, parent: str) -> bool:
    child_abs = os.path.normcase(os.path.abspath(child))
    parent_abs = os.path.normcase(os.path.abspath(parent))
    try:
        common = os.path.commonpath([child_abs, parent_abs])
    except ValueError:
        return False
    if common != parent_abs or child_abs == parent_abs:
        return False
    child_real = os.path.normcase(os.path.realpath(child))
    parent_real = os.path.normcase(os.path.realpath(parent))
    try:
        common_real = os.path.commonpath([child_real, parent_real])
    except ValueError:
        return False
    return common_real == parent_real and child_real != parent_real


# --------------------------------------------------------------------------- #
# Identity-stable, deny-delete file handles.                                   #
# --------------------------------------------------------------------------- #


class _HeldFile:
    """An open, identity-pinned read handle kept alive across execution."""

    def __init__(self, stream, identity, path: str) -> None:
        self._stream = stream
        self.identity = identity  # (device, inode, size, mtime_ns)
        self.path = path

    def read_verified(self, limit, expected_sha=None, expected_identity=None):
        try:
            before = _fstat_identity(self._stream.fileno())
            self._stream.seek(0)
            digest = hashlib.sha256()
            total = 0
            chunks = []
            while True:
                chunk = self._stream.read(1024 * 1024)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise _BootstrapError("file-read-failed")
                total += len(chunk)
                if total > limit:
                    raise _BootstrapError("file-too-large")
                digest.update(chunk)
                chunks.append(chunk)
            after = _fstat_identity(self._stream.fileno())
        except _BootstrapError:
            raise
        except OSError:
            raise _BootstrapError("file-read-failed") from None
        if before != after or before != self.identity:
            raise _BootstrapError("file-changed-during-read")
        if expected_identity is not None and before != expected_identity:
            raise _BootstrapError("file-identity-mismatch")
        data = b"".join(chunks)
        sha = digest.hexdigest()
        if expected_sha is not None and sha != expected_sha:
            raise _BootstrapError("file-hash-mismatch")
        return data, sha

    def close(self) -> None:
        try:
            self._stream.close()
        except OSError:
            pass


def _fstat_identity(fileno: int):
    info = os.fstat(fileno)
    if not stat.S_ISREG(info.st_mode):
        raise _BootstrapError("path-not-file")
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def _open_pinned(canonical: str) -> _HeldFile:
    if os.name == "nt":
        return _open_pinned_windows(canonical)
    return _open_pinned_posix(canonical)


def _final_path_by_handle(handle) -> str:
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    length = _GetFinalPathNameByHandleW(handle, buffer, size, 0)  # VOLUME_NAME_DOS
    if length == 0 or length >= size:
        raise _BootstrapError("file-final-path-failed")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\") or value.startswith("\\\\.\\"):
        raise _BootstrapError("file-final-path-device")
    if value.startswith("\\\\?\\"):
        value = value[4:]
    if value.startswith("\\\\"):
        raise _BootstrapError("file-final-path-unc")
    return value


def _open_pinned_windows(canonical: str) -> _HeldFile:
    import msvcrt

    handle = _CreateFileW(
        canonical,
        _GENERIC_READ,
        _FILE_SHARE_READ,  # deny write + delete sharing
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle is None or int(handle) == _INVALID_HANDLE:
        raise _BootstrapError("file-open-failed")
    try:
        final = _final_path_by_handle(handle)
        if os.path.normcase(final) != os.path.normcase(canonical):
            raise _BootstrapError("file-final-path-mismatch")
    except BaseException:
        _CloseHandle(handle)
        raise
    try:
        descriptor = msvcrt.open_osfhandle(
            int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except (OSError, OverflowError):
        _CloseHandle(handle)
        raise _BootstrapError("file-open-failed") from None
    # The CRT descriptor now owns the Windows handle.
    try:
        stream = os.fdopen(descriptor, "rb", closefd=True)
        identity = _fstat_identity(stream.fileno())
    except _BootstrapError:
        raise
    except OSError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise _BootstrapError("file-open-failed") from None
    return _HeldFile(stream, identity, canonical)


def _open_pinned_posix(canonical: str) -> _HeldFile:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(canonical, flags)
    except OSError:
        raise _BootstrapError("file-open-failed") from None
    try:
        identity = _fstat_identity(descriptor)
        real = os.path.realpath("/proc/self/fd/%d" % descriptor)
        if os.path.exists(real) and os.path.normcase(real) != os.path.normcase(
            os.path.abspath(canonical)
        ):
            raise _BootstrapError("file-final-path-mismatch")
        stream = os.fdopen(descriptor, "rb", closefd=True)
    except _BootstrapError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    except OSError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise _BootstrapError("file-open-failed") from None
    return _HeldFile(stream, identity, canonical)


# --------------------------------------------------------------------------- #
# JSON parsing (closed, duplicate-key + NaN/Infinity hostile).                 #
# --------------------------------------------------------------------------- #


def _pairs_no_dup(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _BootstrapError("json-duplicate-key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise _BootstrapError("json-constant-forbidden")


def _load_json(raw: bytes, code: str):
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise _BootstrapError(code) from None
    try:
        document = json.loads(
            text, object_pairs_hook=_pairs_no_dup, parse_constant=_reject_constant
        )
    except _BootstrapError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise _BootstrapError(code) from None
    return document


def _is_str(value) -> bool:
    return isinstance(value, str)


def _is_int(value) -> bool:
    return type(value) is int


def _require_mapping(obj, keys, code) -> None:
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise _BootstrapError(code)


def _validate_pin(obj, code):
    _require_mapping(obj, ("path", "sha256", "identity"), code)
    if not _is_str(obj["path"]):
        raise _BootstrapError(code)
    sha = obj["sha256"]
    if not _is_str(sha) or _SHA256_RE.fullmatch(sha) is None:
        raise _BootstrapError(code)
    ident = obj["identity"]
    _require_mapping(ident, ("device", "inode", "size", "mtime_ns"), code)
    for field_name in ("device", "inode", "size", "mtime_ns"):
        if not _is_int(ident[field_name]):
            raise _BootstrapError(code)
    identity = (
        ident["device"],
        ident["inode"],
        ident["size"],
        ident["mtime_ns"],
    )
    return obj["path"], sha, identity


# --------------------------------------------------------------------------- #
# Dependency manifest + module-name grammar.                                   #
# --------------------------------------------------------------------------- #


def _validate_relative(rel: object):
    if not _is_str(rel) or not rel or len(rel) > 240:
        raise _BootstrapError("manifest-path-invalid")
    if "\\" in rel or ":" in rel or "\x00" in rel:
        raise _BootstrapError("manifest-path-invalid")
    pure = PurePosixPath(rel)
    parts = pure.parts
    if pure.is_absolute() or any(part in ("", ".", "..") for part in parts):
        raise _BootstrapError("manifest-traversal")
    if pure.as_posix() != rel:
        raise _BootstrapError("manifest-path-invalid")
    for part in parts:
        if part.rstrip(" .") != part or part.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
            raise _BootstrapError("manifest-path-invalid")
    return parts


def _dependency_module(rel: str):
    parts = _validate_relative(rel)
    if len(parts) < 2 or parts[0] != "autonomy" or not parts[-1].endswith(".py"):
        raise _BootstrapError("manifest-not-autonomy-module")
    leaf = parts[-1][:-3]
    is_package = leaf == "__init__"
    module_parts = parts[:-1] if is_package else (*parts[:-1], leaf)
    if not module_parts or any(
        (not part.isascii()) or (not part.isidentifier()) or keyword.iskeyword(part)
        for part in module_parts
    ):
        raise _BootstrapError("manifest-module-invalid")
    return ".".join(module_parts), is_package, parts


def _parse_manifest(raw: bytes):
    document = _load_json(raw, "manifest-json-invalid")
    if not isinstance(document, dict) or set(document) != {"version", "dependencies"}:
        raise _BootstrapError("manifest-schema")
    if not _is_int(document["version"]) or document["version"] != 1:
        raise _BootstrapError("manifest-schema")
    dependencies = document["dependencies"]
    if not isinstance(dependencies, list) or not dependencies:
        raise _BootstrapError("manifest-schema")
    seen = set()
    result = []
    for entry in dependencies:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise _BootstrapError("manifest-schema")
        rel = entry["path"]
        _validate_relative(rel)
        key = rel.casefold()
        if key in seen:
            raise _BootstrapError("manifest-duplicate")
        seen.add(key)
        sha = entry["sha256"]
        if not _is_str(sha) or _SHA256_RE.fullmatch(sha) is None:
            raise _BootstrapError("manifest-sha")
        result.append((rel, sha))
    return result


# --------------------------------------------------------------------------- #
# argv (closed schema).                                                        #
# --------------------------------------------------------------------------- #


def _parse_argv(argv):
    if not isinstance(argv, list) or len(argv) != 21:
        raise _BootstrapError("argv-arity")
    bootstrap = argv[0]
    if not _is_str(bootstrap):
        raise _BootstrapError("argv-invalid")
    rest = argv[1:]
    flags = tuple(rest[0::2])
    values = rest[1::2]
    if flags != _FLAGS:
        raise _BootstrapError("argv-schema")
    if not all(_is_str(value) for value in values):
        raise _BootstrapError("argv-invalid")
    mapping = dict(zip(_FLAGS, values))
    task_id = mapping["--task-id"]
    if _TASK_ID_RE.fullmatch(task_id) is None or task_id.lower() in _WINDOWS_RESERVED:
        raise _BootstrapError("argv-task-id")
    profile = mapping["--profile"]
    if _PROFILE_RE.fullmatch(profile) is None or profile.lower() in _WINDOWS_RESERVED:
        raise _BootstrapError("argv-profile")
    model = mapping["--model"]
    if _MODEL_RE.fullmatch(model) is None or ".." in model or model.endswith("."):
        raise _BootstrapError("argv-model")
    if _NONCE_RE.fullmatch(mapping["--nonce"]) is None:
        raise _BootstrapError("argv-nonce")
    if _SHA256_RE.fullmatch(mapping["--task-spec-sha256"]) is None:
        raise _BootstrapError("argv-sha256")
    if _ATTEMPT_RE.fullmatch(mapping["--attempt"]) is None:
        raise _BootstrapError("argv-attempt")
    attempt = int(mapping["--attempt"])
    return bootstrap, mapping, attempt


# --------------------------------------------------------------------------- #
# The validated, closed plan handed to _execute.                               #
# --------------------------------------------------------------------------- #


class _Plan:
    def __init__(self) -> None:
        self.held = []
        self.repo = None
        self.root = None
        self.finder_modules = {}
        self.load_order = ()
        self.context_data = {}

    def close(self) -> None:
        while self.held:
            self.held.pop().close()


def _validate(argv, *, sid_provider=None, executable=None, isolated_ok=None) -> _Plan:
    if isolated_ok is None:
        isolated_ok = bool(sys.flags.isolated) and bool(sys.flags.no_site)
    if not isolated_ok:
        raise _BootstrapError("interpreter-not-isolated")
    if sid_provider is None:
        sid_provider = _current_user_sid
    if executable is None:
        executable = sys.executable

    bootstrap_arg, flags, attempt = _parse_argv(argv)

    arg_root = _resolve_existing(flags["--root"], "dir")
    arg_config = _resolve_existing(flags["--config"], "file")
    arg_manifest = _resolve_existing(flags["--dependency-manifest"], "file")
    arg_spec = _resolve_existing(flags["--task-spec"], "file")
    arg_bootstrap = _resolve_existing(bootstrap_arg, "file")

    plan = _Plan()
    try:
        # -- task-spec: read through an identity-stable handle, bind digest -- #
        spec_handle = _open_pinned(arg_spec)
        plan.held.append(spec_handle)
        spec_bytes, spec_sha = spec_handle.read_verified(_MAX_SPEC_BYTES)
        if spec_sha != flags["--task-spec-sha256"]:
            raise _BootstrapError("task-spec-digest-mismatch")
        document = _load_json(spec_bytes, "task-spec-json-invalid")
        if not isinstance(document, dict):
            raise _BootstrapError("task-spec-json-invalid")

        _bind_and_load(
            document,
            flags,
            attempt,
            argv,
            bootstrap_arg,
            arg_root,
            arg_config,
            arg_manifest,
            arg_spec,
            arg_bootstrap,
            sid_provider,
            executable,
            plan,
        )
        return plan
    except BaseException:
        plan.close()
        raise


def _bind_and_load(
    document,
    flags,
    attempt,
    argv,
    bootstrap_arg,
    arg_root,
    arg_config,
    arg_manifest,
    arg_spec,
    arg_bootstrap,
    sid_provider,
    executable,
    plan,
) -> None:
    _require_mapping(
        document,
        ("version", "identity", "paths", "pins", "launch", "scheduler_policy"),
        "task-spec-schema",
    )
    if not _is_int(document["version"]) or document["version"] != 1:
        raise _BootstrapError("task-spec-version")

    # ---- identity ---- #
    identity = document["identity"]
    _require_mapping(
        identity, ("task_id", "attempt", "nonce", "profile", "model"), "task-spec-identity"
    )
    task_id = identity["task_id"]
    if not _is_str(task_id) or _TASK_ID_RE.fullmatch(task_id) is None or task_id.lower() in _WINDOWS_RESERVED:
        raise _BootstrapError("task-spec-identity")
    if not _is_int(identity["attempt"]) or identity["attempt"] not in (1, 2):
        raise _BootstrapError("task-spec-identity")
    if not _is_str(identity["nonce"]) or _NONCE_RE.fullmatch(identity["nonce"]) is None:
        raise _BootstrapError("task-spec-identity")
    profile = identity["profile"]
    if not _is_str(profile) or _PROFILE_RE.fullmatch(profile) is None or profile.lower() in _WINDOWS_RESERVED:
        raise _BootstrapError("task-spec-identity")
    model = identity["model"]
    if not _is_str(model) or _MODEL_RE.fullmatch(model) is None or ".." in model or model.endswith("."):
        raise _BootstrapError("task-spec-identity")
    if (
        identity["task_id"] != flags["--task-id"]
        or identity["attempt"] != attempt
        or identity["nonce"] != flags["--nonce"]
        or identity["profile"] != flags["--profile"]
        or identity["model"] != flags["--model"]
    ):
        raise _BootstrapError("argv-spec-identity-mismatch")

    # ---- paths ---- #
    paths = document["paths"]
    _require_mapping(
        paths,
        (
            "approved_repo_root",
            "repo",
            "root",
            "attempt",
            "config",
            "bootstrap",
            "dependency_manifest",
            "task_spec",
            "task_xml",
        ),
        "task-spec-paths",
    )
    if not all(_is_str(paths[key]) for key in paths):
        raise _BootstrapError("task-spec-paths")
    if (
        paths["root"] != flags["--root"]
        or paths["config"] != flags["--config"]
        or paths["dependency_manifest"] != flags["--dependency-manifest"]
        or paths["task_spec"] != flags["--task-spec"]
        or paths["bootstrap"] != bootstrap_arg
    ):
        raise _BootstrapError("argv-spec-path-mismatch")

    repo = _resolve_existing(paths["repo"], "dir")
    if paths["approved_repo_root"] != paths["repo"]:
        raise _BootstrapError("repo-not-approved")
    if not _contained(arg_root, repo):
        raise _BootstrapError("root-outside-repo")
    if not _contained(arg_config, arg_root):
        raise _BootstrapError("config-outside-root")
    if not _contained(arg_manifest, arg_root):
        raise _BootstrapError("manifest-outside-root")
    if not _contained(arg_spec, arg_root):
        raise _BootstrapError("spec-outside-root")

    expected_bootstrap = os.path.join(repo, "autonomy", "runner_bootstrap.py")
    if paths["bootstrap"] != expected_bootstrap or arg_bootstrap != expected_bootstrap:
        raise _BootstrapError("bootstrap-path-unexpected")

    attempt_dir = _resolve_existing(paths["attempt"], "dir")
    expected_attempt = os.path.join(arg_root, "attempts", task_id, "a" + str(attempt))
    if paths["attempt"] != expected_attempt or attempt_dir != expected_attempt:
        raise _BootstrapError("attempt-path-unexpected")
    if not _contained(attempt_dir, arg_root):
        raise _BootstrapError("attempt-outside-root")
    expected_spec = os.path.join(attempt_dir, "task-spec.json")
    if paths["task_spec"] != expected_spec or arg_spec != expected_spec:
        raise _BootstrapError("spec-path-unexpected")
    expected_xml = os.path.join(attempt_dir, "runner-task.xml")
    if paths["task_xml"] != expected_xml:
        raise _BootstrapError("task-xml-path-unexpected")

    # ---- launch ---- #
    launch = document["launch"]
    _require_mapping(
        launch,
        (
            "command",
            "arguments_before_task_spec_sha256",
            "task_spec_sha256_argument",
            "working_directory",
        ),
        "task-spec-launch",
    )
    python_path = launch["command"]
    if not _is_str(python_path):
        raise _BootstrapError("task-spec-launch")
    if launch["working_directory"] != paths["repo"]:
        raise _BootstrapError("launch-working-directory")
    if launch["task_spec_sha256_argument"] != "--task-spec-sha256":
        raise _BootstrapError("launch-sha-argument")
    before = launch["arguments_before_task_spec_sha256"]
    if not isinstance(before, list) or not all(_is_str(item) for item in before):
        raise _BootstrapError("launch-arguments")
    if before != ["-I", "-S"] + list(argv[:-2]):
        raise _BootstrapError("launch-arguments-mismatch")

    expected_python = os.path.join(repo, ".venv", "Scripts", "python.exe")
    if python_path != expected_python:
        raise _BootstrapError("python-path-unexpected")
    if executable != expected_python:
        raise _BootstrapError("executable-mismatch")
    arg_python = _resolve_existing(python_path, "file")
    if os.path.basename(arg_python).lower() != "python.exe":
        raise _BootstrapError("python-name-invalid")

    # ---- scheduler policy ---- #
    policy = document["scheduler_policy"]
    _require_mapping(
        policy,
        (
            "folder",
            "principal_user_sid",
            "logon_type",
            "run_level",
            "settings",
            "idle_settings",
            "triggers",
        ),
        "task-spec-policy",
    )
    if policy["folder"] != TASK_FOLDER:
        raise _BootstrapError("policy-folder")
    if policy["logon_type"] != "InteractiveToken":
        raise _BootstrapError("policy-logon-type")
    if policy["run_level"] != "LeastPrivilege":
        raise _BootstrapError("policy-run-level")
    if policy["settings"] != _SECURITY_SETTINGS:
        raise _BootstrapError("policy-settings")
    if policy["idle_settings"] != _IDLE_SETTINGS:
        raise _BootstrapError("policy-idle-settings")
    if policy["triggers"] != _EXPECTED_TRIGGERS:
        raise _BootstrapError("policy-triggers")
    sid = policy["principal_user_sid"]
    if not _is_str(sid) or _SID_RE.fullmatch(sid) is None or len(sid) > 184:
        raise _BootstrapError("policy-sid-invalid")
    current_sid = sid_provider()
    if sid != current_sid:
        raise _BootstrapError("policy-sid-mismatch")

    # ---- pins ---- #
    pins = document["pins"]
    _require_mapping(
        pins,
        ("python", "config", "bootstrap", "dependency_manifest", "dependencies"),
        "task-spec-pins",
    )
    py_path, py_sha, py_ident = _validate_pin(pins["python"], "pin-python")
    cfg_path, cfg_sha, cfg_ident = _validate_pin(pins["config"], "pin-config")
    bs_path, bs_sha, bs_ident = _validate_pin(pins["bootstrap"], "pin-bootstrap")
    mf_path, mf_sha, mf_ident = _validate_pin(pins["dependency_manifest"], "pin-manifest")
    if py_path != python_path:
        raise _BootstrapError("pin-path-mismatch")
    if cfg_path != paths["config"]:
        raise _BootstrapError("pin-path-mismatch")
    if bs_path != paths["bootstrap"]:
        raise _BootstrapError("pin-path-mismatch")
    if mf_path != paths["dependency_manifest"]:
        raise _BootstrapError("pin-path-mismatch")

    python_handle = _open_pinned(arg_python)
    plan.held.append(python_handle)
    python_handle.read_verified(_MAX_EXE_BYTES, py_sha, py_ident)

    bootstrap_handle = _open_pinned(arg_bootstrap)
    plan.held.append(bootstrap_handle)
    bootstrap_handle.read_verified(_MAX_DURABLE_BYTES, bs_sha, bs_ident)

    config_handle = _open_pinned(arg_config)
    plan.held.append(config_handle)
    config_handle.read_verified(_MAX_DURABLE_BYTES, cfg_sha, cfg_ident)

    manifest_handle = _open_pinned(arg_manifest)
    plan.held.append(manifest_handle)
    manifest_bytes, _ = manifest_handle.read_verified(
        _MAX_MANIFEST_BYTES, mf_sha, mf_ident
    )

    # ---- dependencies (spec pins) ---- #
    dependency_pins = pins["dependencies"]
    if not isinstance(dependency_pins, list) or not dependency_pins:
        raise _BootstrapError("pin-dependencies")
    spec_deps = []
    seen_rel = set()
    for entry in dependency_pins:
        _require_mapping(
            entry, ("relative_path", "path", "sha256", "identity"), "pin-dependency"
        )
        rel = entry["relative_path"]
        module_name, is_package, parts = _dependency_module(rel)
        key = rel.casefold()
        if key in seen_rel:
            raise _BootstrapError("pin-dependency-duplicate")
        seen_rel.add(key)
        dep_sha = entry["sha256"]
        if not _is_str(dep_sha) or _SHA256_RE.fullmatch(dep_sha) is None:
            raise _BootstrapError("pin-dependency")
        dep_ident_obj = entry["identity"]
        _require_mapping(
            dep_ident_obj, ("device", "inode", "size", "mtime_ns"), "pin-dependency"
        )
        for field_name in ("device", "inode", "size", "mtime_ns"):
            if not _is_int(dep_ident_obj[field_name]):
                raise _BootstrapError("pin-dependency")
        dep_ident = (
            dep_ident_obj["device"],
            dep_ident_obj["inode"],
            dep_ident_obj["size"],
            dep_ident_obj["mtime_ns"],
        )
        abspath = _resolve_existing(os.path.join(repo, *parts), "file")
        if entry["path"] != abspath:
            raise _BootstrapError("pin-dependency-path")
        if not _contained(abspath, repo):
            raise _BootstrapError("dependency-outside-repo")
        spec_deps.append((rel, abspath, dep_sha, dep_ident, module_name, is_package))

    # ---- manifest must match the task-spec dependency pins exactly ---- #
    manifest_deps = _parse_manifest(manifest_bytes)
    spec_pairs = sorted((rel.casefold(), sha) for rel, _, sha, _, _, _ in spec_deps)
    manifest_pairs = sorted((rel.casefold(), sha) for rel, sha in manifest_deps)
    if len(manifest_deps) != len(spec_deps) or spec_pairs != manifest_pairs:
        raise _BootstrapError("manifest-spec-mismatch")

    # ---- read + compile each dependency from its pinned handle ---- #
    finder_modules = {}
    context_deps = []
    for rel, abspath, dep_sha, dep_ident, module_name, is_package in spec_deps:
        handle = _open_pinned(abspath)
        plan.held.append(handle)
        raw, _ = handle.read_verified(_MAX_DURABLE_BYTES, dep_sha, dep_ident)
        try:
            source = raw.decode("utf-8-sig", "strict")
            code = compile(source, abspath, "exec")
        except (UnicodeDecodeError, SyntaxError, ValueError, TypeError):
            raise _BootstrapError("dependency-source-invalid") from None
        if module_name in finder_modules:
            raise _BootstrapError("dependency-module-duplicate")
        finder_modules[module_name] = (code, is_package, abspath)
        context_deps.append((rel, abspath, dep_sha, dep_ident))
    if "autonomy" not in finder_modules or "autonomy.runner" not in finder_modules:
        raise _BootstrapError("manifest-missing-runner")
    if "autonomy.supervisor_tick" not in finder_modules:
        raise _BootstrapError("manifest-missing-supervisor")
    # The boot clock must be pinned as exactly the normalized relative file
    # autonomy/boot_clock.py; a package autonomy/boot_clock/__init__.py maps
    # to the same module name but is NOT a substitute.
    if not any(rel == "autonomy/boot_clock.py" for rel, _, _, _ in context_deps):
        raise _BootstrapError("manifest-missing-boot-clock")

    plan.repo = repo
    plan.root = arg_root
    plan.finder_modules = finder_modules
    plan.load_order = tuple(sorted(finder_modules))
    plan.context_data = {
        "task_id": task_id,
        "attempt": attempt,
        "nonce": identity["nonce"],
        "profile": profile,
        "model": model,
        "repo": repo,
        "root": arg_root,
        "attempt_dir": attempt_dir,
        "config": arg_config,
        "config_sha256": cfg_sha,
        "bootstrap": arg_bootstrap,
        "python": arg_python,
        "dependency_manifest": arg_manifest,
        "task_spec": arg_spec,
        # Equal to the digest verified against the task-spec bytes above.
        "task_spec_sha256": flags["--task-spec-sha256"],
        "principal_sid": current_sid,
        "deps": context_deps,
    }


# --------------------------------------------------------------------------- #
# Private in-memory import system (ordinary imports use verified bytes).        #
# --------------------------------------------------------------------------- #


class _UnlistedAutonomyImport(ImportError):
    """Raised by the private finder for any un-pinned ``autonomy.*`` import."""


class _PinnedLoader:
    def __init__(self, code, origin: str, is_package: bool, handoff=None) -> None:
        self._code = code
        self._origin = origin
        self._is_package = is_package
        self._handoff = handoff

    def create_module(self, spec):
        return None

    def exec_module(self, module) -> None:
        if self._handoff is not None:
            module.__dict__["_BOOTSTRAP_HANDOFF"] = self._handoff
        exec(self._code, module.__dict__)


class _PinnedFinder:
    def __init__(self, modules, runner_handoff) -> None:
        self._modules = modules
        self._runner_handoff = runner_handoff

    def find_spec(self, name, path=None, target=None):
        if name == "autonomy" or name.startswith("autonomy."):
            entry = self._modules.get(name)
            if entry is None:
                raise _UnlistedAutonomyImport(name)
            code, is_package, origin = entry
            handoff = self._runner_handoff if name == "autonomy.runner" else None
            loader = _PinnedLoader(code, origin, is_package, handoff)
            spec = importlib.machinery.ModuleSpec(name, loader, origin=origin)
            if is_package:
                spec.submodule_search_locations = []
            return spec
        return None


def _sanitize_sys_path(repo: str, root: str) -> None:
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = None
    bases = []
    for base in (repo, root, cwd):
        if base is None:
            continue
        try:
            bases.append(os.path.normcase(os.path.realpath(base)))
        except (OSError, ValueError):
            continue
    keep = []
    for entry in sys.path:
        if not isinstance(entry, str) or entry in ("", "."):
            continue
        try:
            real = os.path.normcase(os.path.realpath(entry))
        except (OSError, ValueError):
            continue
        if any(real == base or real.startswith(base + os.sep) for base in bases):
            continue
        keep.append(entry)
    sys.path[:] = keep


def _purge_autonomy_modules() -> None:
    for name in [n for n in list(sys.modules) if n == "autonomy" or n.startswith("autonomy.")]:
        del sys.modules[name]


def _safe_code(code) -> str:
    if isinstance(code, str) and _CODE_RE.fullmatch(code) is not None:
        return code
    return "runner-error"


def _build_context(runner_module, plan, handoff):
    data = plan.context_data
    dependency_type = runner_module._DependencyPin
    dependencies = tuple(
        dependency_type(
            relative_path=rel,
            path=path,
            sha256=sha,
            device=identity[0],
            inode=identity[1],
            size=identity[2],
            mtime_ns=identity[3],
        )
        for rel, path, sha, identity in data["deps"]
    )
    return runner_module._BootstrapContext(
        _handoff=handoff,
        task_id=data["task_id"],
        attempt=data["attempt"],
        nonce=data["nonce"],
        profile=data["profile"],
        model=data["model"],
        repo=data["repo"],
        root=data["root"],
        attempt_dir=data["attempt_dir"],
        config=data["config"],
        config_sha256=data["config_sha256"],
        bootstrap=data["bootstrap"],
        python=data["python"],
        dependency_manifest=data["dependency_manifest"],
        task_spec=data["task_spec"],
        task_spec_sha256=data["task_spec_sha256"],
        principal_sid=data["principal_sid"],
        dependencies=dependencies,
    )


def _execute(plan: _Plan) -> int:
    _sanitize_sys_path(plan.repo, plan.root)
    _purge_autonomy_modules()
    handoff = object()
    finder = _PinnedFinder(plan.finder_modules, handoff)
    sys.meta_path.insert(0, finder)
    importlib.invalidate_caches()
    try:
        for name in plan.load_order:
            try:
                importlib.import_module(name)
            except _UnlistedAutonomyImport:
                raise _BootstrapError("unlisted-autonomy-import") from None
            except _BootstrapError:
                raise
            except BaseException:
                raise _BootstrapError("autonomy-load-failed") from None
    except BaseException:
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            pass
        raise

    runner_module = sys.modules.get("autonomy.runner")
    if runner_module is None:
        raise _BootstrapError("runner-not-loaded")
    if sys.modules.get("autonomy.supervisor_tick") is None:
        raise _BootstrapError("supervisor-tick-unavailable")
    if sys.modules.get("autonomy.boot_clock") is None:
        raise _BootstrapError("boot-clock-unavailable")

    context = _build_context(runner_module, plan, handoff)
    try:
        result = runner_module._main_from_bootstrap(context)
    except runner_module.RunnerError as error:
        raise _BootstrapError(_safe_code(error.code)) from None
    except _BootstrapError:
        raise
    except BaseException:
        raise _BootstrapError("runner-invocation-failed") from None
    return result


# --------------------------------------------------------------------------- #
# Diagnostics + entrypoint.                                                     #
# --------------------------------------------------------------------------- #


def _emit(code) -> None:
    text = code if (isinstance(code, str) and _CODE_RE.fullmatch(code) is not None) else "bootstrap-error"
    payload = '{"ok":false,"error":"' + text + '"}'
    try:
        data = payload.encode("ascii", "strict")
    except UnicodeEncodeError:
        data = b'{"ok":false,"error":"bootstrap-error"}'
    try:
        sys.stderr.buffer.write(data + b"\n")
        sys.stderr.buffer.flush()
    except BaseException:
        pass


def main(argv=None) -> int:
    argv = list(sys.argv) if argv is None else list(argv)
    plan = None
    try:
        try:
            plan = _validate(argv)
            result = _execute(plan)
        finally:
            if plan is not None:
                plan.close()
    except _BootstrapError as error:
        _emit(error.code)
        return _EXIT_FAILCLOSED
    except BaseException:
        _emit("bootstrap-internal-error")
        return _EXIT_FAILCLOSED
    if type(result) is not int or type(result) is bool or result < 0 or result > 125:
        _emit("runner-exit-invalid")
        return _EXIT_FAILCLOSED
    return result


if __name__ == "__main__":
    sys.exit(main())
