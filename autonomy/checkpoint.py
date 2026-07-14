"""Durable checkpoint and progress documents for one night-autonomy claim attempt (M2).

Standalone stdlib-only slice: no imports from live agentchattr modules and no
integration with wrapper.py yet.  A worker records where it stands by writing
two small JSON documents into the attempt directory created by ``claim``
(see contract.json: ``attempts/<task_id>/a<attempt>/``):

- ``checkpoint.json`` -- resumable position: last completed step, next step,
  artifact paths.  Compact summary, hard-capped at MAX_CHECKPOINT_BYTES.
- ``progress.json``   -- operator-facing status line.  Distinct from the
  heartbeat and changes ONLY when a caller explicitly writes it.

Both documents are written with a temp file in the same opened directory followed by
an identity-preserving atomic rename; the temp file is removed when the write fails.  Reads validate
the exact closed schema and fail closed on corruption, oversize data, path
escapes, task/attempt mismatches and non-UTC timestamps.

The queue root is authenticated on every operation through retained directory
handles by strictly reading the
``autonomy-root.json`` marker: bounded ASCII JSON, duplicate keys and
NaN/Infinity rejected, exact closed ``{version, name}`` schema matching
autonomy/contract.json, and the marker itself may not be a symlink or any
other reparse point.

An attempt directory is never "any directory under the root": every
checkpoint/progress/heartbeat read and write binds the caller-supplied
directory to the ONE canonical path ``attempts/<task_id>/a<attempt>`` for the
caller's exact task_id and attempt.  ``.``/``..`` segments, case or
short-name aliases of the tail, directories of another task or attempt, and
symlink/junction/reparse components fail closed with PathEscapeError.

Threat-model boundary: these primitives detect and recover deterministic races
from ordinary concurrent writers, but they are not a sandbox against a
continuously hostile process running as the same directory owner.  Windows has
no share flag that prevents that owner from adding a hard link, and POSIX
directory locks are advisory.  Deployment therefore MUST make the queue tree
writable only by the autonomy service identity.  Within that boundary, a
detected commit race restores and re-verifies the prior destination identity
before returning failure.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

__all__ = [
    "CheckpointError",
    "SchemaError",
    "SizeLimitError",
    "PathEscapeError",
    "StateMismatchError",
    "MissingDocumentError",
    "ROOT_MARKER",
    "ROOT_MARKER_VERSION",
    "ROOT_MARKER_NAME",
    "ROOT_MARKER_MAX_BYTES",
    "ATTEMPTS_DIRNAME",
    "CHECKPOINT_FILENAME",
    "PROGRESS_FILENAME",
    "SCHEMA_VERSION",
    "MAX_CHECKPOINT_BYTES",
    "MAX_PROGRESS_BYTES",
    "validate_task_id",
    "validate_attempt",
    "validate_artifact_relpath",
    "format_utc",
    "validate_updated_at",
    "authenticate_root_marker",
    "resolve_queue_root",
    "resolve_attempt_dir",
    "guard_state_file",
    "atomic_write_document",
    "read_document",
    "read_state_document",
    "require_exact_keys",
    "validate_version",
    "write_checkpoint",
    "read_checkpoint",
    "write_progress",
    "read_progress",
]

ROOT_MARKER = "autonomy-root.json"
# The marker must carry exactly the version/name published in autonomy/contract.json.
ROOT_MARKER_VERSION = 1
ROOT_MARKER_NAME = "agentchattr-autonomy-queue"
ROOT_MARKER_MAX_BYTES = 1024
ATTEMPTS_DIRNAME = "attempts"
CHECKPOINT_FILENAME = "checkpoint.json"
PROGRESS_FILENAME = "progress.json"
SCHEMA_VERSION = 1

MAX_CHECKPOINT_BYTES = 2048
MAX_PROGRESS_BYTES = 2048

MAX_ATTEMPT = 1_000_000
MAX_ARTIFACTS = 16
MAX_ARTIFACT_CHARS = 200
MAX_ARTIFACT_SEGMENTS = 8
MAX_TIMESTAMP_CHARS = 64

# task_id mirrors contract.json exactly; anything path-like fails the pattern.
_TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# Steps: 1..128 printable ASCII, no leading/trailing space.
_STEP_RE = re.compile(r"^[\x21-\x7e](?:[\x20-\x7e]{0,126}[\x21-\x7e])?$")
_STATUS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_DETAIL_RE = re.compile(r"^[\x20-\x7e]{0,512}$")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# contract.json created_utc format: yyyy-MM-ddTHH:mm:ss.fffZ
_UPDATED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

_CHECKPOINT_KEYS = (
    "version",
    "task_id",
    "attempt",
    "completed_step",
    "next_step",
    "artifacts",
    "updated_at",
)
_PROGRESS_KEYS = ("version", "task_id", "attempt", "status", "detail", "updated_at")
_ROOT_MARKER_KEYS = ("version", "name")


if os.name == "nt":
    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _DELETE = 0x00010000
    _FILE_LIST_DIRECTORY = 0x00000001
    _FILE_READ_ATTRIBUTES = 0x00000080
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_TYPE_DISK = 0x0001
    _FILE_RENAME_INFO_CLASS = 3
    _FILE_DISPOSITION_INFO_CLASS = 4
    _ERROR_FILE_NOT_FOUND = 2
    _ERROR_PATH_NOT_FOUND = 3
    _ERROR_FILE_EXISTS = 80
    _ERROR_ALREADY_EXISTS = 183

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _FILE_RENAME_INFO(ctypes.Structure):
        # The first field is the ReplaceIfExists/Flags union.  DWORD gives the
        # correct layout for both FileRenameInfo and FileRenameInfoEx.
        _fields_ = [
            ("flags", wintypes.DWORD),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * 1),
        ]

    class _FILE_DISPOSITION_INFO(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BOOL)]

    class _UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum_length", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class _OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root_directory", wintypes.HANDLE),
            ("object_name", ctypes.POINTER(_UNICODE_STRING)),
            ("attributes", wintypes.ULONG),
            ("security_descriptor", wintypes.LPVOID),
            ("security_quality_of_service", wintypes.LPVOID),
        ]

    class _IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]

    _NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)
    _SYNCHRONIZE = 0x00100000
    _NT_FILE_CREATE = 2
    _NT_FILE_RENAME_INFORMATION = 10
    _FILE_NON_DIRECTORY_FILE = 0x00000040
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _STATUS_OBJECT_NAME_COLLISION = ctypes.c_long(0xC0000035).value

    _KERNEL32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    _KERNEL32.GetFileInformationByHandle.restype = wintypes.BOOL
    _KERNEL32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _KERNEL32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _KERNEL32.GetFileType.argtypes = [wintypes.HANDLE]
    _KERNEL32.GetFileType.restype = wintypes.DWORD
    _KERNEL32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _KERNEL32.ReadFile.restype = wintypes.BOOL
    _KERNEL32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _KERNEL32.WriteFile.restype = wintypes.BOOL
    _KERNEL32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _KERNEL32.FlushFileBuffers.restype = wintypes.BOOL
    _KERNEL32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _KERNEL32.SetFileInformationByHandle.restype = wintypes.BOOL
    _NTDLL.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_OBJECT_ATTRIBUTES),
        ctypes.POINTER(_IO_STATUS_BLOCK),
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _NTDLL.NtCreateFile.restype = ctypes.c_long
    _NTDLL.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
    _NTDLL.RtlNtStatusToDosError.restype = wintypes.ULONG
    _NTDLL.NtSetInformationFile.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_IO_STATUS_BLOCK),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.c_int,
    ]
    _NTDLL.NtSetInformationFile.restype = ctypes.c_long


class CheckpointError(Exception):
    """Base class for every fail-closed refusal in the M2 state layer."""


class SchemaError(CheckpointError):
    """Malformed input value or corrupt/mistyped stored document."""


class SizeLimitError(CheckpointError):
    """Serialized payload or stored file exceeds its byte cap."""


class PathEscapeError(CheckpointError):
    """A caller-controlled path would leave the queue root or attempt dir."""


class StateMismatchError(CheckpointError):
    """Stored task_id/attempt differ from what the caller expected."""


class MissingDocumentError(CheckpointError):
    """The requested state document does not exist (normal for a fresh attempt)."""


def validate_task_id(task_id):
    if not isinstance(task_id, str) or not _TASK_ID_RE.fullmatch(task_id):
        raise SchemaError(f"malformed task_id: {task_id!r}")
    if task_id in _WINDOWS_RESERVED:
        raise SchemaError(f"task_id is a reserved device name: {task_id!r}")
    return task_id


def validate_attempt(attempt):
    if isinstance(attempt, bool) or not isinstance(attempt, int):
        raise SchemaError(f"malformed attempt: {attempt!r}")
    if not 1 <= attempt <= MAX_ATTEMPT:
        raise SchemaError(f"attempt out of range 1..{MAX_ATTEMPT}: {attempt!r}")
    return attempt


def format_utc(moment=None):
    """Render a tz-aware UTC datetime as the contract's yyyy-MM-ddTHH:mm:ss.fffZ."""
    if moment is None:
        moment = datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() != timedelta(0)
    ):
        raise SchemaError(f"timestamps must be timezone-aware UTC datetimes: {moment!r}")
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def validate_updated_at(value):
    if not isinstance(value, str) or len(value) > MAX_TIMESTAMP_CHARS:
        raise SchemaError(f"updated_at must be a short string: {value!r}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SchemaError(f"updated_at is not a valid timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise SchemaError(f"updated_at must be UTC: {value!r}")
    if not _UPDATED_AT_RE.fullmatch(value):
        raise SchemaError(
            f"updated_at must use the contract format yyyy-MM-ddTHH:mm:ss.fffZ: {value!r}"
        )
    return value


def validate_artifact_relpath(value):
    """Lexical checks only; containment against the attempt dir happens separately."""
    if not isinstance(value, str):
        raise SchemaError(f"artifact path must be a string: {value!r}")
    if not 1 <= len(value) <= MAX_ARTIFACT_CHARS:
        raise SchemaError(f"artifact path length out of 1..{MAX_ARTIFACT_CHARS}: {value!r}")
    if "\\" in value:
        raise SchemaError(f"artifact paths use forward slashes only: {value!r}")
    segments = value.split("/")
    if len(segments) > MAX_ARTIFACT_SEGMENTS:
        raise SchemaError(f"artifact path has too many segments: {value!r}")
    for segment in segments:
        if segment in ("..", "."):
            raise PathEscapeError(f"artifact path may not traverse: {value!r}")
        if not _SEGMENT_RE.fullmatch(segment) or segment.endswith("."):
            raise SchemaError(f"malformed artifact path segment {segment!r} in {value!r}")
        if segment.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
            raise SchemaError(f"artifact segment is a reserved device name: {segment!r}")
    return value


def _path_text(value, label):
    if not isinstance(value, (str, os.PathLike)):
        raise PathEscapeError(f"{label} must be a path: {value!r}")
    text = os.fspath(value)
    if not isinstance(text, str) or not text or "\0" in text:
        raise PathEscapeError(f"{label} must be a non-empty str path: {value!r}")
    return text


def _validate_exact_absolute_spelling(text, label):
    """Reject aliases lexically, before any realpath/canonicalization call."""
    if os.name == "nt":
        if text.startswith("\\\\"):
            raise PathEscapeError(f"{label} may not be UNC/device syntax: {text!r}")
        if "/" in text:
            raise PathEscapeError(f"{label} must use exact backslash spelling: {text!r}")
        if not re.match(r"^[A-Z]:\\", text):
            raise PathEscapeError(f"{label} must be an absolute uppercase drive path: {text!r}")
        if len(text) <= 3 or text.endswith("\\") or "\\\\" in text[3:]:
            raise PathEscapeError(f"{label} has duplicate/trailing separators: {text!r}")
        segments = text[3:].split("\\")
        if any(
            not segment
            or segment in (".", "..")
            or segment.endswith((".", " "))
            or ":" in segment
            for segment in segments
        ):
            raise PathEscapeError(f"{label} has an aliased or dot component: {text!r}")
        return text[:3], segments
    if not text.startswith("/") or text.startswith("//"):
        raise PathEscapeError(f"{label} must be one exact absolute POSIX path: {text!r}")
    if text == "/" or text.endswith("/") or "//" in text[1:]:
        raise PathEscapeError(f"{label} has duplicate/trailing separators: {text!r}")
    segments = text[1:].split("/")
    if any(not segment or segment in (".", "..") for segment in segments):
        raise PathEscapeError(f"{label} has an aliased or dot component: {text!r}")
    return "/", segments


def _validate_exact_attempt_spelling(text, root_text, expected_tail):
    relative = os.path.join(*expected_tail)
    absolute = os.path.join(root_text, *expected_tail)
    if os.name == "nt":
        if text.startswith("\\\\") or "/" in text or "\\\\" in text:
            raise PathEscapeError(f"attempt dir has aliased separators: {text!r}")
        if text.endswith("\\") or any(
            part in ("", ".", "..") for part in text.split("\\")
        ):
            raise PathEscapeError(f"attempt dir has dot/trailing components: {text!r}")
        if os.path.isabs(text) or (len(text) >= 2 and text[1] == ":"):
            if text != absolute:
                raise PathEscapeError(
                    f"absolute attempt dir must spell the exact canonical path: {text!r}"
                )
        elif text != relative:
            raise PathEscapeError(
                f"relative attempt dir must spell only the exact canonical tail: {text!r}"
            )
    else:
        if text.startswith("//") or "//" in text or text.endswith("/"):
            raise PathEscapeError(f"attempt dir has aliased separators: {text!r}")
        if any(part in ("", ".", "..") for part in text.split("/")):
            raise PathEscapeError(f"attempt dir has dot/trailing components: {text!r}")
        if os.path.isabs(text):
            if text != absolute:
                raise PathEscapeError(
                    f"absolute attempt dir must spell the exact canonical path: {text!r}"
                )
        elif text != relative:
            raise PathEscapeError(
                f"relative attempt dir must spell only the exact canonical tail: {text!r}"
            )


if os.name == "nt":
    def _win_error(message):
        return PathEscapeError(f"{message}: {ctypes.WinError(ctypes.get_last_error())}")


    def _win_close(handle):
        if handle not in (None, _INVALID_HANDLE_VALUE):
            _KERNEL32.CloseHandle(handle)


    def _win_info(handle):
        info = _BY_HANDLE_FILE_INFORMATION()
        if not _KERNEL32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise _win_error("GetFileInformationByHandle failed")
        return info


    def _win_identity(info):
        return (info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow)


    def _win_stamp(info):
        return (
            _win_identity(info),
            info.nFileSizeHigh,
            info.nFileSizeLow,
            info.ftLastWriteTime.dwHighDateTime,
            info.ftLastWriteTime.dwLowDateTime,
        )


    def _win_size(info):
        return (info.nFileSizeHigh << 32) | info.nFileSizeLow


    def _win_final_path(handle):
        capacity = 32768
        buffer = ctypes.create_unicode_buffer(capacity)
        length = _KERNEL32.GetFinalPathNameByHandleW(handle, buffer, capacity, 0)
        if not length:
            raise _win_error("GetFinalPathNameByHandleW failed")
        if length >= capacity:
            raise PathEscapeError("final handle path is ambiguous or overlong")
        value = buffer.value
        if not value.startswith("\\\\?\\") or value.startswith("\\\\?\\UNC\\"):
            raise PathEscapeError(f"unexpected final handle path syntax: {value!r}")
        return value[4:]


    def _win_create(path, access, share, disposition, flags, *, missing_ok=False):
        handle = _KERNEL32.CreateFileW(
            path, access, share, None, disposition, flags, None
        )
        if handle == _INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            if missing_ok and error in (_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND):
                return None
            if disposition == _CREATE_NEW and error in (
                _ERROR_FILE_EXISTS,
                _ERROR_ALREADY_EXISTS,
            ):
                raise FileExistsError(error, f"temporary path already exists: {path}")
            raise _win_error(f"CreateFileW refused {path!r}")
        return handle


    def _win_create_relative(directory_handle, name, *, access, share):
        """Create one new regular file relative to an already-bound directory handle.

        Win32 ``CreateFileW`` has no RootDirectory parameter.  Using its absolute
        path here would reopen the attempt-dir swap window after the final binding
        verification.  ``NtCreateFile`` is the native primitive behind it and can
        resolve exactly one relative component against our retained handle.
        """
        if (
            not isinstance(name, str)
            or not name
            or name in (".", "..")
            or "\\" in name
            or "/" in name
            or "\0" in name
        ):
            raise PathEscapeError(f"relative state filename is invalid: {name!r}")
        name_buffer = ctypes.create_unicode_buffer(name)
        unicode_name = _UNICODE_STRING(
            len(name.encode("utf-16-le")),
            len(name.encode("utf-16-le")) + 2,
            ctypes.cast(name_buffer, wintypes.LPWSTR),
        )
        attributes = _OBJECT_ATTRIBUTES(
            ctypes.sizeof(_OBJECT_ATTRIBUTES),
            directory_handle,
            ctypes.pointer(unicode_name),
            0,
            None,
            None,
        )
        iosb = _IO_STATUS_BLOCK()
        result = wintypes.HANDLE()
        status = _NTDLL.NtCreateFile(
            ctypes.byref(result),
            access | _SYNCHRONIZE,
            ctypes.byref(attributes),
            ctypes.byref(iosb),
            None,
            _FILE_ATTRIBUTE_NORMAL,
            share,
            _NT_FILE_CREATE,
            _FILE_NON_DIRECTORY_FILE | _FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        )
        if status < 0:
            if status == _STATUS_OBJECT_NAME_COLLISION:
                raise FileExistsError(f"temporary path already exists: {name}")
            error = int(_NTDLL.RtlNtStatusToDosError(status))
            raise ctypes.WinError(error)
        return result.value


    def _win_dispose_handle(handle):
        """Delete the exact link through which *handle* was opened on close."""
        disposition = _FILE_DISPOSITION_INFO(True)
        if not _KERNEL32.SetFileInformationByHandle(
            handle,
            _FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            raise ctypes.WinError(ctypes.get_last_error())


    def _win_rename_handle(handle, directory_handle, filename, *, replace):
        """Rename an opened file to one name in the retained directory."""
        encoded = filename.encode("utf-16-le")
        offset = _FILE_RENAME_INFO.file_name.offset
        size = offset + len(encoded) + 2
        buffer = ctypes.create_string_buffer(size)
        info = ctypes.cast(buffer, ctypes.POINTER(_FILE_RENAME_INFO)).contents
        info.flags = 1 if replace else 0
        info.root_directory = directory_handle
        info.file_name_length = len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + offset, encoded, len(encoded))
        iosb = _IO_STATUS_BLOCK()
        status = _NTDLL.NtSetInformationFile(
            handle,
            ctypes.byref(iosb),
            buffer,
            size,
            _NT_FILE_RENAME_INFORMATION,
        )
        if status < 0:
            error = int(_NTDLL.RtlNtStatusToDosError(status))
            raise ctypes.WinError(error)


    def _win_validate_directory_handle(handle, expected, identity=None):
        info = _win_info(handle)
        if not info.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise PathEscapeError(f"not a directory: {expected}")
        if info.dwFileAttributes & _REPARSE_FLAG:
            raise PathEscapeError(f"reparse directory component forbidden: {expected}")
        if _win_final_path(handle) != expected:
            raise PathEscapeError(f"directory spelling is not exact: {expected!r}")
        if identity is not None and _win_identity(info) != identity:
            raise PathEscapeError(f"directory identity changed: {expected}")
        return info


    def _win_validate_file_handle(handle, expected, *, max_bytes=None, identity=None):
        info = _win_info(handle)
        if (
            info.dwFileAttributes & (_FILE_ATTRIBUTE_DIRECTORY | _REPARSE_FLAG)
            or _KERNEL32.GetFileType(handle) != _FILE_TYPE_DISK
            or info.nNumberOfLinks != 1
        ):
            raise PathEscapeError(f"state document is not one regular non-reparse file: {expected}")
        if _win_final_path(handle) != expected:
            raise PathEscapeError(f"state handle final path is not exact: {expected!r}")
        if identity is not None and _win_identity(info) != identity:
            raise PathEscapeError(f"state file identity changed: {expected}")
        if max_bytes is not None and _win_size(info) > max_bytes:
            raise SizeLimitError(
                f"{Path(expected).name} is {_win_size(info)} bytes on disk; limit is {max_bytes}"
            )
        return info


class _DirectoryBinding:
    """Open directory chain retained for the full state operation."""

    def __init__(self, root_text, anchor, segments):
        self.root = Path(root_text)
        self.path = Path(anchor)
        self._closed = False
        self._guarded_files = {}
        if os.name == "nt":
            self._records = []
            self._open_windows_component(anchor, None)
        else:
            if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
                raise PathEscapeError("platform lacks required nofollow directory APIs")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            flags |= getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(anchor, flags)
            except OSError as exc:
                raise PathEscapeError(f"cannot open directory anchor {anchor!r}: {exc}") from exc
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                os.close(fd)
                raise PathEscapeError(f"directory anchor is not a directory: {anchor}")
            self._records = [(fd, anchor, (st.st_dev, st.st_ino), None, None)]
        try:
            self.append(segments)
        except BaseException:
            # __init__ has not returned, so _open_exact_directory cannot own
            # and close us yet.  Release every retained no-SHARE_DELETE handle
            # here or a rejected alias pins the caller's temporary tree.
            self.close()
            raise

    @property
    def directory_token(self):
        return self._records[-1][0]

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()
        return False

    def _open_windows_component(self, expected, component):
        handle = _win_create(
            expected,
            _FILE_READ_ATTRIBUTES | _FILE_LIST_DIRECTORY,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,  # deliberately no SHARE_DELETE
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        try:
            info = _win_validate_directory_handle(handle, expected)
            if component is not None:
                parent = os.fspath(self.path)
                try:
                    with os.scandir(parent) as entries:
                        if not any(entry.name == component for entry in entries):
                            raise PathEscapeError(
                                f"directory component is a case/short-name alias: {component!r}"
                            )
                except OSError as exc:
                    raise PathEscapeError(f"cannot enumerate exact parent {parent!r}: {exc}") from exc
        except BaseException:
            _win_close(handle)
            raise
        self._records.append((handle, expected, _win_identity(info), None, None))

    def append(self, segments):
        for component in segments:
            parent_token = self.directory_token
            parent_path = os.fspath(self.path)
            expected = os.path.join(parent_path, component)
            if os.name == "nt":
                self._open_windows_component(expected, component)
            else:
                fd = None
                try:
                    if component not in os.listdir(parent_token):
                        raise PathEscapeError(
                            f"directory component is not spelled exactly: {component!r}"
                        )
                    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    flags |= getattr(os, "O_CLOEXEC", 0)
                    fd = os.open(component, flags, dir_fd=parent_token)
                    st = os.fstat(fd)
                    named = os.stat(component, dir_fd=parent_token, follow_symlinks=False)
                    if not stat.S_ISDIR(st.st_mode) or not os.path.samestat(st, named):
                        raise PathEscapeError(f"directory component changed while opening: {expected}")
                except BaseException:
                    if fd is not None:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    raise
                self._records.append(
                    (fd, expected, (st.st_dev, st.st_ino), parent_token, component)
                )
            self.path = Path(expected)

    def verify(self):
        if self._closed:
            raise PathEscapeError("directory binding is already closed")
        for token, expected, identity, parent_token, component in self._records:
            if os.name == "nt":
                _win_validate_directory_handle(token, expected, identity)
            else:
                try:
                    opened = os.fstat(token)
                    if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != identity:
                        raise PathEscapeError(f"opened directory identity changed: {expected}")
                    if parent_token is not None:
                        named = os.stat(
                            component, dir_fd=parent_token, follow_symlinks=False
                        )
                        if not stat.S_ISDIR(named.st_mode) or not os.path.samestat(opened, named):
                            raise PathEscapeError(f"directory chain was renamed or swapped: {expected}")
                except PathEscapeError:
                    raise
                except OSError as exc:
                    raise PathEscapeError(f"cannot recheck directory {expected}: {exc}") from exc

    def close(self):
        if self._closed:
            return
        self._closed = True
        for record in reversed(self._records):
            if os.name == "nt":
                _win_close(record[0])
            else:
                try:
                    os.close(record[0])
                except OSError:
                    pass


def _open_exact_directory(value, label="directory"):
    text = _path_text(value, label)
    anchor, segments = _validate_exact_absolute_spelling(text, label)
    binding = None
    try:
        binding = _DirectoryBinding(text, anchor, segments)
        # This comparison is deliberately after lexical rejection and handle
        # inspection.  realpath is evidence only; it never repairs an alias.
        if os.path.realpath(text) != text:
            raise PathEscapeError(f"{label} is not its exact real path: {text!r}")
        binding.verify()
        return binding
    except PathEscapeError:
        if binding is not None:
            binding.close()
        raise
    except OSError as exc:
        if binding is not None:
            binding.close()
        raise PathEscapeError(f"cannot bind exact {label} {text!r}: {exc}") from exc


def _state_io_barrier(binding, _stage):
    """Security recheck point (also gives race tests a deterministic barrier)."""
    binding.verify()


def _read_windows_bound(binding, filename, max_bytes):
    expected = os.path.join(os.fspath(binding.path), filename)
    _state_io_barrier(binding, "read-before-open")
    handle = _win_create(
        expected,
        _GENERIC_READ | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ,  # no WRITE and, critically, no DELETE sharing
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        missing_ok=True,
    )
    if handle is None:
        if filename in binding._guarded_files and binding._guarded_files[filename] is not None:
            raise PathEscapeError(f"guarded state document vanished before open: {expected}")
        raise MissingDocumentError(f"state document missing: {expected}")
    try:
        before = _win_validate_file_handle(handle, expected, max_bytes=max_bytes)
        if (
            filename in binding._guarded_files
            and binding._guarded_files[filename] != _win_identity(before)
        ):
            raise PathEscapeError(f"guarded state file identity changed before open: {expected}")
        _state_io_barrier(binding, "read-after-open")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            size = min(remaining, 65536)
            buffer = ctypes.create_string_buffer(size)
            received = wintypes.DWORD()
            if not _KERNEL32.ReadFile(
                handle, buffer, size, ctypes.byref(received), None
            ):
                raise _win_error(f"ReadFile failed for {expected!r}")
            if not received.value:
                break
            chunks.append(buffer.raw[: received.value])
            remaining -= received.value
        data = b"".join(chunks)
        after = _win_validate_file_handle(
            handle, expected, max_bytes=max_bytes, identity=_win_identity(before)
        )
        if _win_stamp(after) != _win_stamp(before):
            raise PathEscapeError(f"state file changed while being read: {expected}")
        _state_io_barrier(binding, "read-after-data")
    finally:
        _win_close(handle)
    if len(data) > max_bytes:
        raise SizeLimitError(f"{filename} grew past {max_bytes} bytes while reading")
    return data


def _read_posix_bound(binding, filename, max_bytes):
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    _state_io_barrier(binding, "read-before-open")
    try:
        fd = os.open(filename, flags, dir_fd=binding.directory_token)
    except FileNotFoundError as exc:
        if filename in binding._guarded_files and binding._guarded_files[filename] is not None:
            raise PathEscapeError(
                f"guarded state document vanished before open: {binding.path / filename}"
            ) from exc
        raise MissingDocumentError(f"state document missing: {binding.path / filename}") from exc
    except OSError as exc:
        raise PathEscapeError(f"cannot nofollow-open state document {filename!r}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PathEscapeError(f"state document is not one regular file: {filename}")
        if (
            filename in binding._guarded_files
            and binding._guarded_files[filename] != (before.st_dev, before.st_ino)
        ):
            raise PathEscapeError(f"guarded state file identity changed before open: {filename}")
        if before.st_size > max_bytes:
            raise SizeLimitError(
                f"{filename} is {before.st_size} bytes on disk; limit is {max_bytes}"
            )
        _state_io_barrier(binding, "read-after-open")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        named = os.stat(
            filename, dir_fd=binding.directory_token, follow_symlinks=False
        )
        if (
            not os.path.samestat(before, after)
            or not os.path.samestat(after, named)
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise PathEscapeError(f"state file changed while being read: {filename}")
        _state_io_barrier(binding, "read-after-data")
    except FileNotFoundError as exc:
        raise PathEscapeError(f"state file vanished while being read: {filename}") from exc
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise SizeLimitError(f"{filename} grew past {max_bytes} bytes while reading")
    return data


def _read_bound_bytes(binding, filename, max_bytes):
    if not isinstance(filename, str) or filename in ("", ".", ".."):
        raise PathEscapeError(f"invalid state filename: {filename!r}")
    if os.path.basename(filename) != filename or os.path.altsep and os.path.altsep in filename:
        raise PathEscapeError(f"state filename must be one exact component: {filename!r}")
    if os.name == "nt":
        return _read_windows_bound(binding, filename, max_bytes)
    return _read_posix_bound(binding, filename, max_bytes)


def _authenticate_root_marker_bound(binding):
    document = read_document(
        binding.path / ROOT_MARKER,
        ROOT_MARKER_MAX_BYTES,
        _binding=binding,
    )
    require_exact_keys(document, _ROOT_MARKER_KEYS, ROOT_MARKER)
    version = document["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != ROOT_MARKER_VERSION:
        raise SchemaError(f"root marker version must be {ROOT_MARKER_VERSION}: {version!r}")
    name = document["name"]
    if not isinstance(name, str) or name != ROOT_MARKER_NAME:
        raise SchemaError(f"root marker name must be {ROOT_MARKER_NAME!r}: {name!r}")
    return document


def authenticate_root_marker(root_real):
    """Authenticate a marker through an exact, retained root directory handle."""
    binding = _open_exact_directory(root_real, "queue root")
    try:
        return _authenticate_root_marker_bound(binding)
    except PathEscapeError:
        raise
    except (CheckpointError, OSError) as exc:
        raise PathEscapeError(
            f"queue root not authenticated by {ROOT_MARKER}: {root_real} ({exc})"
        ) from exc
    finally:
        binding.close()


def resolve_queue_root(queue_root):
    binding = _open_exact_directory(queue_root, "queue root")
    try:
        _authenticate_root_marker_bound(binding)
        return binding.root
    except PathEscapeError:
        raise
    except (CheckpointError, OSError) as exc:
        raise PathEscapeError(
            f"queue root not authenticated by {ROOT_MARKER}: {queue_root} ({exc})"
        ) from exc
    finally:
        binding.close()


def _open_attempt_binding(queue_root, attempt_dir, *, task_id, attempt):
    task = validate_task_id(task_id)
    attempt_number = validate_attempt(attempt)
    binding = _open_exact_directory(queue_root, "queue root")
    try:
        try:
            _authenticate_root_marker_bound(binding)
        except PathEscapeError:
            raise
        except (CheckpointError, OSError) as exc:
            raise PathEscapeError(
                f"queue root not authenticated by {ROOT_MARKER}: {queue_root} ({exc})"
            ) from exc
        text = _path_text(attempt_dir, "attempt dir")
        expected_tail = (ATTEMPTS_DIRNAME, task, f"a{attempt_number}")
        _validate_exact_attempt_spelling(text, os.fspath(binding.root), expected_tail)
        binding.append(expected_tail)
        if os.path.realpath(os.fspath(binding.path)) != os.fspath(binding.path):
            raise PathEscapeError(f"attempt dir is not its exact real path: {text!r}")
        binding.verify()
        return binding
    except BaseException:
        binding.close()
        raise


def resolve_attempt_dir(queue_root, attempt_dir, *, task_id, attempt):
    """Resolve the exact canonical attempt spelling; state I/O retains this binding."""
    binding = _open_attempt_binding(
        queue_root, attempt_dir, task_id=task_id, attempt=attempt
    )
    try:
        return binding.root, binding.path
    finally:
        binding.close()


def guard_state_file(attempt_dir_real, filename, *, _binding=None):
    """Compose a state path and snapshot its identity on the retained binding."""
    directory = Path(attempt_dir_real)
    if not isinstance(filename, str) or os.path.basename(filename) != filename:
        raise PathEscapeError(f"state filename must be one component: {filename!r}")
    if _binding is not None:
        if directory != _binding.path:
            raise PathEscapeError("state path is not attached to its directory binding")
        _binding.verify()
        _binding._guarded_files[filename] = _snapshot_bound_destination(
            _binding, filename
        )
    return directory / filename


def _fsync_directory(directory, *, _binding=None):
    """Durably persist the completed rename through the already-open dirfd."""
    if os.name == "nt":
        return
    if _binding is not None:
        _binding.verify()
        os.fsync(_binding.directory_token)
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _BoundTemp:
    def __init__(self, binding, name, token, identity):
        self.binding = binding
        self.name = name
        self.token = token
        self.identity = identity
        self.replaced = False


def _snapshot_bound_destination(binding, filename):
    if os.name == "nt":
        expected = os.path.join(os.fspath(binding.path), filename)
        handle = _win_create(
            expected,
            _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            missing_ok=True,
        )
        if handle is None:
            return None
        try:
            info = _win_validate_file_handle(handle, expected)
            return _win_identity(info)
        finally:
            _win_close(handle)
    try:
        info = os.stat(
            filename, dir_fd=binding.directory_token, follow_symlinks=False
        )
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PathEscapeError(f"state destination is not one regular file: {filename}")
    return (info.st_dev, info.st_ino)


def _create_bound_temp(binding, filename):
    for _index in range(128):
        name = f"{filename}.{secrets.token_hex(12)}.tmp"
        if os.name == "nt":
            expected = os.path.join(os.fspath(binding.path), name)
            try:
                handle = _win_create_relative(
                    binding.directory_token,
                    name,
                    access=_GENERIC_READ
                    | _GENERIC_WRITE
                    | _DELETE
                    | _FILE_READ_ATTRIBUTES,
                    share=_FILE_SHARE_READ | _FILE_SHARE_WRITE,  # no SHARE_DELETE
                )
            except FileExistsError:
                continue
            try:
                info = _win_validate_file_handle(handle, expected)
            except BaseException as original:
                cleanup_error = None
                try:
                    _win_dispose_handle(handle)
                except BaseException as exc:
                    cleanup_error = exc
                finally:
                    _win_close(handle)
                if cleanup_error is not None:
                    raise PathEscapeError(
                        "failed to remove a rejected bound temporary file"
                    ) from cleanup_error
                raise original
            return _BoundTemp(binding, name, handle, _win_identity(info))
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(name, flags, 0o600, dir_fd=binding.directory_token)
        except FileExistsError:
            continue
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(fd)
            raise PathEscapeError(f"temporary state file is not regular: {name}")
        return _BoundTemp(binding, name, fd, (info.st_dev, info.st_ino))
    raise PathEscapeError("could not allocate a unique bound temporary state file")


def _write_temp_bytes(temp, data):
    if os.name == "nt":
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + 65536]
            buffer = ctypes.create_string_buffer(chunk)
            written = wintypes.DWORD()
            if not _KERNEL32.WriteFile(
                temp.token, buffer, len(chunk), ctypes.byref(written), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not written.value:
                raise OSError("WriteFile made no progress")
            offset += written.value
        return
    view = memoryview(data)
    while view:
        written = os.write(temp.token, view)
        if not written:
            raise OSError("os.write made no progress")
        view = view[written:]


def _flush_temp(temp):
    """User-space flush barrier (writes above are already unbuffered)."""
    return None


def _fsync_temp(temp):
    if os.name == "nt":
        if not _KERNEL32.FlushFileBuffers(temp.token):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    os.fsync(temp.token)


def _verify_temp(temp, expected_name, expected_size):
    if os.name == "nt":
        expected = os.path.join(os.fspath(temp.binding.path), expected_name)
        info = _win_validate_file_handle(
            temp.token, expected, identity=temp.identity
        )
        if _win_size(info) != expected_size:
            raise PathEscapeError("temporary state file size changed")
        return
    info = os.fstat(temp.token)
    if (info.st_dev, info.st_ino) != temp.identity or info.st_size != expected_size:
        raise PathEscapeError("temporary state file identity or size changed")


def _replace_bound_temp(temp, filename):
    binding = temp.binding
    if os.name == "nt":
        destination = os.path.join(os.fspath(binding.path), filename)
        # This check lives *inside* the commit primitive.  A hard link added
        # after the caller's last verification is detected before the rename.
        _win_validate_file_handle(
            temp.token,
            os.path.join(os.fspath(binding.path), temp.name),
            identity=temp.identity,
        )
        _win_rename_handle(
            temp.token, binding.directory_token, filename, replace=True
        )
        temp.replaced = True
        _win_validate_file_handle(temp.token, destination, identity=temp.identity)
        return
    opened = os.fstat(temp.token)
    try:
        named = os.stat(
            temp.name, dir_fd=binding.directory_token, follow_symlinks=False
        )
    except FileNotFoundError as exc:
        raise PathEscapeError("temporary state name vanished before replacement") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or not os.path.samestat(opened, named)
        or (opened.st_dev, opened.st_ino) != temp.identity
    ):
        raise PathEscapeError("temporary state name or link count changed before replacement")
    os.replace(
        temp.name,
        filename,
        src_dir_fd=binding.directory_token,
        dst_dir_fd=binding.directory_token,
    )
    temp.replaced = True
    named = os.stat(filename, dir_fd=binding.directory_token, follow_symlinks=False)
    opened = os.fstat(temp.token)
    if not os.path.samestat(opened, named) or (opened.st_dev, opened.st_ino) != temp.identity:
        raise PathEscapeError("atomic replacement lost temporary file identity")


def _close_and_cleanup_temp(temp):
    if os.name == "nt":
        if temp.token is None:
            return
        cleanup_error = None
        if not temp.replaced:
            try:
                # Path-free cleanup remains attached to the created link even
                # if an injected junction changes the visible directory name.
                _win_dispose_handle(temp.token)
            except BaseException as exc:
                cleanup_error = exc
        _win_close(temp.token)
        temp.token = None
        if cleanup_error is not None:
            raise PathEscapeError("failed to delete bound temporary file") from cleanup_error
        return
    try:
        if not temp.replaced:
            # Never unlink merely by the old name: an attacker may have parked
            # our inode and substituted its own entry.  Remove only names that
            # still resolve to the retained temp identity.
            _cleanup_temp_identity(temp)
    finally:
        os.close(temp.token)


class _DestinationRollback:
    def __init__(self, binding, filename, initial, backup_name=None):
        self.binding = binding
        self.filename = filename
        self.initial = initial
        self.backup_name = backup_name


def _raw_bound_file_info(binding, filename):
    """Return (identity, link-count) without imposing the normal nlink==1 rule."""
    if os.name == "nt":
        expected = os.path.join(os.fspath(binding.path), filename)
        handle = _win_create(
            expected,
            _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            missing_ok=True,
        )
        if handle is None:
            return None
        try:
            info = _win_info(handle)
            if (
                info.dwFileAttributes & (_FILE_ATTRIBUTE_DIRECTORY | _REPARSE_FLAG)
                or _KERNEL32.GetFileType(handle) != _FILE_TYPE_DISK
                or _win_final_path(handle) != expected
            ):
                raise PathEscapeError(f"rollback file is not exact and regular: {expected}")
            return (_win_identity(info), info.nNumberOfLinks)
        finally:
            _win_close(handle)
    try:
        info = os.stat(filename, dir_fd=binding.directory_token, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise PathEscapeError(f"rollback file is not regular: {filename}")
    return ((info.st_dev, info.st_ino), info.st_nlink)


def _unlink_bound_name(binding, filename):
    if os.name == "nt":
        os.unlink(os.path.join(os.fspath(binding.path), filename))
    else:
        os.unlink(filename, dir_fd=binding.directory_token)


def _replace_bound_names(binding, source, destination):
    if os.name == "nt":
        os.replace(
            os.path.join(os.fspath(binding.path), source),
            os.path.join(os.fspath(binding.path), destination),
        )
    else:
        os.replace(
            source,
            destination,
            src_dir_fd=binding.directory_token,
            dst_dir_fd=binding.directory_token,
        )


def _prepare_destination_rollback(binding, filename, initial):
    """Keep the original inode/file-id recoverable until post-commit checks pass."""
    if initial is None:
        return _DestinationRollback(binding, filename, initial)
    current = _raw_bound_file_info(binding, filename)
    if current is None or current[0] != initial or current[1] != 1:
        raise PathEscapeError("state destination changed before rollback guard")
    for _index in range(128):
        backup = f"{filename}.{secrets.token_hex(12)}.rollback"
        try:
            if os.name == "nt":
                os.link(
                    os.path.join(os.fspath(binding.path), filename),
                    os.path.join(os.fspath(binding.path), backup),
                )
            else:
                os.link(
                    filename,
                    backup,
                    src_dir_fd=binding.directory_token,
                    dst_dir_fd=binding.directory_token,
                    follow_symlinks=False,
                )
        except FileExistsError:
            continue
        except OSError as exc:
            raise PathEscapeError("cannot create rollback link for state destination") from exc
        try:
            source = _raw_bound_file_info(binding, filename)
            saved = _raw_bound_file_info(binding, backup)
            if (
                source is None
                or saved is None
                or source[0] != initial
                or saved[0] != initial
                or source[1] != 2
                or saved[1] != 2
            ):
                raise PathEscapeError("rollback link does not preserve destination identity")
            return _DestinationRollback(binding, filename, initial, backup)
        except BaseException:
            try:
                if _raw_bound_file_info(binding, backup) is not None:
                    _unlink_bound_name(binding, backup)
            except OSError:
                pass
            raise
    raise PathEscapeError("could not allocate a unique rollback link")


def _cleanup_temp_identity(temp):
    """Remove a renamed temp when it is still discoverable in the bound directory."""
    if os.name == "nt":
        if temp.token is not None:
            _win_dispose_handle(temp.token)
            _win_close(temp.token)
            temp.token = None
        return
    try:
        names = os.listdir(temp.binding.directory_token)
    except OSError:
        names = []
    for name in names:
        try:
            info = os.stat(
                name,
                dir_fd=temp.binding.directory_token,
                follow_symlinks=False,
            )
            if (info.st_dev, info.st_ino) == temp.identity:
                os.unlink(name, dir_fd=temp.binding.directory_token)
        except FileNotFoundError:
            continue


def _rollback_destination(guard, temp):
    binding = guard.binding
    binding.verify()
    current = _raw_bound_file_info(binding, guard.filename)
    if guard.initial is None:
        if current is not None:
            # Restore the exact prior absence.  This is deterministic recovery,
            # not a claim that an uncooperative directory owner can be excluded.
            if os.name == "nt" and current[0] == temp.identity:
                _cleanup_temp_identity(temp)
            else:
                _unlink_bound_name(binding, guard.filename)
        _cleanup_temp_identity(temp)
        if _raw_bound_file_info(binding, guard.filename) is not None:
            raise PathEscapeError("rollback did not restore absent destination")
        return

    backup = guard.backup_name
    saved = _raw_bound_file_info(binding, backup)
    if saved is None or saved[0] != guard.initial:
        raise PathEscapeError("rollback identity was lost")
    if current is not None and current[0] == guard.initial:
        _unlink_bound_name(binding, backup)
    else:
        if os.name == "nt" and temp.token is not None:
            _cleanup_temp_identity(temp)
        _replace_bound_names(binding, backup, guard.filename)
    _cleanup_temp_identity(temp)
    restored = _raw_bound_file_info(binding, guard.filename)
    if restored is None or restored[0] != guard.initial or restored[1] != 1:
        raise PathEscapeError("rollback did not restore original destination identity")


def _finalize_destination(guard, temp):
    binding = guard.binding
    current = _raw_bound_file_info(binding, guard.filename)
    if current is None or current[0] != temp.identity or current[1] != 1:
        raise PathEscapeError("committed destination is aliased or has wrong identity")
    if guard.backup_name is not None:
        _unlink_bound_name(binding, guard.backup_name)


def atomic_write_document(path, payload, max_bytes, *, _binding=None):
    """Write through a retained directory binding with identity-checked rename."""
    path = Path(path)
    data = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
        "ascii"
    )
    if len(data) > max_bytes:
        raise SizeLimitError(f"{path.name} would be {len(data)} bytes; limit is {max_bytes}")
    owned = None
    binding = _binding
    if binding is None:
        owned = _open_exact_directory(path.parent, "state directory")
        binding = owned
    try:
        if path.parent != binding.path or path.name != os.path.basename(path.name):
            raise PathEscapeError("state document path is not bound to its exact directory")
        initial = _snapshot_bound_destination(binding, path.name)
        if (
            path.name in binding._guarded_files
            and binding._guarded_files[path.name] != initial
        ):
            raise PathEscapeError(f"guarded state destination identity changed: {path}")
        _state_io_barrier(binding, "write-before-temp")
        temp = _create_bound_temp(binding, path.name)
        try:
            guard = None
            _write_temp_bytes(temp, data)
            _flush_temp(temp)
            _fsync_temp(temp)
            _verify_temp(temp, temp.name, len(data))
            _state_io_barrier(binding, "write-before-commit")
            current = _snapshot_bound_destination(binding, path.name)
            if current != initial:
                raise PathEscapeError(f"state destination identity changed: {path}")
            guard = _prepare_destination_rollback(binding, path.name, initial)
            try:
                _replace_bound_temp(temp, path.name)
                _verify_temp(temp, path.name, len(data))
                _state_io_barrier(binding, "write-after-commit")
                _finalize_destination(guard, temp)
            except BaseException as original:
                try:
                    _rollback_destination(guard, temp)
                except BaseException as rollback_error:
                    raise PathEscapeError(
                        "state commit failed and exact destination rollback failed"
                    ) from rollback_error
                raise original
        finally:
            _close_and_cleanup_temp(temp)
        _fsync_directory(path.parent, _binding=binding)
        return data
    finally:
        if owned is not None:
            owned.close()


def _reject_duplicate_keys(pairs):
    merged = {}
    for key, value in pairs:
        if key in merged:
            raise SchemaError(f"duplicate key {key!r} in state document")
        merged[key] = value
    return merged


def _reject_json_constant(name):
    raise SchemaError(f"forbidden JSON constant {name!r} in state document")


def read_document(path, max_bytes, *, _binding=None):
    """Read through one retained directory/file identity, then parse strict JSON."""
    path = Path(path)
    owned = None
    binding = _binding
    if binding is None:
        owned = _open_exact_directory(path.parent, "state directory")
        binding = owned
    try:
        if path.parent != binding.path:
            raise PathEscapeError("state document path is not bound to its exact directory")
        data = _read_bound_bytes(binding, path.name, max_bytes)
    finally:
        if owned is not None:
            owned.close()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SchemaError(f"{path.name} is not ASCII JSON") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except SchemaError:
        raise
    except ValueError as exc:
        raise SchemaError(f"corrupt JSON in {path.name}: {exc}") from exc
    if not isinstance(document, dict):
        raise SchemaError(f"{path.name} must contain a JSON object")
    return document


def require_exact_keys(document, keys, name):
    actual, expected = set(document), set(keys)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise SchemaError(f"{name}: wrong key set (missing={missing}, unexpected={unexpected})")


def validate_version(value):
    if isinstance(value, bool) or not isinstance(value, int) or value != SCHEMA_VERSION:
        raise SchemaError(f"unsupported schema version: {value!r}")


def read_state_document(queue_root, attempt_dir, *, filename, max_bytes, keys, task_id, attempt, field_check):
    """Shared fail-closed read path for checkpoint/progress/heartbeat documents."""
    expected_task = validate_task_id(task_id)
    expected_attempt = validate_attempt(attempt)
    binding = _open_attempt_binding(
        queue_root, attempt_dir, task_id=expected_task, attempt=expected_attempt
    )
    try:
        path = guard_state_file(binding.path, filename, _binding=binding)
        document = read_document(path, max_bytes, _binding=binding)
        require_exact_keys(document, keys, filename)
        validate_version(document["version"])
        validate_task_id(document["task_id"])
        validate_attempt(document["attempt"])
        validate_updated_at(document["updated_at"])
        field_check(document, binding.path)
        if document["task_id"] != expected_task or document["attempt"] != expected_attempt:
            raise StateMismatchError(
                f"{filename} belongs to task {document['task_id']!r} attempt "
                f"{document['attempt']}; expected task {expected_task!r} attempt {expected_attempt}"
            )
        return dict(document)
    finally:
        binding.close()


def _validate_step(value, field):
    if value is None:
        return None
    if not isinstance(value, str) or not _STEP_RE.fullmatch(value):
        raise SchemaError(f"malformed {field}: {value!r}")
    return value


def _confine_artifact(attempt_dir_real, relpath):
    candidate = Path(os.path.realpath(attempt_dir_real.joinpath(*relpath.split("/"))))
    if candidate == attempt_dir_real or not candidate.is_relative_to(attempt_dir_real):
        raise PathEscapeError(f"artifact path escapes the attempt dir: {relpath!r}")


def _validate_artifacts(value, attempt_dir_real):
    if not isinstance(value, list):
        raise SchemaError(f"artifacts must be a list of relative paths: {value!r}")
    if len(value) > MAX_ARTIFACTS:
        raise SchemaError(f"too many artifacts ({len(value)} > {MAX_ARTIFACTS})")
    for item in value:
        validate_artifact_relpath(item)
        _confine_artifact(attempt_dir_real, item)
    if len(set(value)) != len(value):
        raise SchemaError("duplicate artifact paths")
    return list(value)


def _validate_status(value):
    if not isinstance(value, str) or not _STATUS_RE.fullmatch(value):
        raise SchemaError(f"malformed status: {value!r}")
    return value


def _validate_detail(value):
    if not isinstance(value, str) or not _DETAIL_RE.fullmatch(value):
        raise SchemaError(f"malformed detail: {value!r}")
    return value


def _check_checkpoint_fields(document, attempt_dir_real):
    _validate_step(document["completed_step"], "completed_step")
    _validate_step(document["next_step"], "next_step")
    _validate_artifacts(document["artifacts"], attempt_dir_real)


def _check_progress_fields(document, _attempt_dir_real):
    _validate_status(document["status"])
    _validate_detail(document["detail"])


def write_checkpoint(
    queue_root,
    attempt_dir,
    *,
    task_id,
    attempt,
    completed_step,
    next_step,
    artifacts=(),
    now=None,
):
    """Atomically persist the resumable checkpoint; returns the document path."""
    task = validate_task_id(task_id)
    attempt_number = validate_attempt(attempt)
    completed = _validate_step(completed_step, "completed_step")
    upcoming = _validate_step(next_step, "next_step")
    if isinstance(artifacts, (str, bytes)) or not isinstance(artifacts, (list, tuple)):
        raise SchemaError(f"artifacts must be a list of relative paths: {artifacts!r}")
    binding = _open_attempt_binding(
        queue_root, attempt_dir, task_id=task, attempt=attempt_number
    )
    try:
        document = {
            "version": SCHEMA_VERSION,
            "task_id": task,
            "attempt": attempt_number,
            "completed_step": completed,
            "next_step": upcoming,
            "artifacts": _validate_artifacts(list(artifacts), binding.path),
            "updated_at": format_utc(now),
        }
        path = guard_state_file(binding.path, CHECKPOINT_FILENAME, _binding=binding)
        atomic_write_document(
            path, document, MAX_CHECKPOINT_BYTES, _binding=binding
        )
        return path
    finally:
        binding.close()


def read_checkpoint(queue_root, attempt_dir, *, task_id, attempt):
    return read_state_document(
        queue_root,
        attempt_dir,
        filename=CHECKPOINT_FILENAME,
        max_bytes=MAX_CHECKPOINT_BYTES,
        keys=_CHECKPOINT_KEYS,
        task_id=task_id,
        attempt=attempt,
        field_check=_check_checkpoint_fields,
    )


def write_progress(queue_root, attempt_dir, *, task_id, attempt, status, detail="", now=None):
    """Explicit-only progress update; the heartbeat sidecar never calls this."""
    task = validate_task_id(task_id)
    attempt_number = validate_attempt(attempt)
    status_value = _validate_status(status)
    detail_value = _validate_detail(detail)
    binding = _open_attempt_binding(
        queue_root, attempt_dir, task_id=task, attempt=attempt_number
    )
    try:
        document = {
            "version": SCHEMA_VERSION,
            "task_id": task,
            "attempt": attempt_number,
            "status": status_value,
            "detail": detail_value,
            "updated_at": format_utc(now),
        }
        path = guard_state_file(binding.path, PROGRESS_FILENAME, _binding=binding)
        atomic_write_document(path, document, MAX_PROGRESS_BYTES, _binding=binding)
        return path
    finally:
        binding.close()


def read_progress(queue_root, attempt_dir, *, task_id, attempt):
    return read_state_document(
        queue_root,
        attempt_dir,
        filename=PROGRESS_FILENAME,
        max_bytes=MAX_PROGRESS_BYTES,
        keys=_PROGRESS_KEYS,
        task_id=task_id,
        attempt=attempt,
        field_check=_check_progress_fields,
    )
