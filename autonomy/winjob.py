"""Windows Job Object containment for one unattended child process tree.

The autonomy supervisor may only transition a task after it has *proved* that
the process tree it started is gone (``stop_verified``).  On Windows the only
primitive that gives that proof for a whole tree -- including grandchildren the
parent never told us about -- is a Job Object.

This module owns exactly that primitive and nothing else: no agent, session or
queue logic.  Its design rules, each of which exists because the naive version
silently fails to contain anything:

* The child is launched from an explicit absolute image.  We never shell out to
  ``cmd.exe /c`` or ``wt.exe``: a broker-style launcher returns immediately and
  the real work ends up in a process we never assigned to the Job.
* The child is created SUSPENDED **and assigned to the Job by CreateProcessW**
  through ``STARTUPINFOEXW`` / ``PROC_THREAD_ATTRIBUTE_JOB_LIST``.  It is then
  verified in the Job with ``IsProcessInJob`` and only then resumed.  A
  post-create ``AssignProcessToJobObject`` has two fatal gaps: a running child
  can spawn before assignment, and an owner crash after CREATE_SUSPENDED but
  before assignment can strand a suspended process outside kill-on-close.
* Any failure before the resume terminates the still-suspended process, verifies
  that its fresh Job is empty, and checked-closes every handle.  If cleanup
  cannot finish, a typed ``CleanupRequiredError`` privately retains unresolved
  ownership for explicit retry; unwinding locals never discards a handle.
* A required ``before_resume`` callback gets only immutable, already-verified
  evidence (pid and Job limit flags).  It runs once, with the child still
  suspended, after every path, membership, limit and non-inheritability check.
  It cannot receive a handle or resume capability; an exception or non-``None``
  return destroys the suspended Job without running the child.
* ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` is set and the breakaway limits are
  verified *absent* by reading the limits back.  Kill-on-close means even a
  crash of this process takes the tree down with it.
* Job, process and thread handles are non-inheritable, so a future child of this
  process can never inherit a handle that keeps the Job alive past its close.
* After resume, one lexical owner keeps Job/process/thread handles until the
  thread is checked-closed and a returned ``ContainedProcess`` has been
  constructed successfully.  Post-resume failure snapshots members, terminates
  the Job, proves the primary and observed tree exited, then checked-closes all
  handles.  Callers must retain a ``CleanupRequiredError`` until its idempotent
  ``retry_cleanup()`` completes.
* ``launch_contained`` is legal only inside ``fatal_owner_scope`` (normally via
  ``run_fatal_owner``), installed by the dedicated per-attempt owner before any
  handle acquisition and kept around the entire ``ContainedProcess`` lifetime.
  Every public operation/property that can touch owned handle state, including
  ``CleanupRequiredError.retry_cleanup()``, checks that same scope before its
  first access.  An ordinary-exception cleanup/retry must therefore be caught
  and completed *inside* the scope.
  Synchronous ``Exception`` failures use the checked cleanup protocol above.
  ``BaseException`` is different: no Python cleanup or retry runs while its
  native outcome may be ambiguous.  It reaches the outer scope, which ends the
  sacrificial owner with ``FATAL_OWNER_EXIT_CODE``; process teardown closes the
  anonymous sole Job handle and kill-on-close destroys its tree.
  Callers must not put ``close()`` in a ``finally`` nested inside the fatal
  scope: catch ``Exception`` to checked-close and re-raise, close explicitly on
  success, and let every ``BaseException`` reach the outer scope untouched.

The namespace checks have a deliberately narrow boundary.  The launch path
first records the file identity of the image, cwd, allowed root and every
ancestor, then opens those *same* objects and keeps non-delete-sharing handles
while ``CreateProcessW`` creates a suspended child.  Windows does not make the
path lookup and our handle snapshots one atomic namespace operation: in
particular, an ordinary directory can still be renamed/replaced by a same-user
writer while its binding handle is open.  We therefore bracket process creation
with ``bindings.verify_stable()`` calls.  A changed binding after creation kills
the already-contained, still-suspended child before resume.

Those bracketed checks are race/misuse detection, not an authenticity sandbox
and not proof of the exact image/cwd objects selected internally by
``CreateProcessW``.  The public Windows API used here does not expose both of
those selected object identities for comparison.  Deliberately hostile code
running as the same user is consequently outside this module's trust boundary;
isolate it with a lower-privilege service identity/ACL or stronger OS sandbox.
The API also accepts paths rather than a caller-held image handle/digest, so an
in-place image write completed before binding is outside this module's proof.
A caller that needs byte provenance must separately pin/verify it; this module
does not silently pretend a path identity is a content hash.

The fatal-owner rule closes Python's scalar Win32 return gap for asynchronous
``BaseException`` (KeyboardInterrupt, SystemExit, GeneratorExit and equivalent
cancellation).  Deliberately injected asynchronous *ordinary* ``Exception`` at
an exact post-syscall bytecode boundary is outside this MVP: surviving that
while continuing the same Python process requires a native handle broker (or a
dedicated helper thread with an independently queryable handle table), not
trace suppression or another Python assignment.

Import is safe on any platform.  The fatal-owner scope guard applies first on
every platform; once explicitly installed, calls fail closed with
``unsupported-platform`` off Windows so test suites can skip cleanly.
"""

from __future__ import annotations

import math
import os
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, NoReturn, Sequence


IS_WINDOWS = sys.platform == "win32"

# Brokers: they hand the real work to an out-of-job process and exit, so the Job
# would contain nothing.  Rejected by image name before any filesystem access.
BROKER_DENYLIST = frozenset({"wt.exe", "explorer.exe"})

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
EXTENDED_STARTUPINFO_PRESENT = 0x00080000

# ProcThreadAttributeValue(13, FALSE, TRUE, FALSE).  The input is an array of
# Job handles and causes the kernel to associate the new process with every Job
# in the list as part of process creation, before CreateProcessW returns.
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D

JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_BREAKAWAY_FLAGS = (
    JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
)

_JobObjectBasicAccountingInformation = 1
_JobObjectBasicProcessIdList = 3
_JobObjectExtendedLimitInformation = 9

_HANDLE_FLAG_INHERIT = 0x00000001
_WAIT_OBJECT_0 = 0x00000000
_WAIT_ABANDONED_0 = 0x00000080
_WAIT_TIMEOUT = 0x00000102
_WAIT_FAILED = 0xFFFFFFFF
_SYNCHRONIZE = 0x00100000
_GENERIC_READ = 0x80000000
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_TYPE_DISK = 0x00000001
_VOLUME_NAME_DOS = 0x0
_ERROR_MORE_DATA = 234
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_NOT_SUPPORTED = 50
_ERROR_CALL_NOT_IMPLEMENTED = 120
# The kernel returns ERROR_INVALID_PARAMETER for a pid that no longer names a
# process; that is the *only* OpenProcess failure we read as "already gone".
_ERROR_INVALID_PARAMETER = 87
_ERROR_ACCESS_DENIED = 5
_TERMINATE_EXIT_CODE = 1

# terminate_and_verify caps: a nonsensical or unbounded timeout is rejected, and
# quiescence must hold continuously for a small window before it is believed --
# a single zero-reading is the Job's optimistic accounting, not a dead tree.
_MAX_TERMINATE_TIMEOUT = 3600.0
_STABILITY_WINDOW = 0.03
# Bounded wait for a suspended process to signal during failed-launch cleanup.
_CLEANUP_WAIT_SECONDS = 5.0

# Reserved exit status for a dedicated per-attempt owner that encountered a
# BaseException.  It is owner diagnostics only, never a payload exit/result.
FATAL_OWNER_EXIT_CODE = 247

# Only these creation flags may reach CreateProcessW.  CREATE_SUSPENDED is added
# by the launcher itself; CREATE_NO_WINDOW is the sole caller-supplied flag we
# accept.  Anything else (a new console, a detached process, breakaway, ...) is
# rejected rather than silently forwarded.
_ALLOWED_CREATION_FLAGS = CREATE_NO_WINDOW | CREATE_SUSPENDED


class ContainmentError(RuntimeError):
    """Fail-closed containment failure.

    ``code`` is a stable, kebab-case identifier; callers (and the supervisor)
    branch on it rather than on the human-readable message.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


_FATAL_OWNER_LOCAL = threading.local()


def _fatal_owner_exit() -> NoReturn:
    """End the sacrificial owner immediately, without Python unwinding."""
    os._exit(FATAL_OWNER_EXIT_CODE)


class _FatalOwnerScope:
    """Outermost BaseException boundary for one dedicated owner process."""

    __slots__ = ("_entered",)

    def __init__(self) -> None:
        self._entered = False

    def __enter__(self) -> "_FatalOwnerScope":
        if getattr(_FATAL_OWNER_LOCAL, "scope", None) is not None:
            raise ContainmentError("fatal-owner-scope-nested")
        _FATAL_OWNER_LOCAL.scope = self
        self._entered = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if not self._entered or getattr(_FATAL_OWNER_LOCAL, "scope", None) is not self:
            raise ContainmentError("fatal-owner-scope-invalid")
        if exc_type is not None and not issubclass(exc_type, Exception):
            # Do not clear thread-local state, close handles, run finalizers or
            # translate the exception.  os._exit is the one non-returning action.
            _fatal_owner_exit()
        _FATAL_OWNER_LOCAL.scope = None
        self._entered = False
        return False


def fatal_owner_scope() -> _FatalOwnerScope:
    """Create the explicit lifetime scope required by ``launch_contained``.

    The scope must enclose launch, every ``ContainedProcess`` operation and its
    final checked close.  Production normally uses :func:`run_fatal_owner` so a
    BaseException cannot escape into a long-lived coordinator process.  Inside
    it, use ``except Exception`` for checked cleanup and an explicit success
    close; never a ``finally`` that would also run during fatal unwinding.
    """
    return _FatalOwnerScope()


def run_fatal_owner(entrypoint: Callable[[], int]) -> int:
    """Run one per-attempt owner entrypoint under the process-fatal boundary."""
    if not callable(entrypoint):
        raise ContainmentError("fatal-owner-entrypoint-invalid")
    with fatal_owner_scope():
        result = entrypoint()
    if type(result) is not int:
        raise ContainmentError("fatal-owner-result-invalid")
    return result


def _require_fatal_owner_scope() -> None:
    if getattr(_FATAL_OWNER_LOCAL, "scope", None) is None:
        raise ContainmentError("fatal-owner-scope-required")


class CleanupRequiredError(ContainmentError):
    """A launch failed and still owns OS resources that require retry cleanup.

    Callers must retain and catch this typed exception *inside the same fatal
    owner scope* until :meth:`retry_cleanup` succeeds.  Its public surface
    deliberately exposes no token or raw handle; the exception is the sole
    owner of a private cleanup token after the launch frame unwinds.
    """

    __slots__ = ("__cleanup_owner", "__original")

    def __init__(self, detail: str, cleanup_owner: object, original: Exception) -> None:
        _require_fatal_owner_scope()
        super().__init__("cleanup-failed", detail)
        self.__cleanup_owner = cleanup_owner
        self.__original = original

    @property
    def cleanup_pending(self) -> bool:
        _require_fatal_owner_scope()
        owner = self.__cleanup_owner
        return owner is not None and owner._has_unresolved_ownership()

    def retry_cleanup(self) -> None:
        """Retry unresolved cleanup; idempotent after a successful retry."""
        _require_fatal_owner_scope()
        owner = self.__cleanup_owner
        if owner is None:
            return
        try:
            owner._retry_cleanup()
        except Exception as retry_error:
            if not owner._has_unresolved_ownership():
                self.__cleanup_owner = None
            self.detail = (
                f"retry {type(retry_error).__name__}: {retry_error}"
            )
            self.args = (f"{self.code}: {self.detail}",)
            # Keep the originating launch failure as the stable public cause;
            # the retry detail is carried in this exception's message.
            raise self from self.__original
        if owner._has_unresolved_ownership():
            self.detail = "retry returned with unresolved ownership"
            self.args = (f"{self.code}: {self.detail}",)
            raise self from self.__original
        self.__cleanup_owner = None


@dataclass(frozen=True, slots=True)
class AssignedProcess:
    """Immutable evidence available at the pre-resume handoff boundary.

    These values are copied only after the suspended primary has been proved a
    member of the fresh Job and the Job's containment-critical limits have been
    read back.  Deliberately no raw Job/process/thread handles or resume method
    are exposed: the callback can record the assignment, but cannot become a
    second owner or start the process itself.
    """

    pid: int
    job_limit_flags: int


if IS_WINDOWS:  # pragma: no branch - platform guard
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    class _STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class _STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", _STARTUPINFOW),
            ("lpAttributeList", wintypes.LPVOID),
        ]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

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

    _k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD
    ]
    _k32.SetInformationJobObject.restype = wintypes.BOOL
    _k32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _k32.QueryInformationJobObject.restype = wintypes.BOOL
    _k32.IsProcessInJob.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)
    ]
    _k32.IsProcessInJob.restype = wintypes.BOOL
    _k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateJobObject.restype = wintypes.BOOL
    _k32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW),
        ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    _k32.CreateProcessW.restype = wintypes.BOOL

    # These entry points exist on currently supported Windows, but lookup is
    # deliberately optional so import remains safe on an older/trimmed host.
    # launch then fails closed with job-list-unsupported; it never falls back
    # to the racy post-create AssignProcessToJobObject path.
    _init_proc_thread_attributes = getattr(
        _k32, "InitializeProcThreadAttributeList", None
    )
    _update_proc_thread_attribute = getattr(
        _k32, "UpdateProcThreadAttribute", None
    )
    _delete_proc_thread_attributes = getattr(
        _k32, "DeleteProcThreadAttributeList", None
    )
    if _init_proc_thread_attributes is not None:
        _init_proc_thread_attributes.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        _init_proc_thread_attributes.restype = wintypes.BOOL
    if _update_proc_thread_attribute is not None:
        _update_proc_thread_attribute.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.c_size_t,
            wintypes.LPVOID,
            ctypes.c_size_t,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        _update_proc_thread_attribute.restype = wintypes.BOOL
    if _delete_proc_thread_attributes is not None:
        _delete_proc_thread_attributes.argtypes = [wintypes.LPVOID]
        _delete_proc_thread_attributes.restype = None
    _k32.ResumeThread.argtypes = [wintypes.HANDLE]
    _k32.ResumeThread.restype = wintypes.DWORD
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateProcess.restype = wintypes.BOOL
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)
    ]
    _k32.GetExitCodeProcess.restype = wintypes.BOOL
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.SetHandleInformation.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD
    ]
    _k32.SetHandleInformation.restype = wintypes.BOOL
    _k32.GetHandleInformation.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)
    ]
    _k32.GetHandleInformation.restype = wintypes.BOOL
    _k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD
    ]
    _k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _k32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION)
    ]
    _k32.GetFileInformationByHandle.restype = wintypes.BOOL
    _k32.GetFileType.argtypes = [wintypes.HANDLE]
    _k32.GetFileType.restype = wintypes.DWORD


def _fail(code: str) -> "ContainmentError":
    """Build a ContainmentError carrying the current Win32 error text."""
    err = ctypes.WinError(ctypes.get_last_error())
    return ContainmentError(code, str(err))


def _require_windows() -> None:
    if not IS_WINDOWS:
        raise ContainmentError("unsupported-platform", sys.platform)


# --- Win32 wrappers -------------------------------------------------------
# One thin function per syscall.  Tests patch these by name to simulate the
# failure modes (attribute setup / verify / resume) that cannot be provoked for real.


def _create_job(owner: "_LaunchCleanupToken | None" = None) -> int:
    job = _k32.CreateJobObjectW(None, None)
    if not job:
        raise _fail("job-create-failed")
    job_value = int(job)
    if owner is not None:
        owner._capture_job(job_value)
    try:
        _set_not_inheritable(job_value)
    except Exception as setup_error:
        if owner is not None:
            # The enclosing launch frame already owns the Job and performs the
            # ordinary checked cleanup.  BaseException never enters this arm.
            raise
        # A Job whose handle is still inheritable must never be returned: a
        # future child of this process could inherit it and keep the whole tree
        # alive past our close, defeating kill-on-close.  Drop it and surface
        # the original setup failure.
        cleanup_owner = _LaunchCleanupToken(job_value)

        def clear_job() -> None:
            if cleanup_owner._job == job_value:
                cleanup_owner._job = None

        try:
            _close_handle(job_value, on_closed=clear_job)
        except Exception as close_error:
            # Keep the unresolved Job in the same typed retry protocol used by
            # later launch failures; never discard it from this setup frame.
            detail = (
                f"job-handle-unresolved after {setup_error}; "
                f"close {type(close_error).__name__}: {close_error}"
            )
            raise CleanupRequiredError(
                detail, cleanup_owner, setup_error
            ) from setup_error
        raise
    return job_value


def _configure_job(job: int) -> int:
    """Set kill-on-close, then read the limits back and prove what we require.

    A blind SetInformationJobObject is not proof: we assert kill-on-close is
    present and that neither breakaway limit is, so a process in this Job can
    never escape it even if it asks to.
    """
    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not _k32.SetInformationJobObject(
        job, _JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise _fail("job-limit-failed")

    return _verify_job_limits(job)


def _verify_job_limits(job: int) -> int:
    """Read back the containment-critical limits from the live Job handle."""
    flags = _job_limit_flags(job)
    if not flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:
        raise ContainmentError("job-limit-unverified", "kill-on-job-close absent")
    if flags & JOB_OBJECT_BREAKAWAY_FLAGS:
        raise ContainmentError("job-limit-unverified", f"breakaway present: {flags:#x}")
    return flags


def _job_limit_flags(job: int) -> int:
    out = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    if not _k32.QueryInformationJobObject(
        job,
        _JobObjectExtendedLimitInformation,
        ctypes.byref(out),
        ctypes.sizeof(out),
        None,
    ):
        raise _fail("job-query-failed")
    return int(out.BasicLimitInformation.LimitFlags)


def _job_active_processes(job: int) -> int:
    out = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    if not _k32.QueryInformationJobObject(
        job,
        _JobObjectBasicAccountingInformation,
        ctypes.byref(out),
        ctypes.sizeof(out),
        None,
    ):
        raise _fail("job-query-failed")
    return int(out.ActiveProcesses)


def _job_process_ids(job: int) -> list[int]:
    """Pids currently assigned to the Job, grandchildren included."""
    capacity = 64
    for _ in range(8):
        class _PidList(ctypes.Structure):
            _fields_ = [
                ("NumberOfAssignedProcesses", wintypes.DWORD),
                ("NumberOfProcessIdsInList", wintypes.DWORD),
                ("ProcessIdList", ctypes.c_size_t * capacity),
            ]

        out = _PidList()
        if _k32.QueryInformationJobObject(
            job,
            _JobObjectBasicProcessIdList,
            ctypes.byref(out),
            ctypes.sizeof(out),
            None,
        ):
            return [int(p) for p in out.ProcessIdList[: out.NumberOfProcessIdsInList]]
        if ctypes.get_last_error() != _ERROR_MORE_DATA:
            raise _fail("job-query-failed")
        capacity *= 4  # buffer too small: the tree grew between calls
    raise ContainmentError("job-query-failed", "process id list did not converge")


def _wait_result(handle: int, ms: int) -> int:
    """WaitForSingleObject with a fail-closed result contract.

    For a process handle only two results carry a liveness proof: WAIT_OBJECT_0
    means the object is signaled (the process has exited) and WAIT_TIMEOUT means
    it is still running.  WAIT_FAILED, WAIT_ABANDONED or any other value tells us
    nothing -- so we raise rather than guess.  Treating an unexpected result as
    "exited" is exactly the false-clean that would let the supervisor advance a
    task whose tree is still alive.
    """
    result = int(_k32.WaitForSingleObject(handle, ms)) & 0xFFFFFFFF
    if result not in (_WAIT_OBJECT_0, _WAIT_TIMEOUT):
        raise _fail("wait-failed")
    return result


def _get_exit_code(process: int) -> int:
    """Return the exact exit code from an already-signaled process handle."""
    code = wintypes.DWORD()
    if not _k32.GetExitCodeProcess(process, ctypes.byref(code)):
        raise _fail("exit-code-failed")
    return int(code.value)


def _open_sync_handle(
    pid: int, retained: dict[int, int] | None = None
) -> int | None:
    """Open a SYNCHRONIZE handle to a Job member, or None if it is proven gone.

    A NULL OpenProcess is only read as "already gone" for
    ERROR_INVALID_PARAMETER -- the code the kernel returns for a pid that no
    longer denotes a process.  Access-denied or any other error is *unknown*,
    never dead: we raise so the caller blocks (false-block) instead of counting
    an unobservable process as terminated.  The returned handle is owned by the
    caller and must be closed.
    """
    # A scalar handle cannot be made atomically recoverable by another Python
    # assignment.  Normal execution records it immediately.  BaseException at
    # any point in this native-return window deliberately escapes untouched to
    # fatal_owner_scope; the process exits and the OS closes the handle.
    handle = _k32.OpenProcess(_SYNCHRONIZE, False, pid)
    if handle:
        value = int(handle)
        if retained is not None:
            retained[pid] = value
        return value
    err = ctypes.get_last_error()
    if err == _ERROR_INVALID_PARAMETER:
        return None
    raise ContainmentError("pid-probe-unknown", f"pid={pid} err={err}")


class _JobAttributeList:
    """Own one initialized PROC_THREAD_ATTRIBUTE_LIST and its backing memory."""

    def __init__(self, buffer: object, pointer: object, job_handles: object) -> None:
        self.buffer = buffer
        self.pointer = pointer
        self.job_handles = job_handles
        self.closed = False

    def close(self) -> None:
        if self.closed:
            return
        # DeleteProcThreadAttributeList returns void.  A Python exception here
        # can only be an ABI/mocking fault, but is still cleanup ambiguity and
        # must prevent a created child from being returned to the caller.
        try:
            _delete_proc_thread_attributes(self.pointer)
        except Exception as exc:
            self.closed = True
            raise ContainmentError(
                "job-attribute-cleanup-failed", str(exc)
            ) from exc
        self.closed = True


def _preserved_winerror(code: str, error: int) -> ContainmentError:
    """Build an error after cleanup without losing the originating last-error."""
    return ContainmentError(code, str(ctypes.WinError(error)))


def _create_job_attribute_list(job: int) -> _JobAttributeList:
    """Create a one-entry JOB_LIST attribute, or fail without fallback.

    The sizing call has an unusually strict Win32 contract: it must fail with
    ERROR_INSUFFICIENT_BUFFER while returning a non-zero size.  Treat any other
    result as unsupported/ambiguous rather than guessing an allocation size.
    """
    if (
        _init_proc_thread_attributes is None
        or _update_proc_thread_attribute is None
        or _delete_proc_thread_attributes is None
    ):
        raise ContainmentError("job-list-unsupported", "attribute API missing")

    size = ctypes.c_size_t()
    ctypes.set_last_error(0)
    probe_ok = bool(
        _init_proc_thread_attributes(None, 1, 0, ctypes.byref(size))
    )
    probe_error = ctypes.get_last_error()
    if probe_ok or probe_error != _ERROR_INSUFFICIENT_BUFFER or size.value <= 0:
        code = (
            "job-list-unsupported"
            if probe_error in (_ERROR_NOT_SUPPORTED, _ERROR_CALL_NOT_IMPLEMENTED)
            else "job-attribute-probe-ambiguous"
        )
        raise ContainmentError(
            code,
            f"ok={probe_ok} error={probe_error} size={size.value}",
        )

    buffer = ctypes.create_string_buffer(size.value)
    pointer = ctypes.cast(buffer, wintypes.LPVOID)
    ctypes.set_last_error(0)
    if not _init_proc_thread_attributes(pointer, 1, 0, ctypes.byref(size)):
        error = ctypes.get_last_error()
        code = (
            "job-list-unsupported"
            if error in (_ERROR_NOT_SUPPORTED, _ERROR_CALL_NOT_IMPLEMENTED)
            else "job-attribute-init-failed"
        )
        raise _preserved_winerror(code, error)

    try:
        attributes = _JobAttributeList(buffer, pointer, None)
    except Exception as setup_error:
        try:
            _delete_proc_thread_attributes(pointer)
        except Exception as cleanup_error:
            raise ContainmentError(
                "cleanup-failed",
                f"after {type(setup_error).__name__}: attribute delete: {cleanup_error}",
            ) from setup_error
        raise

    try:
        job_handles = (wintypes.HANDLE * 1)(job)
        attributes.job_handles = job_handles
        ctypes.set_last_error(0)
        updated = bool(
            _update_proc_thread_attribute(
                pointer,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST,
                ctypes.cast(job_handles, wintypes.LPVOID),
                ctypes.sizeof(job_handles),
                None,
                None,
            )
        )
        error = ctypes.get_last_error()
    except Exception as setup_error:
        try:
            attributes.close()
        except ContainmentError as cleanup_error:
            raise ContainmentError(
                "cleanup-failed",
                f"after {type(setup_error).__name__}: {cleanup_error}",
            ) from setup_error
        raise

    if not updated:
        try:
            attributes.close()
        except ContainmentError as cleanup_error:
            raise ContainmentError(
                "cleanup-failed",
                f"after job-attribute-update-failed: {cleanup_error}",
            ) from cleanup_error
        code = (
            "job-list-unsupported"
            if error in (_ERROR_NOT_SUPPORTED, _ERROR_CALL_NOT_IMPLEMENTED)
            else "job-attribute-update-failed"
        )
        raise _preserved_winerror(code, error)
    return attributes


def _create_suspended_process(
    job: int,
    executable: str,
    command_line: str,
    cwd: str,
    creation_flags: int,
    *,
    owner: "_LaunchCleanupToken | None" = None,
) -> tuple[int, int, int]:
    """Atomically create a suspended process already associated with ``job``.

    There is intentionally no AssignProcessToJobObject fallback.  Before the
    syscall there is no child; once it returns successfully, kill-on-close
    already owns the child even if this process crashes on the next instruction.
    """
    attributes = _create_job_attribute_list(job)
    created: tuple[int, int, int] | None = None
    create_error = 0

    def close_attributes() -> None:
        try:
            attributes.close()
        except ContainmentError as attribute_error:
            cleanup_detail = ""
            if created is not None and owner is None:
                try:
                    _cleanup_suspended(
                        job, created[0], created[1], close_job=False
                    )
                except ContainmentError as cleanup_error:
                    cleanup_detail = f"; child: {cleanup_error.detail}"
            raise ContainmentError(
                "cleanup-failed", f"attributes: {attribute_error}{cleanup_detail}"
            ) from attribute_error

    try:
        # Keep every allocation after attribute-list initialization inside the
        # cleanup frame too; even a Python allocation/encoding exception must
        # call DeleteProcThreadAttributeList.
        startup = _STARTUPINFOEXW()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.lpAttributeList = attributes.pointer
        pi = owner._process_info if owner is not None else _PROCESS_INFORMATION()
        cmdline = ctypes.create_unicode_buffer(command_line)
        ok = _k32.CreateProcessW(
            executable,
            cmdline,
            None,  # NULL process attrs -> non-inheritable process handle
            None,  # NULL thread attrs  -> non-inheritable thread handle
            False,  # bInheritHandles (JOB_LIST does not require inheritance)
            creation_flags | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
            None,
            cwd,
            ctypes.cast(ctypes.byref(startup), ctypes.POINTER(_STARTUPINFOW)),
            ctypes.byref(pi),
        )
        if ok:
            process = int(pi.hProcess)
            thread = int(pi.hThread)
            pid = int(pi.dwProcessId)
            created = (process, thread, pid)
        else:
            create_error = ctypes.get_last_error()
    # Deliberately no BaseException arm and no finally: fatal unwinding must not
    # delete attributes or touch a handle before fatal_owner_scope exits.
    except Exception:
        close_attributes()
        raise
    else:
        close_attributes()

    if created is None:
        raise _preserved_winerror("process-create-failed", create_error)
    return created


def _process_in_job(process: int, job: int) -> bool:
    result = wintypes.BOOL()
    if not _k32.IsProcessInJob(process, job, ctypes.byref(result)):
        raise _fail("job-verify-failed")
    return bool(result.value)


def _resume_thread(thread: int) -> None:
    previous_count = int(_k32.ResumeThread(thread)) & 0xFFFFFFFF
    if previous_count == 0xFFFFFFFF:
        raise _fail("resume-failed")
    if previous_count != 1:
        raise ContainmentError(
            "resume-count-unexpected", f"previous_suspend_count={previous_count}"
        )


def _terminate_job(job: int) -> None:
    if not _k32.TerminateJobObject(job, _TERMINATE_EXIT_CODE):
        raise _fail("terminate-job-failed")


def _terminate_process(process: int) -> None:
    if not _k32.TerminateProcess(process, _TERMINATE_EXIT_CODE):
        raise _fail("terminate-process-failed")


def _process_alive(process: int) -> bool:
    """True iff the process is still running; raises on an ambiguous wait."""
    return _wait_result(process, 0) == _WAIT_TIMEOUT


def _process_exited(handle: int) -> bool:
    """True iff the handle is signaled (exited); raises on an ambiguous wait."""
    return _wait_result(handle, 0) == _WAIT_OBJECT_0


def _wait_for_exit(handle: int, timeout: float) -> bool:
    """Block up to ``timeout`` seconds for the handle to signal.

    True means it exited, False means it was still alive at the deadline.  An
    ambiguous wait raises (never reported as exited).
    """
    ms = int(max(0.0, timeout) * 1000)
    return _wait_result(handle, ms) == _WAIT_OBJECT_0


def _close_handle(
    handle: int, *, on_closed: Callable[[], None] | None = None
) -> None:
    """Close a handle with the result checked.

    A failed CloseHandle leaves ownership unresolved; callers must not treat the
    handle as released.  We raise so that state surfaces rather than being lost.
    """
    # A BaseException after kernel success but before owner bookkeeping is an
    # ambiguous scalar-return boundary.  Never retry it in Python: it propagates
    # to fatal_owner_scope and process teardown closes everything still open.
    if not _k32.CloseHandle(handle):
        raise _fail("handle-close-failed")
    if on_closed is not None:
        on_closed()


def _set_not_inheritable(handle: int) -> None:
    """Defensive: NULL security attrs already yield non-inheritable handles."""
    if not _k32.SetHandleInformation(handle, _HANDLE_FLAG_INHERIT, 0):
        raise _fail("handle-flags-failed")


def handle_is_inheritable(handle: int) -> bool:
    """Exposed for the containment tests; not used by the launch path."""
    _require_fatal_owner_scope()
    _require_windows()
    flags = wintypes.DWORD()
    if not _k32.GetHandleInformation(handle, ctypes.byref(flags)):
        raise _fail("handle-flags-failed")
    return bool(flags.value & _HANDLE_FLAG_INHERIT)


def _verify_not_inheritable(handle: int, label: str) -> None:
    """Read a live handle's flags back; syscall success alone is not proof."""
    if handle_is_inheritable(handle):
        raise ContainmentError("handle-inheritable", label)


# --- Namespace binding ----------------------------------------------------


def _close_binding_handle(handle: int) -> None:
    """Close a path-pinning handle and make an ambiguous close fatal."""
    if not _k32.CloseHandle(handle):
        raise _fail("binding-handle-close-failed")


def _final_dos_path(handle: int) -> str:
    """Return the normalized DOS path naming the object opened by ``handle``."""
    needed = int(_k32.GetFinalPathNameByHandleW(handle, None, 0, _VOLUME_NAME_DOS))
    if needed <= 0:
        raise _fail("path-binding-query-failed")
    buffer = ctypes.create_unicode_buffer(needed + 1)
    written = int(
        _k32.GetFinalPathNameByHandleW(
            handle, buffer, len(buffer), _VOLUME_NAME_DOS
        )
    )
    if written <= 0 or written >= len(buffer):
        raise _fail("path-binding-query-failed")
    path = buffer.value
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    return os.path.normpath(path)


def _bound_snapshot(handle: int, expect_directory: bool) -> tuple[str, tuple[int, int, int], int]:
    """Prove path, type and stable file identity for an open path handle."""
    if int(_k32.GetFileType(handle)) != _FILE_TYPE_DISK:
        raise ContainmentError("path-binding-type-mismatch", "not a disk object")
    info = _BY_HANDLE_FILE_INFORMATION()
    if not _k32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise _fail("path-binding-query-failed")
    attrs = int(info.dwFileAttributes)
    if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise ContainmentError("path-binding-reparse-point")
    is_directory = bool(attrs & _FILE_ATTRIBUTE_DIRECTORY)
    if is_directory != expect_directory:
        expected = "directory" if expect_directory else "file"
        raise ContainmentError("path-binding-type-mismatch", expected)
    identity = (
        int(info.dwVolumeSerialNumber),
        int(info.nFileIndexHigh),
        int(info.nFileIndexLow),
    )
    return _final_dos_path(handle), identity, attrs


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


@dataclass(frozen=True)
class _PathExpectation:
    """Identity sampled by the authoritative namespace validation pass."""

    path: str
    expect_directory: bool
    identity: tuple[int, int, int]


def _identity_from_stat(value: os.stat_result) -> tuple[int, int, int]:
    """Translate CPython's Windows stat identity to BY_HANDLE identity.

    ``st_dev`` contains the volume serial in its low DWORD and ``st_ino`` is
    the 64-bit file index exposed as high/low DWORDs by
    ``GetFileInformationByHandle``.  Keeping one representation lets the
    authoritative path probe be compared to the subsequently opened object.
    """
    inode = int(value.st_ino)
    return (
        int(value.st_dev) & 0xFFFFFFFF,
        (inode >> 32) & 0xFFFFFFFF,
        inode & 0xFFFFFFFF,
    )


def _capture_path_expectation(
    path: str, expect_directory: bool, label: str
) -> _PathExpectation:
    """Capture the exact ordinary object that binding must later reopen."""
    normalized = os.path.normpath(os.path.abspath(path))
    try:
        snapshot = os.lstat(normalized)
        attrs = int(snapshot.st_file_attributes)
    except OSError as exc:
        raise ContainmentError(
            "path-identity-probe-failed", f"{label}: {normalized}: {exc}"
        ) from exc
    except AttributeError as exc:
        raise ContainmentError(
            "path-identity-probe-failed",
            f"{label}: {normalized}: file identity unavailable",
        ) from exc
    if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise ContainmentError("path-binding-reparse-point", label)
    if stat.S_ISDIR(snapshot.st_mode) != expect_directory:
        expected = "directory" if expect_directory else "file"
        raise ContainmentError("path-binding-type-mismatch", f"{label}: {expected}")
    return _PathExpectation(
        normalized, expect_directory, _identity_from_stat(snapshot)
    )


def _before_bind_path(path: str, label: str) -> None:
    """Deterministic acquisition-race injection point used only by tests."""


class _BoundPath:
    """One launch-path object retained through the post-create verification."""

    def __init__(
        self,
        path: str,
        expect_directory: bool,
        label: str,
        expected_identity: tuple[int, int, int],
    ) -> None:
        self.expected_path = os.path.normpath(os.path.abspath(path))
        self.expect_directory = expect_directory
        self.label = label
        self.handle: int | None = None
        self.final_path = ""
        self.identity: tuple[int, int, int] | None = None
        self.attributes = 0

        access = _FILE_READ_ATTRIBUTES
        share = _FILE_SHARE_READ | _FILE_SHARE_WRITE
        flags = _FILE_FLAG_OPEN_REPARSE_POINT
        if expect_directory:
            flags |= _FILE_FLAG_BACKUP_SEMANTICS
        else:
            # A read handle with no write/delete sharing pins both the file
            # identity and its bytes while CreateProcessW maps the image.
            access |= _GENERIC_READ
            share = _FILE_SHARE_READ

        # The expectation was sampled by the authoritative validation pass.
        # Tests replace an ordinary (non-reparse) object at this exact boundary
        # to prove that opening "whatever now has this name" is not accepted.
        _before_bind_path(self.expected_path, label)
        raw = _k32.CreateFileW(
            self.expected_path,
            access,
            share,  # deliberately excludes FILE_SHARE_DELETE
            None,
            _OPEN_EXISTING,
            flags,
            None,
        )
        value = int(raw) if raw else 0
        invalid = int(ctypes.c_void_p(-1).value)
        if not value or value == invalid:
            raise _fail("path-binding-open-failed")
        self.handle = value
        try:
            _set_not_inheritable(value)
            if handle_is_inheritable(value):
                raise ContainmentError("path-binding-inheritable", label)
            final_path, identity, attrs = _bound_snapshot(value, expect_directory)
            if identity != expected_identity:
                raise ContainmentError(
                    "path-binding-identity-mismatch",
                    f"{label}: expected {expected_identity}, opened {identity}",
                )
            if not _same_path(final_path, self.expected_path):
                raise ContainmentError(
                    "path-binding-path-mismatch",
                    f"{label}: {self.expected_path} != {final_path}",
                )
            self.final_path = final_path
            self.identity = identity
            self.attributes = attrs
        except Exception as original:
            try:
                _close_binding_handle(value)
                self.handle = None
            except ContainmentError as close_error:
                raise ContainmentError(
                    "cleanup-failed",
                    f"binding {label} unresolved after {original}; close: {close_error}",
                ) from original
            raise

    def verify_stable(self) -> None:
        if self.handle is None or self.identity is None:
            raise ContainmentError("path-binding-closed", self.label)
        final_path, identity, attrs = _bound_snapshot(
            self.handle, self.expect_directory
        )
        if (
            not _same_path(final_path, self.final_path)
            or identity != self.identity
            or attrs != self.attributes
            or handle_is_inheritable(self.handle)
        ):
            raise ContainmentError("path-binding-changed", self.label)


def _path_chain(path: str) -> list[str]:
    """Filesystem anchor and every normalized component down to ``path``."""
    absolute = os.path.normpath(os.path.abspath(path))
    drive, tail = os.path.splitdrive(absolute)
    anchor = drive + os.sep if drive else os.sep
    result = [anchor]
    current = anchor
    for part in tail.lstrip("\\/").replace("/", os.sep).split(os.sep):
        if not part:
            continue
        current = os.path.join(current, part)
        result.append(current)
    return result


def _launch_path_specs(
    executable: str, cwd: str, allowed_root: str
) -> dict[str, tuple[str, bool, str]]:
    """Ordered, deduplicated set of every object relevant to process launch."""
    specs: dict[str, tuple[str, bool, str]] = {}

    def add_chain(path: str, leaf_directory: bool, label: str) -> None:
        chain = _path_chain(path)
        for index, component in enumerate(chain):
            is_leaf = index == len(chain) - 1
            expect_directory = leaf_directory if is_leaf else True
            key = os.path.normcase(os.path.abspath(component))
            previous = specs.get(key)
            if previous is not None and previous[1] != expect_directory:
                raise ContainmentError("path-binding-type-mismatch", component)
            if previous is None:
                specs[key] = (component, expect_directory, f"{label}:{index}")

    add_chain(allowed_root, True, "allowed-root")
    add_chain(cwd, True, "cwd")
    add_chain(executable, False, "executable")
    return specs


def _capture_launch_expectations(
    executable: str, cwd: str, allowed_root: str
) -> dict[str, _PathExpectation]:
    """Authoritatively sample all identities that binding must preserve.

    The capture itself is intentionally not claimed to be atomic.  Each later
    open is compared with its own sample, and already-opened ancestors exclude
    delete sharing.  Success is only reported once every comparison succeeded
    and all handles are simultaneously held.
    """
    result: dict[str, _PathExpectation] = {}
    for key, (path, expect_directory, label) in _launch_path_specs(
        executable, cwd, allowed_root
    ).items():
        result[key] = _capture_path_expectation(path, expect_directory, label)
    return result


class _LaunchBindings:
    def __init__(
        self,
        entries: list[_BoundPath],
        executable: _BoundPath,
        cwd: _BoundPath,
        allowed_root: _BoundPath,
    ) -> None:
        self.entries = entries
        self.executable = executable
        self.cwd = cwd
        self.allowed_root = allowed_root

    def verify_stable(self) -> None:
        for entry in self.entries:
            entry.verify_stable()

    def close(self) -> None:
        errors: list[str] = []
        unresolved: list[_BoundPath] = []
        for entry in reversed(self.entries):
            if entry.handle is None:
                continue
            try:
                _close_binding_handle(entry.handle)
                entry.handle = None
            except ContainmentError as exc:
                unresolved.append(entry)
                errors.append(f"{entry.label}: {exc.detail}")
        self.entries = list(reversed(unresolved))
        if errors:
            raise ContainmentError("binding-close-failed", "; ".join(errors))


def _acquire_launch_bindings(
    executable: str,
    cwd: str,
    allowed_root: str,
    expectations: dict[str, _PathExpectation],
) -> _LaunchBindings:
    """Retain every relevant component through the post-create verification.

    Holding only the leaf directory is insufficient: an attacker can rename an
    ancestor and replace it with a junction after validation.  Each component
    is therefore opened without FILE_SHARE_DELETE, including the filesystem
    anchor, the allowed-root chain, cwd chain and executable chain.  The open
    handles are useful identity witnesses, but are not claimed to prevent every
    same-user rename on Windows; the caller must verify them again after the
    suspended child is created.
    """
    specs = _launch_path_specs(executable, cwd, allowed_root)
    if set(expectations) != set(specs):
        raise ContainmentError("path-binding-expectations-mismatch")

    entries: list[_BoundPath] = []
    by_key: dict[str, _BoundPath] = {}
    try:
        for key, (path, expect_directory, label) in specs.items():
            expected = expectations[key]
            if (
                not _same_path(expected.path, path)
                or expected.expect_directory != expect_directory
            ):
                raise ContainmentError("path-binding-expectations-mismatch", label)
            entry = _BoundPath(
                path, expect_directory, label, expected.identity
            )
            entries.append(entry)
            by_key[key] = entry
        result = _LaunchBindings(
            entries,
            by_key[os.path.normcase(os.path.abspath(executable))],
            by_key[os.path.normcase(os.path.abspath(cwd))],
            by_key[os.path.normcase(os.path.abspath(allowed_root))],
        )
        try:
            common = os.path.commonpath(
                [
                    os.path.normcase(result.allowed_root.final_path),
                    os.path.normcase(result.cwd.final_path),
                ]
            )
        except ValueError:
            raise ContainmentError("cwd-outside-allowed-root") from None
        if common != os.path.normcase(result.allowed_root.final_path):
            raise ContainmentError("cwd-outside-allowed-root")
        result.verify_stable()
        return result
    except Exception as original:
        if entries:
            partial = _LaunchBindings(entries, entries[0], entries[0], entries[0])
            try:
                partial.close()
            except ContainmentError as close_error:
                raise ContainmentError(
                    "cleanup-failed",
                    f"path bindings unresolved after {original}; {close_error}",
                ) from original
        raise


def _before_create_process() -> None:
    """Deterministic race-injection point used only by containment tests."""


# --- Path validation ------------------------------------------------------


def _is_reparse_point(path: str) -> bool:
    try:
        attrs = os.lstat(path).st_file_attributes
    except OSError as exc:
        # An unreadable component is unknown, never proof that it is a normal
        # directory.  Returning False here would turn access-denied and path
        # races into a fail-open cell in both executable and cwd validation.
        raise ContainmentError("path-probe-failed", f"{path}: {exc}") from exc
    except AttributeError as exc:
        # This should be unreachable on Windows, but the validator must still
        # fail closed if a runtime cannot expose the reparse attribute.
        raise ContainmentError(
            "path-probe-failed", f"{path}: file attributes unavailable"
        ) from exc
    return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_reparse_in_chain(path: str, code: str) -> None:
    """Refuse a reparse point anywhere from the filesystem anchor down to path.

    Walks the *literal* components (never the resolved target) so a junction or
    app-execution-alias in any ancestor -- not just the leaf -- is seen.  A link
    higher up the chain can redirect the whole path to a broker just as a link
    on the image itself would.
    """
    # Do not call abspath/normpath/realpath before walking.  In particular,
    # normalising ``junction\\..\\child`` would erase the junction component
    # before it can be inspected.  Build the path exactly as Windows traverses
    # its literal components, checking a component before processing a later
    # ``..``.
    drive, tail = os.path.splitdrive(path)
    anchor = (drive + os.sep) if drive else os.sep
    current = anchor
    if _is_reparse_point(current):
        raise ContainmentError(code, current)

    if os.altsep:
        tail = tail.replace(os.altsep, os.sep)
    for part in tail.split(os.sep):
        if not part or part == os.curdir:
            continue
        if part == os.pardir:
            # The component being left was checked when it was appended.  Move
            # back without ever normalising the uninspected tail.
            parent = os.path.dirname(current.rstrip(os.sep))
            current = parent + os.sep if parent == drive else parent
            if not current:
                current = anchor
            continue
        current = os.path.join(current, part)
        if _is_reparse_point(current):
            raise ContainmentError(code, current)


def _validate_executable(executable: str) -> str:
    if not isinstance(executable, str) or not executable:
        raise ContainmentError("executable-invalid")
    if not os.path.isabs(executable):
        raise ContainmentError("executable-not-absolute", executable)
    if os.path.basename(executable).lower() in BROKER_DENYLIST:
        raise ContainmentError("executable-broker-denied", executable)
    if not os.path.exists(executable):
        raise ContainmentError("executable-missing", executable)
    if not os.path.isfile(executable):
        raise ContainmentError("executable-not-file", executable)
    # An app-execution-alias / symlink anywhere from the drive root down to the
    # image is a redirect to a broker; reject the whole chain, not just the leaf.
    _reject_reparse_in_chain(executable, "executable-reparse-point")
    return executable


def _validate_cwd(cwd: str, allowed_root: str) -> str:
    for label, path in (("cwd", cwd), ("allowed-root", allowed_root)):
        if not isinstance(path, str) or not path:
            raise ContainmentError(f"{label}-invalid")
        if not os.path.isabs(path):
            raise ContainmentError(f"{label}-not-absolute", path)
    if not os.path.isdir(allowed_root):
        raise ContainmentError("allowed-root-missing", allowed_root)

    # The trust boundary itself is part of the path being trusted.  Check the
    # literal allowed_root and every ancestor before abspath/realpath can erase
    # an alias.  The root-below-cwd check alone is not enough: it would start at
    # the root and therefore could not discover that the root (or a parent) is
    # a junction.
    _reject_reparse_in_chain(allowed_root, "allowed-root-reparse-point")

    if not os.path.exists(cwd):
        raise ContainmentError("cwd-missing", cwd)
    if not os.path.isdir(cwd):
        raise ContainmentError("cwd-not-directory", cwd)

    literal_root = os.path.abspath(allowed_root)
    literal_cwd = os.path.abspath(cwd)
    real_root = os.path.realpath(allowed_root)
    real_cwd = os.path.realpath(cwd)

    # Two containment checks, because either one alone has a hole. The literal
    # one refuses a path that only reaches the root by traversing a link from
    # outside it; the resolved one refuses a link *inside* the root whose target
    # is outside (a junction needs no privilege to create, so this is an escape
    # an unprivileged agent can actually build).
    for label, root, path in (
        ("literal", literal_root, literal_cwd),
        ("resolved", real_root, real_cwd),
    ):
        try:
            common = os.path.commonpath([os.path.normcase(root), os.path.normcase(path)])
        except ValueError:  # different drives
            raise ContainmentError("cwd-outside-allowed-root", f"{label}: {cwd}") from None
        if common != os.path.normcase(root):
            raise ContainmentError("cwd-outside-allowed-root", f"{label}: {cwd}")

    # Refuse any reparse point in the literal cwd traversal, even one that
    # currently resolves back inside the root: its target can be re-pointed
    # between this check and the launch.  Reusing the full-chain walker also
    # preserves components such as ``junction\\..`` that abspath erased for the
    # containment comparison above.
    _reject_reparse_in_chain(cwd, "cwd-reparse-point")
    return real_cwd


def _validate_creation_flags(creation_flags: int) -> int:
    if isinstance(creation_flags, bool) or not isinstance(creation_flags, int):
        raise ContainmentError("creation-flags-invalid")
    if creation_flags < 0:
        raise ContainmentError("creation-flags-invalid", f"{creation_flags}")
    # Breakaway first, for its specific code; it is also excluded by the
    # allowlist below, but callers branch on this exact identifier.
    if creation_flags & CREATE_BREAKAWAY_FROM_JOB:
        raise ContainmentError("creation-flags-breakaway", f"{creation_flags:#x}")
    if creation_flags & ~_ALLOWED_CREATION_FLAGS:
        raise ContainmentError("creation-flags-not-allowlisted", f"{creation_flags:#x}")
    return creation_flags


def _validate_timeout(timeout: object) -> float:
    """Reject bool, NaN, +/-inf, non-positive and excessive timeouts.

    ``bool`` is a subclass of ``int`` and must be excluded explicitly; a NaN
    would make every deadline comparison false and hang the drain loop; an
    unbounded timeout would let a stuck tree block the supervisor forever.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ContainmentError("timeout-invalid", repr(timeout))
    # Compare integers before math.isfinite coerces them to C double.  Very
    # large Python ints (for example 10**400) otherwise leak OverflowError
    # instead of the stable fail-closed API error.
    if isinstance(timeout, int):
        if timeout <= 0 or timeout > _MAX_TERMINATE_TIMEOUT:
            raise ContainmentError("timeout-invalid", repr(timeout))
        return float(timeout)
    if not math.isfinite(timeout):
        raise ContainmentError("timeout-invalid", repr(timeout))
    if timeout <= 0 or timeout > _MAX_TERMINATE_TIMEOUT:
        raise ContainmentError("timeout-invalid", repr(timeout))
    return float(timeout)


def _primary_wait_milliseconds(timeout: object) -> int:
    """Validate a primary-process wait timeout and convert it without truncation.

    Unlike the termination deadline, zero is meaningful here: it is an exact
    non-blocking poll.  Rounding upward prevents a positive sub-millisecond
    request from becoming an unintended zero-time poll.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ContainmentError("timeout-invalid", repr(timeout))
    if isinstance(timeout, int):
        if timeout < 0 or timeout > _MAX_TERMINATE_TIMEOUT:
            raise ContainmentError("timeout-invalid", repr(timeout))
        seconds = float(timeout)
    else:
        if not math.isfinite(timeout):
            raise ContainmentError("timeout-invalid", repr(timeout))
        if timeout < 0 or timeout > _MAX_TERMINATE_TIMEOUT:
            raise ContainmentError("timeout-invalid", repr(timeout))
        seconds = float(timeout)
    return int(math.ceil(seconds * 1000.0))


def _invoke_before_resume(
    callback: Callable[[AssignedProcess], None], evidence: AssignedProcess
) -> None:
    """Run the one narrow handoff callback and enforce its ``None`` contract."""
    try:
        result = callback(evidence)
    except Exception as exc:
        raise ContainmentError(
            "before-resume-callback-failed", f"{type(exc).__name__}: {exc}"
        ) from exc
    if result is not None:
        raise ContainmentError(
            "before-resume-return-invalid", type(result).__name__
        )


def _verify_suspended_job_empty(job: int, process: int) -> None:
    """Prove a failed launch's fresh Job has no remaining process tree."""
    deadline = time.monotonic() + _CLEANUP_WAIT_SECONDS
    stable_since: float | None = None
    last_pids: list[int] = []
    last_active = -1
    while True:
        process_exited = _process_exited(process)
        last_pids = _job_process_ids(job)
        last_active = _job_active_processes(job)
        now = time.monotonic()
        if process_exited and not last_pids and last_active == 0:
            if stable_since is None:
                stable_since = now
            elif now - stable_since >= _STABILITY_WINDOW:
                return
        else:
            stable_since = None
        if now >= deadline:
            raise ContainmentError(
                "cleanup-tree-not-empty",
                f"primary_exited={process_exited} pids={last_pids} active={last_active}",
            )
        time.sleep(min(0.005, deadline - now))


class _LaunchCleanupToken:
    """Single lexical owner for every handle acquired by one launch attempt.

    The same private object becomes exception-owned when cleanup cannot finish.
    It never exposes a handle through ``CleanupRequiredError``.  Every handle is
    cleared only after ``CloseHandle`` succeeds, so a retry cannot double-close
    anything already released.
    """

    def __init__(self, job: int | None = None) -> None:
        self._job: int | None = job
        # CreateProcessW writes directly into owner-held storage.  Therefore an
        # asynchronous exception immediately after the syscall cannot strand
        # successful process/thread handles in a temporary local structure.
        self._process_info = _PROCESS_INFORMATION()
        self._members: dict[int, int] = {}
        self._bindings: _LaunchBindings | None = None
        self._resumed = False
        self._quiescent = False
        self._defer_close_once: set[str] = set()

    def _capture_job(self, job: int) -> None:
        if self._job is not None:
            raise ContainmentError("ownership-invalid", "job already captured")
        self._job = job

    @property
    def _process(self) -> int | None:
        value = self._process_info.hProcess
        return int(value) if value else None

    @_process.setter
    def _process(self, value: int | None) -> None:
        self._process_info.hProcess = value or 0

    @property
    def _thread(self) -> int | None:
        value = self._process_info.hThread
        return int(value) if value else None

    @_thread.setter
    def _thread(self, value: int | None) -> None:
        self._process_info.hThread = value or 0

    @property
    def _pid(self) -> int | None:
        value = int(self._process_info.dwProcessId)
        return value if value else None

    @_pid.setter
    def _pid(self, value: int | None) -> None:
        self._process_info.dwProcessId = value or 0

    def _capture_process(
        self, process: int, thread: int | None, pid: int
    ) -> None:
        if self._process is not None or self._thread is not None:
            raise ContainmentError("ownership-invalid", "process already captured")
        self._process = process
        self._thread = thread
        self._pid = pid

    def _attach_bindings(self, bindings: _LaunchBindings) -> None:
        if self._bindings is not None:
            raise ContainmentError("ownership-invalid", "bindings already captured")
        self._bindings = bindings

    def _close_bindings(self) -> None:
        if self._bindings is None:
            return
        self._bindings.close()
        self._bindings = None

    def _mark_resume_attempted(self) -> None:
        # Set before calling ResumeThread.  From this point cleanup must assume
        # the primary may be running even if the syscall or Python frame is
        # interrupted before a result reaches us.
        self._resumed = True

    def _close_thread_for_return(self) -> None:
        if self._thread is None:
            raise ContainmentError("ownership-invalid", "thread already released")
        thread = self._thread

        def clear_thread() -> None:
            if self._thread == thread:
                self._thread = None

        try:
            _close_handle(thread, on_closed=clear_thread)
        except Exception:
            # The post-resume cleanup round must not silently turn this failed
            # close into an internal retry.  It will close everything else and
            # leave this exact handle in the exception-owned token for the
            # caller's explicit retry_cleanup().
            if self._thread is not None:
                self._defer_close_once.add("thread")
            raise

    def _adopt(self, candidate: "ContainedProcess") -> None:
        """Validate that the returned candidate retains this same sole owner."""
        if self._thread is not None:
            raise ContainmentError("ownership-invalid", "thread not closed")
        if not candidate._uses_owner(self):
            raise ContainmentError("ownership-invalid", "candidate owner mismatch")

    def _capture_members(self) -> None:
        if self._job is None:
            raise ContainmentError("ownership-invalid", "job unavailable")
        for pid in _job_process_ids(self._job):
            if pid in self._members:
                continue
            _open_sync_handle(pid, self._members)

    def _prove_resumed_tree_empty(self) -> None:
        if self._job is None or self._process is None:
            raise ContainmentError("ownership-invalid", "tree handles unavailable")
        deadline = time.monotonic() + _CLEANUP_WAIT_SECONDS
        stable_since: float | None = None
        while True:
            # Retain handles for any member that became observable just before
            # termination.  A probe ambiguity aborts proof and retains all
            # ownership for retry rather than accepting Job accounting alone.
            self._capture_members()
            primary_exited = _process_exited(self._process)
            members_exited = all(
                _process_exited(handle) for handle in self._members.values()
            )
            pids = _job_process_ids(self._job)
            active = _job_active_processes(self._job)
            now = time.monotonic()
            if primary_exited and members_exited and not pids and active == 0:
                if stable_since is None:
                    stable_since = now
                elif now - stable_since >= _STABILITY_WINDOW:
                    self._quiescent = True
                    return
            else:
                stable_since = None
            if now >= deadline:
                raise ContainmentError(
                    "cleanup-tree-not-empty",
                    "primary_exited={} members_exited={} pids={} active={}".format(
                        primary_exited, members_exited, pids, active
                    ),
                )
            time.sleep(min(0.005, deadline - now))

    def _close_after_quiescence(self) -> list[str]:
        problems: list[str] = []
        deferred = self._defer_close_once
        self._defer_close_once = set()

        if self._thread is not None:
            if "thread" in deferred:
                problems.append("thread: prior handle-close-failed")
            else:
                thread = self._thread

                def clear_thread() -> None:
                    if self._thread == thread:
                        self._thread = None

                try:
                    _close_handle(thread, on_closed=clear_thread)
                except ContainmentError as exc:
                    problems.append(f"thread: {exc}")

        for pid, handle in list(self._members.items()):
            def clear_member(pid: int = pid, handle: int = handle) -> None:
                if self._members.get(pid) == handle:
                    del self._members[pid]

            try:
                _close_handle(handle, on_closed=clear_member)
            except ContainmentError as exc:
                problems.append(f"member pid={pid}: {exc}")

        if self._process is not None:
            process = self._process

            def clear_process() -> None:
                if self._process == process:
                    self._process = None

            try:
                _close_handle(process, on_closed=clear_process)
            except ContainmentError as exc:
                problems.append(f"process: {exc}")

        # The Job is always last.  Until this checked close succeeds the token
        # remains its sole long-lived owner and kill-on-close cannot be defeated
        # by losing the integer in an unwinding local frame.
        if self._job is not None:
            job = self._job

            def clear_job() -> None:
                if self._job == job:
                    self._job = None

            try:
                _close_handle(job, on_closed=clear_job)
            except ContainmentError as exc:
                problems.append(f"job: {exc}")
        return problems

    def _cleanup(self, *, close_job: bool = True) -> None:
        problems: list[str] = []

        if self._process is not None and not self._quiescent:
            if self._resumed:
                try:
                    self._capture_members()
                except ContainmentError as exc:
                    problems.append(f"member-snapshot: {exc}")
                if self._job is not None:
                    try:
                        _terminate_job(self._job)
                    except ContainmentError as exc:
                        problems.append(str(exc))
                try:
                    self._prove_resumed_tree_empty()
                except ContainmentError as exc:
                    problems.append(str(exc))
            else:
                try:
                    _terminate_process(self._process)
                except ContainmentError as exc:
                    problems.append(str(exc))
                if self._job is not None:
                    try:
                        _terminate_job(self._job)
                    except ContainmentError as exc:
                        problems.append(str(exc))
                if self._job is not None:
                    try:
                        _verify_suspended_job_empty(self._job, self._process)
                    except ContainmentError as exc:
                        problems.append(str(exc))
                    else:
                        self._quiescent = True
        elif self._process is None:
            # No child was ever created, or a prior cleanup already checked and
            # closed its process handle.  The remaining handles may be closed.
            self._quiescent = True

        try:
            self._close_bindings()
        except ContainmentError as exc:
            problems.append(f"bindings: {exc}")

        if self._quiescent:
            if close_job:
                problems.extend(self._close_after_quiescence())
            else:
                job = self._job
                self._job = None
                problems.extend(self._close_after_quiescence())
                self._job = job

        if problems:
            raise ContainmentError("cleanup-failed", "; ".join(problems))

    def _retry_cleanup(self) -> None:
        self._cleanup()

    def _has_unresolved_ownership(self) -> bool:
        bindings_pending = self._bindings is not None and bool(self._bindings.entries)
        return bool(
            self._job is not None
            or self._process is not None
            or self._thread is not None
            or self._members
            or bindings_pending
        )


def _raise_cleanup_failure(
    owner: _LaunchCleanupToken,
    original: Exception,
    cleanup_error: Exception,
) -> None:
    code = getattr(original, "code", type(original).__name__)
    cleanup_detail = getattr(cleanup_error, "detail", "") or str(cleanup_error)
    detail = (
        f"after {code}: cleanup {type(cleanup_error).__name__}: "
        f"{cleanup_detail}"
    )
    if owner._has_unresolved_ownership():
        raise CleanupRequiredError(detail, owner, original) from original
    raise ContainmentError("cleanup-failed", detail) from original


def _cleanup_suspended(
    job: int,
    process: int,
    thread: int,
    *,
    close_job: bool = True,
) -> None:
    """Fail-closed teardown of a launch that failed before the resume.

    The child is still suspended and already in the Job and must never run.  We
    terminate the process and the Job, prove the process handle is signaled and
    the Job remains empty for a stability window, and close every handle with
    the result checked.  ``close_job=False`` is used only while the outer launch frame
    still owns and will close the Job after an attribute-list cleanup fault.
    If any step cannot be verified we raise ``cleanup-failed``.  The real launch
    path wraps unresolved ownership in ``CleanupRequiredError``; this helper is
    retained only for the standalone ABI test surface.
    """
    owner = _LaunchCleanupToken(job)
    owner._capture_process(process, thread, 0)
    owner._cleanup(close_job=close_job)


# --- Owner object ---------------------------------------------------------


class ContainedProcess:
    """Owns the Job handle for one contained process tree.

    ProcessAdapter-compatible surface: ``pid``, ``is_alive()``,
    ``wait_primary_exit()``, ``terminate_and_verify()``, ``close()``.  The Job
    handle is held for the whole lifetime -- dropping it early would fire
    kill-on-close and take the tree down.  Member probe handles also remain
    object-owned until checked close; close failures are retryable via another
    ``close()`` call.  Except for the immutable scalar ``pid``, the public
    surface requires the same live fatal-owner scope that created the object.
    """

    def __init__(
        self,
        job: int,
        process: int,
        pid: int,
        *,
        _owner: _LaunchCleanupToken | None = None,
    ) -> None:
        _require_fatal_owner_scope()
        if _owner is None:
            owner = _LaunchCleanupToken(job)
            owner._capture_process(process, None, pid)
            owner._resumed = True
        else:
            owner = _owner
            if (
                owner._job != job
                or owner._process != process
                or owner._pid != pid
                or owner._thread is not None
            ):
                raise ContainmentError("ownership-invalid", "candidate inputs")
        # The returned object retains the exact same owner object used by the
        # launch frame.  No raw-handle transfer/clear window exists: interruption
        # before return leaves the frame able to clean it, while a completed
        # return leaves this reference alive in the caller's object.
        self.__owner = owner
        self.__pid = pid

    @property
    def _job(self) -> int | None:
        return self.__owner._job

    @_job.setter
    def _job(self, value: int | None) -> None:
        self.__owner._job = value

    @property
    def _process(self) -> int | None:
        return self.__owner._process

    @_process.setter
    def _process(self, value: int | None) -> None:
        self.__owner._process = value

    @property
    def _retained(self) -> dict[int, int]:
        return self.__owner._members

    def _uses_owner(self, owner: _LaunchCleanupToken) -> bool:
        return self.__owner is owner

    def __enter__(self) -> "ContainedProcess":
        _require_fatal_owner_scope()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        _require_fatal_owner_scope()
        if exc_type is not None and not issubclass(exc_type, Exception):
            # A nested context manager must not turn fatal unwinding into a
            # Python CloseHandle attempt before the outer owner scope exits.
            return
        self.close()

    @property
    def pid(self) -> int:
        """PID of the launched process -- the launcher we started, nothing more.

        With a venv or py-launcher image this is the *redirector* PID, not the
        PID of the interpreter that ends up running the script; that interpreter
        is a separate Job member with a different PID.  Use this only as the
        launcher identity, never as a tree-liveness signal -- see ``is_alive``.
        """
        return self.__pid

    @property
    def closed(self) -> bool:
        _require_fatal_owner_scope()
        return (
            self._job is None
            and self._process is None
            and not self._retained
        )

    @property
    def job_handle(self) -> int | None:
        """Raw Job handle; for tests and diagnostics only."""
        _require_fatal_owner_scope()
        return self._job

    @property
    def process_handle(self) -> int | None:
        """Raw process handle; for tests and diagnostics only."""
        _require_fatal_owner_scope()
        return self._process

    def limit_flags(self) -> int:
        _require_fatal_owner_scope()
        if self._job is None:
            raise ContainmentError("closed")
        return _job_limit_flags(self._job)

    def is_alive(self) -> bool:
        """Tree-centric liveness: True while *any* process remains in the Job.

        Deliberately not launcher-centric.  The launched process may be a
        venv/py redirector that exits the instant it has re-spawned the real
        interpreter, or a script that forks a daemon and returns -- in both
        cases the launcher is gone but the tree is still running, and the
        supervisor must not treat the task as stopped.  ``ActiveProcesses`` is
        the Job's own count of live members, grandchildren included; the launcher
        exiting alone never drives this to zero.  Use ``primary_is_alive`` when
        you specifically mean the launcher.
        """
        _require_fatal_owner_scope()
        if self._job is None:
            return False
        return _job_active_processes(self._job) > 0

    @property
    def primary_is_alive(self) -> bool:
        """True only while the originally launched process (``pid``) is running.

        Kept separate from ``is_alive`` precisely so the two are never conflated:
        the launcher can be long dead while the Job -- and thus ``is_alive`` --
        is still true.
        """
        _require_fatal_owner_scope()
        if self._process is None:
            return False
        return _process_alive(self._process)

    def wait_primary_exit(self, timeout: float) -> int | None:
        """Wait for the exact launched primary and return its Win32 exit code.

        ``None`` means the primary handle was not signaled by the deadline; an
        integer is returned only after ``WaitForSingleObject`` proved that exact
        handle signaled and ``GetExitCodeProcess`` succeeded.  This says nothing
        about descendants: only ``terminate_and_verify`` proves tree quiescence.
        The process handle stays owned until ``close()``, so repeated successful
        calls re-prove the signal and return the same kernel-held exit code.
        """
        _require_fatal_owner_scope()
        if self._process is None:
            raise ContainmentError("closed")
        milliseconds = _primary_wait_milliseconds(timeout)
        if _wait_result(self._process, milliseconds) == _WAIT_TIMEOUT:
            return None
        return _get_exit_code(self._process)

    def active_processes(self) -> int:
        """Live processes in the Job, including grandchildren."""
        _require_fatal_owner_scope()
        if self._job is None:
            raise ContainmentError("closed")
        return _job_active_processes(self._job)

    def terminate_and_verify(self, timeout: float = 10.0) -> bool:
        """Kill the whole tree and return only once quiescence is *proved*.

        Returns True only when every process is confirmed gone and stays gone
        for a bounded stability window within ``timeout``; False otherwise.
        False is the supervisor's ``stop_verified=False`` -- it must block
        rather than retry the task, because an unverified stop may still be
        holding the task's resources.  This method, never ``close()``, is the
        only quiescence proof.

        ``ActiveProcesses == 0`` is deliberately *not* accepted as proof on its
        own.  The Job's accounting is decremented when TerminateJobObject marks
        the processes, not when they exit: measured on Win11, the counter reads
        zero ~0.1ms after the call while every process in the tree is still
        alive for ~3ms more.  Trusting it would hand the supervisor a
        ``stop_verified=True`` for a tree that is still running.  So before the
        kill we open and *retain* a SYNCHRONIZE handle for every observable Job
        member (re-enumerating each round to catch a process that spawned just
        before the kill), and require, held stable over ``_STABILITY_WINDOW``:

        * the launched process handle is signaled (a kernel-true exit);
        * every retained member handle is signaled;
        * the Job reports an empty pid list and zero active processes.

        Any enumeration/open/wait ambiguity resolves to False or an exception,
        never True: we prefer a false block over a false clean.  Probe handles
        survive False and exceptional returns in this object; a later retry or
        ``close()`` checked-closes them, and only successful closes clear them.
        """
        _require_fatal_owner_scope()
        if self._job is None:
            raise ContainmentError("closed")
        _validate_timeout(timeout)

        # Retain handles *before* the kill: once TerminateJobObject fires the pid
        # list empties promptly and a member could no longer be opened.
        self._retain_members()
        _terminate_job(self._job)

        deadline = time.monotonic() + timeout
        stable_since: float | None = None
        delay = 0.002
        while True:
            # Re-enumerate every round so a process that became visible only
            # after the snapshot is retained and waited on too.
            self._retain_members()
            now = time.monotonic()
            if self._members_quiescent():
                if stable_since is None:
                    stable_since = now
                elif now - stable_since >= _STABILITY_WINDOW:
                    self._close_retained()
                    return True
            else:
                stable_since = None
            remaining = deadline - now
            if remaining <= 0:
                return False
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 0.05)

    def _retain_members(self) -> None:
        """Open and keep a SYNCHRONIZE handle for every current Job member.

        Members already retained are skipped; a member proven gone (None from
        ``_open_sync_handle``) is not retained.  An open ambiguity propagates.
        """
        for pid in _job_process_ids(self._job):
            if pid in self._retained:
                continue
            _open_sync_handle(pid, self._retained)

    def _members_quiescent(self) -> bool:
        """True iff launcher, every retained member, and the Job all read dead.

        Any ambiguous wait or query raises out of here (caught nowhere in the
        drain loop, so it surfaces) rather than being read as quiescent.
        """
        if self._process is not None and _process_alive(self._process):
            return False
        for handle in self._retained.values():
            if not _process_exited(handle):
                return False
        if _job_process_ids(self._job):
            return False
        return _job_active_processes(self._job) == 0

    def _close_retained(self) -> None:
        """Close every retained probe handle, checked; raise if any close fails."""
        failures: list[str] = []
        for pid, handle in list(self._retained.items()):
            def clear_member(pid: int = pid, handle: int = handle) -> None:
                if self._retained.get(pid) == handle:
                    del self._retained[pid]

            try:
                _close_handle(handle, on_closed=clear_member)
            except ContainmentError as exc:
                failures.append(f"pid={pid}: {exc}")
        if failures:
            raise ContainmentError("handle-close-failed", "; ".join(failures))

    def close(self) -> None:
        """Release handles.  Kill-on-close destroys any surviving tree.

        Idempotent, but not a quiescence proof -- only ``terminate_and_verify``
        is.  Each handle's ownership is cleared *only after* its CloseHandle
        succeeds: a failed close leaves that handle owned and unresolved and
        raises, rather than silently dropping a reference we could not release.
        The Job handle is closed last: it is the one whose release fires
        ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``.
        """
        _require_fatal_owner_scope()
        failures: list[str] = []
        try:
            self._close_retained()
        except ContainmentError as exc:
            failures.append(f"members: {exc.detail or exc}")
        if self._process is not None:
            process = self._process

            def clear_process() -> None:
                if self._process == process:
                    self._process = None

            try:
                _close_handle(process, on_closed=clear_process)
            except ContainmentError as exc:
                failures.append(f"process: {exc}")
        if self._job is not None:
            job = self._job

            def clear_job() -> None:
                if self._job == job:
                    self._job = None

            try:
                _close_handle(job, on_closed=clear_job)
            except ContainmentError as exc:
                failures.append(f"job: {exc}")
        if failures:
            raise ContainmentError("handle-close-failed", "; ".join(failures))


def launch_contained(
    argv: Sequence[str],
    *,
    allowed_root: str,
    cwd: str,
    before_resume: Callable[[AssignedProcess], None],
    creation_flags: int = CREATE_NO_WINDOW,
) -> ContainedProcess:
    """Launch ``argv`` inside a fresh kill-on-close Job Object.

    ``argv[0]`` is the absolute image to execute -- it is passed as
    lpApplicationName, so there is no PATH search and no shell or terminal
    broker anywhere in the chain.  ``cwd`` must be an existing directory inside
    ``allowed_root`` with no reparse point on the way down.

    ``before_resume`` is a required synchronous handoff: it receives immutable
    ``AssignedProcess`` evidence, must return ``None``, and is invoked exactly
    once after every containment check while the child is still suspended.  It
    receives no handle or resume capability.  Every failure before the child is
    resumed is fail-closed: the suspended Job tree is terminated and verified
    empty and every handle is checked-closed.  Unresolved cleanup raises a
    ``CleanupRequiredError`` that the caller must retain and retry.  The child
    never executes a single instruction unless it is proved to be inside the
    Job and the callback accepts the handoff.
    """
    _require_fatal_owner_scope()
    _require_windows()
    if not argv or isinstance(argv, (str, bytes)):
        raise ContainmentError("argv-invalid")
    argv = list(argv)
    if not all(isinstance(a, str) for a in argv):
        raise ContainmentError("argv-invalid")
    if not callable(before_resume):
        raise ContainmentError("before-resume-callback-invalid")

    executable = _validate_executable(argv[0])
    real_cwd = _validate_cwd(cwd, allowed_root)
    flags = _validate_creation_flags(creation_flags)

    owner = _LaunchCleanupToken()
    try:
        _create_job(owner)
        if owner._job is None:  # defensive invariant for type narrowing
            raise ContainmentError("ownership-invalid", "job missing")
        _configure_job(owner._job)

        # Preliminary validation produces no durable proof.  Revalidate, then
        # retain the image, cwd, allowed root and every ancestor with handles
        # that exclude FILE_SHARE_DELETE.  The owner captures those bindings as
        # well, so an exception cannot discard an unresolved close.
        executable = _validate_executable(argv[0])
        real_cwd = _validate_cwd(cwd, allowed_root)
        expectations = _capture_launch_expectations(
            executable, real_cwd, allowed_root
        )
        bindings = _acquire_launch_bindings(
            executable, real_cwd, allowed_root, expectations
        )
        owner._attach_bindings(bindings)
        bound_argv = list(argv)
        bound_argv[0] = bindings.executable.final_path
        command_line = subprocess.list2cmdline(bound_argv)
        _before_create_process()
        bindings.verify_stable()
        process, thread, pid = _create_suspended_process(
            owner._job,
            bindings.executable.final_path,
            command_line,
            bindings.cwd.final_path,
            flags,
            owner=owner,
        )

        # CreateProcessW consumed paths, not the retained handles.  Re-check the
        # same bindings around creation and checked-close them before handoff.
        bindings.verify_stable()
        owner._close_bindings()

        _set_not_inheritable(process)
        _set_not_inheritable(thread)
        _verify_not_inheritable(owner._job, "job")
        _verify_not_inheritable(process, "process")
        _verify_not_inheritable(thread, "thread")
        if not _process_in_job(process, owner._job):
            raise ContainmentError("job-verify-failed", "process not in job")
        verified_job_limit_flags = _verify_job_limits(owner._job)
        evidence = AssignedProcess(
            pid=pid, job_limit_flags=verified_job_limit_flags
        )
        _invoke_before_resume(before_resume, evidence)
        owner._mark_resume_attempted()
        _resume_thread(thread)

        # The thread handle is never transferred.  Its checked close precedes
        # candidate construction, while job/process remain owned here until the
        # candidate constructor has returned successfully.
        owner._close_thread_for_return()
        candidate = ContainedProcess(
            owner._job, owner._process, pid, _owner=owner
        )
        owner._adopt(candidate)
        return candidate
    except Exception as original:
        try:
            owner._cleanup()
        except Exception as cleanup_error:
            _raise_cleanup_failure(owner, original, cleanup_error)
        raise
