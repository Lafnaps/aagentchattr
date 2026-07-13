"""Containment tests for autonomy.winjob.

Hermetic: temp directories, short-lived local python children, bounded waits.
No network, no agentchattr modules, no live processes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import FrozenInstanceError, fields
from unittest import mock

from autonomy import winjob
from autonomy.winjob import ContainmentError, launch_contained


WINDOWS = sys.platform == "win32"

if WINDOWS:
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateProcess.restype = wintypes.BOOL

_SYNCHRONIZE = 0x00100000
_PROCESS_TERMINATE = 0x00000001
_WAIT_TIMEOUT = 0x00000102

# The child/grandchild self-exit: if containment ever regresses, the test leaks
# a process for at most this long instead of forever.
CHILD_LIFETIME_SECONDS = 60

# The child records its own pid and its grandchild's, then publishes them
# atomically so the test can never read a half-written file.
CHILD_SOURCE = """\
import os, subprocess, sys, time

marker, grandchild_script = sys.argv[1], sys.argv[2]
grandchild = subprocess.Popen([sys.executable, grandchild_script])
tmp = marker + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    handle.write("%d\\n%d\\n" % (os.getpid(), grandchild.pid))
os.replace(tmp, marker)
time.sleep({lifetime})
""".format(lifetime=CHILD_LIFETIME_SECONDS)

GRANDCHILD_SOURCE = "import time; time.sleep({lifetime})\n".format(
    lifetime=CHILD_LIFETIME_SECONDS
)

PRIMARY_EXIT_SOURCE = """\
import os, sys, time

marker, delay, code = sys.argv[1:]
with open(marker, "w", encoding="ascii") as handle:
    handle.write(str(os.getpid()))
time.sleep(float(delay))
os._exit(int(code))
"""

# A launcher that spawns a long-lived grandchild, publishes both pids, then
# EXITS immediately. Models the venv/py-launcher case: the launched primary
# goes away while a Job member keeps running -- so tree-centric is_alive must
# stay true after primary_is_alive has gone false.
LAUNCHER_EXIT_SOURCE = """\
import os, subprocess, sys

marker, grandchild_script = sys.argv[1], sys.argv[2]
grandchild = subprocess.Popen([sys.executable, grandchild_script])
tmp = marker + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    handle.write("%d\\n%d\\n" % (os.getpid(), grandchild.pid))
os.replace(tmp, marker)
# launcher returns here -- the grandchild is left running inside the Job
"""

CRASH_OWNER_SOURCE = """\
import os, sys, time
from autonomy.winjob import fatal_owner_scope, launch_contained

root, probe, marker = sys.argv[1:]
with fatal_owner_scope():
    launch_contained(
        [sys.executable, probe, marker],
        allowed_root=root,
        cwd=root,
        before_resume=lambda evidence: None,
    )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and not os.path.exists(marker):
        time.sleep(0.01)
    if not os.path.exists(marker):
        os._exit(3)
    # Deliberately skip Python cleanup/finalizers.  Closing the owner process must
    # close the sole Job handle and kill the already-associated probe.
    os._exit(0)
"""

CRASH_PROBE_SOURCE = """\
import os, sys, time
marker = sys.argv[1]
tmp = marker + '.tmp'
with open(tmp, 'w', encoding='utf-8') as handle:
    handle.write(str(os.getpid()))
os.replace(tmp, marker)
time.sleep(60)
"""

FATAL_OWNER_SOURCE = r'''\
import asyncio
import ctypes
from ctypes import wintypes
import os
import sys
import time

from autonomy import winjob

root, child_script, grandchild_script, pid_marker, event_log, terminal_marker, mode = sys.argv[1:]

def log(message):
    with open(event_log, "a", encoding="ascii") as handle:
        handle.write(message + "\n")
        handle.flush()

def wait_for_pid_marker():
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and not os.path.exists(pid_marker):
        time.sleep(0.005)
    if not os.path.exists(pid_marker):
        raise RuntimeError("pid marker missing")

def launch(before_resume=lambda _evidence: None):
    return winjob.launch_contained(
        [sys.executable, child_script, pid_marker, grandchild_script],
        allowed_root=root,
        cwd=root,
        before_resume=before_resume,
    )

real_cleanup = winjob._LaunchCleanupToken._cleanup
def cleanup_spy(owner, *args, **kwargs):
    log("PYTHON_CLEANUP")
    return real_cleanup(owner, *args, **kwargs)
winjob._LaunchCleanupToken._cleanup = cleanup_spy

real_retry_cleanup = winjob._LaunchCleanupToken._retry_cleanup
def retry_cleanup_spy(owner, *args, **kwargs):
    log("PYTHON_RETRY")
    return real_retry_cleanup(owner, *args, **kwargs)
winjob._LaunchCleanupToken._retry_cleanup = retry_cleanup_spy

real_contained_close = winjob.ContainedProcess.close
def contained_close_spy(contained):
    log("CALLER_CLOSE_BEGIN")
    result = real_contained_close(contained)
    log("CALLER_CLOSE_DONE")
    return result
winjob.ContainedProcess.close = contained_close_spy

def run_mode():
    if mode == "create-job":
        real_create = winjob._k32.CreateJobObjectW
        def create_then_fatal(*args):
            raw = real_create(*args)
            if raw:
                log("INJECT create-job")
                raise KeyboardInterrupt("after CreateJobObjectW")
            return raw
        winjob._k32.CreateJobObjectW = create_then_fatal
        launch()
        return

    if mode == "create-file":
        real_create = winjob._k32.CreateFileW
        invalid = int(ctypes.c_void_p(-1).value)
        def create_then_fatal(*args):
            raw = real_create(*args)
            value = int(raw) if raw else 0
            if value and value != invalid:
                log("INJECT create-file")
                raise KeyboardInterrupt("after CreateFileW")
            return raw
        winjob._k32.CreateFileW = create_then_fatal
        launch()
        return

    if mode == "post-resume":
        real_resume = winjob._k32.ResumeThread
        def resume_then_fatal(thread):
            previous = int(real_resume(thread)) & 0xFFFFFFFF
            if previous != 0xFFFFFFFF:
                wait_for_pid_marker()
                log("INJECT post-resume")
                raise KeyboardInterrupt("after ResumeThread")
            return previous
        winjob._k32.ResumeThread = resume_then_fatal
        launch()
        return

    if mode == "open-process":
        proc = launch()
        wait_for_pid_marker()
        real_open = winjob._k32.OpenProcess
        def open_then_fatal(*args):
            raw = real_open(*args)
            if raw:
                log("INJECT open-process")
                raise KeyboardInterrupt("after OpenProcess")
            return raw
        winjob._k32.OpenProcess = open_then_fatal
        proc.terminate_and_verify(timeout=10.0)
        return

    if mode == "close-reuse":
        real_close = winjob._k32.CloseHandle
        native = ctypes.WinDLL("kernel32", use_last_error=True)
        native.CreateEventW.argtypes = [
            wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR
        ]
        native.CreateEventW.restype = wintypes.HANDLE
        native.CloseHandle.argtypes = [wintypes.HANDLE]
        native.CloseHandle.restype = wintypes.BOOL
        held = []
        state = {"target": None}

        def force_reuse(target):
            for _index in range(4096):
                candidate = native.CreateEventW(None, False, False, None)
                if not candidate:
                    break
                held.append(candidate)
                if int(candidate) == target:
                    return True
            return False

        def close_then_fatal(handle):
            value = int(handle)
            target = state["target"]
            if target is not None:
                if value == target:
                    log("DOUBLE_CLOSE_REUSED")
                else:
                    log("PYTHON_CLOSE_AFTER_FATAL")
                return real_close(handle)
            wait_for_pid_marker()
            closed = bool(real_close(handle))
            if not closed:
                return 0
            reused = force_reuse(value)
            state["target"] = value
            log("INJECT close-reuse reuse=" + ("1" if reused else "0"))
            raise KeyboardInterrupt("after CloseHandle success")

        def install_close(_evidence):
            winjob._k32.CloseHandle = close_then_fatal
            return None

        launch(before_resume=install_close)
        return

    if mode == "launch-return":
        def trace_return(frame, event, value):
            if (
                frame.f_code is winjob.launch_contained.__code__
                and event == "return"
                and isinstance(value, winjob.ContainedProcess)
            ):
                wait_for_pid_marker()
                log("INJECT launch-return")
                raise KeyboardInterrupt("at launch return")
            return trace_return
        sys.settrace(trace_return)
        launch()
        return

    if mode in (
        "lifecycle-baseexception",
        "lifecycle-exception",
        "lifecycle-success",
    ):
        proc = launch()
        try:
            wait_for_pid_marker()
            log("INJECT " + mode)
            if mode == "lifecycle-baseexception":
                raise KeyboardInterrupt("lifecycle BaseException")
            if mode == "lifecycle-exception":
                raise RuntimeError("lifecycle Exception")
        except Exception:
            log("ORDINARY_HANDLER")
            proc.close()
            log("ORDINARY_RETHROW")
            raise
        proc.close()
        log("SUCCESS_RETURN")
        return

    if mode == "system-exit":
        log("INJECT system-exit")
        raise SystemExit(19)
    if mode == "generator-exit":
        log("INJECT generator-exit")
        raise GeneratorExit("injected")
    if mode == "cancelled-error":
        log("INJECT cancelled-error")
        raise asyncio.CancelledError("injected")
    raise RuntimeError("unknown mode: " + mode)

try:
    with winjob.fatal_owner_scope():
        run_mode()
finally:
    log("TERMINAL_EVIDENCE")
    with open(terminal_marker, "w", encoding="ascii") as handle:
        handle.write("TERMINAL_EVIDENCE\n")
'''


def pid_alive(pid: int) -> bool:
    """True while `pid` is running.  A dead-but-unreaped process is signaled."""
    handle = _k32.OpenProcess(_SYNCHRONIZE, False, pid)
    if not handle:
        return False
    try:
        return _k32.WaitForSingleObject(handle, 0) == _WAIT_TIMEOUT
    finally:
        _k32.CloseHandle(handle)


def terminate_pid(pid: int) -> None:
    """Best-effort test cleanup for a probe that containment failed to kill."""
    if not WINDOWS:
        return
    handle = _k32.OpenProcess(_PROCESS_TERMINATE | _SYNCHRONIZE, False, pid)
    if not handle:
        return
    try:
        _k32.TerminateProcess(handle, 1)
        _k32.WaitForSingleObject(handle, 5000)
    finally:
        _k32.CloseHandle(handle)


def wait_until(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def base_python_executable() -> str:
    """The real interpreter image, bypassing any venv redirector executable."""
    return os.path.realpath(getattr(sys, "_base_executable", None) or sys.executable)


class AssignedProcessContractTests(unittest.TestCase):
    def test_evidence_is_frozen_and_exposes_only_verified_values(self):
        evidence = winjob.AssignedProcess(pid=123, job_limit_flags=0x2000)

        self.assertEqual(
            [field.name for field in fields(evidence)],
            ["pid", "job_limit_flags"],
        )
        self.assertFalse(hasattr(evidence, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            evidence.pid = 456

    def test_callback_exception_and_non_none_return_have_stable_errors(self):
        evidence = winjob.AssignedProcess(pid=123, job_limit_flags=0x2000)

        def fail(_evidence):
            raise ValueError("injected")

        with self.assertRaises(ContainmentError) as caught:
            winjob._invoke_before_resume(fail, evidence)
        self.assertEqual(caught.exception.code, "before-resume-callback-failed")
        self.assertIsInstance(caught.exception.__cause__, ValueError)

        with self.assertRaises(ContainmentError) as caught:
            winjob._invoke_before_resume(lambda _evidence: False, evidence)
        self.assertEqual(caught.exception.code, "before-resume-return-invalid")


class FatalOwnerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self._fatal_owner_scope = winjob.fatal_owner_scope()
        self._fatal_owner_scope.__enter__()
        self.addCleanup(
            self._fatal_owner_scope.__exit__, None, None, None
        )


@unittest.skipUnless(WINDOWS, "Job Objects are Windows-only")
class WinJobTestCase(FatalOwnerTestCase):
    def setUp(self) -> None:
        super().setUp()
        # realpath: the temp dir may sit behind a short (8.3) path component.
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="winjob-"))
        self._launched: list[winjob.ContainedProcess] = []
        self.addCleanup(self._cleanup)

        self.marker = os.path.join(self.root, "pids.txt")
        self.child_script = self._write("child.py", CHILD_SOURCE)
        self.grandchild_script = self._write("grandchild.py", GRANDCHILD_SOURCE)

    def _cleanup(self) -> None:
        # Never let a failed assertion leak a live tree into the next test.
        for proc in self._launched:
            if not proc.closed:
                proc.close()
        # The tree holds `root` as its cwd, so the directory only becomes
        # removable once kill-on-close has finished. Bounded retry, then give up.
        for _ in range(50):
            shutil.rmtree(self.root, ignore_errors=True)
            if not os.path.isdir(self.root):
                return
            time.sleep(0.02)

    def _write(self, name: str, source: str) -> str:
        path = os.path.join(self.root, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        return path

    def launch(self, **overrides) -> winjob.ContainedProcess:
        kwargs = {
            "argv": [
                sys.executable,
                self.child_script,
                self.marker,
                self.grandchild_script,
            ],
            "allowed_root": self.root,
            "cwd": self.root,
            "before_resume": lambda evidence: None,
        }
        kwargs.update(overrides)
        proc = launch_contained(kwargs.pop("argv"), **kwargs)
        self._launched.append(proc)
        return proc

    def read_pids(self) -> tuple[int, int]:
        self.assertTrue(
            wait_until(lambda: os.path.exists(self.marker)),
            "child never published its pids",
        )
        with open(self.marker, encoding="utf-8") as handle:
            child_pid, grandchild_pid = [int(x) for x in handle.read().split()]
        return child_pid, grandchild_pid


class ContainmentTests(WinJobTestCase):
    def test_callback_is_last_suspended_boundary_with_verified_evidence(self):
        captured: dict[str, object] = {}
        events: list[str] = []
        real_acquire = winjob._acquire_launch_bindings
        real_create = winjob._create_suspended_process
        real_resume = winjob._resume_thread

        def acquire(*args, **kwargs):
            bindings = real_acquire(*args, **kwargs)
            captured["bindings"] = bindings
            return bindings

        def create(job, *args, **kwargs):
            process, thread, pid = real_create(job, *args, **kwargs)
            captured.update(job=job, process=process, thread=thread, pid=pid)
            return process, thread, pid

        def before_resume(evidence):
            events.append("callback")
            self.assertIsInstance(evidence, winjob.AssignedProcess)
            self.assertEqual(evidence.pid, captured["pid"])
            bindings = captured["bindings"]
            self.assertEqual(bindings.entries, [], "path handles still owned")
            self.assertFalse(os.path.exists(self.marker), "suspended child ran")
            self.assertTrue(
                winjob._process_in_job(captured["process"], captured["job"])
            )
            self.assertEqual(
                winjob._verify_job_limits(captured["job"]),
                evidence.job_limit_flags,
            )
            for label in ("job", "process", "thread"):
                self.assertFalse(
                    winjob.handle_is_inheritable(captured[label]),
                    f"{label} handle was inheritable",
                )
            return None

        def resume(thread):
            events.append("resume")
            self.assertEqual(events, ["callback", "resume"])
            return real_resume(thread)

        with mock.patch.object(
            winjob, "_acquire_launch_bindings", side_effect=acquire
        ), mock.patch.object(
            winjob, "_create_suspended_process", side_effect=create
        ), mock.patch.object(winjob, "_resume_thread", side_effect=resume):
            proc = self.launch(before_resume=before_resume)

        self.assertEqual(events, ["callback", "resume"])
        self.assertEqual(proc.pid, captured["pid"])
        self.assertTrue(proc.is_alive())

    def test_terminate_kills_child_and_grandchild_and_verifies_quiescence(self):
        proc = self.launch()
        child_pid, grandchild_pid = self.read_pids()

        # proc.pid is the *launcher* pid. With the repo's own .venv python.exe --
        # a redirector stub -- the launched image is not the interpreter that
        # runs child.py, so proc.pid deliberately need NOT equal child_pid (the
        # script's own os.getpid()). Asserting equality was wrong; the contract
        # is only that the launcher pid is a real process we started.
        self.assertGreater(proc.pid, 0)
        # is_alive is tree-centric: true because the Job has live members,
        # regardless of whether the launcher itself is still the primary.
        self.assertTrue(proc.is_alive())
        self.assertTrue(wait_until(lambda: pid_alive(grandchild_pid)))
        # The grandchild was spawned by the child, never assigned by us: it is
        # in the Job only because Job membership is inherited. The count is >= 2
        # rather than == 2 on purpose -- Windows also pulls in processes neither
        # we nor the child asked for (a conhost.exe for the grandchild's new
        # console), which is precisely what a Job is for. The contract is that
        # everything in the Job dies, not that we can predict what lands in it.
        self.assertTrue(wait_until(lambda: proc.active_processes() >= 2))

        self.assertTrue(proc.terminate_and_verify(timeout=10.0))

        # No wait_until here, deliberately: "verified" has to mean the tree is
        # already gone the instant the call returns. These four assertions are
        # the regression guard for the Job's optimistic accounting -- it reports
        # zero active processes ~3ms before the tree is actually dead, so a
        # terminate_and_verify that trusted the counter would fail right here.
        self.assertEqual(proc.active_processes(), 0)
        self.assertFalse(proc.is_alive())
        self.assertFalse(pid_alive(child_pid))
        self.assertFalse(pid_alive(grandchild_pid))

    def test_retained_member_close_failure_survives_until_retryable_close(self):
        proc = self.launch()
        child_pid, grandchild_pid = self.read_pids()
        self.assertTrue(wait_until(lambda: pid_alive(grandchild_pid)))

        real_open = winjob._open_sync_handle
        real_close = winjob._close_handle
        probe_handles: set[int] = set()
        successful_closes: list[int] = []
        failed_probe: int | None = None

        def record_open(pid, retained=None):
            handle = real_open(pid, retained)
            if handle is not None:
                probe_handles.add(handle)
            return handle

        def fail_one_probe_close(handle, *, on_closed=None):
            nonlocal failed_probe
            if handle in probe_handles and failed_probe is None:
                failed_probe = handle
                raise ContainmentError("handle-close-failed", "probe injected")
            result = real_close(handle, on_closed=on_closed)
            successful_closes.append(handle)
            return result

        with mock.patch.object(
            winjob, "_open_sync_handle", side_effect=record_open
        ), mock.patch.object(
            winjob, "_close_handle", side_effect=fail_one_probe_close
        ):
            with self.assertRaises(ContainmentError) as caught:
                proc.terminate_and_verify(timeout=10.0)
            self.assertEqual(caught.exception.code, "handle-close-failed")
            self.assertIsNotNone(failed_probe)
            self.assertIn(failed_probe, proc._retained.values())
            self.assertFalse(proc.closed)
            self.assertFalse(pid_alive(child_pid))
            self.assertFalse(pid_alive(grandchild_pid))

            proc.close()
            self.assertTrue(proc.closed)
            proc.close()

        self.assertEqual(successful_closes.count(failed_probe), 1)

    def test_is_alive_is_tree_centric_when_launcher_exits(self):
        # Launch the base interpreter directly, never a venv redirector, so the
        # exact primary PID/exit-code assertions below identify the script
        # process itself.  Its descendant remains a separate live Job member.
        launcher = self._write("launcher.py", LAUNCHER_EXIT_SOURCE)
        proc = self.launch(
            argv=[
                base_python_executable(),
                launcher,
                self.marker,
                self.grandchild_script,
            ]
        )
        child_pid, grandchild_pid = self.read_pids()

        self.assertEqual(proc.pid, child_pid)
        self.assertEqual(proc.wait_primary_exit(timeout=10.0), 0)
        self.assertEqual(proc.wait_primary_exit(timeout=0), 0)

        self.assertTrue(
            wait_until(lambda: pid_alive(grandchild_pid)), "grandchild never started"
        )
        self.assertFalse(proc.primary_is_alive)
        # ...but the tree is still alive, so is_alive() must remain true.
        self.assertTrue(pid_alive(grandchild_pid))
        self.assertTrue(
            proc.is_alive(), "is_alive went false while a Job member remained"
        )
        self.assertGreaterEqual(proc.active_processes(), 1)

        # Containment still tears the survivor down and proves quiescence.
        self.assertTrue(proc.terminate_and_verify(timeout=10.0))
        self.assertEqual(proc.active_processes(), 0)
        self.assertFalse(proc.is_alive())
        self.assertFalse(proc.primary_is_alive)
        self.assertFalse(pid_alive(grandchild_pid))

    def test_wait_primary_exit_returns_exact_base_interpreter_exit_codes(self):
        script = self._write("primary_exit.py", PRIMARY_EXIT_SOURCE)
        for index, expected in enumerate((0, 37)):
            with self.subTest(exit_code=expected):
                marker = os.path.join(self.root, f"primary-{index}.pid")
                assigned: list[winjob.AssignedProcess] = []
                proc = self.launch(
                    argv=[
                        base_python_executable(),
                        script,
                        marker,
                        "0",
                        str(expected),
                    ],
                    before_resume=assigned.append,
                )

                self.assertEqual(proc.wait_primary_exit(timeout=10.0), expected)
                with open(marker, encoding="ascii") as handle:
                    script_pid = int(handle.read())
                self.assertEqual(proc.pid, script_pid)
                self.assertEqual([item.pid for item in assigned], [script_pid])
                # A repeated call must re-prove the same handle signaled and
                # return the kernel-retained exact code, not a guessed status.
                self.assertEqual(proc.wait_primary_exit(timeout=0), expected)

    def test_wait_primary_exit_returns_real_dword_259_after_signal(self):
        # 259 is STILL_ACTIVE only before a process handle is signaled.  It is
        # also a legal final DWORD, which must be returned exactly after wait.
        script = self._write("primary_exit_259.py", PRIMARY_EXIT_SOURCE)
        marker = os.path.join(self.root, "primary-259.pid")
        proc = self.launch(
            argv=[
                base_python_executable(),
                script,
                marker,
                "0",
                "259",
            ]
        )

        self.assertEqual(proc.wait_primary_exit(timeout=10.0), 259)
        self.assertFalse(proc.primary_is_alive)
        self.assertEqual(proc.wait_primary_exit(timeout=0), 259)

    def test_wait_primary_exit_distinguishes_timeout_then_exact_exit(self):
        script = self._write("primary_delay.py", PRIMARY_EXIT_SOURCE)
        marker = os.path.join(self.root, "primary-delay.pid")
        proc = self.launch(
            argv=[
                base_python_executable(),
                script,
                marker,
                "0.3",
                "23",
            ]
        )

        self.assertIsNone(proc.wait_primary_exit(timeout=0))
        self.assertEqual(proc.wait_primary_exit(timeout=10.0), 23)

    def test_close_without_terminate_kills_tree(self):
        proc = self.launch()
        child_pid, grandchild_pid = self.read_pids()
        self.assertTrue(wait_until(lambda: pid_alive(grandchild_pid)))

        proc.close()  # no TerminateJobObject: kill-on-close must do it

        self.assertTrue(
            wait_until(lambda: not pid_alive(child_pid)), "child survived close()"
        )
        self.assertTrue(
            wait_until(lambda: not pid_alive(grandchild_pid)),
            "grandchild survived close()",
        )
        self.assertTrue(proc.closed)
        self.assertFalse(proc.is_alive())

    def test_close_is_idempotent_and_terminate_after_close_fails_closed(self):
        proc = self.launch()
        self.read_pids()
        proc.close()
        proc.close()

        with self.assertRaises(ContainmentError) as caught:
            proc.terminate_and_verify(timeout=1.0)
        self.assertEqual(caught.exception.code, "closed")
        for _ in range(2):
            with self.assertRaises(ContainmentError) as caught:
                proc.wait_primary_exit(timeout=0)
            self.assertEqual(caught.exception.code, "closed")

    def test_job_limits_kill_on_close_without_breakaway(self):
        proc = self.launch()
        flags = proc.limit_flags()

        self.assertTrue(flags & winjob.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        self.assertFalse(flags & winjob.JOB_OBJECT_LIMIT_BREAKAWAY_OK)
        self.assertFalse(flags & winjob.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)

    def test_create_returns_with_child_already_in_job_and_never_assigns_afterward(self):
        # The assertion runs inside the create wrapper spy, before launch can do
        # any post-create work.  Membership must already be true at that exact
        # boundary, and the legacy post-create API must never be called.
        real_create = winjob._create_suspended_process
        observed: list[bool] = []

        def create_and_probe(job, *args, **kwargs):
            result = real_create(job, *args, **kwargs)
            observed.append(winjob._process_in_job(result[0], job))
            return result

        late_assign = mock.Mock(
            side_effect=AssertionError("post-create assignment must not occur")
        )
        with mock.patch.object(
            winjob, "_create_suspended_process", side_effect=create_and_probe
        ), mock.patch.object(
            winjob._k32, "AssignProcessToJobObject", late_assign
        ):
            proc = self.launch()

        self.assertEqual(observed, [True])
        late_assign.assert_not_called()
        self.assertTrue(proc.is_alive())

    def test_abrupt_owner_exit_kills_probe_without_cleanup_frame(self):
        owner = self._write("crash_owner.py", CRASH_OWNER_SOURCE)
        probe = self._write("crash_probe.py", CRASH_PROBE_SOURCE)
        marker = os.path.join(self.root, "crash-probe.pid")
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            project_root if not existing else project_root + os.pathsep + existing
        )
        parent = subprocess.Popen(
            [sys.executable, owner, self.root, probe, marker],
            cwd=self.root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        probe_pid: int | None = None
        try:
            self.assertEqual(parent.wait(timeout=15.0), 0)
            self.assertTrue(os.path.isfile(marker), "probe never published its pid")
            with open(marker, encoding="utf-8") as handle:
                probe_pid = int(handle.read())
            self.assertTrue(
                wait_until(lambda: not pid_alive(probe_pid), timeout=10.0),
                "probe survived abrupt death of the sole Job owner",
            )
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait(timeout=5.0)
            if probe_pid is not None and pid_alive(probe_pid):
                terminate_pid(probe_pid)

    def test_handles_are_not_inheritable(self):
        proc = self.launch()

        self.assertFalse(winjob.handle_is_inheritable(proc.job_handle))
        self.assertFalse(winjob.handle_is_inheritable(proc.process_handle))

    def test_terminate_and_verify_rejects_bad_timeout(self):
        proc = self.launch()
        for bad in (0, -1, "5"):
            with self.subTest(timeout=bad):
                with self.assertRaises(ContainmentError) as caught:
                    proc.terminate_and_verify(timeout=bad)
                self.assertEqual(caught.exception.code, "timeout-invalid")


@unittest.skipUnless(WINDOWS, "Job Objects are Windows-only")
class FatalOwnerSubprocessTests(unittest.TestCase):
    """Sacrificial owner probes: BaseException must end the process, not clean."""

    def setUp(self) -> None:
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="winjob-fatal-"))
        self.owner_script = self._write("fatal_owner.py", FATAL_OWNER_SOURCE)
        self.child_script = self._write("child.py", CHILD_SOURCE)
        self.grandchild_script = self._write("grandchild.py", GRANDCHILD_SOURCE)
        self.addCleanup(shutil.rmtree, self.root, True)

    def _write(self, name: str, source: str) -> str:
        path = os.path.join(self.root, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        return path

    def _run_owner_mode(
        self,
        mode: str,
        *,
        expect_tree: bool,
        expected_returncode: int = winjob.FATAL_OWNER_EXIT_CODE,
        expect_terminal: bool = False,
        expect_caller_close: bool = False,
    ) -> str:
        pid_marker = os.path.join(self.root, f"{mode}.pids")
        event_log = os.path.join(self.root, f"{mode}.events")
        terminal_marker = os.path.join(self.root, f"{mode}.terminal")
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            project_root if not existing else project_root + os.pathsep + existing
        )
        command = [
            base_python_executable(),
            self.owner_script,
            self.root,
            self.child_script,
            self.grandchild_script,
            pid_marker,
            event_log,
            terminal_marker,
            mode,
        ]
        owner = subprocess.Popen(
            command,
            cwd=project_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        observed_pids: list[int] = []
        try:
            stdout, stderr = owner.communicate(timeout=20.0)
            self.assertEqual(
                owner.returncode,
                expected_returncode,
                f"mode={mode} stdout={stdout!r} stderr={stderr!r}",
            )
            self.assertTrue(os.path.isfile(event_log), f"mode={mode} no injection log")
            with open(event_log, encoding="ascii") as handle:
                events = handle.read()
            self.assertIn(f"INJECT {mode}", events)
            self.assertNotIn("PYTHON_CLEANUP", events)
            self.assertNotIn("PYTHON_RETRY", events)
            self.assertNotIn("PYTHON_CLOSE_AFTER_FATAL", events)
            self.assertNotIn("DOUBLE_CLOSE_REUSED", events)
            self.assertEqual(
                "CALLER_CLOSE_BEGIN" in events,
                expect_caller_close,
                f"mode={mode} caller close ordering mismatch: {events!r}",
            )
            self.assertEqual(
                "CALLER_CLOSE_DONE" in events,
                expect_caller_close,
                f"mode={mode} caller close completion mismatch: {events!r}",
            )
            self.assertEqual(
                "TERMINAL_EVIDENCE" in events,
                expect_terminal,
                f"mode={mode} terminal event ordering mismatch: {events!r}",
            )
            self.assertEqual(
                os.path.exists(terminal_marker),
                expect_terminal,
                f"mode={mode} terminal marker mismatch",
            )

            if expect_tree:
                self.assertTrue(
                    os.path.isfile(pid_marker), f"mode={mode} child published no pids"
                )
                with open(pid_marker, encoding="utf-8") as handle:
                    observed_pids = [int(value) for value in handle.read().split()]
                self.assertGreaterEqual(len(observed_pids), 2)
                self.assertTrue(
                    wait_until(
                        lambda: all(not pid_alive(pid) for pid in observed_pids),
                        timeout=10.0,
                    ),
                    f"mode={mode} Job tree survived fatal owner exit: {observed_pids}",
                )
            else:
                self.assertFalse(
                    os.path.exists(pid_marker), f"mode={mode} unexpectedly ran child"
                )
            return events
        finally:
            if owner.poll() is None:
                owner.kill()
                owner.wait(timeout=5.0)
            for pid in observed_pids:
                if pid_alive(pid):
                    terminate_pid(pid)

    def test_create_job_scalar_return_baseexception_is_process_fatal(self):
        self._run_owner_mode("create-job", expect_tree=False)

    def test_create_file_scalar_return_baseexception_is_process_fatal(self):
        self._run_owner_mode("create-file", expect_tree=False)

    def test_open_process_scalar_return_baseexception_kills_whole_job(self):
        self._run_owner_mode("open-process", expect_tree=True)

    def test_close_success_forced_reuse_never_retries_stale_handle(self):
        events = self._run_owner_mode("close-reuse", expect_tree=True)
        self.assertIn("INJECT close-reuse reuse=1", events)

    def test_post_resume_baseexception_kills_whole_job_without_cleanup(self):
        self._run_owner_mode("post-resume", expect_tree=True)

    def test_launch_return_baseexception_kills_whole_job_without_cleanup(self):
        self._run_owner_mode("launch-return", expect_tree=True)

    def test_lifecycle_baseexception_skips_caller_cleanup_and_kills_tree(self):
        events = self._run_owner_mode(
            "lifecycle-baseexception", expect_tree=True
        )
        self.assertNotIn("ORDINARY_HANDLER", events)
        self.assertNotIn("ORDINARY_RETHROW", events)

    def test_lifecycle_exception_checked_closes_before_rethrow_and_terminal(self):
        events = self._run_owner_mode(
            "lifecycle-exception",
            expect_tree=True,
            expected_returncode=1,
            expect_terminal=True,
            expect_caller_close=True,
        )
        ordered = [
            "INJECT lifecycle-exception",
            "ORDINARY_HANDLER",
            "CALLER_CLOSE_BEGIN",
            "CALLER_CLOSE_DONE",
            "ORDINARY_RETHROW",
            "TERMINAL_EVIDENCE",
        ]
        positions = [events.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions), events)

    def test_lifecycle_success_explicitly_closes_before_terminal(self):
        events = self._run_owner_mode(
            "lifecycle-success",
            expect_tree=True,
            expected_returncode=0,
            expect_terminal=True,
            expect_caller_close=True,
        )
        ordered = [
            "INJECT lifecycle-success",
            "CALLER_CLOSE_BEGIN",
            "CALLER_CLOSE_DONE",
            "SUCCESS_RETURN",
            "TERMINAL_EVIDENCE",
        ]
        positions = [events.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions), events)

    def test_system_generator_and_cancelled_baseexceptions_use_reserved_exit(self):
        for mode in ("system-exit", "generator-exit", "cancelled-error"):
            with self.subTest(mode=mode):
                self._run_owner_mode(mode, expect_tree=False)


class FailClosedLaunchTests(WinJobTestCase):
    """Every failure between create-suspended and resume must fail closed."""

    def setUp(self) -> None:
        super().setUp()
        self.created: list[tuple[int, int, int]] = []
        self.closed: list[int] = []

        real_create = winjob._create_suspended_process
        real_close = winjob._close_handle

        def spy_create(*args, **kwargs):
            result = real_create(*args, **kwargs)
            self.created.append(result)
            return result

        def spy_close(handle, *, on_closed=None):
            self.closed.append(handle)
            return real_close(handle, on_closed=on_closed)

        for name, spy in (
            ("_create_suspended_process", spy_create),
            ("_close_handle", spy_close),
        ):
            patcher = mock.patch.object(winjob, name, spy)
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_failed_closed(self, code: str, **overrides) -> None:
        with self.assertRaises(ContainmentError) as caught:
            self.launch(**overrides)
        self.assertEqual(caught.exception.code, code)

        self.assertEqual(len(self.created), 1, "expected exactly one child")
        process, thread, pid = self.created[0]

        self.assertTrue(
            wait_until(lambda: not pid_alive(pid)),
            "suspended process survived a failed launch",
        )
        # It was suspended the whole time, so it never reached its first line.
        self.assertFalse(
            os.path.exists(self.marker), "child ran before it was verified in the Job"
        )
        # Job, process and thread handles are closed.  A failure at or after the
        # resume boundary conservatively uses resumed-tree cleanup and may also
        # open/close one or more retained member probes.
        self.assertGreaterEqual(len(self.closed), 3, f"leaked handles: {self.closed}")
        self.assertIn(process, self.closed)
        self.assertIn(thread, self.closed)

    def test_second_limit_verification_failure_terminates_atomic_job_child(self):
        real_verify = winjob._verify_job_limits
        calls = 0
        callback = mock.Mock(return_value=None)

        def fail_second(job):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ContainmentError("job-limit-unverified", "injected")
            return real_verify(job)

        with mock.patch.object(
            winjob, "_verify_job_limits", side_effect=fail_second
        ):
            self.assert_failed_closed(
                "job-limit-unverified", before_resume=callback
            )
        self.assertEqual(calls, 2, "limits were not re-read after process creation")
        callback.assert_not_called()

    def test_verify_failure_terminates_suspended_child(self):
        # Assignment "succeeds" but IsProcessInJob says the child is not in the
        # Job: the only safe move is to kill it rather than resume it.
        callback = mock.Mock(return_value=None)
        with mock.patch.object(winjob, "_process_in_job", return_value=False):
            self.assert_failed_closed(
                "job-verify-failed", before_resume=callback
            )
        callback.assert_not_called()

    def test_resume_failure_terminates_suspended_child(self):
        callback = mock.Mock(return_value=None)
        suspended_cleanup = mock.Mock(
            side_effect=AssertionError("resume attempt used suspended cleanup")
        )
        with mock.patch.object(
            winjob,
            "_resume_thread",
            side_effect=ContainmentError("resume-failed", "mocked"),
        ), mock.patch.object(
            winjob, "_verify_suspended_job_empty", suspended_cleanup
        ):
            self.assert_failed_closed("resume-failed", before_resume=callback)
        callback.assert_called_once()
        suspended_cleanup.assert_not_called()
        self.assertIsInstance(callback.call_args.args[0], winjob.AssignedProcess)

    def test_post_resume_thread_close_failure_is_exception_owned_and_retryable(self):
        checked_close = winjob._close_handle
        failed = False

        def fail_thread_once(handle, *, on_closed=None):
            nonlocal failed
            thread = self.created[0][1] if self.created else None
            if handle == thread and not failed:
                failed = True
                raise ContainmentError("handle-close-failed", "thread injected")
            return checked_close(handle, on_closed=on_closed)

        with mock.patch.object(
            winjob, "_close_handle", side_effect=fail_thread_once
        ):
            with self.assertRaises(winjob.CleanupRequiredError) as caught:
                self.launch()
            error = caught.exception
            self.assertTrue(error.cleanup_pending)
            self.assertIsInstance(error.__cause__, ContainmentError)
            for public_name in (
                "job_handle",
                "process_handle",
                "thread_handle",
                "cleanup_token",
                "token",
            ):
                self.assertFalse(hasattr(error, public_name))
            self.assertFalse(
                any(
                    word in key
                    for key in vars(error)
                    for word in ("owner", "token", "handle")
                )
            )

            process, thread, pid = self.created[0]
            self.assertTrue(wait_until(lambda: not pid_alive(pid)))
            self.assertNotIn(thread, self.closed, "failed close lost ownership")
            error.retry_cleanup()
            self.assertFalse(error.cleanup_pending)
            error.retry_cleanup()  # idempotent after success

        self.assertEqual(self.closed.count(thread), 1, "thread double-closed")
        self.assertEqual(self.closed.count(process), 1, "process double-closed")

    def test_retry_cleanup_partial_failure_keeps_same_token_until_success(self):
        checked_close = winjob._close_handle
        failures = 0

        def fail_thread_twice(handle, *, on_closed=None):
            nonlocal failures
            thread = self.created[0][1] if self.created else None
            if handle == thread and failures < 2:
                failures += 1
                raise ContainmentError(
                    "handle-close-failed", f"thread injected {failures}"
                )
            return checked_close(handle, on_closed=on_closed)

        with mock.patch.object(
            winjob, "_close_handle", side_effect=fail_thread_twice
        ):
            with self.assertRaises(winjob.CleanupRequiredError) as caught:
                self.launch()
            error = caught.exception
            original = error.__cause__
            self.assertTrue(error.cleanup_pending)

            with self.assertRaises(winjob.CleanupRequiredError) as retry_caught:
                error.retry_cleanup()
            self.assertIs(retry_caught.exception, error)
            self.assertIs(error.__cause__, original)
            self.assertTrue(error.cleanup_pending)

            error.retry_cleanup()
            self.assertFalse(error.cleanup_pending)
            error.retry_cleanup()

        _process, thread, _pid = self.created[0]
        self.assertEqual(self.closed.count(thread), 1, "thread double-closed")

    def test_candidate_constructor_failure_after_resume_is_fully_cleaned(self):
        resumed = mock.Mock(wraps=winjob._resume_thread)
        constructor_error = RuntimeError("candidate injected")

        with mock.patch.object(
            winjob, "_resume_thread", resumed
        ), mock.patch.object(
            winjob, "ContainedProcess", side_effect=constructor_error
        ):
            with self.assertRaises(RuntimeError) as caught:
                self.launch()

        self.assertIs(caught.exception, constructor_error)
        resumed.assert_called_once()
        process, thread, pid = self.created[0]
        self.assertTrue(wait_until(lambda: not pid_alive(pid)))
        if os.path.isfile(self.marker):
            with open(self.marker, encoding="utf-8") as handle:
                observed = [int(value) for value in handle.read().split()]
            self.assertTrue(all(not pid_alive(value) for value in observed))
        # A subsequently opened member-probe handle may reuse the numeric value
        # of the already-closed thread handle, so raw-value counts cannot prove
        # double-close here.  The lexical owner clears the thread on success;
        # its dedicated failure/retry tests below assert exact close counts.
        self.assertIn(thread, self.closed)
        self.assertEqual(self.closed.count(process), 1)

    def test_candidate_failure_with_partial_cleanup_is_retryable(self):
        checked_close = winjob._close_handle
        process_close_failed = False

        def fail_process_once(handle, *, on_closed=None):
            nonlocal process_close_failed
            process = self.created[0][0] if self.created else None
            if handle == process and not process_close_failed:
                process_close_failed = True
                raise ContainmentError("handle-close-failed", "process injected")
            return checked_close(handle, on_closed=on_closed)

        constructor_error = RuntimeError("candidate injected")
        with mock.patch.object(
            winjob, "ContainedProcess", side_effect=constructor_error
        ), mock.patch.object(
            winjob, "_close_handle", side_effect=fail_process_once
        ):
            with self.assertRaises(winjob.CleanupRequiredError) as caught:
                self.launch()
            error = caught.exception
            self.assertIs(error.__cause__, constructor_error)
            self.assertTrue(error.cleanup_pending)
            process, thread, pid = self.created[0]
            self.assertTrue(wait_until(lambda: not pid_alive(pid)))
            if os.path.isfile(self.marker):
                with open(self.marker, encoding="utf-8") as handle:
                    observed = [int(value) for value in handle.read().split()]
                self.assertTrue(all(not pid_alive(value) for value in observed))
            self.assertNotIn(process, self.closed)
            self.assertIn(thread, self.closed)

            error.retry_cleanup()
            self.assertFalse(error.cleanup_pending)
            error.retry_cleanup()

        self.assertEqual(self.closed.count(process), 1, "process double-closed")

    def test_createprocess_exception_after_success_keeps_owner_handles(self):
        real_create_process = winjob._k32.CreateProcessW
        created_pids: list[int] = []
        callback = mock.Mock(return_value=None)

        def create_then_interrupt(*args):
            ok = real_create_process(*args)
            if ok:
                pi = ctypes.cast(
                    args[-1], ctypes.POINTER(winjob._PROCESS_INFORMATION)
                ).contents
                created_pids.append(int(pi.dwProcessId))
                raise RuntimeError("after CreateProcessW")
            return ok

        with mock.patch.object(
            winjob._k32, "CreateProcessW", side_effect=create_then_interrupt
        ):
            with self.assertRaises(RuntimeError):
                self.launch(before_resume=callback)

        callback.assert_not_called()
        self.assertEqual(len(created_pids), 1)
        self.assertTrue(wait_until(lambda: not pid_alive(created_pids[0])))
        self.assertFalse(os.path.exists(self.marker))

    def test_resume_syscall_exception_uses_resumed_tree_cleanup(self):
        real_resume = winjob._k32.ResumeThread
        callback = mock.Mock(return_value=None)
        suspended_cleanup = mock.Mock(
            side_effect=AssertionError("resume syscall used suspended cleanup")
        )

        def resume_then_interrupt(thread):
            previous_count = real_resume(thread)
            self.assertEqual(previous_count, 1)
            raise RuntimeError("after ResumeThread")

        with mock.patch.object(
            winjob._k32, "ResumeThread", side_effect=resume_then_interrupt
        ), mock.patch.object(
            winjob, "_verify_suspended_job_empty", suspended_cleanup
        ):
            with self.assertRaises(RuntimeError):
                self.launch(before_resume=callback)

        callback.assert_called_once()
        suspended_cleanup.assert_not_called()
        _process, _thread, pid = self.created[0]
        self.assertTrue(wait_until(lambda: not pid_alive(pid)))
        if os.path.isfile(self.marker):
            with open(self.marker, encoding="utf-8") as handle:
                observed = [int(value) for value in handle.read().split()]
            self.assertTrue(all(not pid_alive(value) for value in observed))

    def test_exception_after_candidate_adoption_keeps_same_owner(self):
        real_adopt = winjob._LaunchCleanupToken._adopt

        def adopt_then_interrupt(owner, candidate):
            real_adopt(owner, candidate)
            raise RuntimeError("after adoption")

        with mock.patch.object(
            winjob._LaunchCleanupToken, "_adopt", new=adopt_then_interrupt
        ):
            with self.assertRaises(RuntimeError):
                self.launch()

        process, _thread, pid = self.created[0]
        self.assertTrue(wait_until(lambda: not pid_alive(pid)))
        self.assertEqual(self.closed.count(process), 1)
        if os.path.isfile(self.marker):
            with open(self.marker, encoding="utf-8") as handle:
                observed = [int(value) for value in handle.read().split()]
            self.assertTrue(all(not pid_alive(value) for value in observed))

    def test_cleanup_exception_becomes_retryable_typed_error(self):
        real_cleanup = winjob._LaunchCleanupToken._cleanup
        cleanup_calls = 0

        def interrupt_first_cleanup(owner, *args, **kwargs):
            nonlocal cleanup_calls
            cleanup_calls += 1
            if cleanup_calls == 1:
                raise RuntimeError("cleanup interrupted")
            return real_cleanup(owner, *args, **kwargs)

        constructor_error = RuntimeError("candidate injected")
        with mock.patch.object(
            winjob, "ContainedProcess", side_effect=constructor_error
        ), mock.patch.object(
            winjob._LaunchCleanupToken,
            "_cleanup",
            new=interrupt_first_cleanup,
        ):
            with self.assertRaises(winjob.CleanupRequiredError) as caught:
                self.launch()
            error = caught.exception
            self.assertIs(error.__cause__, constructor_error)
            self.assertTrue(error.cleanup_pending)
            error.retry_cleanup()
            self.assertFalse(error.cleanup_pending)
            error.retry_cleanup()

        _process, _thread, pid = self.created[0]
        self.assertTrue(wait_until(lambda: not pid_alive(pid)))

    def test_retry_cleanup_exception_preserves_token_and_original(self):
        checked_close = winjob._close_handle
        failed = False

        def fail_thread_once(handle, *, on_closed=None):
            nonlocal failed
            thread = self.created[0][1] if self.created else None
            if handle == thread and not failed:
                failed = True
                raise ContainmentError("handle-close-failed", "thread injected")
            return checked_close(handle, on_closed=on_closed)

        with mock.patch.object(
            winjob, "_close_handle", side_effect=fail_thread_once
        ):
            with self.assertRaises(winjob.CleanupRequiredError) as caught:
                self.launch()
            error = caught.exception
            original = error.__cause__

            def interrupt_retry(_owner):
                raise RuntimeError("retry interrupted")

            with mock.patch.object(
                winjob._LaunchCleanupToken,
                "_retry_cleanup",
                new=interrupt_retry,
            ):
                with self.assertRaises(winjob.CleanupRequiredError) as retry_caught:
                    error.retry_cleanup()
            self.assertIs(retry_caught.exception, error)
            self.assertIs(error.__cause__, original)
            self.assertTrue(error.cleanup_pending)

            error.retry_cleanup()
            self.assertFalse(error.cleanup_pending)

    def test_callback_exception_destroys_suspended_job_without_running(self):
        assigned: list[winjob.AssignedProcess] = []

        def fail(evidence):
            assigned.append(evidence)
            self.assertFalse(os.path.exists(self.marker))
            raise RuntimeError("injected")

        self.assert_failed_closed(
            "before-resume-callback-failed", before_resume=fail
        )
        self.assertEqual(len(assigned), 1)
        self.assertFalse(pid_alive(assigned[0].pid))

    def test_callback_non_none_return_destroys_suspended_job(self):
        callback = mock.Mock(return_value=False)

        self.assert_failed_closed(
            "before-resume-return-invalid", before_resume=callback
        )
        callback.assert_called_once()

    def test_cleanup_failure_is_surfaced_and_forbids_retry(self):
        # The termination syscall succeeds but its wrapper reports a fault.
        # Quiescence and every close still complete, yet the cleanup fault must
        # be surfaced rather than replaced by the original resume error.
        real_terminate_job = winjob._terminate_job

        def terminate_then_report_failure(job):
            real_terminate_job(job)
            raise ContainmentError("terminate-job-failed", "injected")

        with mock.patch.object(
            winjob,
            "_resume_thread",
            side_effect=ContainmentError("resume-failed", "mocked"),
        ), mock.patch.object(
            winjob, "_terminate_job", side_effect=terminate_then_report_failure
        ):
            with self.assertRaises(ContainmentError) as caught:
                self.launch()
        self.assertEqual(caught.exception.code, "cleanup-failed")

        self.assertEqual(len(self.created), 1, "expected exactly one child")
        _process, _thread, pid = self.created[0]
        self.assertTrue(
            wait_until(lambda: not pid_alive(pid)),
            "suspended process leaked after cleanup-failed",
        )
        self.assertFalse(
            os.path.exists(self.marker), "child ran despite failed launch"
        )

    def test_binding_close_ambiguity_kills_suspended_child_before_resume(self):
        # Even after CreateProcessW succeeds, path-pinning handles are still a
        # pre-resume obligation.  A reported close failure must tear down the
        # suspended process; it may never be resumed under ambiguous ownership.
        real_close = winjob._close_binding_handle
        faulted = False

        def close_then_report_failure(handle):
            nonlocal faulted
            real_close(handle)  # do not leak a real handle in the test
            if not faulted:
                faulted = True
                raise ContainmentError("binding-handle-close-failed", "injected")

        with mock.patch.object(
            winjob, "_close_binding_handle", side_effect=close_then_report_failure
        ):
            with self.assertRaises(ContainmentError) as caught:
                self.launch()
        self.assertEqual(caught.exception.code, "cleanup-failed")
        self.assertEqual(len(self.created), 1, "expected one suspended child")
        _process, _thread, pid = self.created[0]
        self.assertTrue(wait_until(lambda: not pid_alive(pid)))
        self.assertFalse(os.path.exists(self.marker), "ambiguous child was resumed")

    def test_cwd_replacement_after_precheck_kills_suspended_child(self):
        # Regression for the final-check -> CreateProcessW race.  Contrary to
        # the old assumption, current Windows permits this ordinary directory
        # rename while our non-delete-sharing binding handle is still open.
        # CreateProcessW therefore reaches the replacement path.  The required
        # post-create verification must catch the original binding's changed
        # final path while the child is still suspended, then destroy it before
        # ResumeThread.
        cwd = os.path.join(self.root, "postcheck-cwd")
        moved = os.path.join(self.root, "postcheck-cwd-original")
        os.mkdir(cwd)
        replaced = False
        real_create = winjob._create_suspended_process
        real_binding_close = winjob._close_binding_handle
        binding_closes: list[int] = []

        def replace_then_create(*args, **kwargs):
            nonlocal replaced
            os.rename(cwd, moved)
            os.mkdir(cwd)
            replaced = True
            return real_create(*args, **kwargs)

        def spy_binding_close(handle):
            binding_closes.append(handle)
            return real_binding_close(handle)

        assign = mock.Mock(side_effect=AssertionError("late Job assignment reached"))
        resume = mock.Mock(side_effect=AssertionError("ResumeThread reached"))
        callback = mock.Mock(return_value=None)
        expected_bindings = len(
            winjob._launch_path_specs(
                winjob._validate_executable(sys.executable),
                winjob._validate_cwd(cwd, self.root),
                self.root,
            )
        )

        with mock.patch.object(
            winjob, "_create_suspended_process", side_effect=replace_then_create
        ), mock.patch.object(
            winjob, "_close_binding_handle", side_effect=spy_binding_close
        ), mock.patch.object(
            winjob._k32, "AssignProcessToJobObject", assign
        ), mock.patch.object(
            winjob, "_resume_thread", resume
        ):
            self.assert_failed_closed(
                "path-binding-changed", cwd=cwd, before_resume=callback
            )

        self.assertTrue(replaced, "deterministic post-precheck race did not run")
        assign.assert_not_called()
        resume.assert_not_called()
        callback.assert_not_called()
        self.assertEqual(
            len(binding_closes), expected_bindings, "a launch binding leaked"
        )
        # Deleting both identities proves the original and replacement cwd are
        # no longer retained by either a binding or the destroyed child.
        os.rmdir(moved)
        os.rmdir(cwd)

    def test_job_limit_verification_failure_closes_job_and_spawns_nothing(self):
        # A Job whose limits read back with breakaway present is unusable.
        breakaway = (
            winjob.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | winjob.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
        )
        with mock.patch.object(winjob, "_job_limit_flags", return_value=breakaway):
            with self.assertRaises(ContainmentError) as caught:
                self.launch()

        self.assertEqual(caught.exception.code, "job-limit-unverified")
        self.assertEqual(self.created, [], "child created despite unusable job")
        self.assertEqual(len(self.closed), 1, "job handle leaked")


class ValidationTests(WinJobTestCase):
    """Nothing is launched until the paths and flags are proved safe."""

    def assert_rejected(self, code: str, **overrides) -> None:
        with mock.patch.object(
            winjob, "_create_suspended_process", side_effect=AssertionError("launched")
        ):
            with self.assertRaises(ContainmentError) as caught:
                self.launch(**overrides)
        self.assertEqual(caught.exception.code, code)

    def test_rejects_relative_executable(self):
        self.assert_rejected("executable-not-absolute", argv=["python.exe"])

    def test_rejects_missing_executable(self):
        self.assert_rejected(
            "executable-missing", argv=[os.path.join(self.root, "nope.exe")]
        )

    def test_rejects_directory_as_executable(self):
        self.assert_rejected("executable-not-file", argv=[self.root])

    def test_rejects_terminal_broker(self):
        self.assert_rejected(
            "executable-broker-denied", argv=[r"C:\Windows\System32\wt.exe"]
        )

    def test_rejects_empty_argv(self):
        self.assert_rejected("argv-invalid", argv=[])

    def test_rejects_relative_cwd(self):
        self.assert_rejected("cwd-not-absolute", cwd="subdir")

    def test_rejects_missing_cwd(self):
        self.assert_rejected("cwd-missing", cwd=os.path.join(self.root, "nope"))

    def test_rejects_file_as_cwd(self):
        self.assert_rejected("cwd-not-directory", cwd=self.child_script)

    def test_rejects_cwd_outside_allowed_root(self):
        with tempfile.TemporaryDirectory() as outside:
            self.assert_rejected(
                "cwd-outside-allowed-root", cwd=os.path.realpath(outside)
            )

    def test_rejects_relative_allowed_root(self):
        self.assert_rejected("allowed-root-not-absolute", allowed_root="rel")

    def test_rejects_missing_allowed_root(self):
        self.assert_rejected(
            "allowed-root-missing", allowed_root=os.path.join(self.root, "nope")
        )

    def make_junction(self, link: str, target: str) -> None:
        # Junctions, unlike symlinks, need no privilege -- so this is the escape
        # an unprivileged agent could actually build. mklink is only ever used
        # here in the test; the module itself never invokes a shell.
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", link, target],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.skipTest(f"junction creation failed: {result.stdout}{result.stderr}")

    def test_rejects_junction_escaping_allowed_root(self):
        with tempfile.TemporaryDirectory() as outside:
            escape = os.path.join(self.root, "escape")
            self.make_junction(escape, os.path.realpath(outside))
            self.assert_rejected("cwd-outside-allowed-root", cwd=escape)

    def test_rejects_allowed_root_that_is_itself_a_junction(self):
        target = os.path.join(self.root, "root-target")
        link = os.path.join(self.root, "root-junction")
        os.mkdir(target)
        self.make_junction(link, target)

        self.assert_rejected(
            "allowed-root-reparse-point", allowed_root=link, cwd=link
        )

    def test_rejects_allowed_root_below_a_junction_ancestor(self):
        target = os.path.join(self.root, "ancestor-target")
        child = os.path.join(target, "child")
        link = os.path.join(self.root, "ancestor-junction")
        os.makedirs(child)
        self.make_junction(link, target)
        through_link = os.path.join(link, "child")

        self.assert_rejected(
            "allowed-root-reparse-point",
            allowed_root=through_link,
            cwd=through_link,
        )

    def test_reparse_walk_checks_component_erased_by_dotdot(self):
        alias = os.path.join(self.root, "alias")
        raw_path = os.path.join(alias, os.pardir, "child")
        probed: list[str] = []

        def probe(path: str) -> bool:
            probed.append(path)
            return os.path.normcase(path) == os.path.normcase(alias)

        with mock.patch.object(winjob, "_is_reparse_point", side_effect=probe):
            with self.assertRaises(ContainmentError) as caught:
                winjob._reject_reparse_in_chain(raw_path, "test-reparse")
        self.assertEqual(caught.exception.code, "test-reparse")
        self.assertIn(alias, probed)

    def test_rejects_junction_inside_allowed_root(self):
        inside = os.path.join(self.root, "real")
        link = os.path.join(self.root, "junction")
        os.mkdir(inside)
        self.make_junction(link, inside)
        # Resolves back inside the root, but its target can be re-pointed after
        # the check, so it is refused anyway.
        self.assert_rejected("cwd-reparse-point", cwd=link)

    def test_rejects_symlink_escaping_allowed_root(self):
        with tempfile.TemporaryDirectory() as outside:
            escape = os.path.join(self.root, "escape")
            try:
                os.symlink(os.path.realpath(outside), escape, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation not permitted: {exc}")
            # Resolves outside the root, so containment -- not the reparse check
            # -- is what rejects it.
            self.assert_rejected("cwd-outside-allowed-root", cwd=escape)

    def test_rejects_reparse_point_inside_allowed_root(self):
        inside = os.path.join(self.root, "real")
        link = os.path.join(self.root, "link")
        os.mkdir(inside)
        try:
            os.symlink(inside, link, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation not permitted: {exc}")
        # Points back inside the root, but its target can be re-pointed after
        # the check, so it is refused anyway.
        self.assert_rejected("cwd-reparse-point", cwd=link)

    def test_executable_ordinary_replacement_during_binding_is_rejected(self):
        image_dir = os.path.join(self.root, "ordinary-image")
        os.mkdir(image_dir)
        image = os.path.join(image_dir, "worker.exe")
        replacement = os.path.join(image_dir, "replacement.exe")
        shutil.copy2(sys.executable, image)
        shutil.copy2(sys.executable, replacement)
        replaced = False

        def race(path: str, _label: str) -> None:
            nonlocal replaced
            if not replaced and os.path.normcase(path) == os.path.normcase(image):
                os.replace(replacement, image)
                replaced = True

        create = mock.Mock(side_effect=AssertionError("CreateProcessW reached"))
        with mock.patch.object(winjob, "_before_bind_path", side_effect=race), \
             mock.patch.object(winjob, "_create_suspended_process", create):
            with self.assertRaises(ContainmentError) as caught:
                self.launch(argv=[image])

        self.assertTrue(replaced, "the deterministic replacement hook did not run")
        self.assertEqual(caught.exception.code, "path-binding-identity-mismatch")
        create.assert_not_called()

    def test_cwd_ordinary_replacement_during_binding_is_rejected(self):
        cwd = os.path.join(self.root, "ordinary-cwd")
        original = os.path.join(self.root, "ordinary-cwd-original")
        os.mkdir(cwd)
        replaced = False

        def race(path: str, _label: str) -> None:
            nonlocal replaced
            if not replaced and os.path.normcase(path) == os.path.normcase(cwd):
                os.rename(cwd, original)
                os.mkdir(cwd)
                replaced = True

        create = mock.Mock(side_effect=AssertionError("CreateProcessW reached"))
        with mock.patch.object(winjob, "_before_bind_path", side_effect=race), \
             mock.patch.object(winjob, "_create_suspended_process", create):
            with self.assertRaises(ContainmentError) as caught:
                self.launch(cwd=cwd)

        self.assertTrue(replaced, "the deterministic replacement hook did not run")
        self.assertEqual(caught.exception.code, "path-binding-identity-mismatch")
        create.assert_not_called()
        self.assertTrue(os.path.isdir(original), "original cwd identity was lost")

    def test_cwd_ancestor_rename_to_junction_is_blocked_at_precreate_hook(self):
        ancestor = os.path.join(self.root, "cwd-ancestor")
        cwd = os.path.join(ancestor, "leaf")
        moved = os.path.join(self.root, "cwd-ancestor-moved")
        os.makedirs(cwd)
        with tempfile.TemporaryDirectory() as outside:
            def race() -> None:
                try:
                    os.rename(ancestor, moved)
                except OSError as exc:
                    raise ContainmentError("test-race-blocked", str(exc)) from exc
                self.make_junction(ancestor, os.path.realpath(outside))

            create = mock.Mock(side_effect=AssertionError("CreateProcessW reached"))
            with mock.patch.object(winjob, "_before_create_process", side_effect=race), \
                 mock.patch.object(winjob, "_create_suspended_process", create):
                with self.assertRaises(ContainmentError) as caught:
                    self.launch(cwd=cwd)

        self.assertEqual(caught.exception.code, "test-race-blocked")
        create.assert_not_called()
        self.assertTrue(os.path.isdir(cwd), "cwd ancestor was replaced")
        self.assertFalse(os.path.exists(moved), "cwd ancestor rename succeeded")

    def test_executable_ancestor_rename_to_junction_is_blocked_at_precreate_hook(self):
        ancestor = os.path.join(self.root, "image-ancestor")
        image_dir = os.path.join(ancestor, "bin")
        moved = os.path.join(self.root, "image-ancestor-moved")
        os.makedirs(image_dir)
        image = os.path.join(image_dir, "worker.exe")
        shutil.copy2(sys.executable, image)

        with tempfile.TemporaryDirectory() as outside:
            outside_bin = os.path.join(outside, "bin")
            os.makedirs(outside_bin)
            shutil.copy2(sys.executable, os.path.join(outside_bin, "worker.exe"))

            def race() -> None:
                try:
                    os.rename(ancestor, moved)
                except OSError as exc:
                    raise ContainmentError("test-race-blocked", str(exc)) from exc
                self.make_junction(ancestor, os.path.realpath(outside))

            create = mock.Mock(side_effect=AssertionError("CreateProcessW reached"))
            with mock.patch.object(winjob, "_before_create_process", side_effect=race), \
                 mock.patch.object(winjob, "_create_suspended_process", create):
                with self.assertRaises(ContainmentError) as caught:
                    self.launch(argv=[image])

        self.assertEqual(caught.exception.code, "test-race-blocked")
        create.assert_not_called()
        self.assertTrue(os.path.isfile(image), "executable ancestor was replaced")
        self.assertFalse(os.path.exists(moved), "executable ancestor rename succeeded")

    def test_rejects_breakaway_creation_flags(self):
        self.assert_rejected(
            "creation-flags-breakaway",
            creation_flags=winjob.CREATE_BREAKAWAY_FROM_JOB,
        )

    def test_rejects_breakaway_flag_combined_with_others(self):
        self.assert_rejected(
            "creation-flags-breakaway",
            creation_flags=winjob.CREATE_NO_WINDOW | winjob.CREATE_BREAKAWAY_FROM_JOB,
        )

    def test_rejects_non_allowlisted_creation_flags(self):
        # CREATE_NEW_CONSOLE (0x10) is neither breakaway nor on the allowlist:
        # only explicitly-permitted flags may reach CreateProcessW.
        self.assert_rejected(
            "creation-flags-not-allowlisted",
            creation_flags=winjob.CREATE_NO_WINDOW | 0x00000010,
        )


@unittest.skipUnless(WINDOWS, "Job Objects are Windows-only")
class AtomicJobListAbiTests(FatalOwnerTestCase):
    """Deterministic checks of the STARTUPINFOEX/JOB_LIST ABI and cleanup."""

    def attribute_api(self, events, *, update_ok=True, delete_raises=False):
        def initialize(pointer, count, flags, size_pointer):
            self.assertEqual(count, 1)
            self.assertEqual(flags, 0)
            size = ctypes.cast(
                size_pointer, ctypes.POINTER(ctypes.c_size_t)
            )
            if not pointer:
                events.append("probe")
                size[0] = 256
                ctypes.set_last_error(winjob._ERROR_INSUFFICIENT_BUFFER)
                return 0
            events.append("initialize")
            self.assertEqual(size[0], 256)
            return 1

        def update(pointer, flags, attribute, value, value_size, previous, returned):
            events.append("update")
            self.assertTrue(pointer)
            self.assertEqual(flags, 0)
            self.assertEqual(attribute, winjob.PROC_THREAD_ATTRIBUTE_JOB_LIST)
            self.assertEqual(value_size, ctypes.sizeof(wintypes.HANDLE))
            self.assertEqual(
                int(ctypes.cast(value, ctypes.POINTER(wintypes.HANDLE))[0]),
                0xCAFE,
            )
            self.assertIsNone(previous)
            self.assertIsNone(returned)
            if not update_ok:
                ctypes.set_last_error(winjob._ERROR_ACCESS_DENIED)
                return 0
            return 1

        def delete(pointer):
            events.append("delete")
            self.assertTrue(pointer)
            if delete_raises:
                raise RuntimeError("injected delete fault")

        return initialize, update, delete

    def fake_create(self, events, *, ok=True):
        def create(
            executable,
            command_line,
            process_attrs,
            thread_attrs,
            inherit,
            flags,
            environment,
            cwd,
            startup_pointer,
            process_info_pointer,
        ):
            events.append("create")
            self.assertEqual(executable, r"C:\worker.exe")
            self.assertFalse(inherit)
            self.assertIsNone(process_attrs)
            self.assertIsNone(thread_attrs)
            self.assertIsNone(environment)
            self.assertTrue(flags & winjob.CREATE_SUSPENDED)
            self.assertTrue(flags & winjob.EXTENDED_STARTUPINFO_PRESENT)
            startup = ctypes.cast(
                startup_pointer, ctypes.POINTER(winjob._STARTUPINFOEXW)
            ).contents
            self.assertEqual(
                startup.StartupInfo.cb, ctypes.sizeof(winjob._STARTUPINFOEXW)
            )
            self.assertTrue(startup.lpAttributeList)
            if not ok:
                ctypes.set_last_error(winjob._ERROR_ACCESS_DENIED)
                return 0
            pi = ctypes.cast(
                process_info_pointer, ctypes.POINTER(winjob._PROCESS_INFORMATION)
            ).contents
            pi.hProcess = 0x111
            pi.hThread = 0x222
            pi.dwProcessId = 333
            return 1

        return create

    def patches(self, events, *, update_ok=True, delete_raises=False, create_ok=True):
        initialize, update, delete = self.attribute_api(
            events, update_ok=update_ok, delete_raises=delete_raises
        )
        return (
            mock.patch.object(winjob, "_init_proc_thread_attributes", initialize),
            mock.patch.object(winjob, "_update_proc_thread_attribute", update),
            mock.patch.object(winjob, "_delete_proc_thread_attributes", delete),
            mock.patch.object(
                winjob._k32, "CreateProcessW", self.fake_create(events, ok=create_ok)
            ),
        )

    def test_job_list_is_built_before_create_and_deleted_afterward(self):
        events: list[str] = []
        patches = self.patches(events)
        with patches[0], patches[1], patches[2], patches[3]:
            result = winjob._create_suspended_process(
                0xCAFE,
                r"C:\worker.exe",
                r'"C:\worker.exe" --probe',
                "C:\\",
                winjob.CREATE_NO_WINDOW,
            )
        self.assertEqual(result, (0x111, 0x222, 333))
        self.assertEqual(events, ["probe", "initialize", "update", "create", "delete"])

    def test_update_failure_deletes_list_and_never_creates_child(self):
        events: list[str] = []
        patches = self.patches(events, update_ok=False)
        with patches[0], patches[1], patches[2], patches[3]:
            with self.assertRaises(ContainmentError) as caught:
                winjob._create_suspended_process(
                    0xCAFE, r"C:\worker.exe", "worker", "C:\\", 0
                )
        self.assertEqual(caught.exception.code, "job-attribute-update-failed")
        self.assertEqual(events, ["probe", "initialize", "update", "delete"])

    def test_create_failure_still_deletes_attribute_list(self):
        events: list[str] = []
        patches = self.patches(events, create_ok=False)
        with patches[0], patches[1], patches[2], patches[3]:
            with self.assertRaises(ContainmentError) as caught:
                winjob._create_suspended_process(
                    0xCAFE, r"C:\worker.exe", "worker", "C:\\", 0
                )
        self.assertEqual(caught.exception.code, "process-create-failed")
        self.assertEqual(events, ["probe", "initialize", "update", "create", "delete"])

    def test_delete_exception_after_create_destroys_child_without_closing_outer_job(self):
        events: list[str] = []
        patches = self.patches(events, delete_raises=True)
        cleanup = mock.Mock()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            winjob, "_cleanup_suspended", cleanup
        ):
            with self.assertRaises(ContainmentError) as caught:
                winjob._create_suspended_process(
                    0xCAFE, r"C:\worker.exe", "worker", "C:\\", 0
                )
        self.assertEqual(caught.exception.code, "cleanup-failed")
        cleanup.assert_called_once_with(
            0xCAFE, 0x111, 0x222, close_job=False
        )
        self.assertEqual(events, ["probe", "initialize", "update", "create", "delete"])

    def test_missing_attribute_api_fails_closed_without_fallback(self):
        create = mock.Mock(side_effect=AssertionError("CreateProcessW reached"))
        assign = mock.Mock(side_effect=AssertionError("late assignment reached"))
        with mock.patch.object(winjob, "_init_proc_thread_attributes", None), \
             mock.patch.object(winjob._k32, "CreateProcessW", create), \
             mock.patch.object(winjob._k32, "AssignProcessToJobObject", assign):
            with self.assertRaises(ContainmentError) as caught:
                winjob._create_suspended_process(
                    0xCAFE, r"C:\worker.exe", "worker", "C:\\", 0
                )
        self.assertEqual(caught.exception.code, "job-list-unsupported")
        create.assert_not_called()
        assign.assert_not_called()


@unittest.skipUnless(WINDOWS, "Job Objects are Windows-only")
class FaultInjectionTests(FatalOwnerTestCase):
    """Win32-boundary fault injection: bounded, no real children, no network.

    Drives the fail-closed branches that a real process cannot provoke on
    demand -- an ambiguous wait, an access-denied probe, a CloseHandle that
    lies, a late spawn -- by patching the thin kernel32 wrappers or the
    module-level syscall shims.
    """

    # -- finding 2: only WAIT_OBJECT_0/WAIT_TIMEOUT are trusted -------------

    def test_resume_requires_exact_fresh_suspend_count(self):
        with mock.patch.object(winjob._k32, "ResumeThread", return_value=1):
            winjob._resume_thread(0x1234)

        for result in (0, 2, 17):
            with self.subTest(previous_suspend_count=result), mock.patch.object(
                winjob._k32, "ResumeThread", return_value=result
            ):
                with self.assertRaises(ContainmentError) as caught:
                    winjob._resume_thread(0x1234)
                self.assertEqual(caught.exception.code, "resume-count-unexpected")

        with mock.patch.object(
            winjob._k32, "ResumeThread", return_value=0xFFFFFFFF
        ):
            with self.assertRaises(ContainmentError) as caught:
                winjob._resume_thread(0x1234)
        self.assertEqual(caught.exception.code, "resume-failed")

    def test_wait_failed_raises_and_is_never_read_as_dead(self):
        with mock.patch.object(
            winjob._k32, "WaitForSingleObject", return_value=winjob._WAIT_FAILED
        ):
            with self.assertRaises(ContainmentError) as caught:
                winjob._process_alive(0x1234)
        self.assertEqual(caught.exception.code, "wait-failed")

    def test_wait_abandoned_raises(self):
        with mock.patch.object(
            winjob._k32, "WaitForSingleObject", return_value=winjob._WAIT_ABANDONED_0
        ):
            with self.assertRaises(ContainmentError) as caught:
                winjob._process_exited(0x1234)
        self.assertEqual(caught.exception.code, "wait-failed")

    def test_wait_primary_timeout_does_not_read_an_exit_code(self):
        proc = winjob.ContainedProcess(job=0xAA, process=0xBB, pid=100)
        read_code = mock.Mock(side_effect=AssertionError("exit code read on timeout"))
        try:
            with mock.patch.object(
                winjob, "_wait_result", return_value=winjob._WAIT_TIMEOUT
            ), mock.patch.object(winjob, "_get_exit_code", read_code):
                self.assertIsNone(proc.wait_primary_exit(timeout=0.001))
            read_code.assert_not_called()
        finally:
            proc._process = proc._job = None

    def test_wait_primary_exit_code_failure_has_stable_error(self):
        proc = winjob.ContainedProcess(job=0xAA, process=0xBB, pid=100)

        def fail_get_exit_code(_process, _code_pointer):
            ctypes.set_last_error(winjob._ERROR_ACCESS_DENIED)
            return 0

        try:
            with mock.patch.object(
                winjob, "_wait_result", return_value=winjob._WAIT_OBJECT_0
            ), mock.patch.object(
                winjob._k32, "GetExitCodeProcess", side_effect=fail_get_exit_code
            ):
                with self.assertRaises(ContainmentError) as caught:
                    proc.wait_primary_exit(timeout=1.0)
            self.assertEqual(caught.exception.code, "exit-code-failed")
        finally:
            proc._process = proc._job = None

    def test_wait_primary_rejects_invalid_timeout_before_waiting(self):
        proc = winjob.ContainedProcess(job=0xAA, process=0xBB, pid=100)
        wait = mock.Mock(side_effect=AssertionError("wait reached"))
        try:
            with mock.patch.object(winjob, "_wait_result", wait):
                for bad in (
                    -1,
                    True,
                    "1",
                    float("nan"),
                    float("inf"),
                    winjob._MAX_TERMINATE_TIMEOUT + 1,
                    10**400,
                ):
                    with self.subTest(timeout=bad):
                        with self.assertRaises(ContainmentError) as caught:
                            proc.wait_primary_exit(timeout=bad)
                        self.assertEqual(caught.exception.code, "timeout-invalid")
            wait.assert_not_called()
        finally:
            proc._process = proc._job = None

    def test_open_sync_handle_invalid_parameter_is_gone(self):
        def fake_open(_access, _inherit, _pid):
            ctypes.set_last_error(winjob._ERROR_INVALID_PARAMETER)
            return 0

        with mock.patch.object(winjob._k32, "OpenProcess", side_effect=fake_open):
            self.assertIsNone(winjob._open_sync_handle(4321))

    def test_open_sync_handle_access_denied_is_unknown_not_dead(self):
        def fake_open(_access, _inherit, _pid):
            ctypes.set_last_error(winjob._ERROR_ACCESS_DENIED)
            return 0

        with mock.patch.object(winjob._k32, "OpenProcess", side_effect=fake_open):
            with self.assertRaises(ContainmentError) as caught:
                winjob._open_sync_handle(4321)
        self.assertEqual(caught.exception.code, "pid-probe-unknown")

    def test_open_sync_handle_return_exception_leaves_probe_owner_recorded(self):
        retained: dict[int, int] = {}
        return_events: list[int] = []

        def interrupt_on_return(frame, event, value):
            if (
                frame.f_code is winjob._open_sync_handle.__code__
                and event == "return"
            ):
                return_events.append(int(value))
                raise RuntimeError("open return interrupted")
            return interrupt_on_return

        with mock.patch.object(winjob._k32, "OpenProcess", return_value=0xDD):
            sys.settrace(interrupt_on_return)
            try:
                with self.assertRaisesRegex(RuntimeError, "open return"):
                    winjob._open_sync_handle(4321, retained)
            finally:
                sys.settrace(None)

        self.assertEqual(return_events, [0xDD])
        self.assertEqual(retained, {4321: 0xDD})

    # -- findings 3 & 4: checked terminate/close ---------------------------

    def test_terminate_process_false_raises(self):
        with mock.patch.object(winjob._k32, "TerminateProcess", return_value=0):
            with self.assertRaises(ContainmentError) as caught:
                winjob._terminate_process(0x1234)
        self.assertEqual(caught.exception.code, "terminate-process-failed")

    def test_close_handle_false_raises(self):
        with mock.patch.object(winjob._k32, "CloseHandle", return_value=0):
            with self.assertRaises(ContainmentError) as caught:
                winjob._close_handle(0x1234)
        self.assertEqual(caught.exception.code, "handle-close-failed")

    def test_close_return_exception_clears_owner_before_retry(self):
        proc = winjob.ContainedProcess(job=0xAA, process=0xBB, pid=100)
        close_calls: list[int] = []
        return_events = 0

        def fake_close(handle):
            close_calls.append(int(handle))
            return 1

        def interrupt_on_return(frame, event, _value):
            nonlocal return_events
            if frame.f_code is winjob._close_handle.__code__ and event == "return":
                return_events += 1
                raise RuntimeError("close return interrupted")
            return interrupt_on_return

        with mock.patch.object(winjob._k32, "CloseHandle", side_effect=fake_close):
            sys.settrace(interrupt_on_return)
            try:
                with self.assertRaisesRegex(RuntimeError, "close return"):
                    proc.close()
            finally:
                sys.settrace(None)

            self.assertEqual(return_events, 1)
            self.assertIsNone(proc.process_handle)
            self.assertEqual(proc.job_handle, 0xAA)
            proc.close()

        self.assertTrue(proc.closed)
        self.assertEqual(close_calls, [0xBB, 0xAA])
        self.assertEqual(close_calls.count(0xBB), 1, "process handle double-closed")

    def test_close_retains_ownership_when_closehandle_fails(self):
        # A failed CloseHandle must leave the handle owned (unresolved) and raise,
        # not silently drop the reference.
        proc = winjob.ContainedProcess(job=0xAA, process=0xBB, pid=100)
        with mock.patch.object(winjob._k32, "CloseHandle", return_value=0):
            with self.assertRaises(ContainmentError) as caught:
                proc.close()
        self.assertEqual(caught.exception.code, "handle-close-failed")
        self.assertEqual(proc.process_handle, 0xBB, "process ownership was dropped")
        self.assertFalse(proc.closed, "job ownership was dropped before close proven")
        proc._process = proc._job = None  # neutralize the fake handles

    # -- finding 6: _create_job closes the Job on flag-setup failure -------

    def test_create_job_closes_job_when_flag_setup_fails(self):
        closed: list[int] = []

        def fake_close(handle):
            closed.append(int(handle))
            return 1

        with mock.patch.object(
            winjob._k32, "CreateJobObjectW", return_value=0x999
        ), mock.patch.object(
            winjob._k32, "SetHandleInformation", return_value=0
        ), mock.patch.object(
            winjob._k32, "CloseHandle", side_effect=fake_close
        ):
            with self.assertRaises(ContainmentError) as caught:
                winjob._create_job()
        self.assertEqual(caught.exception.code, "handle-flags-failed")
        self.assertIn(0x999, closed, "job handle leaked when flag setup failed")

    def test_create_job_surfaces_cleanup_ambiguity_when_close_also_fails(self):
        close_calls = 0

        def fail_close_once(_handle):
            nonlocal close_calls
            close_calls += 1
            return int(close_calls > 1)

        with mock.patch.object(
            winjob._k32, "CreateJobObjectW", return_value=0x999
        ), mock.patch.object(
            winjob._k32, "SetHandleInformation", return_value=0
        ), mock.patch.object(
            winjob._k32, "CloseHandle", side_effect=fail_close_once
        ):
            with self.assertRaises(winjob.CleanupRequiredError) as caught:
                winjob._create_job()
            error = caught.exception
            self.assertEqual(error.code, "cleanup-failed")
            self.assertIn("job-handle-unresolved", error.detail)
            self.assertTrue(error.cleanup_pending)
            error.retry_cleanup()
            self.assertFalse(error.cleanup_pending)
            error.retry_cleanup()
        self.assertEqual(close_calls, 2)

    def test_reparse_probe_oserror_fails_closed(self):
        with mock.patch.object(
            winjob.os, "lstat", side_effect=PermissionError("mocked denied")
        ):
            with self.assertRaises(ContainmentError) as caught:
                winjob._is_reparse_point(r"C:\\denied")
        self.assertEqual(caught.exception.code, "path-probe-failed")

    # -- finding 5: timeout validation and the drain loop ------------------

    def test_terminate_and_verify_rejects_nan_inf_bool_and_excessive(self):
        # job is non-None so we reach _validate_timeout; validation precedes any
        # syscall, so the fake handles are never touched.
        proc = winjob.ContainedProcess(job=1, process=2, pid=3)
        try:
            for bad in (
                float("nan"),
                float("inf"),
                float("-inf"),
                True,
                False,
                winjob._MAX_TERMINATE_TIMEOUT + 1.0,
                10**400,
            ):
                with self.subTest(timeout=bad):
                    with self.assertRaises(ContainmentError) as caught:
                        proc.terminate_and_verify(timeout=bad)
                    self.assertEqual(caught.exception.code, "timeout-invalid")
        finally:
            proc._process = proc._job = None

    def test_verify_true_when_tree_quiescent(self):
        proc = winjob.ContainedProcess(job=10, process=20, pid=100)
        with mock.patch.object(winjob, "_terminate_job", lambda job: None), \
             mock.patch.object(winjob, "_process_alive", lambda h: False), \
             mock.patch.object(winjob, "_job_process_ids", lambda job: []), \
             mock.patch.object(winjob, "_job_active_processes", lambda job: 0), \
             mock.patch.object(
                 winjob,
                 "_close_handle",
                 lambda _h, *, on_closed=None: on_closed and on_closed(),
             ):
            self.assertTrue(proc.terminate_and_verify(timeout=2.0))
        proc._process = proc._job = None

    def test_late_spawn_is_re_enumerated_and_blocks_false_clean(self):
        # The pre-kill snapshot is empty; a member appears only during the drain.
        # Re-enumeration must retain it, and because it never dies the verify must
        # block (return False), never falsely report a clean stop.
        proc = winjob.ContainedProcess(job=10, process=20, pid=100)
        opened: list[int] = []
        calls = {"pids": 0}

        def pids(_job):
            calls["pids"] += 1
            return [] if calls["pids"] == 1 else [999]  # spawns after the kill

        def opn(pid, retained=None):
            opened.append(pid)
            if retained is not None:
                retained[pid] = 0x555
            return 0x555  # a live member handle

        with mock.patch.object(winjob, "_terminate_job", lambda job: None), \
             mock.patch.object(winjob, "_process_alive", lambda h: False), \
             mock.patch.object(winjob, "_process_exited", lambda h: False), \
             mock.patch.object(winjob, "_job_process_ids", side_effect=pids), \
             mock.patch.object(winjob, "_job_active_processes", lambda job: 1), \
             mock.patch.object(winjob, "_open_sync_handle", side_effect=opn), \
             mock.patch.object(
                 winjob,
                 "_close_handle",
                 lambda _h, *, on_closed=None: on_closed and on_closed(),
             ):
            result = proc.terminate_and_verify(timeout=0.2)
        self.assertFalse(result, "late spawn was not caught -- false clean")
        self.assertIn(999, opened, "late spawn was never re-enumerated/retained")
        self.assertEqual(proc._retained, {999: 0x555})
        proc._retained.clear()  # neutralize the fake probe handle
        proc._process = proc._job = None


class PlatformGuardTests(unittest.TestCase):
    def test_fatal_owner_scope_preserves_ordinary_exception_semantics(self):
        fatal_exit = mock.Mock(side_effect=AssertionError("fatal exit reached"))
        with mock.patch.object(winjob, "_fatal_owner_exit", fatal_exit):
            with self.assertRaisesRegex(RuntimeError, "ordinary"):
                with winjob.fatal_owner_scope():
                    raise RuntimeError("ordinary")

        fatal_exit.assert_not_called()
        # The ordinary exception must also release the structural guard.
        with winjob.fatal_owner_scope():
            pass

    def test_launch_requires_explicit_fatal_owner_scope_before_validation(self):
        create_job = mock.Mock(side_effect=AssertionError("handle acquisition reached"))
        with mock.patch.object(winjob, "_create_job", create_job):
            with self.assertRaises(ContainmentError) as caught:
                launch_contained(
                    [],
                    allowed_root="ignored",
                    cwd="ignored",
                    before_resume=lambda evidence: None,
                )
        self.assertEqual(caught.exception.code, "fatal-owner-scope-required")
        create_job.assert_not_called()

    def test_contained_process_constructor_requires_scope_before_ownership(self):
        owner_type = mock.Mock(side_effect=AssertionError("owner allocation reached"))
        with mock.patch.object(winjob, "_LaunchCleanupToken", owner_type):
            with self.assertRaises(ContainmentError) as caught:
                winjob.ContainedProcess(job=1, process=2, pid=3)
        self.assertEqual(caught.exception.code, "fatal-owner-scope-required")
        owner_type.assert_not_called()

    @unittest.skipUnless(WINDOWS, "fake handle owner requires Windows structures")
    def test_every_public_handle_operation_requires_live_owner_scope(self):
        with winjob.fatal_owner_scope():
            proc = winjob.ContainedProcess(job=0xAA, process=0xBB, pid=100)

        operations = {
            "enter": lambda: proc.__enter__(),
            "exit": lambda: proc.__exit__(None, None, None),
            "closed": lambda: proc.closed,
            "job_handle": lambda: proc.job_handle,
            "process_handle": lambda: proc.process_handle,
            "limit_flags": lambda: proc.limit_flags(),
            "is_alive": lambda: proc.is_alive(),
            "primary_is_alive": lambda: proc.primary_is_alive,
            "wait_primary_exit": lambda: proc.wait_primary_exit(timeout=0),
            "active_processes": lambda: proc.active_processes(),
            "terminate_and_verify": lambda: proc.terminate_and_verify(timeout=1.0),
            "close": lambda: proc.close(),
        }
        kernel_touch = mock.Mock(side_effect=AssertionError("kernel access reached"))
        with mock.patch.object(winjob, "_job_limit_flags", kernel_touch), \
             mock.patch.object(winjob, "_job_active_processes", kernel_touch), \
             mock.patch.object(winjob, "_process_alive", kernel_touch), \
             mock.patch.object(winjob, "_wait_result", kernel_touch), \
             mock.patch.object(winjob, "_job_process_ids", kernel_touch), \
             mock.patch.object(winjob, "_close_handle", kernel_touch):
            for name, operation in operations.items():
                with self.subTest(operation=name):
                    with self.assertRaises(ContainmentError) as caught:
                        operation()
                    self.assertEqual(
                        caught.exception.code, "fatal-owner-scope-required"
                    )
        kernel_touch.assert_not_called()
        self.assertEqual(proc.pid, 100, "immutable pid needs no handle scope")

        # Neutralize the fake handles without exercising the public surface.
        proc._process = proc._job = None

    def test_cleanup_retry_surface_requires_scope_before_owner_access(self):
        cleanup_owner = mock.Mock()
        cleanup_owner._has_unresolved_ownership.side_effect = AssertionError(
            "owner state reached"
        )
        cleanup_owner._retry_cleanup.side_effect = AssertionError("retry reached")
        with self.assertRaises(ContainmentError) as caught:
            winjob.CleanupRequiredError(
                "injected", cleanup_owner, RuntimeError("original")
            )
        self.assertEqual(caught.exception.code, "fatal-owner-scope-required")

        with winjob.fatal_owner_scope():
            error = winjob.CleanupRequiredError(
                "injected", cleanup_owner, RuntimeError("original")
            )

        for name, operation in (
            ("cleanup_pending", lambda: error.cleanup_pending),
            ("retry_cleanup", error.retry_cleanup),
        ):
            with self.subTest(operation=name):
                with self.assertRaises(ContainmentError) as caught:
                    operation()
                self.assertEqual(caught.exception.code, "fatal-owner-scope-required")
        cleanup_owner._has_unresolved_ownership.assert_not_called()
        cleanup_owner._retry_cleanup.assert_not_called()

    def test_handle_diagnostic_requires_scope_before_platform_or_kernel(self):
        require_windows = mock.Mock(
            side_effect=AssertionError("platform/kernel access reached")
        )
        with mock.patch.object(winjob, "IS_WINDOWS", False), \
             mock.patch.object(winjob, "_require_windows", require_windows):
            with self.assertRaises(ContainmentError) as caught:
                winjob.handle_is_inheritable(0xAA)
        self.assertEqual(caught.exception.code, "fatal-owner-scope-required")
        require_windows.assert_not_called()

    @unittest.skipUnless(WINDOWS, "fake handle owner requires Windows structures")
    def test_nested_process_context_skips_close_for_baseexception(self):
        with winjob.fatal_owner_scope():
            proc = winjob.ContainedProcess(job=0xAA, process=0xBB, pid=100)
            with mock.patch.object(proc, "close") as close:
                self.assertIsNone(
                    proc.__exit__(KeyboardInterrupt, KeyboardInterrupt(), None)
                )
                close.assert_not_called()
                proc.__exit__(RuntimeError, RuntimeError("ordinary"), None)
                close.assert_called_once_with()
            proc._process = proc._job = None

    def test_non_windows_fails_at_call_time_not_import_time(self):
        with winjob.fatal_owner_scope():
            with mock.patch.object(winjob, "IS_WINDOWS", False):
                with self.assertRaises(ContainmentError) as caught:
                    launch_contained(
                        ["/bin/true"],
                        allowed_root="/tmp",
                        cwd="/tmp",
                        before_resume=lambda evidence: None,
                    )
        self.assertEqual(caught.exception.code, "unsupported-platform")


if __name__ == "__main__":
    unittest.main()
