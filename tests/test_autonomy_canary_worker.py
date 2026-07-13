from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from autonomy.canary_worker import (
    CONFIG_ERROR_EXIT,
    CRASH_EXIT,
    FAIL_EXIT,
    MAX_PAYLOAD_BYTES,
    RESULT_FILENAME,
    PathValidationError,
    PayloadError,
    load_payload,
)


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = (ROOT / "autonomy" / "canary_worker.py").resolve(strict=True)
NONCE = "0123456789abcdef0123456789abcdef"
TASK_ID = "canary-task"


class CanaryWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.queue_root = self.root / "queue"
        self.queue_root.mkdir()
        (self.queue_root / "autonomy-root.json").write_bytes(b"{}\n")
        self.attempt_one = self.queue_root / "attempts" / TASK_ID / "a1"
        self.attempt_two = self.queue_root / "attempts" / TASK_ID / "a2"
        self.attempt_one.mkdir(parents=True)
        self.attempt_two.mkdir()
        self.allowed_root = self.root / "allowed"
        self.allowed_root.mkdir()
        self.payload = self.allowed_root / "payload.json"
        self.expected_sha256 = "0" * 64

    def _write_payload(self, scenario: str, duration_ms: int = 0, *, raw=None) -> None:
        if raw is None:
            raw = json.dumps(
                {"version": 1, "scenario": scenario, "duration_ms": duration_ms},
                separators=(",", ":"),
            ).encode("ascii")
        self.payload.write_bytes(raw)
        self.expected_sha256 = hashlib.sha256(raw).hexdigest().upper()

    def _command(
        self,
        *,
        task_id: str = TASK_ID,
        attempt: str = "1",
        contained: bool = False,
    ) -> list[str]:
        attempt_dir = self.attempt_one if attempt == "1" else self.attempt_two
        command = [
            sys.executable,
            "-I",
            "-S",
            str(BOOTSTRAP),
            "--queue-root",
            str(self.queue_root),
            "--allowed-root",
            str(self.allowed_root),
            "--payload",
            str(self.payload),
            "--expected-sha256",
            self.expected_sha256,
            "--attempt-dir",
            str(attempt_dir),
            "--task-id",
            task_id,
            "--attempt",
            attempt,
            "--nonce",
            NONCE,
        ]
        if contained:
            command.append("--contained-by-job")
        return command

    def _run(self, timeout: float = 8.0, **kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self._command(**kwargs),
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _read_result(self, attempt_dir: Path | None = None):
        path = (attempt_dir or self.attempt_one) / RESULT_FILENAME
        raw = path.read_bytes()
        return json.loads(raw.decode("ascii")), raw

    def test_success_is_hash_pinned_canonical_bound_and_idempotent(self) -> None:
        self._write_payload("success")
        first = self._run()
        self.assertEqual(first.returncode, 0, first.stderr)
        document, raw = self._read_result()
        self.assertEqual(
            document,
            {
                "version": 1,
                "kind": "canary-worker-result",
                "task_id": TASK_ID,
                "attempt": 1,
                "nonce": NONCE,
                "scenario": "success",
                "outcome": "success",
            },
        )
        expected = (
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
        self.assertEqual(raw, expected)
        replay = self._run()
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual((self.attempt_one / RESULT_FILENAME).read_bytes(), raw)

    def test_attempt_two_is_accepted_only_at_exact_bound_directory(self) -> None:
        self._write_payload("success")
        completed = self._run(attempt="2")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document, _raw = self._read_result(self.attempt_two)
        self.assertEqual(document["attempt"], 2)

        (self.attempt_two / RESULT_FILENAME).unlink()
        command = self._command(attempt="2")
        command[command.index("--attempt-dir") + 1] = str(self.attempt_one)
        refused = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(refused.returncode, CONFIG_ERROR_EXIT)

    def test_hash_mismatch_and_payload_outside_allowed_root_fail_closed(self) -> None:
        self._write_payload("success")
        command = self._command()
        command[command.index("--expected-sha256") + 1] = "F" * 64
        mismatch = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(mismatch.returncode, CONFIG_ERROR_EXIT)
        self.assertFalse((self.attempt_one / RESULT_FILENAME).exists())

        outside = self.root / "outside.json"
        outside.write_bytes(self.payload.read_bytes())
        command = self._command()
        command[command.index("--payload") + 1] = str(outside)
        escaped = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(escaped.returncode, CONFIG_ERROR_EXIT)

    def test_fail_crash_and_hang_contracts(self) -> None:
        self._write_payload("fail")
        failed = self._run()
        self.assertEqual(failed.returncode, FAIL_EXIT)
        document, _raw = self._read_result()
        self.assertEqual(document["outcome"], "failure")

        (self.attempt_one / RESULT_FILENAME).unlink()
        self._write_payload("crash")
        crashed = self._run()
        self.assertEqual(crashed.returncode, CRASH_EXIT)
        self.assertFalse((self.attempt_one / RESULT_FILENAME).exists())

        self._write_payload("hang", 1000)
        started = time.monotonic()
        hung = self._run()
        elapsed = time.monotonic() - started
        self.assertEqual(hung.returncode, 0, hung.stderr)
        self.assertGreaterEqual(elapsed, 0.9)
        self.assertLess(elapsed, 3.5)
        self.assertFalse((self.attempt_one / RESULT_FILENAME).exists())

    def test_hang_and_spawn_tree_require_minimum_duration(self) -> None:
        for scenario in ("hang", "spawn-tree"):
            with self.subTest(scenario=scenario):
                self._write_payload(scenario, 999)
                completed = self._run()
                self.assertEqual(completed.returncode, CONFIG_ERROR_EXIT)

    def test_spawn_tree_refuses_without_explicit_job_flag(self) -> None:
        self._write_payload("spawn-tree", 5000)
        completed = self._run()
        self.assertEqual(completed.returncode, CONFIG_ERROR_EXIT)
        self.assertIn("contained-by-job", completed.stderr)
        self.assertFalse((self.attempt_one / RESULT_FILENAME).exists())

    @unittest.skipUnless(os.name == "nt", "Windows Job containment is required")
    def test_private_mode_outside_job_refuses_before_child_or_report(self) -> None:
        python = Path(
            getattr(sys, "_base_executable", None) or sys.executable
        ).resolve(strict=True)
        private_report = self.attempt_one / f".canary-spawn-{NONCE}.json"
        public_result = self.attempt_one / RESULT_FILENAME
        environment = {
            key: value
            for key in ("SystemRoot", "WINDIR", "COMSPEC")
            if (value := os.environ.get(key))
        }
        environment.update(
            {
                "AGENTCHATTR_CANARY_TOKEN": "fedcba9876543210fedcba9876543210",
                "AGENTCHATTR_CANARY_LEVEL": "1",
                "AGENTCHATTR_CANARY_DEADLINE_NS": str(
                    time.monotonic_ns() + 10_000_000_000
                ),
                "AGENTCHATTR_CANARY_ATTEMPT_DIR": str(self.attempt_one),
                "AGENTCHATTR_CANARY_NONCE": NONCE,
                "AGENTCHATTR_CANARY_PYTHON": str(python),
                "AGENTCHATTR_CANARY_BOOTSTRAP": str(BOOTSTRAP),
            }
        )

        creation_flags = 0
        if self._current_process_in_job():
            creation_flags = subprocess.CREATE_BREAKAWAY_FROM_JOB

        process: subprocess.Popen[str] | None = None
        observed_descendants: set[int] = set()
        private_report_seen = False
        public_result_seen = False
        natural_returncode: int | None = None
        launched_in_job: bool | None = None
        stdout = ""
        stderr = ""
        try:
            try:
                process = subprocess.Popen(
                    [str(python), "-I", "-S", str(BOOTSTRAP)],
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=creation_flags,
                )
            except OSError as exc:
                if creation_flags:
                    self.skipTest(f"runner Job forbids breakaway: {exc}")
                raise

            launched_in_job = self._process_handle_in_job(int(process._handle))
            observation_deadline = time.monotonic() + 2.0
            while time.monotonic() < observation_deadline:
                observed_descendants.update(self._descendant_pids(process.pid))
                private_report_seen = private_report_seen or private_report.exists()
                public_result_seen = public_result_seen or public_result.exists()
                natural_returncode = process.poll()
                if natural_returncode is not None:
                    break
                time.sleep(0.005)
        finally:
            if process is not None:
                observed_descendants.update(self._descendant_pids(process.pid))
                private_report_seen = private_report_seen or private_report.exists()
                public_result_seen = public_result_seen or public_result.exists()
                cleanup_pids = set(observed_descendants)
                if private_report.exists():
                    try:
                        report = json.loads(private_report.read_text(encoding="ascii"))
                        cleanup_pids.update(
                            int(pid) for pid in report.get("descendant_pids", [])
                        )
                    except (OSError, ValueError, TypeError):
                        pass
                cleanup_pids.discard(process.pid)
                for pid in cleanup_pids:
                    self._terminate_pid(pid)
                if process.poll() is None:
                    process.kill()
                stdout, stderr = process.communicate(timeout=5.0)
                for pid in cleanup_pids | self._descendant_pids(process.pid):
                    self._terminate_pid(pid)
            for path in (private_report, public_result):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

        if launched_in_job:
            self.skipTest("runner could not create an outside-Job subprocess")
        self.assertFalse(launched_in_job, "private regression process was not outside Job")
        self.assertEqual(natural_returncode, CONFIG_ERROR_EXIT, stderr or stdout)
        self.assertEqual(set(), observed_descendants, "private mode created a child")
        self.assertFalse(private_report_seen, "private mode published its PID report")
        self.assertFalse(public_result_seen, "private mode published a public result")

    @unittest.skipUnless(os.name == "nt", "Windows Job containment is required")
    def test_spawn_tree_is_job_contained_and_killed_without_leaks(self) -> None:
        from autonomy.winjob import (
            JOB_OBJECT_BREAKAWAY_FLAGS,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            AssignedProcess,
            fatal_owner_scope,
            launch_contained,
        )

        self._write_payload("spawn-tree", 5000)
        assignments: list[AssignedProcess] = []

        def record_assignment(evidence: AssignedProcess) -> None:
            assignments.append(evidence)
            return None

        with fatal_owner_scope():
            contained = launch_contained(
                self._command(contained=True),
                allowed_root=str(ROOT),
                cwd=str(ROOT),
                before_resume=record_assignment,
            )
            pids: list[int] = []
            try:
                self.assertEqual(1, len(assignments))
                assignment = assignments[0]
                self.assertGreater(assignment.pid, 0)
                self.assertTrue(
                    assignment.job_limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                )
                self.assertFalse(
                    assignment.job_limit_flags & JOB_OBJECT_BREAKAWAY_FLAGS
                )
                result_path = self.attempt_one / RESULT_FILENAME
                deadline = time.monotonic() + 5.0
                while (
                    not result_path.exists()
                    and contained.is_alive()
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertTrue(
                    result_path.exists(), "contained worker published no PID result"
                )
                document, _raw = self._read_result()
                pids = [int(pid) for pid in document["descendant_pids"]]
                self.assertTrue(all(self._pid_alive(pid) for pid in pids))
                self.assertTrue(contained.terminate_and_verify(timeout=5.0))
            except Exception:
                # Checked cleanup is only for an ordinary failure.  A
                # BaseException must skip this arm and reach fatal_owner_scope
                # without any Python handle cleanup or retry.
                contained.close()
                raise
            contained.close()

        for pid in pids:
            self.assertFalse(self._pid_alive(pid), f"descendant leaked: {pid}")
        self.assertEqual([], list(self.attempt_one.glob(".canary-spawn-*.json")))

    def test_payload_schema_duplicate_closed_bool_hash_case_and_bound(self) -> None:
        invalid = [
            b'{"version":1,"version":1,"scenario":"success","duration_ms":0}',
            b'{"version":1,"scenario":"success","duration_ms":0,"extra":1}',
            b'{"version":1,"scenario":"success","duration_ms":true}',
            b'{"version":1,"scenario":"unknown","duration_ms":0}',
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                self._write_payload("success", raw=raw)
                with self.assertRaises(PayloadError):
                    load_payload(
                        self.payload,
                        allowed_root=self.allowed_root,
                        expected_sha256=self.expected_sha256,
                    )
        raw = b" " * (MAX_PAYLOAD_BYTES + 1)
        self._write_payload("success", raw=raw)
        with self.assertRaises(PayloadError):
            load_payload(
                self.payload,
                allowed_root=self.allowed_root,
                expected_sha256=self.expected_sha256,
            )
        self._write_payload("success")
        with self.assertRaises(PayloadError):
            load_payload(
                self.payload,
                allowed_root=self.allowed_root,
                expected_sha256=self.expected_sha256.lower(),
            )

    def test_relative_traversal_unc_device_and_wrong_queue_root_are_rejected(self) -> None:
        self._write_payload("success")
        command = self._command()
        command[command.index("--payload") + 1] = "relative.json"
        self.assertEqual(
            subprocess.run(command, cwd=ROOT, capture_output=True).returncode,
            CONFIG_ERROR_EXIT,
        )
        command = self._command()
        command[command.index("--attempt-dir") + 1] = str(
            self.queue_root / "attempts" / TASK_ID / "unused" / ".." / "a1"
        )
        self.assertEqual(
            subprocess.run(command, cwd=ROOT, capture_output=True).returncode,
            CONFIG_ERROR_EXIT,
        )
        wrong_root = self.root / "not-queue"
        wrong_root.mkdir()
        command = self._command()
        command[command.index("--queue-root") + 1] = str(wrong_root)
        self.assertEqual(
            subprocess.run(command, cwd=ROOT, capture_output=True).returncode,
            CONFIG_ERROR_EXIT,
        )
        if os.name == "nt":
            for unsafe in (r"\\server\share\payload.json", r"\\?\C:\payload.json", r"\\.\C:\payload.json"):
                with self.subTest(unsafe=unsafe), self.assertRaises(PathValidationError):
                    load_payload(
                        unsafe,
                        allowed_root=self.allowed_root,
                        expected_sha256="A" * 64,
                    )

    def test_conflicting_result_is_preserved_and_read_as_stable_regular_file(self) -> None:
        self._write_payload("success")
        path = self.attempt_one / RESULT_FILENAME
        original = b'{"foreign":true}\n'
        path.write_bytes(original)
        completed = self._run()
        self.assertEqual(completed.returncode, CONFIG_ERROR_EXIT)
        self.assertEqual(path.read_bytes(), original)
        path.unlink()
        path.mkdir()
        completed = self._run()
        self.assertEqual(completed.returncode, CONFIG_ERROR_EXIT)
        self.assertTrue(path.is_dir())

    @unittest.skipUnless(os.name == "nt", "junction fallback is Windows-specific")
    def test_attempt_directory_junction_is_rejected(self) -> None:
        self._write_payload("success")
        self.attempt_one.rmdir()
        outside = self.root / "outside-attempt"
        outside.mkdir()
        created = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(self.attempt_one), str(outside)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        if created.returncode != 0:
            self.skipTest(f"junction creation unavailable: {created.stdout.strip()}")

        def remove_junction() -> None:
            if self.attempt_one.exists():
                os.rmdir(self.attempt_one)

        self.addCleanup(remove_junction)
        completed = self._run()
        self.assertEqual(completed.returncode, CONFIG_ERROR_EXIT)
        remove_junction()

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenProcess(0x00100000, False, pid)
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 0x102
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _process_handle_in_job(process_handle: int) -> bool:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.IsProcessInJob.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        kernel32.IsProcessInJob.restype = ctypes.c_int
        in_job = ctypes.c_int()
        if not kernel32.IsProcessInJob(
            ctypes.c_void_p(process_handle), None, ctypes.byref(in_job)
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "IsProcessInJob failed")
        return bool(in_job.value)

    @classmethod
    def _current_process_in_job(cls) -> bool:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        return cls._process_handle_in_job(int(kernel32.GetCurrentProcess()))

    @staticmethod
    def _descendant_pids(root_pid: int) -> set[int]:
        class ProcessEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_ulong),
                ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", ctypes.c_ulong),
                ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.Process32FirstW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessEntry32),
        ]
        kernel32.Process32FirstW.restype = ctypes.c_int
        kernel32.Process32NextW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessEntry32),
        ]
        kernel32.Process32NextW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int

        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            error = ctypes.get_last_error()
            raise OSError(error, "CreateToolhelp32Snapshot failed")
        parents: dict[int, int] = {}
        try:
            entry = ProcessEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            has_entry = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while has_entry:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                has_entry = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)

        descendants: set[int] = set()
        frontier = {root_pid}
        while frontier:
            children = {
                pid
                for pid, parent_pid in parents.items()
                if parent_pid in frontier and pid != root_pid and pid not in descendants
            }
            descendants.update(children)
            frontier = children
        return descendants

    @staticmethod
    def _terminate_pid(pid: int) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel32.TerminateProcess.restype = ctypes.c_int
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenProcess(0x0001 | 0x00100000, False, pid)
        if not handle:
            return
        try:
            kernel32.TerminateProcess(handle, CONFIG_ERROR_EXIT)
            kernel32.WaitForSingleObject(handle, 2000)
        finally:
            kernel32.CloseHandle(handle)


if __name__ == "__main__":
    unittest.main()
