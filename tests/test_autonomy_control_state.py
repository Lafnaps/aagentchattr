from __future__ import annotations

import contextlib
import dataclasses
import errno
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import autonomy.control_state as control_state
from autonomy.control_state import (
    HALT_FILENAME,
    ROOT_MARKER,
    SUPERVISOR_LOCK_FILENAME,
    LockIntegrityError,
    LockUnavailableError,
    MarkerConflictError,
    PathSecurityError,
    PermanentFileLock,
    SchemaError,
    UnsupportedPlatformError,
    create_halt,
    create_once_marker,
    halt_exists,
    parse_halt_document,
    read_halt,
    read_mutable_marker,
    read_once_marker,
    write_mutable_marker,
)


TASK_ID = "task-one"
ATTEMPT = 1
NONCE_A = "a" * 32
NONCE_B = "b" * 32
STAMP = "2026-07-13T12:34:56.789Z"
CANONICAL_ROOT_MARKER = b'{"name":"agentchattr-autonomy-queue","version":1}\n'
REPO_ROOT = Path(__file__).resolve().parents[1]
IS_WINDOWS = os.name == "nt"


def subprocess_environment():
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def hold_lock_range(path, offset):
    """Open a hostile read/share-read handle and lock one byte at ``offset``."""

    handle = control_state._win_create_file(
        path,
        control_state._GENERIC_READ,
        control_state._FILE_SHARE_READ,
        control_state._OPEN_EXISTING,
        0,
    )
    try:
        control_state._win_lock_exclusive(handle, offset)
    except BaseException:
        control_state._win_close(handle)
        raise
    return handle


def release_lock_range(handle, offset):
    try:
        control_state._win_unlock(handle, offset)
    finally:
        control_state._win_close(handle)


def make_junction(link, target):
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", os.fspath(link), os.fspath(target)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )
    return result.returncode == 0, result.stdout.strip()


def traceback_function_names(exc):
    """The function names on ``exc``'s traceback, oldest frame first."""

    names = []
    trace = exc.__traceback__
    while trace is not None:
        names.append(trace.tb_frame.f_code.co_name)
        trace = trace.tb_next
    return names


class ControlStateFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ROOT_MARKER).write_bytes(CANONICAL_ROOT_MARKER)
        self.attempt_dir = self.root / "attempts" / TASK_ID / "a1"
        self.attempt_dir.mkdir(parents=True)

    def create_stop(self, **overrides):
        arguments = {
            "kind": "stop-request",
            "task_id": TASK_ID,
            "attempt": ATTEMPT,
            "nonce": NONCE_A,
            "created_utc": STAMP,
        }
        arguments.update(overrides)
        return create_once_marker(
            self.root,
            self.attempt_dir,
            "stop-request.json",
            **arguments,
        )

    def read_stop(self, **overrides):
        arguments = {
            "kind": "stop-request",
            "task_id": TASK_ID,
            "attempt": ATTEMPT,
            "nonce": NONCE_A,
        }
        arguments.update(overrides)
        return read_once_marker(
            self.root,
            self.attempt_dir,
            "stop-request.json",
            **arguments,
        )


class ImmutableMarkerTests(ControlStateFixture):
    def test_idempotent_publication_accepts_only_exact_canonical_bytes(self):
        first = self.create_stop()
        second = self.create_stop()
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(first.path, second.path)
        raw = first.path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(
            raw,
            json.dumps(
                self.read_stop(),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n",
        )

    def test_same_payload_concurrency_has_exactly_one_creator(self):
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _index: self.create_stop(), range(32)))
        self.assertEqual(1, sum(result.created for result in results))
        self.assertTrue(all(result.path == results[0].path for result in results))
        self.assertEqual(NONCE_A, self.read_stop()["nonce"])
        self.assertEqual([], list(self.attempt_dir.glob(".stop-request.json.*.tmp")))

    def test_conflicting_existing_marker_fails_closed_without_replacement(self):
        original = self.create_stop().path.read_bytes()
        with self.assertRaises(MarkerConflictError):
            self.create_stop(nonce=NONCE_B)
        self.assertEqual(original, (self.attempt_dir / "stop-request.json").read_bytes())

    def test_concurrent_conflicting_publication_has_one_winner(self):
        def publish(nonce):
            try:
                result = self.create_stop(nonce=nonce)
                return "created" if result.created else "existing"
            except MarkerConflictError:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(publish, (NONCE_A, NONCE_B)))
        self.assertEqual(1, results.count("created"))
        self.assertEqual(1, results.count("conflict"))

    def test_publication_failure_removes_its_temp_and_publishes_nothing(self):
        with mock.patch("autonomy.control_state.os.link", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                self.create_stop()
        self.assertFalse((self.attempt_dir / "stop-request.json").exists())
        self.assertEqual([], list(self.attempt_dir.glob(".stop-request.json.*.tmp")))


class StrictSchemaTests(ControlStateFixture):
    def test_binding_kind_task_attempt_and_nonce_are_all_checked(self):
        self.create_stop()
        for override in (
            {"kind": "stopped"},
            {"task_id": "task-two"},
            {"attempt": 2},
            {"nonce": NONCE_B},
        ):
            with self.subTest(override=override), self.assertRaises(
                (SchemaError, PathSecurityError)
            ):
                self.read_stop(**override)

    def test_writer_rejects_bool_numbers_bad_nonce_bad_utc_and_bad_filename(self):
        cases = (
            {"attempt": True},
            {"nonce": "A" * 32},
            {"created_utc": "2026-02-30T12:34:56.789Z"},
        )
        for override in cases:
            with self.subTest(override=override), self.assertRaises(SchemaError):
                self.create_stop(**override)
        with self.assertRaises(SchemaError):
            create_once_marker(
                self.root,
                self.attempt_dir,
                "../stop.json",
                kind="stop-request",
                task_id=TASK_ID,
                attempt=1,
                nonce=NONCE_A,
                created_utc=STAMP,
            )

    def test_reader_rejects_duplicate_keys_nan_oversize_and_noncanonical_bytes(self):
        path = self.attempt_dir / "stop-request.json"
        corruptions = (
            b'{"attempt":1,"attempt":1,"created_utc":"2026-07-13T12:34:56.789Z","kind":"stop-request","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","task_id":"task-one","version":1}\n',
            b'{"attempt":1,"created_utc":"2026-07-13T12:34:56.789Z","kind":"stop-request","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","task_id":"task-one","version":NaN}\n',
            b"{" + b" " * 3000,
            b'{ "attempt": 1 }\n',
        )
        for raw in corruptions:
            with self.subTest(raw=raw[:40]):
                path.write_bytes(raw)
                with self.assertRaises(SchemaError):
                    self.read_stop()

    def test_reader_rejects_canonical_extra_key_and_wrong_version_type(self):
        path = self.attempt_dir / "stop-request.json"
        base = {
            "version": 1,
            "kind": "stop-request",
            "task_id": TASK_ID,
            "attempt": 1,
            "nonce": NONCE_A,
            "created_utc": STAMP,
        }
        for mutation in (
            lambda value: value.update(extra="forbidden"),
            lambda value: value.update(version=True),
        ):
            document = dict(base)
            mutation(document)
            path.write_bytes(
                json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
                + b"\n"
            )
            with self.assertRaises(SchemaError):
                self.read_stop()


class MutableMarkerTests(ControlStateFixture):
    def write_status(self, generation):
        return write_mutable_marker(
            self.root,
            self.attempt_dir,
            "runner-status.json",
            kind="runner-status",
            task_id=TASK_ID,
            attempt=1,
            nonce=NONCE_A,
            generation=generation,
            updated_utc=STAMP,
        )

    def read_status(self):
        return read_mutable_marker(
            self.root,
            self.attempt_dir,
            "runner-status.json",
            kind="runner-status",
            task_id=TASK_ID,
            attempt=1,
            nonce=NONCE_A,
        )

    def test_atomic_replace_updates_generation(self):
        self.write_status(0)
        self.write_status(1)
        self.assertEqual(1, self.read_status()["generation"])
        self.assertEqual([], list(self.attempt_dir.glob(".runner-status.json.*.tmp")))

    def test_replace_failure_keeps_old_bytes_and_removes_temp(self):
        path = self.write_status(0)
        original = path.read_bytes()
        with mock.patch(
            "autonomy.control_state.os.replace", side_effect=OSError("injected")
        ):
            with self.assertRaises(OSError):
                self.write_status(1)
        self.assertEqual(original, path.read_bytes())
        self.assertEqual([], list(self.attempt_dir.glob(".runner-status.json.*.tmp")))

    def test_mutable_marker_rejects_bool_generation(self):
        with self.assertRaises(SchemaError):
            self.write_status(True)


class PathSecurityTests(ControlStateFixture):
    def test_literal_escape_and_wrong_canonical_attempt_dir_are_rejected(self):
        outside = self.root.parent
        with self.assertRaises(PathSecurityError):
            create_once_marker(
                self.root,
                outside,
                "stop-request.json",
                kind="stop-request",
                task_id=TASK_ID,
                attempt=1,
                nonce=NONCE_A,
                created_utc=STAMP,
            )
        wrong = self.root / "attempts" / TASK_ID / "wrong"
        wrong.mkdir()
        with self.assertRaises(PathSecurityError):
            create_once_marker(
                self.root,
                wrong,
                "stop-request.json",
                kind="stop-request",
                task_id=TASK_ID,
                attempt=1,
                nonce=NONCE_A,
                created_utc=STAMP,
            )

    def test_attempt_directory_symlink_or_reparse_escape_is_rejected_when_supported(self):
        self.attempt_dir.rmdir()
        outside = Path(self.temporary.name + "-outside")
        outside.mkdir()
        self.addCleanup(lambda: outside.rmdir() if outside.exists() else None)
        try:
            os.symlink(outside, self.attempt_dir, target_is_directory=True)
        except (OSError, NotImplementedError) as symlink_error:
            if os.name != "nt":
                self.skipTest(f"directory symlinks unavailable: {symlink_error}")
            created, output = make_junction(self.attempt_dir, outside)
            if not created:
                self.skipTest(
                    "directory symlinks and junctions unavailable: "
                    f"symlink={symlink_error}; junction={output}"
                )
        try:
            with self.assertRaises(PathSecurityError):
                self.create_stop()
        finally:
            if self.attempt_dir.exists() or self.attempt_dir.is_symlink():
                os.rmdir(self.attempt_dir)


class HaltAndLockTests(ControlStateFixture):
    def test_halt_create_read_exists_and_conflict(self):
        self.assertFalse(halt_exists(self.root))
        first = create_halt(self.root, nonce=NONCE_A, created_utc=STAMP)
        second = create_halt(self.root, nonce=NONCE_A, created_utc=STAMP)
        self.assertEqual(self.root / HALT_FILENAME, first.path)
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertTrue(halt_exists(self.root))
        self.assertEqual(NONCE_A, read_halt(self.root, nonce=NONCE_A)["nonce"])
        with self.assertRaises(MarkerConflictError):
            create_halt(self.root, nonce=NONCE_B, created_utc=STAMP)

    @unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
    def test_permanent_lock_contends_and_close_is_idempotent(self):
        first = PermanentFileLock(self.root, "supervisor.lock")
        try:
            with self.assertRaises(LockUnavailableError):
                PermanentFileLock(self.root, "supervisor.lock")
        finally:
            first.close()
            first.close()
        with PermanentFileLock(self.root, "supervisor.lock") as acquired:
            self.assertFalse(acquired.closed)
        self.assertTrue(acquired.closed)

    @unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
    def test_permanent_lock_contends_across_processes(self):
        script = (
            "import sys\n"
            "from autonomy.control_state import PermanentFileLock, LockUnavailableError\n"
            "try:\n"
            "    lock = PermanentFileLock(sys.argv[1], 'runner.lock')\n"
            "except LockUnavailableError:\n"
            "    raise SystemExit(23)\n"
            "else:\n"
            "    lock.close()\n"
            "    raise SystemExit(0)\n"
        )

        def probe():
            return subprocess.run(
                [sys.executable, "-c", script, os.fspath(self.root)],
                cwd=REPO_ROOT,
                env=subprocess_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )

        held = PermanentFileLock(self.root, "runner.lock")
        try:
            blocked = probe()
            self.assertEqual(23, blocked.returncode, blocked.stderr)
        finally:
            held.close()
        acquired = probe()
        self.assertEqual(0, acquired.returncode, acquired.stderr)

    def test_lock_name_is_closed_and_non_windows_constructor_is_import_safe(self):
        with self.assertRaises(SchemaError):
            PermanentFileLock(self.root, "other.lock")
        if os.name != "nt":
            with self.assertRaises(UnsupportedPlatformError):
                PermanentFileLock(self.root, "runner.lock")


class RootMarkerAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.marker = self.root / ROOT_MARKER

    def test_exact_canonical_marker_is_accepted(self):
        self.marker.write_bytes(CANONICAL_ROOT_MARKER)
        self.assertFalse(halt_exists(self.root))

    def test_missing_marker_is_rejected(self):
        with self.assertRaises(PathSecurityError):
            halt_exists(self.root)

    def test_marker_content_variants_fail_closed(self):
        corruptions = (
            b"",
            b"{}\n",
            b'{ "name": "agentchattr-autonomy-queue", "version": 1 }\n',
            b'{"name":"agentchattr-autonomy-queue","version":2}\n',
            b'{"name":"agentchattr-autonomy-queue","version":1.0}\n',
            b'{"name":"agentchattr-autonomy-queue","version":true}\n',
            b'{"name":"other-queue","version":1}\n',
            b'{"extra":1,"name":"agentchattr-autonomy-queue","version":1}\n',
            b"{" + b" " * 2000,
        )
        for raw in corruptions:
            with self.subTest(raw=raw[:48]):
                self.marker.write_bytes(raw)
                with self.assertRaises(PathSecurityError):
                    halt_exists(self.root)

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-only")
    def test_marker_junction_is_rejected(self):
        target = self.root / "marker-target-dir"
        target.mkdir()
        created, output = make_junction(self.marker, target)
        if not created:
            self.skipTest(f"junction creation denied by platform: {output}")
        self.addCleanup(lambda: os.rmdir(self.marker) if self.marker.exists() else None)
        with self.assertRaises(PathSecurityError):
            halt_exists(self.root)


class ParseHaltDocumentTests(ControlStateFixture):
    def test_round_trip_of_published_halt_bytes(self):
        create_halt(self.root, nonce=NONCE_A, created_utc=STAMP)
        raw = (self.root / HALT_FILENAME).read_bytes()
        document = parse_halt_document(raw)
        self.assertEqual(NONCE_A, document["nonce"])
        self.assertEqual("halt", document["kind"])

    def test_invalid_bytes_raise_schema_error(self):
        for raw in (b"", b"garbage\n", b'{ "kind": "halt" }\n', b"{" + b" " * 3000):
            with self.subTest(raw=raw[:32]), self.assertRaises(SchemaError):
                parse_halt_document(raw)


@unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
class HardenedLockTests(ControlStateFixture):
    def lock_path(self):
        return self.root / SUPERVISOR_LOCK_FILENAME

    def test_lock_file_is_permanent_one_nul_byte_with_link_count_one(self):
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertTrue(lock._published)
        lock.close()
        self.assertEqual(b"\0", self.lock_path().read_bytes())
        self.assertEqual(1, os.lstat(self.lock_path()).st_nlink)
        self.assertEqual([], list(self.root.glob(f".{SUPERVISOR_LOCK_FILENAME}.*.tmp")))
        again = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertFalse(again._published)
        again.close()
        self.assertEqual(b"\0", self.lock_path().read_bytes())

    def test_zero_length_and_multibyte_residues_fail_closed_without_repair(self):
        for residue in (b"", b"\0\0"):
            with self.subTest(residue=residue):
                self.lock_path().write_bytes(residue)
                with self.assertRaises(LockIntegrityError):
                    PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
                self.assertEqual(residue, self.lock_path().read_bytes())
                self.lock_path().unlink()

    def test_single_nonzero_byte_fails_closed_before_ownership_is_claimed(self):
        self.lock_path().write_bytes(b"x")
        lock_calls = []
        real_lock = control_state._win_lock_exclusive

        def lock_spy(handle, offset):
            lock_calls.append(offset)
            return real_lock(handle, offset)

        with mock.patch(
            "autonomy.control_state._win_lock_exclusive", side_effect=lock_spy
        ):
            with self.assertRaises(LockIntegrityError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertEqual([], lock_calls)
        self.assertEqual(b"x", self.lock_path().read_bytes())

    def test_hardlinked_lock_file_fails_closed(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        os.link(self.lock_path(), self.root / "lock-alias")
        with self.assertRaises(LockIntegrityError):
            PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertEqual(b"\0", self.lock_path().read_bytes())

    def test_symlink_lock_file_fails_closed_when_supported(self):
        target = self.root / "real-lock-bytes"
        target.write_bytes(b"\0")
        try:
            os.symlink(target, self.lock_path())
        except OSError as exc:
            self.skipTest(f"file symlinks denied by platform without privilege: {exc}")
        with self.assertRaises(PathSecurityError):
            PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)

    def test_lock_junction_fails_closed(self):
        target = self.root / "junction-target-dir"
        target.mkdir()
        created, output = make_junction(self.lock_path(), target)
        if not created:
            self.skipTest(f"junction creation denied by platform: {output}")
        self.addCleanup(
            lambda: os.rmdir(self.lock_path()) if self.lock_path().exists() else None
        )
        with self.assertRaises(PathSecurityError):
            PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)

    def test_queue_root_junction_fails_closed(self):
        junction = Path(self.temporary.name + "-junction")
        created, output = make_junction(junction, self.root)
        if not created:
            self.skipTest(f"junction creation denied by platform: {output}")
        self.addCleanup(lambda: os.rmdir(junction) if junction.exists() else None)
        with self.assertRaises(PathSecurityError):
            PermanentFileLock(junction, SUPERVISOR_LOCK_FILENAME)

    def test_name_swap_between_inspection_and_open_fails_closed(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        path = self.lock_path()

        def swap(seen_path):
            os.unlink(path)
            path.write_bytes(b"\0")

        with mock.patch("autonomy.control_state._lock_open_seam", side_effect=swap):
            with self.assertRaises(LockIntegrityError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)

    def test_published_lock_identity_swap_before_retained_open_fails_closed(self):
        path = self.lock_path()

        def swap(seen_path):
            os.unlink(path)
            path.write_bytes(b"\0")

        with mock.patch("autonomy.control_state._lock_open_seam", side_effect=swap):
            with self.assertRaises(LockIntegrityError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)

    def test_injected_winerror_33_from_exact_lockfileex_call_is_contention(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        injected = OSError(errno.EACCES, "injected lock violation", None, 33)
        with mock.patch(
            "autonomy.control_state._win_lock_exclusive", side_effect=injected
        ):
            with self.assertRaises(LockUnavailableError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)

    def test_unknown_locking_errors_are_not_labeled_contention(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        for injected in (
            OSError(errno.EACCES, "injected sharing violation", None, 32),
            OSError(errno.EDEADLK, "injected sharing buffer exceeded", None, 36),
            OSError(errno.EACCES, "injected errno-only"),
            OSError(errno.EAGAIN, "injected errno-only"),
            OSError(errno.EDEADLK, "injected errno-only"),
            OSError(errno.EBADF, "injected"),
        ):
            with self.subTest(injected=injected):
                with mock.patch(
                    "autonomy.control_state._win_lock_exclusive", side_effect=injected
                ):
                    with self.assertRaises(LockIntegrityError):
                        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)

    def test_byte_zero_read_obstruction_is_integrity_not_valid_ownership(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        holder = hold_lock_range(self.lock_path(), 0)
        try:
            with self.assertRaises(LockIntegrityError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        finally:
            release_lock_range(holder, 0)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_corrupt_byte_with_ownership_lock_is_integrity_valid_is_contention(self):
        self.lock_path().write_bytes(b"x")
        holder = hold_lock_range(self.lock_path(), 1)
        try:
            with self.assertRaises(LockIntegrityError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        finally:
            release_lock_range(holder, 1)
        self.lock_path().write_bytes(b"\0")
        holder = hold_lock_range(self.lock_path(), 1)
        try:
            with self.assertRaises(LockUnavailableError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        finally:
            release_lock_range(holder, 1)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_cross_thread_lock_use_fails_closed(self):
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        failures = []

        def hostile():
            try:
                lock.close()
            except LockIntegrityError as exc:
                failures.append(exc)

        worker = threading.Thread(target=hostile)
        worker.start()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(failures))
        self.assertFalse(lock.closed)
        lock.close()

    def test_cross_thread_exit_leaves_fence_fully_active(self):
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        lock.__enter__()
        failures = []

        def hostile():
            try:
                lock.__exit__(None, None, None)
            except LockIntegrityError as exc:
                failures.append(exc)

        worker = threading.Thread(target=hostile)
        worker.start()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(failures))
        self.assertFalse(lock.closed)
        self.assertTrue(lock._entered)
        with self.assertRaises(LockUnavailableError):
            PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        lock.__exit__(None, None, None)
        self.assertTrue(lock.closed)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_same_object_reentry_is_rejected_before_state_changes(self):
        with PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME) as lock:
            with self.assertRaises(LockIntegrityError):
                lock.__enter__()
            self.assertFalse(lock.closed)
            with self.assertRaises(LockUnavailableError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertTrue(lock.closed)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_reentering_a_closed_lock_is_integrity_never_contention(self):
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        lock.close()
        with self.assertRaises(LockIntegrityError) as trap:
            lock.__enter__()
        self.assertNotIsInstance(trap.exception, LockUnavailableError)
        self.assertTrue(lock.closed)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_rename_and_delete_are_denied_while_held(self):
        decoy = self.root / "decoy"
        decoy.write_bytes(b"\0")
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        try:
            with self.assertRaises(OSError):
                os.unlink(self.lock_path())
            with self.assertRaises(OSError):
                os.replace(decoy, self.lock_path())
        finally:
            lock.close()
        self.assertEqual(b"\0", self.lock_path().read_bytes())
        self.assertEqual(1, os.lstat(self.lock_path()).st_nlink)

    def test_root_and_marker_are_retained_and_protected_while_held(self):
        marker = self.root / ROOT_MARKER
        decoy = self.root / "decoy"
        decoy.write_bytes(CANONICAL_ROOT_MARKER)
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        try:
            with self.assertRaises(OSError):
                os.unlink(marker)
            with self.assertRaises(OSError):
                os.rename(marker, self.root / "marker-moved")
            with self.assertRaises(OSError):
                os.replace(decoy, marker)
            with self.assertRaises(OSError):
                marker.open("wb")
            with self.assertRaises(OSError):
                os.rename(self.root, Path(os.fspath(self.root) + "-moved"))
        finally:
            lock.close()
        self.assertEqual(CANONICAL_ROOT_MARKER, marker.read_bytes())
        self.assertEqual(1, os.lstat(marker).st_nlink)

    def test_marker_hardlink_alias_at_a_checkpoint_fails_closed(self):
        marker = self.root / ROOT_MARKER
        alias = self.root / "marker-alias"
        os.link(marker, alias)
        with self.assertRaises(PathSecurityError):
            PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        os.unlink(alias)
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        os.link(marker, alias)
        with self.assertRaises(LockIntegrityError):
            lock.close()
        self.assertTrue(lock.closed)
        os.unlink(alias)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_transient_lock_alias_shares_identity_and_cannot_bypass_ownership(self):
        alias = self.root / "lock-alias"
        decoy = self.root / "decoy"
        decoy.write_bytes(b"\0")
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        try:
            # Share modes do not prevent CreateHardLink; the alias must appear.
            os.link(self.lock_path(), alias)
            self.assertEqual(
                os.lstat(self.lock_path()).st_ino, os.lstat(alias).st_ino
            )
            self.assertEqual(2, os.lstat(alias).st_nlink)
            # The alias resolves to the same file object, so the offset-one
            # kernel ownership range cannot be bypassed through it.
            handle = control_state._win_create_file(
                alias,
                control_state._GENERIC_READ,
                control_state._FILE_SHARE_READ,
                control_state._OPEN_EXISTING,
                0,
            )
            try:
                with self.assertRaises(OSError) as trap:
                    control_state._win_lock_exclusive(handle, 1)
                self.assertEqual(33, trap.exception.winerror)
            finally:
                control_state._win_close(handle)
            # The original name still cannot be renamed or deleted.
            with self.assertRaises(OSError):
                os.unlink(self.lock_path())
            with self.assertRaises(OSError):
                os.replace(decoy, self.lock_path())
            os.unlink(alias)
        except BaseException:
            if alias.exists():
                os.unlink(alias)
            raise
        # The alias was transient, so the final checkpoint passes cleanly.
        lock.close()
        self.assertEqual(b"\0", self.lock_path().read_bytes())
        self.assertEqual(1, os.lstat(self.lock_path()).st_nlink)

    def test_lock_alias_persisting_to_final_checkpoint_fails_closed(self):
        alias = self.root / "lock-alias"
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        os.link(self.lock_path(), alias)
        with self.assertRaises(LockIntegrityError):
            lock.close()
        self.assertTrue(lock.closed)
        os.unlink(alias)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        self.assertEqual(1, os.lstat(self.lock_path()).st_nlink)

    def test_publication_race_loser_disposes_temp_and_authenticates_under_retention(self):
        winner_handles = []

        def close_winner():
            while winner_handles:
                control_state._win_close(winner_handles.pop())

        self.addCleanup(close_winner)

        def hostile_publish(path):
            # Simulate a concurrent winner that publishes first and retains
            # its high-access publisher handle for a while.
            handle = control_state._win_create_file(
                path,
                control_state._GENERIC_READ
                | control_state._GENERIC_WRITE
                | control_state._DELETE_ACCESS,
                control_state._FILE_SHARE_READ,
                control_state._CREATE_NEW,
                control_state._FILE_ATTRIBUTE_NORMAL,
            )
            winner_handles.append(handle)
            control_state._win_write_all(handle, b"\0", 0)
            control_state._win_flush(handle)
            timer = threading.Timer(0.15, close_winner)
            timer.start()
            self.addCleanup(timer.cancel)

        authenticated_under_retention = []
        real_authenticate = control_state._authenticate_published_lock

        def authenticate_spy(root_final, path):
            identity = real_authenticate(root_final, path)
            authenticated_under_retention.append(bool(winner_handles))
            return identity

        started = time.monotonic()
        with mock.patch(
            "autonomy.control_state._lock_publish_seam", side_effect=hostile_publish
        ), mock.patch(
            "autonomy.control_state._authenticate_published_lock",
            side_effect=authenticate_spy,
        ):
            lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        elapsed = time.monotonic() - started
        try:
            self.assertFalse(lock._published)
        finally:
            lock.close()
        self.assertEqual([True], authenticated_under_retention)
        self.assertGreaterEqual(elapsed, 0.1)
        self.assertEqual(b"\0", self.lock_path().read_bytes())
        self.assertEqual(1, os.lstat(self.lock_path()).st_nlink)
        self.assertEqual([], list(self.root.glob(f".{SUPERVISOR_LOCK_FILENAME}.*.tmp")))

    def test_first_use_race_has_one_publication_winner_and_no_corrupt_residue(self):
        successes = []
        errors = []
        publish_outcomes = []
        real_publish = control_state._publish_permanent_lock

        def publish_spy(root, root_final, path):
            outcome = real_publish(root, root_final, path)
            publish_outcomes.append(outcome[0])
            return outcome

        def contender():
            for _attempt in range(2000):
                try:
                    lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
                except LockUnavailableError:
                    continue
                except LockIntegrityError as exc:
                    if getattr(exc.__cause__, "winerror", None) == 32:
                        # Fail-closed publisher-drain sharing window; retry
                        # as a fresh independent invocation.
                        continue
                    errors.append(exc)
                    return
                except Exception as exc:  # pragma: no cover - diagnostic only
                    errors.append(exc)
                    return
                try:
                    successes.append(threading.get_ident())
                finally:
                    lock.close()
                return
            errors.append(TimeoutError("contender never acquired the lock"))

        with mock.patch(
            "autonomy.control_state._publish_permanent_lock", side_effect=publish_spy
        ):
            workers = [threading.Thread(target=contender) for _index in range(8)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=120)
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual([], errors)
        self.assertEqual(8, len(successes))
        self.assertEqual(1, publish_outcomes.count("won"), publish_outcomes)
        self.assertEqual(b"\0", self.lock_path().read_bytes())
        self.assertEqual(1, os.lstat(self.lock_path()).st_nlink)
        self.assertEqual([], list(self.root.glob(f".{SUPERVISOR_LOCK_FILENAME}.*.tmp")))


@unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
class MultiprocessFirstUseRaceTests(unittest.TestCase):
    """Genuine multiprocess first-use publication race, scalable by env vars.

    Every child is a real subprocess; the round only starts once every child
    has reported readiness, so all contenders race the same missing target.
    """

    ROUNDS = max(1, int(os.environ.get("AGENTCHATTR_FENCE_STRESS_ROUNDS", "2")))
    PROCESSES = max(2, int(os.environ.get("AGENTCHATTR_FENCE_STRESS_PROCESSES", "4")))

    CHILD_SCRIPT = textwrap.dedent(
        """
        import os
        import sys
        import time

        import autonomy.control_state as control_state
        from autonomy.control_state import (
            LockIntegrityError,
            LockUnavailableError,
            PermanentFileLock,
        )

        root, start_flag, ready_flag = sys.argv[1], sys.argv[2], sys.argv[3]

        real_publish = control_state._publish_permanent_lock

        def publish_spy(root_path, root_final, path):
            outcome = real_publish(root_path, root_final, path)
            print("PUBLISH", outcome[0], flush=True)
            return outcome

        control_state._publish_permanent_lock = publish_spy

        with open(ready_flag, "wb"):
            pass
        deadline = time.monotonic() + 60.0
        while not os.path.exists(start_flag):
            if time.monotonic() >= deadline:
                raise SystemExit(9)
            time.sleep(0.0005)
        try:
            lock = PermanentFileLock(root, "supervisor.lock")
        except LockUnavailableError:
            print("OUTCOME contended", flush=True)
            raise SystemExit(23)
        except LockIntegrityError as exc:
            if getattr(exc.__cause__, "winerror", None) == 32:
                print("OUTCOME fail-closed-sharing", flush=True)
                raise SystemExit(29)
            raise
        print("OUTCOME acquired", flush=True)
        lock.close()
        raise SystemExit(0)
        """
    )

    def run_round(self):
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            (root / ROOT_MARKER).write_bytes(CANONICAL_ROOT_MARKER)
            start_flag = root / "start-flag"
            children = []
            for index in range(self.PROCESSES):
                ready_flag = root / f"ready-{index}"
                children.append(
                    (
                        subprocess.Popen(
                            [
                                sys.executable,
                                "-c",
                                self.CHILD_SCRIPT,
                                os.fspath(root),
                                os.fspath(start_flag),
                                os.fspath(ready_flag),
                            ],
                            cwd=REPO_ROOT,
                            env=subprocess_environment(),
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        ),
                        ready_flag,
                    )
                )
            results = []
            try:
                deadline = time.monotonic() + 60.0
                while not all(ready.exists() for _child, ready in children):
                    for child, _ready in children:
                        if child.poll() is not None:
                            stdout, stderr = child.communicate(timeout=30)
                            self.fail(f"child exited before start: {stdout} {stderr}")
                    if time.monotonic() >= deadline:
                        self.fail("children never became ready")
                    time.sleep(0.001)
                start_flag.write_bytes(b"go")
                for child, _ready in children:
                    stdout, stderr = child.communicate(timeout=120)
                    results.append((child.returncode, stdout, stderr))
            finally:
                for child, _ready in children:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=30)
            for returncode, stdout, stderr in results:
                self.assertIsNotNone(returncode)
                self.assertIn(
                    returncode, (0, 23, 29), f"rc={returncode} out={stdout} err={stderr}"
                )
            publication_wins = sum(
                stdout.count("PUBLISH won") for _rc, stdout, _err in results
            )
            self.assertEqual(1, publication_wins, results)
            acquired = sum(1 for returncode, _out, _err in results if returncode == 0)
            self.assertGreaterEqual(acquired, 1, results)
            lock_path = root / SUPERVISOR_LOCK_FILENAME
            self.assertEqual(b"\0", lock_path.read_bytes())
            self.assertEqual(1, os.lstat(lock_path).st_nlink)
            self.assertEqual(
                [], list(root.glob(f".{SUPERVISOR_LOCK_FILENAME}.*.tmp"))
            )

    def test_multiprocess_first_use_race_has_exactly_one_publication_winner(self):
        for round_index in range(self.ROUNDS):
            with self.subTest(round=round_index):
                self.run_round()


class NtRenameTargetTests(unittest.TestCase):
    """Deterministic NT rename-namespace conversion, no SMB share required."""

    def test_exact_namespace_conversion_table(self):
        table = {
            "C:\\q\\supervisor.lock": "\\??\\C:\\q\\supervisor.lock",
            "\\\\server\\share\\q\\supervisor.lock": (
                "\\??\\UNC\\server\\share\\q\\supervisor.lock"
            ),
            "\\\\?\\C:\\q\\supervisor.lock": "\\??\\C:\\q\\supervisor.lock",
            "\\\\?\\UNC\\server\\share\\q\\supervisor.lock": (
                "\\??\\UNC\\server\\share\\q\\supervisor.lock"
            ),
        }
        for given, expected in table.items():
            with self.subTest(given=given):
                self.assertEqual(expected, control_state._nt_rename_target(given))

    def test_extended_unc_is_checked_before_generic_extended(self):
        converted = control_state._nt_rename_target(
            "\\\\?\\UNC\\server\\share\\file"
        )
        # Extended UNC must map to \??\UNC\..., never to a blind \??\ prefix
        # of the raw text and never to a double UNC prefix.
        self.assertEqual("\\??\\UNC\\server\\share\\file", converted)
        self.assertNotIn("\\??\\UNC\\UNC\\", converted)
        self.assertNotIn("?\\UNC\\?\\", converted)

    def test_malformed_targets_are_rejected_not_prefixed(self):
        rejected = (
            "",
            "q\\supervisor.lock",
            "C:supervisor.lock",
            "\\q\\supervisor.lock",
            "C:\\",
            "C:/q/supervisor.lock",
            "C:\\q\\supervisor.lock\x00",
            "C:\\q\\..\\supervisor.lock",
            "C:\\q\\.\\supervisor.lock",
            "C:\\q\\\\supervisor.lock",
            "\\\\.\\C:\\q\\supervisor.lock",
            "\\\\.\\PhysicalDrive0",
            "\\\\server",
            "\\\\server\\",
            "\\\\server\\share",
            "\\\\\\share\\file",
            "\\\\server\\share\\..\\file",
            "\\??\\C:\\q\\supervisor.lock",
            "\\??\\UNC\\server\\share\\file",
            "\\\\?\\",
            "\\\\?\\UNC",
            "\\\\?\\UNC\\server",
            "\\\\?\\UNC\\server\\share",
            "\\\\?\\q\\supervisor.lock",
            "\\\\?x\\q\\supervisor.lock",
        )
        for bad in rejected:
            with self.subTest(bad=bad), self.assertRaises(PathSecurityError):
                control_state._nt_rename_target(bad)


class RenameComponentHardeningTests(unittest.TestCase):
    """UNC server/share/tail and drive-tail component hardening."""

    DEVICE_BASENAMES = (
        ("CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$")
        + tuple(f"COM{index}" for index in range(1, 10))
        + tuple(f"LPT{index}" for index in range(1, 10))
    )

    def assert_rejected(self, target):
        with self.assertRaises(PathSecurityError):
            control_state._nt_rename_target(target)

    def test_reserved_device_components_are_rejected_case_insensitively(self):
        for device in self.DEVICE_BASENAMES:
            for component in (device, device.lower(), f"{device}.txt"):
                for target in (
                    f"C:\\q\\{component}",
                    f"C:\\{component}\\supervisor.lock",
                    f"\\\\{component}\\share\\supervisor.lock",
                    f"\\\\server\\{component}\\supervisor.lock",
                    f"\\\\server\\share\\{component}",
                    f"\\\\?\\C:\\q\\{component}",
                    f"\\\\?\\UNC\\server\\share\\{component}",
                ):
                    with self.subTest(target=target):
                        self.assert_rejected(target)

    def test_control_and_reserved_punctuation_components_are_rejected(self):
        # "\x00" and "/" are also rejected structurally before the component
        # predicate; either rejection layer is acceptable because the public
        # conversion entry point is what stays pinned.
        for character in ("\x00", "\x01", "\x1f", "<", ">", ":", '"', "/", "|", "?", "*"):
            for target in (
                f"C:\\q\\bad{character}name",
                f"\\\\server\\share\\bad{character}name",
                f"\\\\ser{character}ver\\share\\supervisor.lock",
                f"\\\\server\\sh{character}are\\supervisor.lock",
            ):
                with self.subTest(target=target.encode("unicode_escape")):
                    self.assert_rejected(target)

    def test_trailing_dot_or_space_components_are_rejected(self):
        for component in ("file.", "file ", "dir.", "dir "):
            for target in (
                f"C:\\q\\{component}",
                f"C:\\{component}\\supervisor.lock",
                f"\\\\server\\share\\{component}",
                f"\\\\{component}\\share\\supervisor.lock",
                f"\\\\server\\{component}\\supervisor.lock",
            ):
                with self.subTest(target=target):
                    self.assert_rejected(target)

    def test_pseudo_nt_form_is_rejected_exactly(self):
        self.assert_rejected("\\??\\C:\\q\\supervisor.lock")

    def test_accepted_canonical_conversions_are_preserved(self):
        table = {
            "C:\\q\\supervisor.lock": "\\??\\C:\\q\\supervisor.lock",
            "\\\\server\\share\\q\\supervisor.lock": (
                "\\??\\UNC\\server\\share\\q\\supervisor.lock"
            ),
            "\\\\?\\C:\\q\\supervisor.lock": "\\??\\C:\\q\\supervisor.lock",
            "\\\\?\\UNC\\server\\share\\q\\supervisor.lock": (
                "\\??\\UNC\\server\\share\\q\\supervisor.lock"
            ),
        }
        for given, expected in table.items():
            with self.subTest(given=given):
                self.assertEqual(expected, control_state._nt_rename_target(given))

    @unittest.skipUnless(os.name == "nt", "the kernel rename seam is Windows-only")
    def test_malformed_targets_never_reach_the_kernel_rename(self):
        kernel_calls = []

        def kernel_sentinel(*arguments):
            kernel_calls.append(arguments)
            raise AssertionError("kernel rename reached with a malformed target")

        with mock.patch.object(
            control_state._kernel32,
            "SetFileInformationByHandle",
            new=kernel_sentinel,
        ):
            for bad in (
                "\\??\\C:\\q\\supervisor.lock",
                "C:\\q\\NUL.txt",
                "C:\\q\\bad<name",
                "C:\\q\\file.",
                "C:\\q\\file ",
                "\\\\server\\share\\CONOUT$",
                "\\\\CLOCK$\\share\\supervisor.lock",
            ):
                with self.subTest(bad=bad), self.assertRaises(PathSecurityError):
                    control_state._win_rename_no_replace(0, bad)
        self.assertEqual([], kernel_calls)


@unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
class PublicationCleanupTests(ControlStateFixture):
    """Handle-bound publication finalization is mandatory, ordered, fail closed."""

    def lock_path(self):
        return self.root / SUPERVISOR_LOCK_FILENAME

    def temp_glob(self):
        return list(self.root.glob(f".{SUPERVISOR_LOCK_FILENAME}.*.tmp"))

    def publisher_capture(self):
        """Spy that records the exact CREATE_NEW publisher temp handle."""

        created = []
        real_create = control_state._win_create_file

        def create_spy(path, access, share, disposition, flags):
            handle = real_create(path, access, share, disposition, flags)
            if disposition == control_state._CREATE_NEW:
                created.append(handle)
            return handle

        return created, mock.patch(
            "autonomy.control_state._win_create_file", side_effect=create_spy
        )

    def collide_seam(self):
        def collide(path):
            path.write_bytes(b"\0")

        return mock.patch(
            "autonomy.control_state._lock_publish_seam", side_effect=collide
        )

    def test_collision_with_disposition_failure_is_integrity_on_same_handle(self):
        created, create_patch = self.publisher_capture()
        dispose_calls = []

        def dispose_fail(handle):
            dispose_calls.append(handle)
            raise OSError(errno.EACCES, "injected disposition failure", None, 5)

        with create_patch, self.collide_seam(), mock.patch(
            "autonomy.control_state._win_dispose", side_effect=dispose_fail
        ):
            with self.assertRaises(LockIntegrityError) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertEqual(1, len(created))
        self.assertEqual(created, dispose_calls)
        self.assertEqual(5, trap.exception.__cause__.winerror)
        # The loser's private temp survives only because disposition was
        # injected to fail; the publisher handle itself was still closed, so
        # this in-fixture unlink succeeds without a sharing violation.
        temps = self.temp_glob()
        self.assertEqual(1, len(temps))
        os.unlink(temps[0])

    def test_disposition_winerror_33_is_integrity_never_contention(self):
        created, create_patch = self.publisher_capture()

        def dispose_fail(handle):
            raise OSError(errno.EACCES, "injected lock violation", None, 33)

        with create_patch, self.collide_seam(), mock.patch(
            "autonomy.control_state._win_dispose", side_effect=dispose_fail
        ):
            with self.assertRaises(LockIntegrityError) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertNotIsInstance(trap.exception, LockUnavailableError)
        self.assertEqual(33, trap.exception.__cause__.winerror)
        temps = self.temp_glob()
        self.assertEqual(1, len(temps))
        os.unlink(temps[0])

    def test_preparation_failure_with_disposition_failure_preserves_both(self):
        def dispose_fail(handle):
            raise OSError(errno.EACCES, "injected disposition failure", None, 5)

        with mock.patch(
            "autonomy.control_state._win_flush",
            side_effect=OSError(errno.EACCES, "injected flush failure", None, 31),
        ), mock.patch(
            "autonomy.control_state._win_dispose", side_effect=dispose_fail
        ):
            with self.assertRaises(BaseExceptionGroup) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        group = trap.exception
        self.assertEqual(2, len(group.exceptions))
        self.assertIsInstance(group.exceptions[0], LockIntegrityError)
        self.assertIn("prepared", str(group.exceptions[0]))
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        self.assertIn("disposed", str(group.exceptions[1]))
        temps = self.temp_glob()
        self.assertEqual(1, len(temps))
        os.unlink(temps[0])

    def test_primary_plus_both_cleanup_failures_raise_ordered_triple(self):
        created, create_patch = self.publisher_capture()
        real_close = control_state._win_close

        def close_spy(handle):
            real_close(handle)
            if created and handle == created[0]:
                raise OSError(errno.EBADF, "injected close failure", None, 6)

        def dispose_fail(handle):
            raise OSError(errno.EACCES, "injected disposition failure", None, 5)

        with create_patch, mock.patch(
            "autonomy.control_state._win_flush",
            side_effect=OSError(errno.EACCES, "injected flush failure", None, 31),
        ), mock.patch(
            "autonomy.control_state._win_dispose", side_effect=dispose_fail
        ), mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        ):
            with self.assertRaises(BaseExceptionGroup) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        group = trap.exception
        self.assertEqual(3, len(group.exceptions))
        self.assertIn("prepared", str(group.exceptions[0]))
        self.assertIn("disposed", str(group.exceptions[1]))
        self.assertIn("close failed", str(group.exceptions[2]))
        for member in group.exceptions:
            self.assertIsInstance(member, LockIntegrityError)
        temps = self.temp_glob()
        self.assertEqual(1, len(temps))
        os.unlink(temps[0])

    def test_collision_close_failure_after_real_disposition_is_integrity(self):
        created, create_patch = self.publisher_capture()
        real_close = control_state._win_close

        def close_spy(handle):
            real_close(handle)
            if created and handle == created[0]:
                raise OSError(errno.EBADF, "injected close failure", None, 6)

        with create_patch, self.collide_seam(), mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        ):
            with self.assertRaises(LockIntegrityError) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertEqual(6, trap.exception.__cause__.winerror)
        # Real disposition plus the real close deleted the loser's temp
        # through the exact publisher handle; nothing was path-unlinked.
        self.assertEqual([], self.temp_glob())
        self.assertEqual(b"\0", self.lock_path().read_bytes())

    def test_successful_rename_never_disposes_and_reports_late_close_failure(self):
        created, create_patch = self.publisher_capture()
        dispose_calls = []

        def dispose_spy(handle):
            dispose_calls.append(handle)
            raise AssertionError("disposition ran after a successful rename")

        real_close = control_state._win_close

        def close_spy(handle):
            real_close(handle)
            if created and handle == created[0]:
                raise OSError(errno.EBADF, "injected close failure", None, 6)

        with create_patch, mock.patch(
            "autonomy.control_state._win_dispose", side_effect=dispose_spy
        ), mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        ):
            with self.assertRaises(LockIntegrityError) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertEqual([], dispose_calls)
        self.assertEqual(6, trap.exception.__cause__.winerror)
        # The published target was validated and never disposed.
        self.assertEqual(b"\0", self.lock_path().read_bytes())
        self.assertEqual([], self.temp_glob())
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()


@unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
class ReleaseExceptionSafetyTests(ControlStateFixture):
    """Every release step runs even under hostile BaseException injection."""

    RELEASE_POSITIONS = (
        "seam",
        "checkpoint",
        "unlock",
        "close-lock",
        "close-marker",
        "close-root",
    )

    def lock_path(self):
        return self.root / SUPERVISOR_LOCK_FILENAME

    def run_release_injection(self, hostile_type, position):
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        retained = (lock._lock_handle, lock._marker_handle, lock._root_handle)
        target_handles = {
            "close-lock": lock._lock_handle,
            "close-marker": lock._marker_handle,
            "close-root": lock._root_handle,
        }
        hostile = hostile_type(f"injected at {position}")
        closes = []
        real_close = control_state._win_close
        real_unlock = control_state._win_unlock

        def close_spy(handle):
            # The real kernel close always runs first so no handle leaks.
            real_close(handle)
            closes.append(handle)
            if handle == target_handles.get(position):
                raise hostile

        patches = [
            mock.patch("autonomy.control_state._win_close", side_effect=close_spy)
        ]
        if position == "seam":
            patches.append(
                mock.patch(
                    "autonomy.control_state._pre_unlock_seam", side_effect=hostile
                )
            )
        elif position == "checkpoint":
            patches.append(
                mock.patch(
                    "autonomy.control_state._revalidate_root_handle",
                    side_effect=hostile,
                )
            )
        elif position == "unlock":

            def unlock_spy(handle, offset):
                real_unlock(handle, offset)
                raise hostile

            patches.append(
                mock.patch(
                    "autonomy.control_state._win_unlock", side_effect=unlock_spy
                )
            )
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaises(hostile_type) as trap:
                lock.close()
        self.assertIs(hostile, trap.exception)
        for handle in retained:
            self.assertIn(handle, closes)
        self.assertTrue(lock.closed)
        follow_up = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        follow_up.close()

    def test_hostile_injection_at_each_release_position_still_releases(self):
        for hostile_type in (KeyboardInterrupt, SystemExit):
            for position in self.RELEASE_POSITIONS:
                with self.subTest(
                    hostile=hostile_type.__name__, position=position
                ):
                    self.run_release_injection(hostile_type, position)

    def test_seam_created_hardlink_is_caught_before_unlock_and_still_released(self):
        alias = self.root / "lock-alias"
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        unlocked = []
        real_unlock = control_state._win_unlock

        def unlock_spy(handle, offset):
            unlocked.append(offset)
            return real_unlock(handle, offset)

        def seam(path):
            os.link(self.lock_path(), alias)

        with mock.patch(
            "autonomy.control_state._pre_unlock_seam", side_effect=seam
        ), mock.patch(
            "autonomy.control_state._win_unlock", side_effect=unlock_spy
        ):
            with self.assertRaises(LockIntegrityError):
                lock.close()
        self.assertTrue(lock.closed)
        self.assertEqual([control_state._LOCK_OWNERSHIP_OFFSET], unlocked)
        os.unlink(alias)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_final_validation_runs_directly_before_unlock(self):
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        order = []
        real_validate = control_state._validate_lock_handle
        real_unlock = control_state._win_unlock

        def validate_spy(*args, **kwargs):
            order.append("validate")
            return real_validate(*args, **kwargs)

        def unlock_spy(handle, offset):
            order.append(("unlock", offset))
            return real_unlock(handle, offset)

        with mock.patch(
            "autonomy.control_state._validate_lock_handle", side_effect=validate_spy
        ), mock.patch(
            "autonomy.control_state._win_unlock", side_effect=unlock_spy
        ):
            lock.close()
        self.assertEqual(
            ["validate", ("unlock", control_state._LOCK_OWNERSHIP_OFFSET)], order
        )

    def test_multiple_release_failures_form_one_ordered_group(self):
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        hostile = KeyboardInterrupt("injected at seam")
        real_unlock = control_state._win_unlock

        def unlock_fail(handle, offset):
            real_unlock(handle, offset)
            raise OSError(errno.EACCES, "injected unlock failure", None, 33)

        with mock.patch(
            "autonomy.control_state._pre_unlock_seam", side_effect=hostile
        ), mock.patch(
            "autonomy.control_state._win_unlock", side_effect=unlock_fail
        ):
            with self.assertRaises(BaseExceptionGroup) as trap:
                lock.close()
        group = trap.exception
        self.assertEqual(2, len(group.exceptions))
        self.assertIs(hostile, group.exceptions[0])
        # WinError 33 outside the one ownership acquisition is integrity.
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        self.assertNotIsInstance(group.exceptions[1], LockUnavailableError)
        self.assertTrue(lock.closed)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def retained_open_capture(self):
        """Record every retained (non-probe) CreateFileW handle."""

        opened = []
        real_create = control_state._win_create_file

        def create_spy(path, access, share, disposition, flags):
            handle = real_create(path, access, share, disposition, flags)
            if access != control_state._FILE_READ_ATTRIBUTES:
                opened.append(handle)
            return handle

        return opened, mock.patch(
            "autonomy.control_state._win_create_file", side_effect=create_spy
        )

    def test_constructor_rollback_releases_every_handle_without_short_circuit(self):
        opened, create_patch = self.retained_open_capture()
        closes = []
        real_close = control_state._win_close

        def close_spy(handle):
            real_close(handle)
            closes.append(handle)

        sentinel = LockIntegrityError("injected constructor checkpoint failure")
        with create_patch, mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        ), mock.patch(
            "autonomy.control_state._revalidate_root_handle", side_effect=sentinel
        ):
            with self.assertRaises(LockIntegrityError) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertIs(sentinel, trap.exception)
        self.assertGreaterEqual(len(opened), 3)
        for handle in opened:
            self.assertIn(handle, closes)
        # The kernel ownership range was released during rollback.
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_constructor_rollback_failure_preserves_primary_in_ordered_group(self):
        sentinel = LockIntegrityError("injected constructor checkpoint failure")
        real_unlock = control_state._win_unlock

        def unlock_fail(handle, offset):
            real_unlock(handle, offset)
            raise OSError(errno.EACCES, "injected rollback unlock failure", None, 33)

        with mock.patch(
            "autonomy.control_state._revalidate_root_handle", side_effect=sentinel
        ), mock.patch(
            "autonomy.control_state._win_unlock", side_effect=unlock_fail
        ):
            with self.assertRaises(BaseExceptionGroup) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        group = trap.exception
        self.assertEqual(2, len(group.exceptions))
        self.assertIs(sentinel, group.exceptions[0])
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()


@unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
class RetainedHostileEvidenceTests(unittest.TestCase):
    """Complete retained-object hostile evidence for root, marker, and lock."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "queue"
        self.root.mkdir()
        (self.root / ROOT_MARKER).write_bytes(CANONICAL_ROOT_MARKER)

    def lock_path(self):
        return self.root / SUPERVISOR_LOCK_FILENAME

    def acquisition_spy(self):
        lock_calls = []
        real_lock = control_state._win_lock_exclusive

        def lock_spy(handle, offset):
            lock_calls.append(offset)
            return real_lock(handle, offset)

        return lock_calls, mock.patch(
            "autonomy.control_state._win_lock_exclusive", side_effect=lock_spy
        )

    def test_root_name_swap_to_canonical_decoy_fails_closed_before_lock(self):
        aside = self.base / "queue-aside"

        def swap(path):
            os.rename(self.root, aside)
            self.root.mkdir()
            (self.root / ROOT_MARKER).write_bytes(CANONICAL_ROOT_MARKER)

        lock_calls, lock_patch = self.acquisition_spy()
        with lock_patch, mock.patch(
            "autonomy.control_state._root_open_seam", side_effect=swap
        ):
            with self.assertRaises(PathSecurityError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertEqual([], lock_calls)

    def test_byte_identical_marker_swap_fails_closed_before_lock(self):
        marker = self.root / ROOT_MARKER

        def swap(path):
            os.unlink(marker)
            marker.write_bytes(CANONICAL_ROOT_MARKER)

        lock_calls, lock_patch = self.acquisition_spy()
        with lock_patch, mock.patch(
            "autonomy.control_state._marker_open_seam", side_effect=swap
        ):
            with self.assertRaises(PathSecurityError):
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        self.assertEqual([], lock_calls)

    def run_final_path_mismatch(self, target_attribute):
        lock = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        target_handle = getattr(lock, target_attribute)
        retained = (lock._lock_handle, lock._marker_handle, lock._root_handle)
        real_facts = control_state._handle_facts
        real_close = control_state._win_close
        closes = []

        def facts_spy(handle):
            facts = real_facts(handle)
            if handle == target_handle:
                return dataclasses.replace(
                    facts, final_path=facts.final_path + "-diverged"
                )
            return facts

        def close_spy(handle):
            real_close(handle)
            closes.append(handle)

        with mock.patch(
            "autonomy.control_state._handle_facts", side_effect=facts_spy
        ), mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        ):
            with self.assertRaises(LockIntegrityError):
                lock.close()
        self.assertTrue(lock.closed)
        for handle in retained:
            self.assertIn(handle, closes)
        # The ownership lock itself was released despite the integrity report.
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()

    def test_root_final_kernel_path_mismatch_reports_integrity_and_releases(self):
        self.run_final_path_mismatch("_root_handle")

    def test_marker_final_kernel_path_mismatch_reports_integrity_and_releases(self):
        self.run_final_path_mismatch("_marker_handle")

    def test_lock_final_kernel_path_mismatch_reports_integrity_and_releases(self):
        self.run_final_path_mismatch("_lock_handle")


@unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
class EvidenceOrderingTests(ControlStateFixture):
    """Byte-zero evidence is validated strictly before ownership acquisition."""

    def test_offsets_and_permanent_bytes_are_pinned(self):
        self.assertEqual(0, control_state._LOCK_EVIDENCE_OFFSET)
        self.assertEqual(1, control_state._LOCK_OWNERSHIP_OFFSET)
        self.assertEqual(b"\0", control_state._PERMANENT_LOCK_BYTES)

    def test_evidence_read_precedes_the_single_ownership_acquisition(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        order = []
        real_read = control_state._win_read_exact
        real_lock = control_state._win_lock_exclusive

        def read_spy(handle, offset, length):
            order.append(("read", offset))
            return real_read(handle, offset, length)

        def lock_spy(handle, offset):
            order.append(("lock", offset))
            return real_lock(handle, offset)

        with mock.patch(
            "autonomy.control_state._win_read_exact", side_effect=read_spy
        ), mock.patch(
            "autonomy.control_state._win_lock_exclusive", side_effect=lock_spy
        ):
            PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        lock_events = [
            index for index, event in enumerate(order) if event[0] == "lock"
        ]
        self.assertEqual(1, len(lock_events))
        self.assertEqual(
            ("lock", control_state._LOCK_OWNERSHIP_OFFSET), order[lock_events[0]]
        )
        evidence_reads = [
            index
            for index, event in enumerate(order)
            if event == ("read", control_state._LOCK_EVIDENCE_OFFSET)
        ]
        self.assertTrue(evidence_reads)
        self.assertLess(min(evidence_reads), lock_events[0])


@unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
class LocalHandleFinalizerTests(ControlStateFixture):
    """Full no-primary/primary x close-outcome matrix for the primitive."""

    def open_local_handle(self):
        target = self.root / "finalizer-target"
        target.write_bytes(b"finalizer")
        return control_state._win_create_file(
            target,
            control_state._GENERIC_READ,
            control_state._FILE_SHARE_READ
            | control_state._FILE_SHARE_WRITE
            | control_state._FILE_SHARE_DELETE,
            control_state._OPEN_EXISTING,
            0,
        )

    def assert_handle_closed(self, handle):
        with self.assertRaises(OSError):
            control_state._handle_facts(handle)

    def raise_primary(self, primary):
        raise primary

    def run_matrix_case(self, primary, injected):
        handle = self.open_local_handle()
        closes = []
        real_close = control_state._win_close

        def close_spy(seen):
            # The real kernel close always runs first, and the injected
            # failure targets only the captured handle.
            real_close(seen)
            closes.append(seen)
            if injected is not None and seen == handle:
                raise injected

        outcome = None
        with mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        ):
            try:
                if primary is None:
                    control_state._finalize_local_handle(
                        handle, None, "matrix close failed"
                    )
                else:
                    try:
                        self.raise_primary(primary)
                    except BaseException as caught:
                        control_state._finalize_local_handle(
                            handle, caught, "matrix close failed"
                        )
                        raise
            except BaseException as raised:
                outcome = raised
        self.assertEqual([handle], closes)
        self.assert_handle_closed(handle)
        return outcome

    def test_no_primary_with_close_success_returns_none(self):
        self.assertIsNone(self.run_matrix_case(None, None))

    def test_no_primary_close_oserror_is_typed_integrity_with_cause(self):
        for winerror in (5, 33):
            with self.subTest(winerror=winerror):
                injected = OSError(
                    errno.EACCES, "injected close failure", None, winerror
                )
                outcome = self.run_matrix_case(None, injected)
                self.assertIsInstance(outcome, LockIntegrityError)
                self.assertNotIsInstance(outcome, LockUnavailableError)
                self.assertIs(injected, outcome.__cause__)

    def test_no_primary_close_keyboard_interrupt_is_preserved(self):
        injected = KeyboardInterrupt("injected close interrupt")
        self.assertIs(injected, self.run_matrix_case(None, injected))

    def test_primary_with_close_success_reraises_same_primary_with_frames(self):
        primary = LockIntegrityError("injected primary")
        outcome = self.run_matrix_case(primary, None)
        self.assertIs(primary, outcome)
        self.assertIn("raise_primary", traceback_function_names(outcome))

    def test_primary_plus_close_oserror_is_one_ordered_group(self):
        for winerror in (5, 33):
            with self.subTest(winerror=winerror):
                primary = LockIntegrityError("injected primary")
                injected = OSError(
                    errno.EACCES, "injected close failure", None, winerror
                )
                outcome = self.run_matrix_case(primary, injected)
                self.assertIsInstance(outcome, BaseExceptionGroup)
                self.assertEqual(2, len(outcome.exceptions))
                self.assertIs(primary, outcome.exceptions[0])
                self.assertIn(
                    "raise_primary",
                    traceback_function_names(outcome.exceptions[0]),
                )
                typed = outcome.exceptions[1]
                self.assertIsInstance(typed, LockIntegrityError)
                self.assertNotIsInstance(typed, LockUnavailableError)
                self.assertIs(injected, typed.__cause__)

    def test_primary_plus_close_keyboard_interrupt_is_one_ordered_group(self):
        primary = LockIntegrityError("injected primary")
        injected = KeyboardInterrupt("injected close interrupt")
        outcome = self.run_matrix_case(primary, injected)
        self.assertIsInstance(outcome, BaseExceptionGroup)
        self.assertEqual(2, len(outcome.exceptions))
        self.assertIs(primary, outcome.exceptions[0])
        self.assertIn(
            "raise_primary", traceback_function_names(outcome.exceptions[0])
        )
        self.assertIs(injected, outcome.exceptions[1])


@unittest.skipUnless(os.name == "nt", "Win32 lock semantics are Windows-only")
class HelperLocalHandleOwnershipTests(ControlStateFixture):
    """Every helper-local handle has exactly one owner and one close attempt."""

    def lock_path(self):
        return self.root / SUPERVISOR_LOCK_FILENAME

    def create_capture(self, probes, retained, closes=None, close_start=None):
        """Capture probe/retained opens; ``close_start[i]`` is the length of
        ``closes`` at the instant ``retained[i]`` was opened.

        Closed Win32 handle values are recycled, so close bookkeeping for a
        retained handle must only consider closes recorded from its own open
        onward; earlier entries can carry the same recycled value.
        """

        real_create = control_state._win_create_file

        def create_spy(path, access, share, disposition, flags):
            handle = real_create(path, access, share, disposition, flags)
            if access == control_state._FILE_READ_ATTRIBUTES:
                probes.append(handle)
            else:
                if close_start is not None and closes is not None:
                    close_start.append(len(closes))
                retained.append(handle)
            return handle

        return mock.patch(
            "autonomy.control_state._win_create_file", side_effect=create_spy
        )

    def assert_one_close_since_open(self, closes, close_start, retained, index):
        self.assertEqual(
            1, closes[close_start[index]:].count(retained[index])
        )

    def close_recorder(self, closes, target_box=None, injected=None):
        real_close = control_state._win_close

        def close_spy(handle):
            # The real kernel close always runs first, and the injected
            # failure targets only the captured handle.
            real_close(handle)
            closes.append(handle)
            if injected is not None and target_box and handle == target_box[0]:
                raise injected

        return mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        )

    def marker_write_open_roundtrip(self):
        # A kernel-visible incompatible write-open proves the retained
        # share-read-only handle is truly gone; a compatible fresh fence
        # acquisition alone would not.
        with (self.root / ROOT_MARKER).open("r+b"):
            pass

    def lock_write_open_roundtrip(self):
        with self.lock_path().open("r+b"):
            pass

    def rename_restore_root(self):
        aside = Path(os.fspath(self.root) + "-aside")
        os.rename(self.root, aside)
        os.rename(aside, self.root)

    # -- transient probe helper ------------------------------------------

    def test_probe_success_close_failure_is_integrity_never_success(self):
        probes, retained, closes = [], [], []
        injected = OSError(errno.EACCES, "injected close failure", None, 33)
        with self.create_capture(probes, retained), self.close_recorder(
            closes, target_box=probes, injected=injected
        ):
            with self.assertRaises(LockIntegrityError) as trap:
                control_state._probe_facts(self.root / ROOT_MARKER)
        self.assertNotIsInstance(trap.exception, LockUnavailableError)
        self.assertIs(injected, trap.exception.__cause__)
        self.assertEqual(1, len(probes))
        self.assertEqual([probes[0]], closes)

    def test_probe_primary_with_close_success_reraises_same_primary(self):
        probes, retained, closes = [], [], []
        primary = KeyboardInterrupt("injected probe primary")

        def facts_fail(handle):
            raise primary

        outcome = None
        with self.create_capture(probes, retained), mock.patch(
            "autonomy.control_state._handle_facts", side_effect=facts_fail
        ), self.close_recorder(closes):
            # A manual trap preserves the traceback that assertRaises clears.
            try:
                control_state._probe_facts(self.root / ROOT_MARKER)
            except BaseException as raised:
                outcome = raised
            else:
                self.fail("probe unexpectedly succeeded")
        self.assertIs(primary, outcome)
        self.assertIn("facts_fail", traceback_function_names(primary))
        self.assertEqual([probes[0]], closes)

    def test_probe_primary_plus_close_failure_is_one_ordered_group(self):
        probes, retained, closes = [], [], []
        primary = KeyboardInterrupt("injected probe primary")
        injected = OSError(errno.EACCES, "injected close failure", None, 5)

        def facts_fail(handle):
            raise primary

        with self.create_capture(probes, retained), mock.patch(
            "autonomy.control_state._handle_facts", side_effect=facts_fail
        ), self.close_recorder(closes, target_box=probes, injected=injected):
            with self.assertRaises(BaseExceptionGroup) as trap:
                control_state._probe_facts(self.root / ROOT_MARKER)
        group = trap.exception
        self.assertEqual(2, len(group.exceptions))
        self.assertIs(primary, group.exceptions[0])
        self.assertIn("facts_fail", traceback_function_names(primary))
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        self.assertIs(injected, group.exceptions[1].__cause__)
        self.assertEqual([probes[0]], closes)

    # -- retained root helper --------------------------------------------

    def test_root_helper_transfers_open_handle_without_premature_close(self):
        closes = []
        with self.close_recorder(closes):
            handle, _final, _identity = control_state._open_root_handle(self.root)
            try:
                transferred_at = len(closes)
                aside = Path(os.fspath(self.root) + "-aside")
                # The kernel-visible rename denial proves the transferred
                # handle is genuinely still open.
                with self.assertRaises(OSError):
                    os.rename(self.root, aside)
            finally:
                control_state._win_close(handle)
        self.assertEqual([handle], closes[transferred_at:])
        self.rename_restore_root()

    def run_root_helper_failure(self, injected):
        probes, retained, closes, close_start = [], [], [], []
        primary = KeyboardInterrupt("injected root validation primary")
        real_facts = control_state._handle_facts

        def facts_fail(handle):
            if retained and handle == retained[0]:
                raise primary
            return real_facts(handle)

        with self.create_capture(
            probes, retained, closes, close_start
        ), mock.patch(
            "autonomy.control_state._handle_facts", side_effect=facts_fail
        ), self.close_recorder(closes, target_box=retained, injected=injected):
            try:
                control_state._open_root_handle(self.root)
            except BaseException as raised:
                outcome = raised
            else:
                self.fail("root helper unexpectedly succeeded")
        self.assertEqual(1, len(retained))
        self.assert_one_close_since_open(closes, close_start, retained, 0)
        self.rename_restore_root()
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        return primary, outcome

    def test_root_helper_failure_with_close_success_reraises_primary(self):
        primary, outcome = self.run_root_helper_failure(None)
        self.assertIs(primary, outcome)
        self.assertIn("facts_fail", traceback_function_names(outcome))

    def test_root_helper_failure_with_close_failure_is_one_ordered_group(self):
        injected = OSError(errno.EACCES, "injected close failure", None, 33)
        primary, outcome = self.run_root_helper_failure(injected)
        self.assertIsInstance(outcome, BaseExceptionGroup)
        self.assertEqual(2, len(outcome.exceptions))
        self.assertIs(primary, outcome.exceptions[0])
        self.assertIn(
            "facts_fail", traceback_function_names(outcome.exceptions[0])
        )
        self.assertIsInstance(outcome.exceptions[1], LockIntegrityError)
        self.assertNotIsInstance(outcome.exceptions[1], LockUnavailableError)
        self.assertIs(injected, outcome.exceptions[1].__cause__)

    # -- retained marker helper ------------------------------------------

    def test_marker_helper_transfers_open_handle_without_premature_close(self):
        root_handle, root_final, _identity = control_state._open_root_handle(
            self.root
        )
        try:
            closes = []
            with self.close_recorder(closes):
                marker_handle, _marker_identity = control_state._open_marker_handle(
                    self.root, root_final
                )
                try:
                    transferred_at = len(closes)
                    # The kernel-visible write-open denial proves the
                    # transferred handle is genuinely still open.
                    with self.assertRaises(OSError):
                        self.marker_write_open_roundtrip()
                finally:
                    control_state._win_close(marker_handle)
            self.assertEqual([marker_handle], closes[transferred_at:])
        finally:
            control_state._win_close(root_handle)
        self.marker_write_open_roundtrip()
        self.assertEqual(
            CANONICAL_ROOT_MARKER, (self.root / ROOT_MARKER).read_bytes()
        )

    def run_marker_helper_failure(self, injected):
        root_handle, root_final, _identity = control_state._open_root_handle(
            self.root
        )
        try:
            probes, retained, closes, close_start = [], [], [], []
            primary = KeyboardInterrupt("injected marker validation primary")
            real_facts = control_state._handle_facts

            def facts_fail(handle):
                if retained and handle == retained[0]:
                    raise primary
                return real_facts(handle)

            with self.create_capture(
                probes, retained, closes, close_start
            ), mock.patch(
                "autonomy.control_state._handle_facts", side_effect=facts_fail
            ), self.close_recorder(
                closes, target_box=retained, injected=injected
            ):
                try:
                    control_state._open_marker_handle(self.root, root_final)
                except BaseException as raised:
                    outcome = raised
                else:
                    self.fail("marker helper unexpectedly succeeded")
            self.assertEqual(1, len(retained))
            self.assert_one_close_since_open(closes, close_start, retained, 0)
        finally:
            control_state._win_close(root_handle)
        self.marker_write_open_roundtrip()
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        return primary, outcome

    def test_marker_helper_failure_with_close_success_reraises_primary(self):
        primary, outcome = self.run_marker_helper_failure(None)
        self.assertIs(primary, outcome)
        self.assertIn("facts_fail", traceback_function_names(outcome))

    def test_marker_helper_failure_with_close_failure_is_one_ordered_group(self):
        injected = OSError(errno.EACCES, "injected close failure", None, 33)
        primary, outcome = self.run_marker_helper_failure(injected)
        self.assertIsInstance(outcome, BaseExceptionGroup)
        self.assertEqual(2, len(outcome.exceptions))
        self.assertIs(primary, outcome.exceptions[0])
        self.assertIsInstance(outcome.exceptions[1], LockIntegrityError)
        self.assertIs(injected, outcome.exceptions[1].__cause__)

    # -- retained permanent-lock helper ------------------------------------

    def test_lock_helper_transfers_open_handle_without_premature_close(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        root_handle, root_final, _identity = control_state._open_root_handle(
            self.root
        )
        try:
            closes = []
            with self.close_recorder(closes):
                handle, _lock_identity, published = control_state._open_permanent_lock(
                    self.root, root_final, self.lock_path()
                )
                try:
                    self.assertFalse(published)
                    transferred_at = len(closes)
                    # The kernel-visible write-open denial proves the
                    # transferred handle is genuinely still open.
                    with self.assertRaises(OSError):
                        self.lock_write_open_roundtrip()
                finally:
                    control_state._win_close(handle)
            self.assertEqual([handle], closes[transferred_at:])
        finally:
            control_state._win_close(root_handle)
        self.lock_write_open_roundtrip()
        self.assertEqual(b"\0", self.lock_path().read_bytes())

    def run_lock_helper_failure(self, injected):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        root_handle, root_final, _identity = control_state._open_root_handle(
            self.root
        )
        try:
            probes, retained, closes, close_start = [], [], [], []
            primary = KeyboardInterrupt("injected lock validation primary")

            def validate_fail(handle, root_final_value, path, expected):
                raise primary

            with self.create_capture(
                probes, retained, closes, close_start
            ), mock.patch(
                "autonomy.control_state._validate_lock_handle",
                side_effect=validate_fail,
            ), self.close_recorder(
                closes, target_box=retained, injected=injected
            ):
                try:
                    control_state._open_permanent_lock(
                        self.root, root_final, self.lock_path()
                    )
                except BaseException as raised:
                    outcome = raised
                else:
                    self.fail("lock helper unexpectedly succeeded")
            self.assertEqual(1, len(retained))
            self.assert_one_close_since_open(closes, close_start, retained, 0)
        finally:
            control_state._win_close(root_handle)
        self.lock_write_open_roundtrip()
        aside = self.root / "lock-aside"
        os.rename(self.lock_path(), aside)
        os.rename(aside, self.lock_path())
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        return primary, outcome

    def test_lock_helper_failure_with_close_success_reraises_primary(self):
        primary, outcome = self.run_lock_helper_failure(None)
        self.assertIs(primary, outcome)
        self.assertIn("validate_fail", traceback_function_names(outcome))

    def test_lock_helper_failure_with_close_failure_is_one_ordered_group(self):
        injected = OSError(errno.EACCES, "injected close failure", None, 33)
        primary, outcome = self.run_lock_helper_failure(injected)
        self.assertIsInstance(outcome, BaseExceptionGroup)
        self.assertEqual(2, len(outcome.exceptions))
        self.assertIs(primary, outcome.exceptions[0])
        self.assertIsInstance(outcome.exceptions[1], LockIntegrityError)
        self.assertNotIsInstance(outcome.exceptions[1], LockUnavailableError)
        self.assertIs(injected, outcome.exceptions[1].__cause__)

    # -- transient post-loss authentication helper -------------------------

    def run_authentication_failure(self, primary, injected):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        root_handle, root_final, _identity = control_state._open_root_handle(
            self.root
        )
        try:
            probes, retained, closes, close_start = [], [], [], []
            patches = [self.create_capture(probes, retained, closes, close_start)]
            if primary is not None:

                def validate_fail(handle, root_final_value, path, expected):
                    raise primary

                patches.append(
                    mock.patch(
                        "autonomy.control_state._validate_lock_handle",
                        side_effect=validate_fail,
                    )
                )
            patches.append(
                self.close_recorder(closes, target_box=retained, injected=injected)
            )
            with contextlib.ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                try:
                    control_state._authenticate_published_lock(
                        root_final, self.lock_path()
                    )
                except BaseException as raised:
                    outcome = raised
                else:
                    self.fail("authentication unexpectedly succeeded")
            self.assertEqual(1, len(retained))
            self.assert_one_close_since_open(closes, close_start, retained, 0)
        finally:
            control_state._win_close(root_handle)
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        return outcome

    def test_authentication_close_failure_is_integrity_never_success(self):
        injected = OSError(errno.EACCES, "injected close failure", None, 33)
        outcome = self.run_authentication_failure(None, injected)
        self.assertIsInstance(outcome, LockIntegrityError)
        self.assertNotIsInstance(outcome, LockUnavailableError)
        self.assertIs(injected, outcome.__cause__)

    def test_authentication_primary_with_close_success_reraises_primary(self):
        primary = KeyboardInterrupt("injected authentication primary")
        outcome = self.run_authentication_failure(primary, None)
        self.assertIs(primary, outcome)
        self.assertIn("validate_fail", traceback_function_names(outcome))

    def test_authentication_primary_plus_close_failure_is_ordered_group(self):
        primary = KeyboardInterrupt("injected authentication primary")
        injected = OSError(errno.EACCES, "injected close failure", None, 5)
        outcome = self.run_authentication_failure(primary, injected)
        self.assertIsInstance(outcome, BaseExceptionGroup)
        self.assertEqual(2, len(outcome.exceptions))
        self.assertIs(primary, outcome.exceptions[0])
        self.assertIsInstance(outcome.exceptions[1], LockIntegrityError)
        self.assertIs(injected, outcome.exceptions[1].__cause__)

    # -- constructor end-to-end --------------------------------------------

    def test_constructor_propagates_helper_group_and_completes_rollback(self):
        probes, retained, closes, close_start = [], [], [], []
        primary = KeyboardInterrupt("injected marker validation primary")
        injected = OSError(errno.EBADF, "injected close failure", None, 6)
        real_facts = control_state._handle_facts
        real_close = control_state._win_close

        def facts_fail(handle):
            if len(retained) >= 2 and handle == retained[1]:
                raise primary
            return real_facts(handle)

        def close_spy(handle):
            real_close(handle)
            closes.append(handle)
            if len(retained) >= 2 and handle == retained[1]:
                raise injected

        with self.create_capture(
            probes, retained, closes, close_start
        ), mock.patch(
            "autonomy.control_state._handle_facts", side_effect=facts_fail
        ), mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        ):
            with self.assertRaises(BaseExceptionGroup) as trap:
                PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        group = trap.exception
        self.assertEqual(
            "helper failure and local handle close both failed", group.message
        )
        self.assertEqual(2, len(group.exceptions))
        self.assertIs(primary, group.exceptions[0])
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        self.assertIs(injected, group.exceptions[1].__cause__)
        self.assertEqual(2, len(retained))
        self.assert_one_close_since_open(closes, close_start, retained, 0)
        self.assert_one_close_since_open(closes, close_start, retained, 1)
        self.rename_restore_root()
        self.marker_write_open_roundtrip()
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()


if __name__ == "__main__":
    unittest.main()
