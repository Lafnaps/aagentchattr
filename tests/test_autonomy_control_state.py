from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from autonomy.control_state import (
    HALT_FILENAME,
    LockUnavailableError,
    MarkerConflictError,
    PathSecurityError,
    PermanentFileLock,
    SchemaError,
    UnsupportedPlatformError,
    create_halt,
    create_once_marker,
    halt_exists,
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


class ControlStateFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "autonomy-root.json").write_bytes(b"{}\n")
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
            result = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", self.attempt_dir, outside],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(
                    "directory symlinks and junctions unavailable: "
                    f"symlink={symlink_error}; junction={result.stdout.strip()}"
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

    @unittest.skipUnless(os.name == "nt", "msvcrt lock semantics are Windows-only")
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

    @unittest.skipUnless(os.name == "nt", "msvcrt lock semantics are Windows-only")
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
                cwd=Path(__file__).resolve().parents[1],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
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


if __name__ == "__main__":
    unittest.main()
