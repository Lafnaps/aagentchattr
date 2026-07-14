"""M2 checkpoint/heartbeat slice: deterministic fail-closed tests.

Hermetic — temp directories only, no live processes.  Threads appear only in
the HeartbeatLoop.start() failure-observability tests and are always joined
with bounded timeouts.  Covers atomic replacement with a full write/flush/
fsync/replace/directory-fsync fault matrix, strict autonomy-root.json marker
authentication, canonical attempts/<task_id>/a<attempt> binding, heartbeat/
progress separation, the 2048-byte cap, corrupt schemas, traversal and
symlink/junction escapes (skipped where the platform cannot create links),
and task/attempt mismatches.
"""

import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from autonomy import checkpoint as cp
from autonomy import heartbeat as hb

NOW = datetime(2026, 7, 13, 1, 2, 3, 123456, tzinfo=timezone.utc)
NOW_TEXT = "2026-07-13T01:02:03.123Z"
TASK = "night-task-7"
ATTEMPT = 2


def make_dir_link(link, target):
    """Directory symlink, or NTFS junction as fallback; False when unsupported."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        try:
            import _winapi

            _winapi.CreateJunction(str(target), str(link))
            return True
        except (ImportError, OSError):
            return False
    return False


def remove_dir_link(link):
    """Remove a directory symlink/junction without traversing its target."""
    if link.is_symlink():
        link.unlink()
    else:
        os.rmdir(link)


class AutonomyStateCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # realpath so path-equality assertions hold when the temp dir itself
        # sits behind a symlink (macOS: /var -> /private/var).
        self.base = Path(os.path.realpath(tmp.name))
        self.root = self.base / "qroot"
        (self.root / "attempts" / TASK).mkdir(parents=True)
        (self.root / cp.ROOT_MARKER).write_text(
            json.dumps({"version": 1, "name": "agentchattr-autonomy-queue"}), encoding="ascii"
        )
        self.adir = self.root / "attempts" / TASK / f"a{ATTEMPT}"
        self.adir.mkdir()

    # -- helpers ----------------------------------------------------------
    def write_cp(self, **overrides):
        kwargs = dict(
            task_id=TASK,
            attempt=ATTEMPT,
            completed_step="fetch",
            next_step="build",
            artifacts=["out/report.md"],
            now=NOW,
        )
        kwargs.update(overrides)
        return cp.write_checkpoint(self.root, self.adir, **kwargs)

    def read_cp(self, task_id=TASK, attempt=ATTEMPT, attempt_dir=None):
        return cp.read_checkpoint(
            self.root, attempt_dir if attempt_dir is not None else self.adir,
            task_id=task_id, attempt=attempt,
        )

    def raw(self, filename):
        return (self.adir / filename).read_bytes()

    def write_raw(self, filename, document):
        (self.adir / filename).write_bytes(
            json.dumps(document, separators=(",", ":")).encode("ascii")
        )

    def valid_cp_doc(self):
        return {
            "version": 1,
            "task_id": TASK,
            "attempt": ATTEMPT,
            "completed_step": "fetch",
            "next_step": "build",
            "artifacts": ["out/report.md"],
            "updated_at": NOW_TEXT,
        }

    def valid_hb_doc(self):
        return {
            "version": 1,
            "task_id": TASK,
            "attempt": ATTEMPT,
            "profile": "night-worker",
            "model": "claude-fable-5",
            "pid": 4242,
            "updated_at": NOW_TEXT,
        }

    def dir_names(self):
        return sorted(entry.name for entry in self.adir.iterdir())


class RoundtripTests(AutonomyStateCase):
    def test_checkpoint_roundtrip(self):
        path = self.write_cp()
        self.assertEqual(path, self.adir / cp.CHECKPOINT_FILENAME)
        doc = self.read_cp()
        self.assertEqual(doc["task_id"], TASK)
        self.assertEqual(doc["attempt"], ATTEMPT)
        self.assertEqual(doc["completed_step"], "fetch")
        self.assertEqual(doc["next_step"], "build")
        self.assertEqual(doc["artifacts"], ["out/report.md"])
        self.assertEqual(doc["updated_at"], NOW_TEXT)

    def test_progress_roundtrip(self):
        cp.write_progress(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            status="running", detail="step 1 of 4", now=NOW,
        )
        doc = cp.read_progress(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)
        self.assertEqual(doc["status"], "running")
        self.assertEqual(doc["detail"], "step 1 of 4")
        self.assertEqual(doc["updated_at"], NOW_TEXT)

    def test_heartbeat_roundtrip(self):
        hb.write_heartbeat(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            profile="night-worker", model="claude-fable-5", pid=4242, now=NOW,
        )
        doc = hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)
        self.assertEqual(doc["profile"], "night-worker")
        self.assertEqual(doc["model"], "claude-fable-5")
        self.assertEqual(doc["pid"], 4242)
        self.assertEqual(doc["updated_at"], NOW_TEXT)

    def test_heartbeat_pid_defaults_to_current_process(self):
        hb.write_heartbeat(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            profile="night-worker", model="claude-fable-5", now=NOW,
        )
        doc = hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)
        self.assertEqual(doc["pid"], os.getpid())

    def test_none_steps_roundtrip(self):
        self.write_cp(completed_step=None, next_step=None, artifacts=[])
        doc = self.read_cp()
        self.assertIsNone(doc["completed_step"])
        self.assertIsNone(doc["next_step"])
        self.assertEqual(doc["artifacts"], [])

    def test_relative_attempt_dir_is_joined_to_root(self):
        relative = Path("attempts") / TASK / f"a{ATTEMPT}"
        cp.write_checkpoint(
            self.root, relative, task_id=TASK, attempt=ATTEMPT,
            completed_step="fetch", next_step=None, now=NOW,
        )
        doc = self.read_cp(attempt_dir=relative)
        self.assertEqual(doc["completed_step"], "fetch")

    def test_missing_checkpoint_raises_missing_document(self):
        with self.assertRaises(cp.MissingDocumentError):
            self.read_cp()

    def test_no_stray_files_after_writes(self):
        self.write_cp()
        cp.write_progress(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT, status="running", now=NOW,
        )
        hb.write_heartbeat(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            profile="night-worker", model="claude-fable-5", pid=1, now=NOW,
        )
        self.assertEqual(
            self.dir_names(),
            sorted([cp.CHECKPOINT_FILENAME, cp.PROGRESS_FILENAME, hb.HEARTBEAT_FILENAME]),
        )


class AtomicWriteTests(AutonomyStateCase):
    def test_replace_called_with_temp_from_same_directory(self):
        calls = []
        real_replace = cp._replace_bound_temp

        def spy(temp, filename):
            calls.append((temp.binding.path / temp.name, temp.binding.path / filename))
            real_replace(temp, filename)

        with mock.patch("autonomy.checkpoint._replace_bound_temp", new=spy):
            self.write_cp()
        self.assertEqual(len(calls), 1)
        src, dst = calls[0]
        self.assertEqual(dst, self.adir / cp.CHECKPOINT_FILENAME)
        self.assertEqual(src.parent, dst.parent)
        self.assertTrue(src.name.startswith(cp.CHECKPOINT_FILENAME + "."))
        self.assertTrue(src.name.endswith(".tmp"))

    def test_old_content_survives_until_replace(self):
        self.write_cp(next_step="build")
        before = self.raw(cp.CHECKPOINT_FILENAME)
        seen = {}
        real_replace = cp._replace_bound_temp

        def spy(temp, filename):
            seen["at_replace"] = (temp.binding.path / filename).read_bytes()
            real_replace(temp, filename)

        with mock.patch("autonomy.checkpoint._replace_bound_temp", new=spy):
            self.write_cp(next_step="test", now=NOW + timedelta(seconds=5))
        self.assertEqual(seen["at_replace"], before)
        self.assertEqual(self.read_cp()["next_step"], "test")

    def test_interrupted_replace_cleans_temp_and_keeps_old_document(self):
        self.write_cp(next_step="build")
        before_bytes = self.raw(cp.CHECKPOINT_FILENAME)
        before_names = self.dir_names()

        def boom(temp, filename):
            raise OSError("simulated crash during replace")

        with mock.patch("autonomy.checkpoint._replace_bound_temp", new=boom):
            with self.assertRaises(OSError):
                self.write_cp(next_step="test", now=NOW + timedelta(seconds=5))
        self.assertEqual(self.dir_names(), before_names)
        self.assertEqual(self.raw(cp.CHECKPOINT_FILENAME), before_bytes)
        self.assertEqual(self.read_cp()["next_step"], "build")

    def test_interrupted_progress_write_cleans_temp(self):
        before_names = self.dir_names()

        def boom(temp, filename):
            raise OSError("simulated crash during replace")

        with mock.patch("autonomy.checkpoint._replace_bound_temp", new=boom):
            with self.assertRaises(OSError):
                cp.write_progress(
                    self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
                    status="running", now=NOW,
                )
        self.assertEqual(self.dir_names(), before_names)


class SizeLimitTests(AutonomyStateCase):
    def oversized_artifacts(self):
        return [f"{'a' * 60}/{'b' * 60}/{'c' * 57}{i:03d}" for i in range(16)]

    def test_oversized_checkpoint_payload_rejected_before_any_write(self):
        with self.assertRaises(cp.SizeLimitError):
            self.write_cp(artifacts=self.oversized_artifacts())
        self.assertEqual(self.dir_names(), [])

    def test_oversized_file_on_disk_fails_closed(self):
        (self.adir / cp.CHECKPOINT_FILENAME).write_bytes(
            b'{"pad":"' + b"x" * 4096 + b'"}'
        )
        with self.assertRaises(cp.SizeLimitError):
            self.read_cp()

    def test_valid_checkpoint_is_compact(self):
        self.write_cp()
        self.assertLessEqual(
            len(self.raw(cp.CHECKPOINT_FILENAME)), cp.MAX_CHECKPOINT_BYTES
        )


class CorruptSchemaTests(AutonomyStateCase):
    def assert_cp_read_fails(self, error=cp.SchemaError):
        with self.assertRaises(error):
            self.read_cp()

    def test_not_json(self):
        (self.adir / cp.CHECKPOINT_FILENAME).write_bytes(b'{"task_id":')
        self.assert_cp_read_fails()

    def test_non_ascii_bytes(self):
        (self.adir / cp.CHECKPOINT_FILENAME).write_bytes(b"\xff\xfe{}")
        self.assert_cp_read_fails()

    def test_json_but_not_object(self):
        (self.adir / cp.CHECKPOINT_FILENAME).write_bytes(b"[]")
        self.assert_cp_read_fails()

    def test_duplicate_keys(self):
        (self.adir / cp.CHECKPOINT_FILENAME).write_bytes(b'{"version":1,"version":1}')
        self.assert_cp_read_fails()

    def test_missing_key(self):
        doc = self.valid_cp_doc()
        del doc["next_step"]
        self.write_raw(cp.CHECKPOINT_FILENAME, doc)
        self.assert_cp_read_fails()

    def test_extra_key(self):
        doc = self.valid_cp_doc()
        doc["note"] = "hi"
        self.write_raw(cp.CHECKPOINT_FILENAME, doc)
        self.assert_cp_read_fails()

    def test_wrong_field_types(self):
        mutations = {
            "attempt-as-string": ("attempt", "2"),
            "attempt-as-bool": ("attempt", True),
            "version-as-bool": ("version", True),
            "version-unsupported": ("version", 2),
            "task-as-int": ("task_id", 7),
            "artifacts-as-string": ("artifacts", "out/report.md"),
            "artifacts-of-ints": ("artifacts", [1]),
            "completed-as-int": ("completed_step", 3),
            "updated-as-int": ("updated_at", 123),
        }
        for label, (key, value) in mutations.items():
            with self.subTest(label):
                doc = self.valid_cp_doc()
                doc[key] = value
                self.write_raw(cp.CHECKPOINT_FILENAME, doc)
                self.assert_cp_read_fails()

    def test_bad_timestamps(self):
        for label, value in {
            "non-utc-offset": "2026-07-13T01:02:03.123+02:00",
            "naive": "2026-07-13T01:02:03.123",
            "utc-but-not-contract-format": "2026-07-13T01:02:03+00:00",
            "garbage": "yesterday",
            "impossible-date": "2026-13-13T01:02:03.123Z",
        }.items():
            with self.subTest(label):
                doc = self.valid_cp_doc()
                doc["updated_at"] = value
                self.write_raw(cp.CHECKPOINT_FILENAME, doc)
                self.assert_cp_read_fails()

    def test_stored_artifact_traversal_fails_closed(self):
        for label, value in {
            "dotdot": ["../../secrets.txt"],
            "absolute": ["/etc/passwd"],
            "drive": ["C:/windows/win.ini"],
            "backslash": ["out\\report.md"],
        }.items():
            with self.subTest(label):
                doc = self.valid_cp_doc()
                doc["artifacts"] = value
                self.write_raw(cp.CHECKPOINT_FILENAME, doc)
                self.assert_cp_read_fails(cp.CheckpointError)

    def test_corrupt_heartbeat_fails_closed(self):
        mutations = {
            "pid-as-string": ("pid", "77"),
            "pid-negative": ("pid", -1),
            "pid-as-bool": ("pid", True),
            "profile-uppercase": ("profile", "Night"),
            "model-bad-chars": ("model", "gpt?4"),
        }
        for label, (key, value) in mutations.items():
            with self.subTest(label):
                doc = self.valid_hb_doc()
                doc[key] = value
                self.write_raw(hb.HEARTBEAT_FILENAME, doc)
                with self.assertRaises(cp.SchemaError):
                    hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)

    def test_heartbeat_missing_key(self):
        doc = self.valid_hb_doc()
        del doc["pid"]
        self.write_raw(hb.HEARTBEAT_FILENAME, doc)
        with self.assertRaises(cp.SchemaError):
            hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)


class MismatchTests(AutonomyStateCase):
    def test_foreign_task_document_in_canonical_dir(self):
        # A validly-shaped document copied in from another task fails closed.
        doc = self.valid_cp_doc()
        doc["task_id"] = "other-task"
        self.write_raw(cp.CHECKPOINT_FILENAME, doc)
        with self.assertRaises(cp.StateMismatchError):
            self.read_cp()

    def test_foreign_attempt_document_in_canonical_dir(self):
        doc = self.valid_cp_doc()
        doc["attempt"] = ATTEMPT + 1
        self.write_raw(cp.CHECKPOINT_FILENAME, doc)
        with self.assertRaises(cp.StateMismatchError):
            self.read_cp()

    def test_foreign_heartbeat_document_in_canonical_dir(self):
        for key, value in (("task_id", "other-task"), ("attempt", ATTEMPT + 1)):
            with self.subTest(key):
                doc = self.valid_hb_doc()
                doc[key] = value
                self.write_raw(hb.HEARTBEAT_FILENAME, doc)
                with self.assertRaises(cp.StateMismatchError):
                    hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)

    def test_caller_ids_disagreeing_with_directory_fail_closed(self):
        # The canonical binding refuses the directory before any read happens.
        self.write_cp()
        with self.assertRaises(cp.PathEscapeError):
            self.read_cp(task_id="other-task")
        with self.assertRaises(cp.PathEscapeError):
            self.read_cp(attempt=ATTEMPT + 1)


class InputValidationTests(AutonomyStateCase):
    def test_malformed_task_ids_rejected(self):
        bad = ["", "UPPER", "has_underscore", "-lead", "a b", "a/b", "a\\b",
               "..", ".", "con", "nul", "x" * 65, None, 7]
        for task_id in bad:
            with self.subTest(repr(task_id)):
                with self.assertRaises(cp.SchemaError):
                    self.write_cp(task_id=task_id)

    def test_malformed_attempts_rejected(self):
        bad = [0, -1, True, False, "2", 2.0, None, cp.MAX_ATTEMPT + 1]
        for attempt in bad:
            with self.subTest(repr(attempt)):
                with self.assertRaises(cp.SchemaError):
                    self.write_cp(attempt=attempt)

    def test_malformed_steps_rejected(self):
        for label, kwargs in {
            "empty": {"completed_step": ""},
            "too-long": {"next_step": "x" * 129},
            "leading-space": {"completed_step": " x"},
            "trailing-space": {"next_step": "x "},
            "non-ascii": {"completed_step": "шаг"},
            "int": {"next_step": 5},
        }.items():
            with self.subTest(label):
                with self.assertRaises(cp.SchemaError):
                    self.write_cp(**kwargs)

    def test_malformed_artifacts_rejected(self):
        bad = ["", "/abs", "a//b", "../x", "a/../b", "dir\\file", "C:/win",
               "nul.txt", "trail.", "x" * 201, "/".join(["d"] * 9)]
        for artifact in bad:
            with self.subTest(repr(artifact)):
                with self.assertRaises(cp.CheckpointError):
                    self.write_cp(artifacts=[artifact])
        with self.subTest("bare-string"):
            with self.assertRaises(cp.SchemaError):
                self.write_cp(artifacts="out/report.md")
        with self.subTest("duplicates"):
            with self.assertRaises(cp.SchemaError):
                self.write_cp(artifacts=["a.txt", "a.txt"])

    def test_malformed_progress_fields_rejected(self):
        with self.assertRaises(cp.SchemaError):
            cp.write_progress(
                self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
                status="Running", now=NOW,
            )
        with self.assertRaises(cp.SchemaError):
            cp.write_progress(
                self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
                status="running", detail="π is not ascii", now=NOW,
            )

    def test_malformed_heartbeat_fields_rejected(self):
        base = dict(task_id=TASK, attempt=ATTEMPT, profile="night-worker",
                    model="claude-fable-5", pid=1, now=NOW)
        for label, overrides in {
            "profile": {"profile": "Night Worker"},
            "model": {"model": "GPT/4"},
            "pid-zero": {"pid": 0},
            "pid-bool": {"pid": True},
            "pid-huge": {"pid": hb.MAX_PID + 1},
        }.items():
            with self.subTest(label):
                kwargs = dict(base)
                kwargs.update(overrides)
                with self.assertRaises(cp.SchemaError):
                    hb.write_heartbeat(self.root, self.adir, **kwargs)


class PathEscapeTests(AutonomyStateCase):
    def test_attempt_dir_outside_root(self):
        outside = self.base / "outside"
        outside.mkdir()
        with self.assertRaises(cp.PathEscapeError):
            cp.write_checkpoint(
                self.root, outside, task_id=TASK, attempt=ATTEMPT,
                completed_step=None, next_step=None, now=NOW,
            )

    def test_attempt_dir_traversal_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        with self.assertRaises(cp.PathEscapeError):
            self.read_cp(attempt_dir=Path("attempts") / ".." / ".." / "outside")

    def test_attempt_dir_equal_to_root_rejected(self):
        with self.assertRaises(cp.PathEscapeError):
            self.read_cp(attempt_dir=self.root)

    def test_missing_attempt_dir_rejected(self):
        # Canonical binding holds (task and attempt match the path), but the
        # directory does not exist.
        with self.assertRaises(cp.PathEscapeError):
            self.read_cp(attempt=9, attempt_dir=self.root / "attempts" / TASK / "a9")

    def test_root_without_marker_rejected(self):
        bare = self.base / "bare"
        (bare / "attempts" / TASK / f"a{ATTEMPT}").mkdir(parents=True)
        with self.assertRaises(cp.PathEscapeError):
            cp.write_checkpoint(
                bare, bare / "attempts" / TASK / f"a{ATTEMPT}",
                task_id=TASK, attempt=ATTEMPT,
                completed_step=None, next_step=None, now=NOW,
            )

    def test_relative_root_rejected(self):
        with self.assertRaises(cp.PathEscapeError):
            cp.write_checkpoint(
                Path("relative-root"), self.adir, task_id=TASK, attempt=ATTEMPT,
                completed_step=None, next_step=None, now=NOW,
            )

    def test_linked_attempt_dir_rejected_even_when_target_is_inside(self):
        # Fail closed on ANY linked attempt dir: escape target and inside
        # target alike.  The links carry canonical names so only the
        # reparse-point check can reject them.
        outside = self.base / "outside-target"
        outside.mkdir()
        escape_link = self.root / "attempts" / TASK / "a3"
        if not make_dir_link(escape_link, outside):
            self.skipTest("platform cannot create directory symlinks or junctions")
        inside_link = self.root / "attempts" / TASK / "a4"
        self.assertTrue(make_dir_link(inside_link, self.adir))
        for attempt, link in ((3, escape_link), (4, inside_link)):
            with self.subTest(link.name):
                with self.assertRaises(cp.PathEscapeError):
                    cp.write_checkpoint(
                        self.root, link, task_id=TASK, attempt=attempt,
                        completed_step=None, next_step=None, now=NOW,
                    )
                with self.assertRaises(cp.PathEscapeError):
                    self.read_cp(attempt=attempt, attempt_dir=link)

    def test_linked_task_dir_rejected(self):
        # A reparse point ABOVE the attempt dir (the task directory) fails closed.
        holder = self.base / "task-holder"
        (holder / "a1").mkdir(parents=True)
        linked_task = self.root / "attempts" / "night-task-6"
        if not make_dir_link(linked_task, holder):
            self.skipTest("platform cannot create directory symlinks or junctions")
        with self.assertRaises(cp.PathEscapeError):
            cp.write_checkpoint(
                self.root, linked_task / "a1", task_id="night-task-6", attempt=1,
                completed_step=None, next_step=None, now=NOW,
            )
        with self.assertRaises(cp.PathEscapeError):
            cp.read_checkpoint(
                self.root, linked_task / "a1", task_id="night-task-6", attempt=1,
            )

    def test_linked_attempts_dir_rejected(self):
        # A queue root whose whole attempts/ tree is a reparse point fails closed.
        root2 = self.base / "qroot2"
        root2.mkdir()
        (root2 / cp.ROOT_MARKER).write_bytes((self.root / cp.ROOT_MARKER).read_bytes())
        holder = self.base / "attempts-holder"
        (holder / TASK / "a1").mkdir(parents=True)
        if not make_dir_link(root2 / "attempts", holder):
            self.skipTest("platform cannot create directory symlinks or junctions")
        with self.assertRaises(cp.PathEscapeError):
            cp.write_checkpoint(
                root2, root2 / "attempts" / TASK / "a1", task_id=TASK, attempt=1,
                completed_step=None, next_step=None, now=NOW,
            )

    def test_artifact_through_linked_subdir_rejected(self):
        outside = self.base / "artifact-target"
        outside.mkdir()
        link = self.adir / "leak"
        if not make_dir_link(link, outside):
            self.skipTest("platform cannot create directory symlinks or junctions")
        with self.assertRaises(cp.PathEscapeError):
            self.write_cp(artifacts=["leak/secret.txt"])

    def test_state_file_symlink_rejected(self):
        target = self.base / "hb-target.json"
        target.write_bytes(json.dumps(self.valid_hb_doc(), separators=(",", ":")).encode())
        try:
            os.symlink(target, self.adir / hb.HEARTBEAT_FILENAME)
        except (OSError, NotImplementedError):
            self.skipTest("platform cannot create file symlinks")
        with self.assertRaises(cp.PathEscapeError):
            hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)
        with self.assertRaises(cp.PathEscapeError):
            hb.write_heartbeat(
                self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
                profile="night-worker", model="claude-fable-5", pid=1, now=NOW,
            )


class SeparationTests(AutonomyStateCase):
    def heartbeat_kwargs(self, **overrides):
        kwargs = dict(task_id=TASK, attempt=ATTEMPT, profile="night-worker",
                      model="claude-fable-5", pid=101)
        kwargs.update(overrides)
        return kwargs

    def test_heartbeat_never_touches_checkpoint_or_progress(self):
        self.write_cp()
        cp.write_progress(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            status="running", detail="step 1 of 4", now=NOW,
        )
        checkpoint_bytes = self.raw(cp.CHECKPOINT_FILENAME)
        progress_bytes = self.raw(cp.PROGRESS_FILENAME)

        for offset in range(3):
            hb.write_heartbeat(
                self.root, self.adir,
                **self.heartbeat_kwargs(now=NOW + timedelta(seconds=offset)),
            )
        loop = hb.HeartbeatLoop(
            hb.bind_heartbeat(self.root, self.adir, **self.heartbeat_kwargs()),
            interval_seconds=60.0,
        )
        loop.request_stop()
        loop.run()

        self.assertEqual(self.raw(cp.CHECKPOINT_FILENAME), checkpoint_bytes)
        self.assertEqual(self.raw(cp.PROGRESS_FILENAME), progress_bytes)
        doc = hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)
        self.assertEqual(doc["pid"], 101)

    def test_progress_changes_only_on_explicit_request(self):
        cp.write_progress(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            status="running", now=NOW,
        )
        before = self.raw(cp.PROGRESS_FILENAME)

        hb.write_heartbeat(self.root, self.adir, **self.heartbeat_kwargs(now=NOW))
        self.write_cp(now=NOW + timedelta(seconds=1))
        self.assertEqual(self.raw(cp.PROGRESS_FILENAME), before)

        cp.write_progress(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            status="reviewing", now=NOW + timedelta(seconds=2),
        )
        self.assertNotEqual(self.raw(cp.PROGRESS_FILENAME), before)
        doc = cp.read_progress(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)
        self.assertEqual(doc["status"], "reviewing")

    def test_state_documents_have_distinct_filenames(self):
        names = {cp.CHECKPOINT_FILENAME, cp.PROGRESS_FILENAME, hb.HEARTBEAT_FILENAME}
        self.assertEqual(len(names), 3)


class HeartbeatLoopTests(AutonomyStateCase):
    def test_prestopped_loop_beats_exactly_once(self):
        beats = []
        loop = hb.HeartbeatLoop(lambda: beats.append(1), interval_seconds=3600)
        loop.request_stop()
        self.assertEqual(loop.run(), 1)
        self.assertEqual(len(beats), 1)
        self.assertEqual(loop.beats, 1)

    def test_loop_stops_after_third_beat(self):
        count = 0
        loop_ref = {}

        def beat():
            nonlocal count
            count += 1
            if count == 3:
                loop_ref["loop"].request_stop()

        loop = hb.HeartbeatLoop(beat, interval_seconds=0.001)
        loop_ref["loop"] = loop
        self.assertEqual(loop.run(), 3)
        self.assertEqual(count, 3)

    def test_loop_writes_real_heartbeats(self):
        beat = hb.bind_heartbeat(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            profile="night-worker", model="claude-fable-5", pid=101,
        )
        loop = hb.HeartbeatLoop(beat, interval_seconds=3600)
        loop.request_stop()
        loop.run()
        doc = hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)
        self.assertEqual(doc["pid"], 101)

    def test_invalid_intervals_rejected(self):
        for interval in [0, -5, float("nan"), float("inf"), True, "5",
                         hb.MAX_INTERVAL_SECONDS + 1]:
            with self.subTest(repr(interval)):
                with self.assertRaises(cp.SchemaError):
                    hb.HeartbeatLoop(lambda: None, interval_seconds=interval)

    def test_non_callable_beat_rejected(self):
        with self.assertRaises(cp.SchemaError):
            hb.HeartbeatLoop("not-callable", interval_seconds=60)

    def test_stop_without_start_is_safe(self):
        loop = hb.HeartbeatLoop(lambda: None, interval_seconds=60)
        self.assertTrue(loop.stop())
        self.assertTrue(loop.stop_requested)

    def test_beat_exception_propagates(self):
        def beat():
            raise RuntimeError("sidecar lost the disk")

        loop = hb.HeartbeatLoop(beat, interval_seconds=60)
        with self.assertRaises(RuntimeError):
            loop.run()
        self.assertEqual(loop.beats, 0)
        self.assertIsInstance(loop.failure, RuntimeError)

    def test_background_beat_failure_is_observable_after_start(self):
        beaten = threading.Event()

        def beat():
            beaten.set()
            raise RuntimeError("sidecar lost the disk")

        loop = hb.HeartbeatLoop(beat, interval_seconds=3600)
        thread = loop.start()
        self.assertTrue(beaten.wait(10.0))
        thread.join(10.0)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(loop.failure, RuntimeError)
        with self.assertRaises(hb.HeartbeatFailure) as raised:
            loop.raise_if_failed()
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)
        # A dead loop never reports a normal stop.
        with self.assertRaises(hb.HeartbeatFailure):
            loop.stop()

    def test_healthy_background_loop_stops_cleanly(self):
        first_beat = threading.Event()
        loop = hb.HeartbeatLoop(lambda: first_beat.set(), interval_seconds=3600)
        loop.start()
        self.assertTrue(first_beat.wait(10.0))
        self.assertTrue(loop.stop())
        self.assertIsNone(loop.failure)
        self.assertEqual(loop.beats, 1)
        loop.raise_if_failed()  # must not raise on a healthy stopped loop

    def test_start_twice_rejected(self):
        loop = hb.HeartbeatLoop(lambda: None, interval_seconds=3600)
        loop.start()
        try:
            with self.assertRaises(RuntimeError):
                loop.start()
        finally:
            self.assertTrue(loop.stop())

    def test_start_after_failure_rejected(self):
        def beat():
            raise RuntimeError("sidecar lost the disk")

        loop = hb.HeartbeatLoop(beat, interval_seconds=60)
        with self.assertRaises(RuntimeError):
            loop.run()
        with self.assertRaises(hb.HeartbeatFailure):
            loop.start()


class RootMarkerTests(AutonomyStateCase):
    def set_marker(self, data):
        (self.root / cp.ROOT_MARKER).write_bytes(data)

    def assert_root_rejected(self):
        with self.assertRaises(cp.PathEscapeError):
            cp.resolve_queue_root(self.root)
        with self.assertRaises(cp.PathEscapeError):
            self.write_cp()
        with self.assertRaises(cp.PathEscapeError):
            self.read_cp()
        with self.assertRaises(cp.PathEscapeError):
            hb.write_heartbeat(
                self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
                profile="night-worker", model="claude-fable-5", pid=1, now=NOW,
            )

    def test_valid_marker_accepted(self):
        self.assertEqual(cp.resolve_queue_root(self.root), self.root)

    def test_marker_constants_match_contract(self):
        # contract.json is owned by the M0/M1 slice; assert exact value
        # alignment for both its marker shapes (bare filename or object).
        contract = json.loads((ROOT / "autonomy" / "contract.json").read_text("ascii"))
        marker = contract["root_marker"]
        if isinstance(marker, str):
            self.assertEqual(cp.ROOT_MARKER, marker)
        else:
            self.assertEqual(cp.ROOT_MARKER, marker["file"])
            self.assertTrue(marker["closed_schema"])
            self.assertEqual(sorted(marker["keys"]), ["name", "version"])
            self.assertEqual(cp.ROOT_MARKER_VERSION, marker["keys"]["version"]["const"])
            self.assertEqual(cp.ROOT_MARKER_NAME, marker["keys"]["name"]["const"])
        self.assertEqual(cp.ROOT_MARKER_NAME, contract["name"])
        self.assertEqual(cp.ROOT_MARKER_VERSION, contract["version"])

    def test_malformed_markers_rejected(self):
        good_name = cp.ROOT_MARKER_NAME.encode("ascii")
        cases = {
            "empty-object": b"{}",
            "wrong-version": b'{"version":2,"name":"' + good_name + b'"}',
            "bool-version": b'{"version":true,"name":"' + good_name + b'"}',
            "string-version": b'{"version":"1","name":"' + good_name + b'"}',
            "nan-version": b'{"version":NaN,"name":"' + good_name + b'"}',
            "infinity-version": b'{"version":Infinity,"name":"' + good_name + b'"}',
            "wrong-name": b'{"version":1,"name":"other-queue"}',
            "name-as-int": b'{"version":1,"name":7}',
            "missing-name": b'{"version":1}',
            "extra-key": b'{"version":1,"name":"' + good_name + b'","x":1}',
            "duplicate-key": b'{"version":1,"version":1,"name":"' + good_name + b'"}',
            "array-not-object": b"[]",
            "truncated-json": b'{"version":',
            "non-ascii": '{"version":1,"name":"agentchattr-autonomy-queue"}'.encode("utf-16"),
            "oversized": b'{"version":1,"name":"' + good_name + b'"}'
            + b" " * cp.ROOT_MARKER_MAX_BYTES,
        }
        for label, data in cases.items():
            with self.subTest(label):
                self.set_marker(data)
                self.assert_root_rejected()

    def test_missing_marker_rejected(self):
        (self.root / cp.ROOT_MARKER).unlink()
        self.assert_root_rejected()

    def test_marker_directory_rejected(self):
        (self.root / cp.ROOT_MARKER).unlink()
        (self.root / cp.ROOT_MARKER).mkdir()
        self.assert_root_rejected()

    def test_marker_symlink_rejected(self):
        target = self.base / "marker-target.json"
        target.write_bytes((self.root / cp.ROOT_MARKER).read_bytes())
        (self.root / cp.ROOT_MARKER).unlink()
        try:
            os.symlink(target, self.root / cp.ROOT_MARKER)
        except (OSError, NotImplementedError):
            self.skipTest("platform cannot create file symlinks")
        self.assert_root_rejected()

    def test_marker_junction_rejected(self):
        # Junctions need no privilege on Windows, so this reparse-marker
        # regression executes where the file-symlink one has to skip.
        target = self.base / "marker-junction-target"
        target.mkdir()
        (self.root / cp.ROOT_MARKER).unlink()
        if not make_dir_link(self.root / cp.ROOT_MARKER, target):
            self.skipTest("platform cannot create directory symlinks or junctions")
        self.assert_root_rejected()


class ExactRootSpellingTests(AutonomyStateCase):
    def assert_root_spelling_rejected(self, spelling):
        relative_attempt = Path("attempts") / TASK / f"a{ATTEMPT}"
        with self.assertRaises(cp.PathEscapeError):
            cp.resolve_queue_root(spelling)
        with self.assertRaises(cp.PathEscapeError):
            cp.write_checkpoint(
                spelling,
                relative_attempt,
                task_id=TASK,
                attempt=ATTEMPT,
                completed_step=None,
                next_step=None,
                now=NOW,
            )

    def test_dot_duplicate_trailing_and_case_root_aliases_rejected_before_realpath(self):
        parent = str(self.root.parent)
        sep = os.sep
        spellings = {
            "dot": parent + sep + "." + sep + self.root.name,
            "dotdot": parent + sep + "unused" + sep + ".." + sep + self.root.name,
            "duplicate": parent + sep + sep + self.root.name,
            "trailing": str(self.root) + sep,
            "case": str(self.root.with_name(self.root.name.upper())),
        }
        if os.name == "nt":
            spellings["drive-case"] = str(self.root)[0].lower() + str(self.root)[1:]
        for label, spelling in spellings.items():
            with self.subTest(label):
                # These aliases must be refused, never repaired into the root.
                with mock.patch(
                    "autonomy.checkpoint.os.path.realpath",
                    side_effect=AssertionError("realpath must not canonicalize this alias"),
                ):
                    self.assert_root_spelling_rejected(spelling)

    @unittest.skipUnless(os.name == "nt", "UNC/device spellings are Windows-only")
    def test_unc_and_device_root_spellings_rejected_lexically(self):
        raw = str(self.root)
        for spelling in ("\\\\?\\" + raw, "\\\\.\\" + raw, r"\\localhost\share\qroot"):
            with self.subTest(spelling):
                with mock.patch(
                    "autonomy.checkpoint.os.path.realpath",
                    side_effect=AssertionError("UNC/device must be rejected before realpath"),
                ):
                    self.assert_root_spelling_rejected(spelling)

    def test_ancestor_alias_is_not_normalized_into_an_accepted_root(self):
        alias = self.base / "ancestor-alias"
        if not make_dir_link(alias, self.base):
            self.skipTest("platform cannot create directory symlinks or junctions")
        self.assert_root_spelling_rejected(alias / self.root.name)

    def test_junction_queue_root_rejected_with_relative_attempt(self):
        alias_root = self.base / "queue-root-alias"
        if not make_dir_link(alias_root, self.root):
            self.skipTest("platform cannot create directory symlinks or junctions")
        self.assert_root_spelling_rejected(alias_root)


class AttemptDirBindingTests(AutonomyStateCase):
    """The only accepted attempt dir is attempts/<task_id>/a<attempt> exactly."""

    def assert_binding_rejected(self, attempt_dir, task_id=TASK, attempt=ATTEMPT):
        with self.assertRaises(cp.PathEscapeError):
            cp.write_checkpoint(
                self.root, attempt_dir, task_id=task_id, attempt=attempt,
                completed_step=None, next_step=None, now=NOW,
            )
        with self.assertRaises(cp.PathEscapeError):
            cp.read_checkpoint(self.root, attempt_dir, task_id=task_id, attempt=attempt)
        with self.assertRaises(cp.PathEscapeError):
            cp.write_progress(
                self.root, attempt_dir, task_id=task_id, attempt=attempt,
                status="running", now=NOW,
            )
        with self.assertRaises(cp.PathEscapeError):
            cp.read_progress(self.root, attempt_dir, task_id=task_id, attempt=attempt)
        with self.assertRaises(cp.PathEscapeError):
            hb.write_heartbeat(
                self.root, attempt_dir, task_id=task_id, attempt=attempt,
                profile="night-worker", model="claude-fable-5", pid=1, now=NOW,
            )
        with self.assertRaises(cp.PathEscapeError):
            hb.read_heartbeat(self.root, attempt_dir, task_id=task_id, attempt=attempt)
        with self.assertRaises(cp.PathEscapeError):
            hb.bind_heartbeat(
                self.root, attempt_dir, task_id=task_id, attempt=attempt,
                profile="night-worker", model="claude-fable-5", pid=1,
            )

    def test_arbitrary_directory_under_root_rejected(self):
        junk = self.root / "junk"
        junk.mkdir()
        self.assert_binding_rejected(junk)

    def test_sibling_attempt_directory_rejected(self):
        sibling = self.root / "attempts" / TASK / "a3"
        sibling.mkdir()
        self.assert_binding_rejected(sibling)

    def test_other_task_attempt_directory_rejected(self):
        other = self.root / "attempts" / "other-task" / f"a{ATTEMPT}"
        other.mkdir(parents=True)
        self.assert_binding_rejected(other)

    def test_dot_segment_rejected(self):
        self.assert_binding_rejected(f"attempts/./{TASK}/a{ATTEMPT}")

    def test_case_alias_rejected(self):
        # Lexical, so it fails closed on case-sensitive AND case-folding filesystems.
        self.assert_binding_rejected(
            str(self.root / "ATTEMPTS" / TASK.upper() / f"A{ATTEMPT}")
        )

    def test_duplicate_trailing_and_absolute_root_alias_attempt_spellings_rejected(self):
        sep = os.sep
        exact = str(self.adir)
        aliases = {
            "duplicate": str(self.root / "attempts") + sep + sep + TASK + sep + f"a{ATTEMPT}",
            "trailing": exact + sep,
            "root-case": str(self.root.with_name(self.root.name.upper()))
            + sep
            + "attempts"
            + sep
            + TASK
            + sep
            + f"a{ATTEMPT}",
        }
        for label, spelling in aliases.items():
            with self.subTest(label):
                self.assert_binding_rejected(spelling)

    def test_canonical_tail_under_foreign_root_rejected(self):
        foreign = self.base / "froot" / "attempts" / TASK / f"a{ATTEMPT}"
        foreign.mkdir(parents=True)
        self.assert_binding_rejected(foreign)

    def test_prefix_alias_above_root_rejected(self):
        # A junction/symlink ABOVE the queue root must not smuggle in an
        # alternate spelling of the canonical attempt dir: the prefix has to
        # be the queue root exactly as supplied or its canonical path.
        alias_base = self.base / "alias-base"
        if not make_dir_link(alias_base, self.base):
            self.skipTest("platform cannot create directory symlinks or junctions")
        aliased = alias_base / "qroot" / "attempts" / TASK / f"a{ATTEMPT}"
        self.assertTrue(aliased.is_dir())  # the alias really reaches the canonical dir
        self.assert_binding_rejected(aliased)

    def test_canonical_binding_still_roundtrips(self):
        # Guard against over-rejection: the true canonical dir keeps working.
        self.write_cp()
        self.assertEqual(self.read_cp()["task_id"], TASK)
        beat = hb.bind_heartbeat(
            self.root, self.adir, task_id=TASK, attempt=ATTEMPT,
            profile="night-worker", model="claude-fable-5", pid=1,
        )
        beat()
        doc = hb.read_heartbeat(self.root, self.adir, task_id=TASK, attempt=ATTEMPT)
        self.assertEqual(doc["pid"], 1)


class BoundStateRaceTests(AutonomyStateCase):
    def run_attempt_swap(self, stage, operation):
        outside = self.base / ("outside-" + stage)
        outside.mkdir()
        parked = self.adir.with_name(self.adir.name + "-parked")
        real_barrier = cp._state_io_barrier
        state = {"hit": False, "moved": False, "linked": False}

        def swap_then_verify(binding, current_stage):
            if binding.path == self.adir and current_stage == stage and not state["hit"]:
                state["hit"] = True
                try:
                    os.replace(self.adir, parked)
                    state["moved"] = True
                except OSError as exc:
                    # Windows' retained no-SHARE_DELETE attempt handle must
                    # make the swap itself fail; that ambiguity is a refusal.
                    raise cp.PathEscapeError("attempt swap blocked by live binding") from exc
                if not make_dir_link(self.adir, outside):
                    raise cp.PathEscapeError("could not install injected attempt junction")
                state["linked"] = True
            return real_barrier(binding, current_stage)

        try:
            with mock.patch("autonomy.checkpoint._state_io_barrier", new=swap_then_verify):
                with self.assertRaises((cp.CheckpointError, OSError)):
                    operation(outside)
        finally:
            if state["linked"]:
                remove_dir_link(self.adir)
            if state["moved"] and parked.exists():
                os.replace(parked, self.adir)
        self.assertTrue(state["hit"], f"race barrier {stage!r} was not reached")
        return outside

    def test_attempt_swap_to_external_junction_refused_for_read(self):
        self.write_cp(next_step="safe")

        def operation(outside):
            (outside / cp.CHECKPOINT_FILENAME).write_bytes(b"outside")
            self.read_cp(attempt_dir=Path("attempts") / TASK / f"a{ATTEMPT}")

        outside = self.run_attempt_swap("read-after-open", operation)
        self.assertEqual((outside / cp.CHECKPOINT_FILENAME).read_bytes(), b"outside")

    def test_attempt_swap_to_external_junction_refused_for_write_and_target_untouched(self):
        sentinel = b"outside-must-not-change"

        def operation(outside):
            (outside / cp.CHECKPOINT_FILENAME).write_bytes(sentinel)
            cp.write_checkpoint(
                self.root,
                Path("attempts") / TASK / f"a{ATTEMPT}",
                task_id=TASK,
                attempt=ATTEMPT,
                completed_step="fetch",
                next_step="unsafe",
                now=NOW,
            )

        outside = self.run_attempt_swap("write-before-temp", operation)
        self.assertEqual((outside / cp.CHECKPOINT_FILENAME).read_bytes(), sentinel)

    @unittest.skipUnless(os.name == "nt", "native directory-handle creation is Windows-only")
    def test_retargeted_temp_create_is_deleted_through_its_handle(self):
        """Even a post-verify retarget cannot leave its newly created external name."""
        outside = self.base / "outside-temp-create"
        outside.mkdir()

        def malicious_create(_directory_handle, name, *, access, share):
            # Model the old absolute CreateFileW race at the exact primitive
            # boundary: the returned handle names an external entry.
            return cp._win_create(
                str(outside / name),
                access,
                share,
                cp._CREATE_NEW,
                cp._FILE_ATTRIBUTE_NORMAL | cp._FILE_FLAG_OPEN_REPARSE_POINT,
            )

        with mock.patch(
            "autonomy.checkpoint._win_create_relative", new=malicious_create
        ):
            with self.assertRaises(cp.PathEscapeError):
                self.write_cp(next_step="must-not-land")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.dir_names(), [])

    @unittest.skipUnless(os.name == "nt", "Windows hard-link commit race")
    def test_hardlink_injected_inside_commit_rolls_back_original_identity(self):
        self.write_cp(next_step="safe")
        destination = self.adir / cp.CHECKPOINT_FILENAME
        before_bytes = destination.read_bytes()
        before_identity = (destination.stat().st_dev, destination.stat().st_ino)
        outside = self.base / "outside-temp-hardlink.json"
        real_rename = cp._win_rename_handle
        hit = []

        def link_then_rename(handle, directory_handle, filename, *, replace):
            if not hit:
                hit.append(True)
                os.link(Path(cp._win_final_path(handle)), outside)
            return real_rename(
                handle, directory_handle, filename, replace=replace
            )

        with mock.patch(
            "autonomy.checkpoint._win_rename_handle", new=link_then_rename
        ):
            with self.assertRaises(cp.PathEscapeError):
                self.write_cp(next_step="must-not-land")
        self.assertTrue(hit)
        self.assertEqual(destination.read_bytes(), before_bytes)
        self.assertEqual(
            (destination.stat().st_dev, destination.stat().st_ino), before_identity
        )
        self.assertTrue(outside.exists())
        self.assertFalse(os.path.samefile(destination, outside))
        self.assertEqual(self.dir_names(), [cp.CHECKPOINT_FILENAME])

    @unittest.skipIf(os.name == "nt", "POSIX dirfd/name substitution race")
    def test_posix_temp_name_substitution_rolls_back_original_identity(self):
        self.write_cp(next_step="safe")
        destination = self.adir / cp.CHECKPOINT_FILENAME
        before_bytes = destination.read_bytes()
        before_identity = (destination.stat().st_dev, destination.stat().st_ino)
        real_replace = os.replace
        hit = []

        def substitute_then_replace(source, target, *args, **kwargs):
            if (
                not hit
                and isinstance(source, str)
                and source.endswith(".tmp")
                and kwargs.get("src_dir_fd") is not None
            ):
                hit.append(True)
                parked = source + ".parked"
                real_replace(source, parked, *args, **kwargs)
                fd = os.open(
                    source,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=kwargs["src_dir_fd"],
                )
                try:
                    os.write(fd, b'{"attacker":true}')
                finally:
                    os.close(fd)
            return real_replace(source, target, *args, **kwargs)

        with mock.patch("autonomy.checkpoint.os.replace", new=substitute_then_replace):
            with self.assertRaises(cp.PathEscapeError):
                self.write_cp(next_step="must-not-land")
        self.assertTrue(hit)
        self.assertEqual(destination.read_bytes(), before_bytes)
        self.assertEqual(
            (destination.stat().st_dev, destination.stat().st_ino), before_identity
        )
        self.assertEqual(self.dir_names(), [cp.CHECKPOINT_FILENAME])

    def test_state_file_replacement_while_open_is_refused(self):
        self.write_cp(next_step="safe")
        replacement = self.adir / "replacement.json"
        changed = self.valid_cp_doc()
        changed["next_step"] = "attacker"
        replacement.write_bytes(json.dumps(changed, separators=(",", ":")).encode("ascii"))
        real_barrier = cp._state_io_barrier
        hit = []

        def replace_after_open(binding, stage):
            if binding.path == self.adir and stage == "read-after-open" and not hit:
                hit.append(True)
                os.replace(replacement, self.adir / cp.CHECKPOINT_FILENAME)
            return real_barrier(binding, stage)

        with mock.patch("autonomy.checkpoint._state_io_barrier", new=replace_after_open):
            with self.assertRaises((cp.CheckpointError, OSError)):
                self.read_cp()
        self.assertTrue(hit)

    def test_guard_to_read_open_regular_replacement_is_refused(self):
        self.write_cp(next_step="safe")
        replacement = self.adir / "guard-read-replacement.json"
        changed = self.valid_cp_doc()
        changed["next_step"] = "attacker"
        replacement.write_bytes(json.dumps(changed, separators=(",", ":")).encode("ascii"))
        real_read = cp.read_document
        hit = []

        def replace_after_guard(path, max_bytes, **kwargs):
            if Path(path).name == cp.CHECKPOINT_FILENAME and not hit:
                hit.append(True)
                os.replace(replacement, path)
            return real_read(path, max_bytes, **kwargs)

        with mock.patch("autonomy.checkpoint.read_document", new=replace_after_guard):
            with self.assertRaises(cp.PathEscapeError):
                self.read_cp()
        self.assertTrue(hit)

    def test_state_hardlink_identity_rejected_for_read_and_write(self):
        outside = self.base / "outside-hardlink.json"
        outside.write_bytes(
            json.dumps(self.valid_cp_doc(), separators=(",", ":")).encode("ascii")
        )
        before = outside.read_bytes()
        try:
            os.link(outside, self.adir / cp.CHECKPOINT_FILENAME)
        except (OSError, NotImplementedError):
            self.skipTest("platform/filesystem cannot create hard links")
        with self.assertRaises(cp.PathEscapeError):
            self.read_cp()
        with self.assertRaises(cp.PathEscapeError):
            self.write_cp(next_step="must-not-land")
        self.assertEqual(outside.read_bytes(), before)

    def test_state_filename_junction_rejected_and_outside_untouched(self):
        outside = self.base / "outside-state-junction"
        outside.mkdir()
        sentinel = outside / "sentinel.bin"
        sentinel.write_bytes(b"outside")
        link = self.adir / cp.CHECKPOINT_FILENAME
        if not make_dir_link(link, outside):
            self.skipTest("platform cannot create directory symlinks or junctions")
        try:
            with self.assertRaises(cp.PathEscapeError):
                self.read_cp()
            with self.assertRaises((cp.PathEscapeError, OSError)):
                self.write_cp(next_step="must-not-land")
            self.assertEqual(sentinel.read_bytes(), b"outside")
        finally:
            remove_dir_link(link)

    def test_destination_replacement_before_commit_refused_and_outside_untouched(self):
        self.write_cp(next_step="safe")
        outside = self.base / "outside-commit.json"
        outside.write_bytes(b"outside-hardlink-target")
        before = outside.read_bytes()
        replacement = self.adir / "commit-replacement.json"
        try:
            os.link(outside, replacement)
        except (OSError, NotImplementedError):
            self.skipTest("platform/filesystem cannot create hard links")
        real_barrier = cp._state_io_barrier
        hit = []

        def replace_before_commit(binding, stage):
            if binding.path == self.adir and stage == "write-before-commit" and not hit:
                hit.append(True)
                os.replace(replacement, self.adir / cp.CHECKPOINT_FILENAME)
            return real_barrier(binding, stage)

        with mock.patch("autonomy.checkpoint._state_io_barrier", new=replace_before_commit):
            with self.assertRaises(cp.PathEscapeError):
                self.write_cp(next_step="must-not-land")
        self.assertTrue(hit)
        self.assertEqual(outside.read_bytes(), before)

    def test_guard_to_write_open_hardlink_replacement_is_refused(self):
        self.write_cp(next_step="safe")
        outside = self.base / "outside-guard-write.json"
        outside.write_bytes(b"outside-guard-target")
        before = outside.read_bytes()
        replacement = self.adir / "guard-write-replacement.json"
        try:
            os.link(outside, replacement)
        except (OSError, NotImplementedError):
            self.skipTest("platform/filesystem cannot create hard links")
        real_write = cp.atomic_write_document
        hit = []

        def replace_after_guard(path, payload, max_bytes, **kwargs):
            if Path(path).name == cp.CHECKPOINT_FILENAME and not hit:
                hit.append(True)
                os.replace(replacement, path)
            return real_write(path, payload, max_bytes, **kwargs)

        with mock.patch(
            "autonomy.checkpoint.atomic_write_document", new=replace_after_guard
        ):
            with self.assertRaises(cp.PathEscapeError):
                self.write_cp(next_step="must-not-land")
        self.assertTrue(hit)
        self.assertEqual(outside.read_bytes(), before)


class AtomicWriteFaultMatrixTests(AutonomyStateCase):
    """Faults at write, flush, fsync, replace and directory fsync.

    Contract: the old complete document may remain, but never a partial final
    JSON; temp files are cleaned where possible; the exception surfaces.
    """

    def fault_patchers(self):
        return {
            "write": mock.patch(
                "autonomy.checkpoint._write_temp_bytes",
                side_effect=OSError("injected write failure"),
            ),
            "flush": mock.patch(
                "autonomy.checkpoint._flush_temp",
                side_effect=OSError("injected flush failure"),
            ),
            "fsync": mock.patch(
                "autonomy.checkpoint._fsync_temp",
                side_effect=OSError("injected fsync failure"),
            ),
            "replace": mock.patch(
                "autonomy.checkpoint._replace_bound_temp",
                side_effect=OSError("injected replace failure"),
            ),
        }

    def test_faults_before_final_replace_keep_old_document(self):
        self.write_cp(next_step="build")
        before = self.raw(cp.CHECKPOINT_FILENAME)
        for label, patcher in self.fault_patchers().items():
            with self.subTest(label):
                with patcher:
                    with self.assertRaises(OSError):
                        self.write_cp(next_step="test", now=NOW + timedelta(seconds=5))
                self.assertEqual(self.dir_names(), [cp.CHECKPOINT_FILENAME])
                self.assertEqual(self.raw(cp.CHECKPOINT_FILENAME), before)
                self.assertEqual(self.read_cp()["next_step"], "build")

    def test_faults_on_first_write_leave_no_document(self):
        for label, patcher in self.fault_patchers().items():
            with self.subTest(label):
                with patcher:
                    with self.assertRaises(OSError):
                        self.write_cp()
                self.assertEqual(self.dir_names(), [])
                with self.assertRaises(cp.MissingDocumentError):
                    self.read_cp()

    def test_directory_fsync_failure_surfaces_after_complete_replace(self):
        self.write_cp(next_step="build")
        with mock.patch(
            "autonomy.checkpoint._fsync_directory",
            side_effect=OSError("injected directory fsync failure"),
        ):
            with self.assertRaises(OSError):
                self.write_cp(next_step="test", now=NOW + timedelta(seconds=5))
        # The replace completed: a full new document, no temp, no partial JSON.
        self.assertEqual(self.dir_names(), [cp.CHECKPOINT_FILENAME])
        self.assertEqual(self.read_cp()["next_step"], "test")

    @unittest.skipIf(os.name == "nt", "directory fsync runs on POSIX only")
    def test_fsync_directory_propagates_oserror(self):
        with mock.patch(
            "autonomy.checkpoint.os.fsync", side_effect=OSError("injected")
        ):
            with self.assertRaises(OSError):
                cp._fsync_directory(self.adir)

    @unittest.skipUnless(os.name == "nt", "windows skips directory fsync")
    def test_fsync_directory_is_noop_on_windows(self):
        with mock.patch(
            "autonomy.checkpoint.os.open",
            side_effect=AssertionError("directory fsync must not open on windows"),
        ):
            self.assertIsNone(cp._fsync_directory(self.adir))


if __name__ == "__main__":
    unittest.main()
