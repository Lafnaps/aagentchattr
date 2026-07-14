"""Deterministic fault-injection tests for persistence transaction safety."""

import asyncio
import copy
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app as app_module
import session_store as session_store_module
import store as store_module
from jobs import JobStore
from rules import RuleStore
from router import Router
from session_engine import SessionEngine
from schedules import ScheduleStore
from session_store import SessionStore
from store import (
    MessageLogCorruptionError, MessageStore, MessageStoreWriteBlockedError,
)
from summaries import SummaryStore


class _JsonRequest:
    def __init__(self, body):
        self._body = body

    async def json(self):
        return copy.deepcopy(self._body)


class StoreTransactionSafetyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _bytes_or_none(self, path: Path):
        return path.read_bytes() if path.exists() else None

    def _assert_disk_unchanged(self, path: Path, before):
        self.assertEqual(self._bytes_or_none(path), before)
        self.assertEqual(
            list(path.parent.glob(f".{path.name}.*.tmp")),
            [],
            "failed save left a temporary file behind",
        )

    def _session_store(self, name: str = "sessions.json") -> SessionStore:
        store = SessionStore(str(self.root / name))
        store._templates["test"] = {"name": "Test session"}
        return store

    def _seed_message_store(self, name: str):
        path = self.root / name
        store = MessageStore(str(path))
        first = store.add(
            "one", "first", channel="lane-one", metadata={"version": 1},
        )
        second = store.add("two", "second", channel="lane-two")
        third = store.add("three", "third", channel="lane-one")
        store.add_todo(first["id"])
        store.add_todo(second["id"])
        return store, path, (first, second, third)

    def _capture_message_store(self, store: MessageStore):
        return {
            "messages": copy.deepcopy(store._messages),
            "next_id": store._next_id,
            # Preserve insertion order too: failed compensation must restore
            # the exact in-memory state, not only an equal mapping.
            "todos": copy.deepcopy(list(store._todos.items())),
        }

    def _capture_message_files(self, store: MessageStore):
        return {
            store._path: self._bytes_or_none(store._path),
            store._todos_path: self._bytes_or_none(store._todos_path),
        }

    def _message_events(self, store: MessageStore):
        events = []
        store.on_message(lambda message: events.append(("message", message["id"])))
        store.on_delete(lambda ids: events.append(("delete", list(ids))))
        store.on_todo(
            lambda message_id, status: events.append(("todo", message_id, status))
        )
        return events

    def _assert_message_failure_unchanged(
        self, store: MessageStore, memory_before, files_before, events,
    ):
        self.assertEqual(self._capture_message_store(store), memory_before)
        for path, content in files_before.items():
            self._assert_disk_unchanged(path, content)
        self.assertEqual(events, [])

    def test_message_add_append_failure_restores_memory_counter_and_callbacks(self):
        path = self.root / "messages.jsonl"
        store = MessageStore(str(path))
        store.add("seed", "kept")
        before_disk = path.read_bytes()
        before_messages = copy.deepcopy(store.get_recent(20))
        before_next_id = store._next_id
        callbacks = []
        store.on_message(callbacks.append)

        with patch.object(store, "_append_message", side_effect=OSError("append failed")):
            with self.assertRaisesRegex(OSError, "append failed"):
                store.add("writer", "must roll back")

        self.assertEqual(store.get_recent(20), before_messages)
        self.assertEqual(store._next_id, before_next_id)
        self.assertEqual(callbacks, [])
        self._assert_disk_unchanged(path, before_disk)

    def test_message_partial_append_fsync_failure_truncates_record(self):
        path = self.root / "messages.jsonl"
        store = MessageStore(str(path))
        store.add("seed", "kept")
        before_disk = path.read_bytes()
        before_messages = copy.deepcopy(store.get_recent(20))
        before_next_id = store._next_id

        # First fsync fails after the full record was written; the second is
        # the compensating fsync after ftruncate.
        with patch("store.os.fsync", side_effect=[OSError("fsync failed"), None]):
            with self.assertRaisesRegex(OSError, "fsync failed"):
                store.add("writer", "partial record")

        self.assertEqual(store.get_recent(20), before_messages)
        self.assertEqual(store._next_id, before_next_id)
        self._assert_disk_unchanged(path, before_disk)

    def test_message_append_and_truncate_double_fault_blocks_without_duplicate(self):
        path = self.root / "messages-double-fault.jsonl"
        instance = MessageStore(str(path))
        instance.add("seed", "kept")
        callbacks = []
        instance.on_message(callbacks.append)
        fsync_calls = 0

        def fail_first_fsync(_fd):
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 1:
                raise OSError("append fsync failed")

        with patch("store.os.fsync", side_effect=fail_first_fsync), patch(
            "store.os.ftruncate", side_effect=OSError("truncate failed"),
        ):
            with self.assertRaises(MessageStoreWriteBlockedError):
                instance.add("writer", "uncertain full record")

        # The full record may be present despite the reported fsync failure.
        # It is reloaded as evidence, but never announced via callbacks.
        messages = instance.get_recent(20)
        self.assertEqual([item["id"] for item in messages], [0, 1])
        self.assertEqual(callbacks, [])
        self.assertTrue(instance._write_block_path.exists())
        blocked_bytes = path.read_bytes()

        with self.assertRaises(MessageStoreWriteBlockedError):
            instance.add("writer", "must not reuse id one")
        self.assertEqual(path.read_bytes(), blocked_bytes)
        self.assertEqual(callbacks, [])
        self.assertEqual([item["id"] for item in instance.get_recent(20)], [0, 1])

        reopened = MessageStore(str(path))
        with self.assertRaises(MessageStoreWriteBlockedError):
            reopened.add("writer", "restart remains blocked")
        self.assertEqual([item["id"] for item in reopened.get_recent(20)], [0, 1])

    def test_message_append_and_compensation_fsync_double_fault_stays_blocked(self):
        path = self.root / "messages-compensation-fsync.jsonl"
        instance = MessageStore(str(path))
        instance.add("seed", "kept")
        before = path.read_bytes()
        callbacks = []
        instance.on_message(callbacks.append)
        fsync_calls = 0

        def fail_append_and_compensation(_fd):
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls <= 2:
                raise OSError(f"fsync failure {fsync_calls}")

        with patch("store.os.fsync", side_effect=fail_append_and_compensation):
            with self.assertRaises(MessageStoreWriteBlockedError):
                instance.add("writer", "truncated but durability uncertain")

        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(instance.get_recent(20)[-1]["text"], "kept")
        self.assertEqual(callbacks, [])
        self.assertTrue(instance._write_block_path.exists())
        with self.assertRaises(MessageStoreWriteBlockedError):
            instance.add("writer", "blocked after uncertain compensation")

    def test_message_delete_rewrite_failure_is_atomic_and_silent(self):
        store, _path, messages = self._seed_message_store("delete-rewrite.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch.object(
            store, "_rewrite_jsonl", side_effect=OSError("rewrite failed"),
        ):
            with self.assertRaisesRegex(OSError, "rewrite failed"):
                store.delete([messages[0]["id"]])

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_delete_todo_save_failure_restores_both_files(self):
        store, _path, messages = self._seed_message_store("delete-todos.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch.object(
            store, "_save_todos", side_effect=OSError("todo save failed"),
        ):
            with self.assertRaisesRegex(OSError, "todo save failed"):
                store.delete([messages[0]["id"]])

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_delete_replace_failure_is_atomic_and_cleans_temp(self):
        store, _path, messages = self._seed_message_store("delete-replace.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch("store.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.delete([messages[0]["id"]])

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_delete_channel_todo_save_failure_restores_everything(self):
        store, _path, _messages = self._seed_message_store("channel-delete-save.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch.object(
            store, "_save_todos", side_effect=OSError("todo save failed"),
        ):
            with self.assertRaisesRegex(OSError, "todo save failed"):
                store.delete_channel("lane-one")

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_delete_channel_replace_failure_is_atomic_and_cleans_temp(self):
        store, _path, _messages = self._seed_message_store("channel-delete-replace.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch("store.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.delete_channel("lane-one")

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_channel_rename_rewrite_failure_is_atomic(self):
        store, _path, _messages = self._seed_message_store("rename-rewrite.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch.object(
            store, "_rewrite_jsonl", side_effect=OSError("rewrite failed"),
        ):
            with self.assertRaisesRegex(OSError, "rewrite failed"):
                store.rename_channel("lane-one", "lane-renamed")

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_sender_rename_replace_failure_is_atomic(self):
        store, _path, _messages = self._seed_message_store("rename-replace.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch("store.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.rename_sender("one", "renamed")

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_update_rewrite_failure_is_atomic(self):
        store, _path, messages = self._seed_message_store("update-rewrite.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch.object(
            store, "_rewrite_jsonl", side_effect=OSError("rewrite failed"),
        ):
            with self.assertRaisesRegex(OSError, "rewrite failed"):
                store.update_message(
                    messages[0]["id"],
                    {"text": "changed", "metadata": {"version": 2}},
                )

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_reply_update_replace_failure_is_atomic(self):
        store, _path, messages = self._seed_message_store("reply-replace.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch("store.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.update_reply_to(messages[0]["id"], messages[1]["id"])

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_message_todo_operations_save_failure_are_atomic_and_silent(self):
        operations = ("add", "complete", "reopen", "remove")
        for operation in operations:
            with self.subTest(operation=operation):
                store, _path, messages = self._seed_message_store(
                    f"todo-{operation}.jsonl"
                )
                if operation == "reopen":
                    store.complete_todo(messages[0]["id"])
                before_memory = self._capture_message_store(store)
                before_files = self._capture_message_files(store)
                events = self._message_events(store)

                if operation == "add":
                    mutate = lambda: store.add_todo(messages[2]["id"])
                elif operation == "complete":
                    mutate = lambda: store.complete_todo(messages[0]["id"])
                elif operation == "reopen":
                    mutate = lambda: store.reopen_todo(messages[0]["id"])
                else:
                    mutate = lambda: store.remove_todo(messages[0]["id"])

                with patch.object(
                    store, "_save_todos", side_effect=OSError("todo save failed"),
                ):
                    with self.assertRaisesRegex(OSError, "todo save failed"):
                        mutate()

                self._assert_message_failure_unchanged(
                    store, before_memory, before_files, events,
                )

    def test_message_todo_replace_failure_is_atomic_and_cleans_temp(self):
        store, _path, messages = self._seed_message_store("todo-replace.jsonl")
        before_memory = self._capture_message_store(store)
        before_files = self._capture_message_files(store)
        events = self._message_events(store)

        with patch("store.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.complete_todo(messages[0]["id"])

        self._assert_message_failure_unchanged(
            store, before_memory, before_files, events,
        )

    def test_create_methods_restore_memory_when_save_is_patched_to_fail(self):
        cases = []

        job_path = self.root / "patched-jobs.json"
        job_store = JobStore(str(job_path))
        cases.append((
            "job", job_store, job_path,
            lambda: job_store.create("job", "task", "general", "user"),
            lambda: (copy.deepcopy(job_store._jobs), job_store._next_id),
        ))

        schedule_path = self.root / "patched-schedules.json"
        schedule_store = ScheduleStore(str(schedule_path))
        cases.append((
            "schedule", schedule_store, schedule_path,
            lambda: schedule_store.create("run", ["worker"], interval_seconds=60),
            lambda: copy.deepcopy(schedule_store._schedules),
        ))

        rule_path = self.root / "patched-rules.json"
        rule_store = RuleStore(str(rule_path))
        cases.append((
            "rule", rule_store, rule_path,
            lambda: rule_store.propose("rule", "user"),
            lambda: (copy.deepcopy(rule_store._rules), rule_store._next_id),
        ))

        summary_path = self.root / "patched-summaries.json"
        summary_store = SummaryStore(str(summary_path))
        cases.append((
            "summary", summary_store, summary_path,
            lambda: summary_store.write("general", "summary", "user"),
            lambda: copy.deepcopy(summary_store._summaries),
        ))

        session_path = self.root / "patched-sessions.json"
        sessions = self._session_store("patched-sessions.json")
        cases.append((
            "session", sessions, session_path,
            lambda: sessions.create("test", "general", {}, "user"),
            lambda: (copy.deepcopy(sessions._sessions), sessions._next_id),
        ))

        for name, instance, path, mutate, snapshot in cases:
            with self.subTest(store=name):
                before_memory = snapshot()
                before_disk = self._bytes_or_none(path)
                with patch.object(instance, "_save", side_effect=OSError("save failed")):
                    with self.assertRaisesRegex(OSError, "save failed"):
                        mutate()
                self.assertEqual(snapshot(), before_memory)
                self._assert_disk_unchanged(path, before_disk)

    def test_job_replace_failure_is_atomic_and_rolls_back_create(self):
        path = self.root / "jobs.json"
        store = JobStore(str(path))
        store.create("seed", "task", "general", "user")
        before_disk = path.read_bytes()
        before_memory = copy.deepcopy(store._jobs)
        before_next_id = store._next_id

        with patch("jobs.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.create("failed", "task", "general", "user")

        self.assertEqual(store._jobs, before_memory)
        self.assertEqual(store._next_id, before_next_id)
        self._assert_disk_unchanged(path, before_disk)

    def test_schedule_replace_failure_is_atomic_and_rolls_back_create(self):
        path = self.root / "schedules.json"
        store = ScheduleStore(str(path))
        store.create("seed", ["worker"], interval_seconds=60)
        before_disk = path.read_bytes()
        before_memory = copy.deepcopy(store._schedules)

        with patch("schedules.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.create("failed", ["worker"], interval_seconds=60)

        self.assertEqual(store._schedules, before_memory)
        self._assert_disk_unchanged(path, before_disk)

    def test_rule_replace_failure_is_atomic_and_rolls_back_propose(self):
        path = self.root / "rules.json"
        store = RuleStore(str(path))
        store.propose("seed", "user")
        before_disk = path.read_bytes()
        before_memory = copy.deepcopy(store._rules)
        before_next_id = store._next_id

        with patch("rules.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.propose("failed", "user")

        self.assertEqual(store._rules, before_memory)
        self.assertEqual(store._next_id, before_next_id)
        self._assert_disk_unchanged(path, before_disk)

    def test_summary_replace_failure_restores_previous_entry(self):
        path = self.root / "summaries.json"
        store = SummaryStore(str(path))
        store.write("general", "seed", "user", uid="seed")
        before_disk = path.read_bytes()
        before_memory = copy.deepcopy(store._summaries)

        with patch("summaries.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.write("general", "failed", "user")

        self.assertEqual(store._summaries, before_memory)
        self._assert_disk_unchanged(path, before_disk)

    def test_session_replace_failure_is_atomic_and_rolls_back_create(self):
        path = self.root / "sessions.json"
        store = self._session_store()
        store.create("test", "seed", {}, "user")
        before_disk = path.read_bytes()
        before_memory = copy.deepcopy(store._sessions)
        before_next_id = store._next_id

        with patch("session_store.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                store.create("test", "failed", {}, "user")

        self.assertEqual(store._sessions, before_memory)
        self.assertEqual(store._next_id, before_next_id)
        self._assert_disk_unchanged(path, before_disk)

    def test_existing_delete_methods_restore_memory_on_save_failure(self):
        jobs_path = self.root / "delete-jobs.json"
        job_store = JobStore(str(jobs_path))
        job = job_store.create("seed", "task", "general", "user")

        schedules_path = self.root / "delete-schedules.json"
        schedule_store = ScheduleStore(str(schedules_path))
        schedule = schedule_store.create("seed", ["worker"], interval_seconds=60)

        rules_path = self.root / "delete-rules.json"
        rule_store = RuleStore(str(rules_path))
        rule = rule_store.propose("seed", "user")
        rule_store.activate(rule["id"])

        summaries_path = self.root / "delete-summaries.json"
        summary_store = SummaryStore(str(summaries_path))
        summary_store.write("general", "seed", "user")
        summary_store.write("other", "keep order", "user")

        sessions_path = self.root / "delete-sessions.json"
        sessions = self._session_store("delete-sessions.json")
        session = sessions.create("test", "general", {}, "user")

        cases = [
            ("job", job_store, jobs_path, lambda: job_store.delete(job["id"]),
             lambda: copy.deepcopy(job_store._jobs)),
            ("schedule", schedule_store, schedules_path,
             lambda: schedule_store.delete(schedule["id"]),
             lambda: copy.deepcopy(schedule_store._schedules)),
            ("rule", rule_store, rules_path, lambda: rule_store.delete(rule["id"]),
             lambda: (copy.deepcopy(rule_store._rules), rule_store._epoch)),
            ("summary", summary_store, summaries_path,
             lambda: summary_store.delete("general"),
             lambda: copy.deepcopy(list(summary_store._summaries.items()))),
            ("session", sessions, sessions_path,
             lambda: sessions.delete(session["id"]),
             lambda: copy.deepcopy(sessions._sessions)),
        ]

        for name, instance, path, mutate, snapshot in cases:
            with self.subTest(store=name):
                before_memory = snapshot()
                before_disk = path.read_bytes()
                with patch.object(instance, "_save", side_effect=OSError("save failed")):
                    with self.assertRaisesRegex(OSError, "save failed"):
                        mutate()
                self.assertEqual(snapshot(), before_memory)
                self._assert_disk_unchanged(path, before_disk)

    def test_session_delete_persists_and_returns_removed_session(self):
        path = self.root / "delete-success-sessions.json"
        store = self._session_store("delete-success-sessions.json")
        session = store.create("test", "general", {}, "user")
        events = []
        store.on_change(lambda action, payload: events.append((action, payload["id"])))

        removed = store.delete(session["id"])

        self.assertEqual(removed["id"], session["id"])
        self.assertEqual(store.list_all(), [])
        self.assertEqual(events, [("delete", session["id"])])
        self.assertEqual(SessionStore(str(path)).list_all(), [])

    def test_job_mutation_failure_matrix_restores_exact_state_and_callbacks(self):
        operations = (
            "status", "title", "assignee", "add_message", "delete_message",
            "reorder", "resolve_message", "list_normalize",
        )
        for operation in operations:
            with self.subTest(operation=operation):
                path = self.root / f"job-update-{operation}.json"
                instance = JobStore(str(path))
                first = instance.create("first", "task", "general", "user")
                second = instance.create("second", "task", "general", "user")
                if operation in {"delete_message", "resolve_message"}:
                    instance.add_message(
                        first["id"], "agent", "suggestion",
                        msg_type="suggestion",
                    )
                if operation == "list_normalize":
                    instance._jobs[0].pop("sort_order", None)
                    instance._save()

                events = []
                instance.on_change(
                    lambda action, payload: events.append(
                        (action, copy.deepcopy(payload))
                    )
                )
                before = (copy.deepcopy(instance._jobs), instance._next_id)
                before_disk = path.read_bytes()

                if operation == "status":
                    mutate = lambda: instance.update_status(first["id"], "open")
                elif operation == "title":
                    mutate = lambda: instance.update_title(first["id"], "changed")
                elif operation == "assignee":
                    mutate = lambda: instance.update_assignee(first["id"], "worker")
                elif operation == "add_message":
                    mutate = lambda: instance.add_message(first["id"], "agent", "new")
                elif operation == "delete_message":
                    mutate = lambda: instance.delete_message(first["id"], 0)
                elif operation == "reorder":
                    mutate = lambda: instance.reorder("done", [first["id"], second["id"]])
                elif operation == "resolve_message":
                    mutate = lambda: instance.resolve_message(first["id"], 0, "accepted")
                else:
                    mutate = instance.list_all

                with patch.object(instance, "_save", side_effect=OSError("save failed")):
                    with self.assertRaisesRegex(OSError, "save failed"):
                        mutate()
                self.assertEqual((instance._jobs, instance._next_id), before)
                self._assert_disk_unchanged(path, before_disk)
                self.assertEqual(events, [])

    def test_schedule_mutation_failure_matrix_restores_exact_state_and_callbacks(self):
        for operation in ("mark_run", "toggle"):
            with self.subTest(operation=operation):
                path = self.root / f"schedule-update-{operation}.json"
                instance = ScheduleStore(str(path))
                schedule = instance.create("seed", ["worker"], interval_seconds=60)
                events = []
                instance.on_change(
                    lambda action, payload: events.append(
                        (action, copy.deepcopy(payload))
                    )
                )
                before = copy.deepcopy(instance._schedules)
                before_disk = path.read_bytes()
                mutate = (
                    (lambda: instance.mark_run(schedule["id"]))
                    if operation == "mark_run"
                    else (lambda: instance.toggle(schedule["id"]))
                )
                with patch.object(instance, "_save", side_effect=OSError("save failed")):
                    with self.assertRaisesRegex(OSError, "save failed"):
                        mutate()
                self.assertEqual(instance._schedules, before)
                self._assert_disk_unchanged(path, before_disk)
                self.assertEqual(events, [])

    def test_rule_mutation_failure_matrix_restores_epoch_keys_and_callbacks(self):
        operations = ("activate", "draft", "deactivate", "edit", "remind")
        for operation in operations:
            with self.subTest(operation=operation):
                path = self.root / f"rule-update-{operation}.json"
                instance = RuleStore(str(path))
                rule = instance.propose("seed", "user")
                if operation in {"draft", "deactivate", "edit"}:
                    instance.activate(rule["id"])
                events = []
                instance.on_change(
                    lambda action, payload: events.append(
                        (action, copy.deepcopy(payload))
                    )
                )
                before = (
                    copy.deepcopy(instance._rules), instance._next_id, instance._epoch,
                )
                before_disk = path.read_bytes()
                if operation == "activate":
                    mutate = lambda: instance.activate(rule["id"])
                elif operation == "draft":
                    mutate = lambda: instance.make_draft(rule["id"])
                elif operation == "deactivate":
                    mutate = lambda: instance.deactivate(rule["id"])
                elif operation == "edit":
                    mutate = lambda: instance.edit(rule["id"], text="changed")
                else:
                    mutate = instance.set_remind
                with patch.object(instance, "_save", side_effect=OSError("save failed")):
                    with self.assertRaisesRegex(OSError, "save failed"):
                        mutate()
                self.assertEqual(
                    (instance._rules, instance._next_id, instance._epoch), before,
                )
                self._assert_disk_unchanged(path, before_disk)
                self.assertEqual(events, [])

    def test_session_mutation_failure_matrix_restores_exact_state_and_callbacks(self):
        operations = (
            "advance_turn", "advance_phase", "waiting", "pause", "resume",
            "complete", "interrupt",
        )
        for operation in operations:
            with self.subTest(operation=operation):
                path = self.root / f"session-update-{operation}.json"
                instance = self._session_store(path.name)
                session = instance.create("test", "general", {}, "user")
                if operation == "resume":
                    instance.pause(session["id"])
                events = []
                instance.on_change(
                    lambda action, payload: events.append(
                        (action, copy.deepcopy(payload))
                    )
                )
                before = (copy.deepcopy(instance._sessions), instance._next_id)
                before_disk = path.read_bytes()
                methods = {
                    "advance_turn": lambda: instance.advance_turn(session["id"], 41),
                    "advance_phase": lambda: instance.advance_phase(session["id"], 42),
                    "waiting": lambda: instance.set_waiting(session["id"], "agent"),
                    "pause": lambda: instance.pause(session["id"]),
                    "resume": lambda: instance.resume(session["id"]),
                    "complete": lambda: instance.complete(session["id"], 43),
                    "interrupt": lambda: instance.interrupt(session["id"], "stop"),
                }
                with patch.object(instance, "_save", side_effect=OSError("save failed")):
                    with self.assertRaisesRegex(OSError, "save failed"):
                        methods[operation]()
                self.assertEqual((instance._sessions, instance._next_id), before)
                self._assert_disk_unchanged(path, before_disk)
                self.assertEqual(events, [])

    def test_update_os_replace_fault_matrix_restores_exact_state(self):
        job_path = self.root / "replace-update-job.json"
        job_store = JobStore(str(job_path))
        job = job_store.create("seed", "task", "general", "user")

        schedule_path = self.root / "replace-update-schedule.json"
        schedule_store = ScheduleStore(str(schedule_path))
        schedule = schedule_store.create("seed", ["worker"], interval_seconds=60)

        rule_path = self.root / "replace-update-rule.json"
        rule_store = RuleStore(str(rule_path))
        rule = rule_store.propose("seed", "user")

        session_path = self.root / "replace-update-session.json"
        session_store = self._session_store(session_path.name)
        session = session_store.create("test", "general", {}, "user")

        cases = (
            (
                "job", "jobs.os.replace", job_path,
                lambda: (copy.deepcopy(job_store._jobs), job_store._next_id),
                lambda: job_store.update_title(job["id"], "changed"), job_store,
            ),
            (
                "schedule", "schedules.os.replace", schedule_path,
                lambda: copy.deepcopy(schedule_store._schedules),
                lambda: schedule_store.toggle(schedule["id"]), schedule_store,
            ),
            (
                "rule", "rules.os.replace", rule_path,
                lambda: (copy.deepcopy(rule_store._rules), rule_store._next_id, rule_store._epoch),
                lambda: rule_store.activate(rule["id"]), rule_store,
            ),
            (
                "session", "session_store.os.replace", session_path,
                lambda: (copy.deepcopy(session_store._sessions), session_store._next_id),
                lambda: session_store.pause(session["id"]), session_store,
            ),
        )
        for name, patch_target, path, snapshot, mutate, instance in cases:
            with self.subTest(store=name):
                before = snapshot()
                before_disk = path.read_bytes()
                events = []
                instance.on_change(
                    lambda action, payload: events.append(
                        (action, copy.deepcopy(payload))
                    )
                )
                with patch(patch_target, side_effect=OSError("replace failed")):
                    with self.assertRaisesRegex(OSError, "replace failed"):
                        mutate()
                self.assertEqual(snapshot(), before)
                self._assert_disk_unchanged(path, before_disk)
                self.assertEqual(events, [])

    def test_custom_template_save_and_delete_are_atomic_and_memory_safe(self):
        instance = self._session_store("custom-sessions.json")
        custom_path = self.root / "custom_templates.json"
        instance.save_custom_template({"id": "one", "name": "One"})
        instance.save_custom_template({"id": "two", "name": "Two"})

        for operation in ("save", "delete"):
            with self.subTest(operation=operation):
                before_templates = copy.deepcopy(instance._templates)
                before_disk = custom_path.read_bytes()
                if operation == "save":
                    mutate = lambda: instance.save_custom_template({
                        "id": "three", "name": "Three",
                    })
                else:
                    mutate = lambda: instance.delete_custom_template("one")
                with patch("session_store.os.replace", side_effect=OSError("replace failed")):
                    with self.assertRaisesRegex(OSError, "replace failed"):
                        mutate()
                self.assertEqual(instance._templates, before_templates)
                self._assert_disk_unchanged(custom_path, before_disk)

    def test_custom_template_lock_serializes_writers_without_lost_update(self):
        instance = self._session_store("concurrent-custom-sessions.json")
        custom_path = self.root / "custom_templates.json"
        first_entered = threading.Event()
        release_first = threading.Event()
        real_write = __import__("session_store")._atomic_write_text
        calls = 0
        errors = []

        def blocked_write(path, content):
            nonlocal calls
            calls += 1
            if calls == 1:
                first_entered.set()
                if not release_first.wait(2):
                    raise TimeoutError("test writer was not released")
            return real_write(path, content)

        def save(template):
            try:
                instance.save_custom_template(template)
            except Exception as exc:
                errors.append(exc)

        with patch("session_store._atomic_write_text", side_effect=blocked_write):
            first = threading.Thread(
                target=save, args=({"id": "one", "name": "One"},), daemon=True,
            )
            second = threading.Thread(
                target=save, args=({"id": "two", "name": "Two"},), daemon=True,
            )
            first.start()
            self.assertTrue(first_entered.wait(1))
            acquired = instance._lock.acquire(blocking=False)
            if acquired:
                instance._lock.release()
            self.assertFalse(acquired)
            second.start()
            release_first.set()
            first.join(2)
            second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(
            [item["id"] for item in json.loads(custom_path.read_text("utf-8"))],
            ["one", "two"],
        )

    def test_message_valid_final_record_without_lf_survives_next_append(self):
        path = self.root / "valid-no-lf.jsonl"
        seed = {"id": 7, "uid": "seed", "sender": "one", "text": "seed"}
        path.write_bytes(json.dumps(seed).encode("utf-8"))
        instance = MessageStore(str(path))
        events = []
        instance.on_message(lambda message: events.append(copy.deepcopy(message)))

        added = instance.add("two", "next")

        records = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
        self.assertEqual([record["id"] for record in records], [7, added["id"]])
        self.assertEqual(len(events), 1)
        self.assertEqual(
            [message["text"] for message in MessageStore(str(path)).get_recent(20)],
            ["seed", "next"],
        )

    def test_message_torn_tail_is_quarantined_then_valid_prefix_survives(self):
        path = self.root / "torn-tail.jsonl"
        seed_bytes = json.dumps({"id": 3, "sender": "one", "text": "seed"}).encode("utf-8") + b"\n"
        torn = b'{"id":4,"sender":"broken"'
        path.write_bytes(seed_bytes + torn)

        instance = MessageStore(str(path))
        quarantines = list(self.root.glob(path.name + ".quarantine-*"))
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(quarantines[0].read_bytes(), torn)
        self.assertEqual(path.read_bytes(), seed_bytes)

        events = []
        instance.on_message(events.append)
        instance.add("two", "next")
        self.assertEqual(len(events), 1)
        self.assertEqual(
            [message["text"] for message in MessageStore(str(path)).get_recent(20)],
            ["seed", "next"],
        )

    def test_message_append_revalidates_and_repairs_or_blocks_new_corruption(self):
        seed = json.dumps({"id": 0, "sender": "one", "text": "seed"}).encode("utf-8") + b"\n"

        torn_path = self.root / "append-torn.jsonl"
        torn_path.write_bytes(seed)
        torn_store = MessageStore(str(torn_path))
        torn = b'{"id":1'
        with open(torn_path, "ab") as handle:
            handle.write(torn)
        events = []
        torn_store.on_message(events.append)
        torn_store.add("two", "next")
        quarantines = list(self.root.glob(torn_path.name + ".quarantine-*"))
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(quarantines[0].read_bytes(), torn)
        self.assertEqual(len(events), 1)
        self.assertEqual(len(MessageStore(str(torn_path)).get_recent(20)), 2)

        corrupt_path = self.root / "append-corrupt.jsonl"
        corrupt_path.write_bytes(seed)
        corrupt_store = MessageStore(str(corrupt_path))
        with open(corrupt_path, "ab") as handle:
            handle.write(b"not-json\n")
        corrupt_before = corrupt_path.read_bytes()
        memory_before = self._capture_message_store(corrupt_store)
        corrupt_events = []
        corrupt_store.on_message(corrupt_events.append)
        with self.assertRaises(MessageLogCorruptionError):
            corrupt_store.add("two", "blocked")
        self.assertEqual(corrupt_path.read_bytes(), corrupt_before)
        self.assertEqual(self._capture_message_store(corrupt_store), memory_before)
        self.assertEqual(corrupt_events, [])

    def test_message_committed_or_interior_corruption_is_fail_closed(self):
        valid = json.dumps({"id": 0, "sender": "one", "text": "seed"}).encode("utf-8") + b"\n"
        later = json.dumps({"id": 1, "sender": "two", "text": "later"}).encode("utf-8") + b"\n"
        cases = {
            "interior": valid + b"not-json\n" + later,
            "committed-tail": valid + b"not-json\n",
        }
        for name, content in cases.items():
            with self.subTest(case=name):
                path = self.root / f"corrupt-{name}.jsonl"
                path.write_bytes(content)
                with self.assertRaises(MessageLogCorruptionError):
                    MessageStore(str(path))
                self.assertEqual(path.read_bytes(), content)
                self.assertEqual(list(self.root.glob(path.name + ".quarantine-*")), [])

    def test_message_torn_tail_repair_fault_windows_never_mutate_live_bytes(self):
        seed = json.dumps({"id": 0, "sender": "one", "text": "seed"}).encode("utf-8") + b"\n"
        torn = b'{"id":1'
        for stage in ("quarantine", "repair"):
            with self.subTest(stage=stage):
                path = self.root / f"repair-fault-{stage}.jsonl"
                original = seed + torn
                path.write_bytes(original)
                real_replace = os.replace
                calls = 0

                def replace(source, destination):
                    nonlocal calls
                    calls += 1
                    if (stage == "quarantine" and calls == 1) or (
                        stage == "repair" and calls == 2
                    ):
                        raise OSError(f"{stage} replace failed")
                    return real_replace(source, destination)

                with patch("store.os.replace", side_effect=replace):
                    with self.assertRaises(MessageLogCorruptionError):
                        MessageStore(str(path))
                self.assertEqual(path.read_bytes(), original)
                quarantines = list(self.root.glob(path.name + ".quarantine-*"))
                self.assertEqual(len(quarantines), 0 if stage == "quarantine" else 1)
                if quarantines:
                    self.assertEqual(quarantines[0].read_bytes(), torn)
                self.assertEqual(list(self.root.glob(f".{path.name}.*.tmp")), [])

    def test_decision_resolution_rewrite_failure_is_atomic_and_silent(self):
        path = self.root / "decision.jsonl"
        instance = MessageStore(str(path))
        decision = instance.add(
            "agent", "choose", msg_type="decision",
            metadata={"choices": ["yes", "no"]},
        )
        events = []
        instance.on_message(lambda payload: events.append(copy.deepcopy(payload)))
        before = self._capture_message_store(instance)
        before_disk = path.read_bytes()
        with patch.object(
            instance, "_rewrite_jsonl", side_effect=OSError("rewrite failed"),
        ):
            with self.assertRaisesRegex(OSError, "rewrite failed"):
                instance.resolve_decision(decision["id"], "yes", "user")
        self.assertEqual(self._capture_message_store(instance), before)
        self._assert_disk_unchanged(path, before_disk)
        self.assertEqual(events, [])

        updated, reply, error = instance.resolve_decision(
            decision["id"], "yes", "user",
        )
        self.assertIsNone(error)
        self.assertTrue(updated["metadata"]["resolved"])
        self.assertEqual(reply["reply_to"], decision["id"])
        self.assertEqual(len(events), 1)
        reloaded = MessageStore(str(path))
        self.assertEqual(len(reloaded.get_recent(20)), 2)

    def test_app_settings_and_hats_failures_restore_exact_memory(self):
        saved_settings = app_module.room_settings
        saved_router = app_module.router
        saved_config = app_module.config
        saved_hats = app_module.agent_hats
        saved_loop = app_module._event_loop
        try:
            app_module.room_settings = {
                "title": "before", "max_agent_hops": 7, "custom_roles": ["one"],
            }
            app_module.router = SimpleNamespace(max_hops=7)
            before_items = copy.deepcopy(list(app_module.room_settings.items()))
            with patch.object(
                app_module, "_save_settings", side_effect=OSError("settings failed"),
            ):
                with self.assertRaisesRegex(OSError, "settings failed"):
                    app_module._apply_room_settings_update({
                        "title": "after", "max_agent_hops": 49,
                        "custom_roles": ["two"],
                    })
            self.assertEqual(list(app_module.room_settings.items()), before_items)
            self.assertEqual(app_module.router.max_hops, 7)

            app_module.config = {"server": {"data_dir": str(self.root)}}
            settings_path = self.root / "settings.json"
            app_module._save_settings()
            before_settings_disk = settings_path.read_bytes()
            with patch("app.os.replace", side_effect=OSError("replace failed")):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    app_module._apply_room_settings_update({
                        "title": "replace-failure", "max_agent_hops": 31,
                    })
            self.assertEqual(list(app_module.room_settings.items()), before_items)
            self.assertEqual(app_module.router.max_hops, 7)
            self.assertEqual(settings_path.read_bytes(), before_settings_disk)
            self.assertEqual(list(self.root.glob(".settings.json.*.tmp")), [])

            app_module.agent_hats = {"agent": "<svg>old</svg>"}
            app_module._event_loop = object()
            hats_path = self.root / "hats.json"
            app_module._save_hats()
            before_hats = copy.deepcopy(app_module.agent_hats)
            before_disk = hats_path.read_bytes()
            with patch.object(
                app_module, "_atomic_write_bytes", side_effect=OSError("hat failed"),
            ), patch.object(app_module.asyncio, "run_coroutine_threadsafe") as dispatch:
                with self.assertRaisesRegex(OSError, "hat failed"):
                    app_module.set_agent_hat("other", "<svg></svg>")
                self.assertEqual(app_module.agent_hats, before_hats)
                self.assertEqual(hats_path.read_bytes(), before_disk)
                dispatch.assert_not_called()
                with self.assertRaisesRegex(OSError, "hat failed"):
                    app_module.clear_agent_hat("agent")
                self.assertEqual(app_module.agent_hats, before_hats)
                self.assertEqual(hats_path.read_bytes(), before_disk)
                dispatch.assert_not_called()
        finally:
            app_module.room_settings = saved_settings
            app_module.router = saved_router
            app_module.config = saved_config
            app_module.agent_hats = saved_hats
            app_module._event_loop = saved_loop

    def test_app_failed_guard_disable_preserves_all_router_channel_state(self):
        saved_settings = app_module.room_settings
        saved_router = app_module.router
        try:
            guard = Router(
                ["alpha", "beta"], default_mention="none", max_hops=1,
            )
            guard.get_targets("alpha", "@beta", "lane")
            guard.get_targets("alpha", "@beta", "lane")
            guard.set_guard_emitted("lane")
            self.assertTrue(guard.is_paused("lane"))
            channels_before = copy.deepcopy(guard._channels)
            app_module.router = guard
            app_module.room_settings = {
                "title": "before", "max_agent_hops": 1,
            }
            settings_before = copy.deepcopy(app_module.room_settings)

            with patch.object(
                app_module, "_save_settings", side_effect=OSError("save failed"),
            ):
                with self.assertRaisesRegex(OSError, "save failed"):
                    app_module._apply_room_settings_update({
                        "title": "after", "max_agent_hops": 0,
                    })

            self.assertEqual(app_module.room_settings, settings_before)
            self.assertEqual(guard.max_hops, 1)
            self.assertEqual(guard._channels, channels_before)
        finally:
            app_module.room_settings = saved_settings
            app_module.router = saved_router

    def test_app_rule_cross_store_failure_restores_rule_and_suppresses_callbacks(self):
        saved_store = app_module.store
        saved_rules = app_module.rules
        saved_loop = app_module._event_loop
        try:
            app_module.store = MessageStore(str(self.root / "rule-cards.jsonl"))
            app_module.rules = RuleStore(str(self.root / "rule-state.json"))
            app_module._event_loop = None
            rule = app_module.rules.propose("seed", "user")
            card = app_module.store.add(
                "agent", "proposal", msg_type="rule_proposal",
                metadata={"rule_id": rule["id"], "status": "pending", "nested": {"x": 1}},
            )
            events = []
            app_module.rules.on_change(
                lambda action, payload: events.append((action, copy.deepcopy(payload)))
            )
            rules_before = app_module.rules.snapshot_state()
            message_before = app_module.store.snapshot_state()
            with patch.object(
                app_module.store, "_rewrite_jsonl", side_effect=OSError("message save failed"),
            ):
                with self.assertRaisesRegex(OSError, "message save failed"):
                    asyncio.run(app_module.resolve_rule_proposal(
                        card["id"], _JsonRequest({"action": "activate"}),
                    ))
            self.assertEqual(app_module.rules._rules, rules_before["rules"])
            self.assertEqual(app_module.rules._next_id, rules_before["next_id"])
            self.assertEqual(app_module.rules._epoch, rules_before["epoch"])
            self.assertEqual(app_module.rules._path.read_bytes(), rules_before["file"][1])
            self.assertEqual(app_module.store._messages, message_before["messages"])
            self.assertEqual(app_module.store._next_id, message_before["next_id"])
            self.assertEqual(events, [])

            result = asyncio.run(app_module.resolve_rule_proposal(
                card["id"], _JsonRequest({"action": "activate"}),
            ))
            self.assertEqual(result["metadata"]["status"], "activated")
            self.assertEqual(app_module.rules.get(rule["id"])["status"], "active")
            self.assertEqual([event[0] for event in events], ["activate"])

            rules_before = app_module.rules.snapshot_state()
            message_before = app_module.store.snapshot_state()
            events_before = copy.deepcopy(events)
            with patch.object(
                app_module.store, "_rewrite_jsonl", side_effect=OSError("demote save failed"),
            ):
                with self.assertRaisesRegex(OSError, "demote save failed"):
                    asyncio.run(app_module.demote_rule_proposal(card["id"]))
            self.assertEqual(app_module.rules._rules, rules_before["rules"])
            self.assertEqual(app_module.rules._epoch, rules_before["epoch"])
            self.assertEqual(app_module.rules._path.read_bytes(), rules_before["file"][1])
            self.assertEqual(app_module.store._messages, message_before["messages"])
            self.assertEqual(events, events_before)
        finally:
            app_module.store = saved_store
            app_module.rules = saved_rules
            app_module._event_loop = saved_loop

    def test_app_job_anchor_zero_rolls_back_whole_message_without_metadata_key(self):
        saved_store = app_module.store
        saved_jobs = app_module.jobs
        saved_settings = app_module.room_settings
        try:
            app_module.store = MessageStore(str(self.root / "job-anchor.jsonl"))
            app_module.jobs = JobStore(str(self.root / "jobs.json"))
            app_module.room_settings = {
                "channels": ["general"], "max_discovered_channels": 8,
            }
            anchor = app_module.store.add(
                "agent", "proposal", msg_type="job_proposal",
                channel="general",
            )
            self.assertEqual(anchor["id"], 0)
            self.assertNotIn("metadata", anchor)
            before = copy.deepcopy(anchor)

            with patch.object(
                app_module, "store_channel_message",
                side_effect=OSError("breadcrumb failed"),
            ):
                response = asyncio.run(app_module.create_job(_JsonRequest({
                    "title": "job", "channel": "general", "anchor_msg_id": 0,
                })))

            self.assertEqual(response.status_code, 500)
            self.assertEqual(app_module.store.get_by_id(0), before)
            self.assertNotIn("metadata", app_module.store.get_by_id(0))
            self.assertEqual(app_module.jobs.list_all(), [])
        finally:
            app_module.store = saved_store
            app_module.jobs = saved_jobs
            app_module.room_settings = saved_settings

    def test_inline_session_template_never_enters_custom_catalogue_under_concurrency(self):
        path = self.root / "inline-sessions.json"
        instance = SessionStore(str(path))
        inline = {
            "id": "draft-0", "name": "Inline", "roles": ["builder"],
            "phases": [{"name": "work", "participants": ["builder"]}],
        }
        custom = {
            "id": "saved", "name": "Saved", "roles": ["reviewer"],
            "phases": [{"name": "review", "participants": ["reviewer"]}],
        }
        session_write_entered = threading.Event()
        allow_session_write = threading.Event()
        custom_started = threading.Event()
        custom_finished = threading.Event()
        errors = []
        original_write = session_store_module._atomic_write_text

        def delayed_write(target, content):
            if Path(target) == path:
                session_write_entered.set()
                if not allow_session_write.wait(5):
                    raise RuntimeError("test timed out waiting to release session save")
            return original_write(target, content)

        def create_inline():
            try:
                instance.create_from_template(
                    inline, "general", {"builder": "agent"}, "user",
                )
            except Exception as exc:
                errors.append(exc)

        def save_custom():
            custom_started.set()
            try:
                instance.save_custom_template(custom)
            except Exception as exc:
                errors.append(exc)
            finally:
                custom_finished.set()

        with patch.object(
            session_store_module, "_atomic_write_text", side_effect=delayed_write,
        ):
            creator = threading.Thread(target=create_inline)
            saver = threading.Thread(target=save_custom)
            creator.start()
            self.assertTrue(session_write_entered.wait(5))
            saver.start()
            self.assertTrue(custom_started.wait(5))
            self.assertFalse(custom_finished.wait(0.05))
            allow_session_write.set()
            creator.join(5)
            saver.join(5)

        self.assertFalse(creator.is_alive())
        self.assertFalse(saver.is_alive())
        self.assertEqual(errors, [])
        self.assertNotIn("draft-0", instance._templates)
        self.assertEqual(
            [item["id"] for item in instance.get_templates()], ["saved"],
        )
        custom_bytes = json.loads(
            (self.root / "custom_templates.json").read_text("utf-8")
        )
        self.assertEqual([item["id"] for item in custom_bytes], ["saved"])
        inline_session = instance.list_all()[0]
        self.assertEqual(
            instance.get_template_for_session(inline_session)["name"], "Inline",
        )
        self.assertIsNone(instance.get_template("draft-0"))

        reloaded = SessionStore(str(path))
        reloaded_session = reloaded.list_all()[0]
        self.assertEqual(
            reloaded.get_template_for_session(reloaded_session)["name"], "Inline",
        )
        self.assertIsNone(reloaded.get_template("draft-0"))

    def test_session_engine_prefers_own_inline_template_on_id_collision_and_reload(self):
        path = self.root / "collision-sessions.json"
        instance = SessionStore(str(path))
        catalogue = {
            "id": "draft-0", "name": "Catalogue", "roles": ["wrong", "also-wrong"],
            "phases": [{
                "name": "Wrong phase", "participants": ["wrong", "also-wrong"],
                "prompt": "wrong prompt",
            }],
        }
        inline = {
            "id": "draft-0", "name": "Inline", "roles": ["builder"],
            "phases": [{
                "name": "Inline phase", "participants": ["builder"],
                "prompt": "inline prompt",
            }],
        }
        instance.save_custom_template(catalogue)
        session = instance.create_from_template(
            inline, "general", {"builder": "inline-agent"}, "user",
        )
        self.assertEqual(instance.get_template("draft-0")["name"], "Catalogue")
        self.assertEqual(
            instance.get_template_for_session(session)["name"], "Inline",
        )

        class _Trigger:
            def __init__(self):
                self.calls = []

            def action_id_for(self, *args):
                return "collision-action"

            def trigger_sync(self, agent, **kwargs):
                self.calls.append((agent, copy.deepcopy(kwargs)))

        class _Registry:
            @staticmethod
            def is_registered(_name):
                return True

        messages = MessageStore(str(self.root / "collision-messages.jsonl"))
        engine = SessionEngine(instance, messages, _Trigger(), _Registry())
        self.assertEqual(engine._get_expected_agent(session), "inline-agent")
        self.assertEqual(engine._enrich(copy.deepcopy(session))["phase_name"], "Inline phase")
        engine.emit_current_phase_banner(session)
        self.assertEqual(messages.get_recent(1)[0]["text"], "Phase: Inline phase")

        # Reload proves the inline bytes, not the colliding custom catalogue,
        # drive resume, trigger prompt, banner, and advance decisions.
        reloaded = SessionStore(str(path))
        reloaded_session = reloaded.list_all()[0]
        self.assertEqual(reloaded.get_template("draft-0")["name"], "Catalogue")
        self.assertEqual(
            reloaded.get_template_for_session(reloaded_session)["name"], "Inline",
        )
        resumed_messages = MessageStore(str(self.root / "resumed-messages.jsonl"))
        trigger = _Trigger()
        resumed_engine = SessionEngine(reloaded, resumed_messages, trigger, _Registry())
        resumed_engine.emit_current_phase_banner(reloaded_session)
        self.assertEqual(
            resumed_messages.get_recent(1)[0]["text"], "Phase: Inline phase",
        )
        resumed_engine.resume_active_sessions()
        self.assertEqual(trigger.calls[0][0], "inline-agent")
        self.assertIn("SESSION: Inline", trigger.calls[0][1]["prompt"])
        self.assertNotIn("Catalogue", trigger.calls[0][1]["prompt"])

        waiting = reloaded.get(reloaded_session["id"])
        resumed_engine._advance(waiting, 77)
        self.assertEqual(reloaded.get(waiting["id"])["state"], "complete")

    def test_save_draft_does_not_alias_message_metadata(self):
        saved_store = app_module.store
        saved_sessions = app_module.session_store
        try:
            app_module.store = MessageStore(str(self.root / "drafts.jsonl"))
            app_module.session_store = SessionStore(str(self.root / "draft-sessions.json"))
            message = app_module.store.add(
                "agent", "draft", msg_type="session_draft",
                metadata={
                    "valid": True,
                    "template": {"name": "Custom", "roles": ["one"], "phases": []},
                },
            )
            before = copy.deepcopy(app_module.store.get_by_id(message["id"]))
            response = asyncio.run(
                app_module.save_draft(_JsonRequest({"message_id": message["id"]}))
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(app_module.store.get_by_id(message["id"]), before)
            self.assertNotIn("id", before["metadata"]["template"])
            self.assertIsNotNone(
                app_module.session_store.get_template(f"custom-{message['id']}")
            )
        finally:
            app_module.store = saved_store
            app_module.session_store = saved_sessions


if __name__ == "__main__":
    unittest.main()
