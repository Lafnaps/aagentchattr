import asyncio
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import agents
import app
import delivery_io
import mcp_bridge
import session_engine
import wrapper
import wrapper_unix


class ProducerEnvelopeTests(unittest.TestCase):
    def test_sync_and_async_entries_have_unique_backward_compatible_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            trigger = agents.AgentTrigger(mock.Mock(), tmp)
            trigger.trigger_sync(
                "worker", "owner: first", "lane-a", action_id="ACT-1"
            )
            asyncio.run(trigger.trigger(
                "worker", "owner: second", "lane-b", job_id=7
            ))
            records = [
                json.loads(line)
                for line in (Path(tmp) / "worker_queue.jsonl")
                .read_text("utf-8").splitlines()
            ]

        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]["event_id"], records[1]["event_id"])
        self.assertTrue(records[0]["event_id"].startswith("evt-"))
        self.assertEqual(records[0]["envelope_version"], 1)
        self.assertEqual(records[0]["action_id"], "ACT-1")
        self.assertEqual(records[0]["channel"], "lane-a")
        self.assertEqual(records[1]["job_id"], 7)
        # Legacy fields remain present for old wrappers/readers.
        self.assertEqual(records[0]["sender"], "owner")
        self.assertIn("time", records[0])

    def test_same_action_id_is_idempotent_across_producer_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            trigger = agents.AgentTrigger(mock.Mock(), tmp)
            first = trigger.trigger_sync(
                "worker", "owner: retry me", "lane-a", action_id="ACT-42"
            )
            second = asyncio.run(trigger.trigger(
                "worker", "owner: retry me", "lane-a", action_id="ACT-42"
            ))
            records = (Path(tmp) / "worker_queue.jsonl").read_text(
                "utf-8"
            ).splitlines()
        self.assertTrue(first)
        self.assertFalse(second)
        self.assertEqual(len(records), 1)

    def test_complete_json_without_newline_cannot_suppress_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = Path(tmp) / "worker_queue.jsonl"
            queue.write_bytes(b'{"action_id":"ACT-TORN","channel":"old"}')
            trigger = agents.AgentTrigger(mock.Mock(), tmp)
            appended = trigger.trigger_sync(
                "worker", "owner: retry", "new", action_id="ACT-TORN"
            )
            lines = queue.read_bytes().splitlines(keepends=True)
        self.assertTrue(appended)
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(line.endswith(b"\n") for line in lines))
        self.assertEqual(
            [json.loads(line)["action_id"] for line in lines],
            ["ACT-TORN", "ACT-TORN"],
        )

    def test_generation_bound_action_id_is_stable_and_rotates(self):
        class Registry:
            epoch = 3

            def get_instance(self, _name):
                return {"identity_id": "identity-a", "epoch": self.epoch}

        registry = Registry()
        trigger = agents.AgentTrigger(registry, ".")
        first = trigger.action_id_for("message", "17:uid", "worker")
        self.assertEqual(
            first, trigger.action_id_for("message", "17:uid", "worker")
        )
        registry.epoch = 4
        self.assertNotEqual(
            first, trigger.action_id_for("message", "17:uid", "worker")
        )

    def test_queue_limit_refuses_without_deleting_and_writes_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            trigger = agents.AgentTrigger(mock.Mock(), tmp)
            with mock.patch.object(agents, "_MAX_QUEUE_BYTES", 32):
                with self.assertRaises(delivery_io.DeliveryBackpressureError):
                    trigger.trigger_sync(
                        "worker", "owner: payload too large", "lane-a"
                    )
            queue = Path(tmp) / "worker_queue.jsonl"
            marker = Path(tmp) / "worker_queue.jsonl.backpressure.json"
            self.assertFalse(queue.exists())
            self.assertEqual(
                json.loads(marker.read_text("utf-8"))["component"],
                "producer-queue",
            )


class NormalRoutingActionIdTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_store_callback_queues_one_generation_bound_action(self):
        class Registry:
            def get_all_names(self):
                return ["worker"]

            def resolve_to_instances(self, _name):
                return ["worker"]

            def get_instance(self, _name):
                return {
                    "name": "worker", "state": "active",
                    "identity_id": "generation-a", "epoch": 7,
                }

            def is_registered(self, _name):
                return True

        class Router:
            max_hops = 10

            def get_targets(self, _sender, _text, _channel):
                return ["worker"]

            def is_paused(self, _channel):
                return False

        class Store:
            def __init__(self, message):
                self.message = message

            def get_by_id(self, msg_id):
                return self.message if msg_id == self.message["id"] else None

            def add(self, *_args, **_kwargs):
                return {}

        saved = {
            "store": app.store, "router": app.router, "registry": app.registry,
            "agents": app.agents, "session_engine": app.session_engine,
            "config": app.config, "room_settings": app.room_settings,
            "broadcast": app.broadcast,
            "broadcast_settings": app.broadcast_settings,
        }
        message = {
            "id": 41, "uid": "durable-source-uid", "sender": "owner",
            "text": "@worker do it", "type": "chat", "channel": "general",
        }
        try:
            with tempfile.TemporaryDirectory() as tmp:
                registry = Registry()
                app.store = Store(message)
                app.router = Router()
                app.registry = registry
                app.agents = agents.AgentTrigger(registry, tmp)
                app.session_engine = None
                app.config = {"agents": {"worker": {}}}
                app.room_settings = {
                    "channels": ["general"], "max_channels": 64,
                    "max_discovered_channels": 128,
                    "catalogue_revision": 0,
                }

                async def no_broadcast(*_args, **_kwargs):
                    return None

                app.broadcast = no_broadcast
                app.broadcast_settings = no_broadcast
                with mock.patch.object(mcp_bridge, "is_online", return_value=True):
                    await app._handle_new_message(message)
                    await app._handle_new_message(message)
                records = [
                    json.loads(line) for line in
                    (Path(tmp) / "worker_queue.jsonl").read_text(
                        "utf-8"
                    ).splitlines()
                ]
            self.assertEqual(len(records), 1)
            expected = app.agents.action_id_for(
                "message", "41:durable-source-uid", "worker"
            )
            self.assertEqual(records[0]["action_id"], expected)
        finally:
            app.store = saved["store"]
            app.router = saved["router"]
            app.registry = saved["registry"]
            app.agents = saved["agents"]
            app.session_engine = saved["session_engine"]
            app.config = saved["config"]
            app.room_settings = saved["room_settings"]
            app.broadcast = saved["broadcast"]
            app.broadcast_settings = saved["broadcast_settings"]


class SessionActionIdentityTests(unittest.TestCase):
    def test_role_turn_identity_is_distinct_and_retry_is_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = mock.Mock()
            store.get_template_for_session.return_value = {
                "name": "two roles",
                "phases": [{
                    "name": "review",
                    "prompt": "review it",
                    "participants": ["builder", "reviewer"],
                }],
            }
            messages = mock.Mock()
            trigger = mock.Mock()
            real_ids = agents.AgentTrigger(None, tmp)
            trigger.action_id_for.side_effect = real_ids.action_id_for
            registry = mock.Mock()
            registry.is_registered.return_value = True
            engine = session_engine.SessionEngine(
                store, messages, trigger, registry=registry
            )
            base = {
                "id": 44,
                "template_id": "roles",
                "current_phase": 0,
                "channel": "lane-a",
                "cast": {"builder": "same-agent", "reviewer": "same-agent"},
            }

            engine._trigger_current(dict(base, current_turn=0))
            engine._trigger_current(dict(base, current_turn=1))
            engine._trigger_current(dict(base, current_turn=0))

        action_ids = [
            call.kwargs["action_id"] for call in trigger.trigger_sync.call_args_list
        ]
        self.assertEqual(len(action_ids), 3)
        self.assertNotEqual(action_ids[0], action_ids[1])
        self.assertEqual(action_ids[0], action_ids[2])
        sources = [
            call.args[1] for call in trigger.action_id_for.call_args_list
        ]
        self.assertEqual(sources, [
            "44:0:0:builder", "44:0:1:reviewer", "44:0:0:builder",
        ])


class DeliveryJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.queue = Path(self.tmp.name) / "worker_queue.jsonl"
        self.stop = threading.Event()

    @staticmethod
    def _rules(*_args, **_kwargs):
        return True, {"epoch": 1, "rules": [], "refresh_interval": 10}

    @staticmethod
    def _role(*_args, **_kwargs):
        return True, ""

    def run_watcher(self, injector, done, **overrides):
        kwargs = {
            "stop_event": self.stop,
            "poll_seconds": 0.01,
            "fetch_role_fn": self._role,
            "fetch_rules_fn": self._rules,
            "report_sync_fn": lambda *_a, **_k: None,
        }
        kwargs.update(overrides)
        thread = threading.Thread(
            target=wrapper._queue_watcher,
            args=(lambda: ("worker", self.queue), injector),
            kwargs=kwargs,
            daemon=True,
        )
        with mock.patch.object(wrapper.time, "sleep"):
            thread.start()
            self.assertTrue(done.wait(5))
            self.stop.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())

    def write_events(self, *records):
        self.queue.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            "utf-8",
        )

    def test_legacy_event_ids_are_stable_and_distinguish_duplicates(self):
        records = [{"channel": "a"}, {"channel": "a"}]
        first = wrapper._prepare_delivery_events(self.queue, records)
        second = wrapper._prepare_delivery_events(self.queue, records)
        self.assertEqual(
            [event["event_id"] for event in first],
            [event["event_id"] for event in second],
        )
        self.assertNotEqual(first[0]["event_id"], first[1]["event_id"])

    def test_legacy_ambiguous_acceptance_names_are_blocked_not_terminal(self):
        for state in ("accepted-legacy", "accepted-uncertain"):
            self.assertNotIn(state, wrapper._TERMINAL_DELIVERY_STATES)
            self.assertIn(state, wrapper._BLOCKED_DELIVERY_STATES)
        for result in (None, False, "injected-uncertain"):
            self.assertIsNone(wrapper._terminal_delivery_state(result))

    def test_legacy_ids_use_absolute_record_offsets_across_batches(self):
        line = '{"channel":"same"}\n'
        payload = line + line
        triggers, malformed, offsets = wrapper._parse_trigger_records(
            payload, 0
        )
        self.assertEqual(malformed, 0)
        both = wrapper._prepare_delivery_events(
            self.queue, triggers, offsets
        )
        self.assertNotEqual(both[0]["event_id"], both[1]["event_id"])

        # Cursor now exposes only the second, byte-identical record.  Its ID
        # is identical across restart/resnapshot, not reset to batch ordinal 0.
        self.queue.write_bytes(payload.encode("utf-8"))
        first_end = len(line.encode("utf-8"))
        wrapper._write_queue_cursor(
            self.queue, first_end, self.queue.read_bytes()
        )
        _status, pending, _end, raw = wrapper._read_pending_triggers(self.queue)
        start = wrapper._read_queue_cursor(self.queue, raw)
        later_triggers, _bad, later_offsets = wrapper._parse_trigger_records(
            pending, start
        )
        later = wrapper._prepare_delivery_events(
            self.queue, later_triggers, later_offsets
        )
        self.assertEqual(later[0]["event_id"], both[1]["event_id"])

    def test_persisted_acceptance_is_deduplicated_after_cursor_crash(self):
        event = {"event_id": "evt-one", "channel": "lane-a"}
        self.write_events(event)
        wrapper._append_delivery_transition(
            self.queue, "accepted", [event], result="injected"
        )
        done = threading.Event()

        def must_not_inject(_prompt):
            self.fail("accepted event was injected twice")

        def wait_for_cursor():
            raw = self.queue.read_bytes()
            while wrapper._read_queue_cursor(self.queue, raw) != len(raw):
                if self.stop.wait(0.01):
                    return
            done.set()

        threading.Thread(target=wait_for_cursor, daemon=True).start()
        self.run_watcher(must_not_inject, done)

    def test_persisted_attempting_state_blocks_crash_replay(self):
        event = {"event_id": "evt-inflight", "channel": "lane-a"}
        self.write_events(event)
        wrapper._append_delivery_transition(
            self.queue, "attempting", [event]
        )
        calls = {"count": 0}

        def must_not_inject(_prompt):
            calls["count"] += 1
            return "injected"

        thread = threading.Thread(
            target=wrapper._queue_watcher,
            args=(lambda: ("worker", self.queue), must_not_inject),
            kwargs={
                "stop_event": self.stop,
                "poll_seconds": 0.01,
                "fetch_role_fn": self._role,
                "fetch_rules_fn": self._rules,
                "report_sync_fn": lambda *_a, **_k: None,
            },
            daemon=True,
        )
        thread.start()
        self.assertFalse(self.stop.wait(0.1))
        self.stop.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(calls["count"], 0)
        self.assertEqual(
            wrapper._read_queue_cursor(self.queue, self.queue.read_bytes()), 0
        )

    def test_mixed_replay_injects_only_unaccepted_event_and_propagates_id(self):
        accepted = {"event_id": "evt-old", "channel": "lane-old"}
        pending = {
            "event_id": "evt-new", "action_id": "ACT-9",
            "channel": "lane-new",
        }
        self.write_events(accepted, pending)
        wrapper._append_delivery_transition(
            self.queue, "accepted", [accepted], result="injected"
        )
        prompts = []
        done = threading.Event()

        def inject(prompt):
            prompts.append(prompt)
            done.set()
            return "injected"

        self.run_watcher(inject, done)
        self.assertEqual(len(prompts), 1)
        self.assertIn("#lane-new", prompts[0])
        self.assertNotIn("#lane-old", prompts[0])
        self.assertIn('"event_ids":["evt-new"]', prompts[0])
        self.assertIn('"action_ids":["ACT-9"]', prompts[0])
        states = wrapper._read_delivery_states(self.queue)
        self.assertEqual(states["evt-old"]["state"], "accepted")
        self.assertEqual(states["evt-new"]["state"], "accepted")

    def test_same_action_id_deduplicates_distinct_event_ids_and_restart(self):
        first = {
            "event_id": "evt-action-a", "action_id": "ACTION-ONE",
            "channel": "lane-a",
        }
        retry = {
            "event_id": "evt-action-b", "action_id": "ACTION-ONE",
            "channel": "lane-a",
        }
        self.write_events(first, retry)
        prompts = []
        done = threading.Event()

        def inject(prompt):
            prompts.append(prompt)
            done.set()
            return "injected"

        self.run_watcher(inject, done)
        self.assertEqual(len(prompts), 1)
        self.assertIn('"event_ids":["evt-action-a"]', prompts[0])
        states, actions = wrapper._read_delivery_indexes(self.queue)
        self.assertEqual(states["evt-action-a"]["state"], "accepted")
        self.assertEqual(states["evt-action-b"]["state"], "accepted")
        self.assertEqual(actions["ACTION-ONE"]["state"], "accepted")

        # Simulate a lost/corrupt cursor: action-level terminal history still
        # prevents either physical event from being injected again.
        wrapper._write_queue_cursor(self.queue, 0, b"")
        self.stop = threading.Event()
        advanced = threading.Event()

        def must_not_inject(_prompt):
            self.fail("logical action was injected twice")

        def watch_cursor():
            raw = self.queue.read_bytes()
            while wrapper._read_queue_cursor(self.queue, raw) != len(raw):
                if self.stop.wait(0.01):
                    return
            advanced.set()

        threading.Thread(target=watch_cursor, daemon=True).start()
        self.run_watcher(must_not_inject, advanced)

    def test_retryable_failure_does_not_dead_letter_or_advance(self):
        event = {"event_id": "evt-failed", "channel": "lane-a"}
        self.write_events(event)
        done = threading.Event()

        def fail(_prompt):
            done.set()
            return "deferred"

        self.run_watcher(fail, done)
        state = wrapper._read_delivery_states(self.queue)["evt-failed"]
        self.assertEqual(state["state"], "retry")
        raw = self.queue.read_bytes()
        self.assertEqual(wrapper._read_queue_cursor(self.queue, raw), 0)

    def test_hung_injector_times_out_once_and_blocks_without_advancing(self):
        event = {"event_id": "evt-hung", "channel": "lane-a"}
        self.write_events(event)
        release = threading.Event()
        state_written = threading.Event()
        calls = {"count": 0}

        def hung(_prompt):
            calls["count"] += 1
            release.wait(5)
            return "injected"

        def wait_state():
            while not self.stop.wait(0.01):
                try:
                    state = wrapper._read_delivery_states(self.queue).get(
                        "evt-hung", {}
                    ).get("state")
                except ValueError:
                    continue
                if state == "injection-timeout":
                    state_written.set()
                    return

        threading.Thread(target=wait_state, daemon=True).start()
        try:
            self.run_watcher(
                hung, state_written, inject_timeout_seconds=0.05
            )
        finally:
            release.set()
        self.assertEqual(calls["count"], 1)
        raw = self.queue.read_bytes()
        self.assertEqual(wrapper._read_queue_cursor(self.queue, raw), 0)
        self.assertEqual(
            wrapper._read_delivery_states(self.queue)["evt-hung"]["state"],
            "injection-timeout",
        )

    def test_watcher_exception_is_visible_and_attempt_stays_blocked(self):
        event = {"event_id": "evt-retry", "channel": "lane-a"}
        self.write_events(event)
        done = threading.Event()
        calls = {"count": 0}

        def flaky(_prompt):
            calls["count"] += 1
            done.set()
            raise RuntimeError("injected test failure")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.run_watcher(flaky, done)
        self.assertIn("queue watcher error (recovering)", output.getvalue())
        records = [
            json.loads(line)
            for line in wrapper._delivery_journal_path(self.queue)
            .read_text("utf-8").splitlines()
        ]
        self.assertTrue(any(r["state"] == "watcher-error" for r in records))
        self.assertEqual(calls["count"], 1)
        self.assertEqual(
            wrapper._read_delivery_states(self.queue)["evt-retry"]["state"],
            "attempting",
        )

    def test_corrupt_delivery_journal_is_quarantined_and_blocks_replay(self):
        event = {"event_id": "evt-recover", "channel": "lane-a"}
        self.write_events(event)
        wrapper._delivery_journal_path(self.queue).write_bytes(b"not-json\n")
        prompts = []

        def inject(prompt):
            prompts.append(prompt)
            return "injected"

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            thread = threading.Thread(
                target=wrapper._queue_watcher,
                args=(lambda: ("worker", self.queue), inject),
                kwargs={
                    "stop_event": self.stop,
                    "poll_seconds": 0.01,
                    "fetch_role_fn": self._role,
                    "fetch_rules_fn": self._rules,
                    "report_sync_fn": lambda *_a, **_k: None,
                },
                daemon=True,
            )
            thread.start()
            self.assertFalse(self.stop.wait(0.15))
            self.stop.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(prompts, [])
        self.assertIn("corrupt delivery journal quarantined", output.getvalue())
        quarantined = list(self.queue.parent.glob(
            self.queue.name + ".delivery.jsonl.quarantine-*"
        ))
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].read_bytes(), b"not-json\n")
        self.assertEqual(
            wrapper._read_delivery_states(self.queue)["evt-recover"]["state"],
            "journal-corrupt-blocked",
        )
        self.assertEqual(
            wrapper._read_queue_cursor(self.queue, self.queue.read_bytes()), 0
        )

    def _assert_bad_journal_blocks_with_evidence(self, raw_journal):
        event = {"event_id": "evt-bad-journal", "channel": "lane-a"}
        self.write_events(event)
        wrapper._delivery_journal_path(self.queue).write_bytes(raw_journal)
        prompts = []

        thread = threading.Thread(
            target=wrapper._queue_watcher,
            args=(lambda: ("worker", self.queue), prompts.append),
            kwargs={
                "stop_event": self.stop,
                "poll_seconds": 0.01,
                "fetch_role_fn": self._role,
                "fetch_rules_fn": self._rules,
                "report_sync_fn": lambda *_a, **_k: None,
            },
            daemon=True,
        )
        thread.start()
        self.assertFalse(self.stop.wait(0.15))
        self.stop.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(prompts, [])
        evidence = list(self.queue.parent.glob(
            self.queue.name + ".delivery.jsonl.quarantine-*"
        ))
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].read_bytes(), raw_journal)
        self.assertEqual(
            wrapper._read_delivery_states(self.queue)["evt-bad-journal"]["state"],
            "journal-corrupt-blocked",
        )
        self.assertEqual(
            wrapper._read_queue_cursor(self.queue, self.queue.read_bytes()), 0
        )

    def test_torn_journal_tail_is_quarantined_before_injection(self):
        # Valid JSON without its commit newline is still a torn record.  It
        # may contain the only persisted "attempting" transition, so ignoring
        # it would allow duplicate terminal input after a crash.
        self._assert_bad_journal_blocks_with_evidence(json.dumps({
            "journal_version": 1,
            "at_ns": 1,
            "state": "attempting",
            "event_ids": ["evt-bad-journal"],
        }).encode("utf-8"))

    def test_unknown_and_non_string_journal_states_are_corruption(self):
        for bad_state in ("future-state", 7, None):
            with self.subTest(state=bad_state):
                self.stop = threading.Event()
                raw = (json.dumps({
                    "journal_version": 1,
                    "at_ns": 1,
                    "state": bad_state,
                    "event_ids": ["evt-bad-journal"],
                }) + "\n").encode("utf-8")
                self._assert_bad_journal_blocks_with_evidence(raw)
                for path in self.queue.parent.iterdir():
                    path.unlink()

    def test_journal_v1_schema_is_strict_and_closed(self):
        valid = {
            "journal_version": 1,
            "at_ns": 1,
            "state": "accepted",
            "event_ids": ["evt-schema"],
            "inject_result": "injected",
        }
        mutations = {
            "missing-version": lambda r: r.pop("journal_version"),
            "future-version": lambda r: r.update(journal_version=2),
            "bool-version": lambda r: r.update(journal_version=True),
            "missing-at-ns": lambda r: r.pop("at_ns"),
            "string-at-ns": lambda r: r.update(at_ns="1"),
            "negative-at-ns": lambda r: r.update(at_ns=-1),
            "event-ids-not-list": lambda r: r.update(event_ids="evt"),
            "invalid-event-id": lambda r: r.update(event_ids=[""]),
            "non-ascii-event-id": lambda r: r.update(event_ids=["evt-я"]),
            "non-string-event-id": lambda r: r.update(event_ids=[1]),
            "duplicate-event-id": lambda r: r.update(
                event_ids=["evt-schema", "evt-schema"]
            ),
            "empty-terminal-events": lambda r: r.update(event_ids=[]),
            "action-ids-not-list": lambda r: r.update(action_ids="act"),
            "empty-action-ids": lambda r: r.update(action_ids=[]),
            "invalid-action-id": lambda r: r.update(action_ids=["bad id"]),
            "non-ascii-action-id": lambda r: r.update(action_ids=["act-я"]),
            "duplicate-action-id": lambda r: r.update(
                action_ids=["act-a", "act-a"]
            ),
            "too-many-action-ids": lambda r: r.update(
                action_ids=["act-a", "act-b"]
            ),
            "cursor-not-bool": lambda r: r.update(cursor_committed=1),
            "cursor-false": lambda r: r.update(cursor_committed=False),
            "error-not-string": lambda r: r.update(error=7),
            "result-not-string": lambda r: r.update(inject_result=None),
            "accepted-wrong-result": lambda r: r.update(inject_result="deferred"),
            "attempting-claims-result": lambda r: r.update(state="attempting"),
            "watcher-error-nonempty": lambda r: r.update(
                state="watcher-error", error="boom"
            ),
            "dead-letter-wrong-result": lambda r: r.update(state="dead-letter"),
            "timeout-wrong-result": lambda r: r.update(state="injection-timeout"),
            "retry-terminal-result": lambda r: r.update(state="retry"),
            "journal-block-missing-error": lambda r: r.update(
                state="journal-corrupt-blocked"
            ),
            "unknown-field": lambda r: r.update(future_field=True),
        }
        journal = wrapper._delivery_journal_path(self.queue)
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                record = dict(valid)
                mutate(record)
                journal.write_text(json.dumps(record) + "\n", "utf-8")
                with self.assertRaises(ValueError):
                    wrapper._read_delivery_indexes(self.queue)

        semantic_records = {
            "watcher-action": {
                "state": "watcher-error", "event_ids": [],
                "error": "boom", "action_ids": ["act-a"],
            },
            "watcher-cursor": {
                "state": "watcher-error", "event_ids": [],
                "error": "boom", "cursor_committed": True,
            },
            "watcher-result": {
                "state": "watcher-error", "event_ids": [],
                "error": "boom", "inject_result": "deferred",
            },
            "attempting-cursor": {
                "state": "attempting", "event_ids": ["evt-schema"],
                "cursor_committed": True,
            },
            "attempting-result": {
                "state": "attempting", "event_ids": ["evt-schema"],
                "inject_result": "injected",
            },
            "blocked-result": {
                "state": "journal-corrupt-blocked",
                "event_ids": ["evt-schema"], "error": "corrupt",
                "inject_result": "deferred",
            },
            "legacy-result": {
                "state": "accepted-legacy", "event_ids": ["evt-schema"],
                "inject_result": "injected-uncertain",
            },
        }
        for name, state_fields in semantic_records.items():
            with self.subTest(case=name):
                record = {
                    "journal_version": 1, "at_ns": 1, **state_fields,
                }
                journal.write_text(json.dumps(record) + "\n", "utf-8")
                with self.assertRaises(ValueError):
                    wrapper._read_delivery_indexes(self.queue)

        for name, raw in {
            "empty-record": b"\n",
            "duplicate-field": (
                b'{"journal_version":1,"journal_version":1,"at_ns":1,'
                b'"state":"accepted","event_ids":["evt-schema"]}\n'
            ),
        }.items():
            with self.subTest(case=name):
                journal.write_bytes(raw)
                with self.assertRaises(ValueError):
                    wrapper._read_delivery_indexes(self.queue)

        # watcher-error is the sole state allowed to describe no event.
        watcher_error = dict(valid, state="watcher-error", event_ids=[])
        watcher_error.pop("inject_result")
        watcher_error["error"] = "visible failure"
        journal.write_text(json.dumps(watcher_error) + "\n", "utf-8")
        self.assertEqual(wrapper._read_delivery_indexes(self.queue), ({}, {}))

    def test_corruption_fault_windows_never_reopen_injection(self):
        original_marker = wrapper._write_delivery_block_marker
        original_append = wrapper._append_delivery_transition

        def fail_first_marker(*_args, **_kwargs):
            raise OSError("marker write fault")

        marker_calls = {"count": 0}

        def fail_marker_evidence_update(*args, **kwargs):
            marker_calls["count"] += 1
            if marker_calls["count"] == 2:
                raise OSError("marker evidence update fault")
            return original_marker(*args, **kwargs)

        def fail_blocker(queue, state, events, **kwargs):
            if state == "journal-corrupt-blocked":
                raise OSError("blocker append fault")
            return original_append(queue, state, events, **kwargs)

        cases = {
            "initial-marker": mock.patch.object(
                wrapper, "_write_delivery_block_marker",
                side_effect=fail_first_marker,
            ),
            "evidence-copy": mock.patch.object(
                wrapper, "write_unique_evidence",
                side_effect=OSError("evidence copy fault"),
            ),
            "marker-evidence-update": mock.patch.object(
                wrapper, "_write_delivery_block_marker",
                side_effect=fail_marker_evidence_update,
            ),
            "source-unlink": mock.patch.object(
                wrapper, "_remove_corrupt_journal",
                side_effect=OSError("unlink fault"),
            ),
            "blocker-append": mock.patch.object(
                wrapper, "_append_delivery_transition",
                side_effect=fail_blocker,
            ),
        }
        for name, patcher in cases.items():
            with self.subTest(window=name):
                marker_calls["count"] = 0
                self.stop = threading.Event()
                for path in self.queue.parent.iterdir():
                    path.unlink()
                self.write_events({
                    "event_id": "evt-fault-window", "channel": "lane-a",
                })
                corrupt = wrapper._delivery_journal_path(self.queue)
                corrupt.write_bytes(b'{"torn":true')
                calls = []

                def inject(prompt):
                    calls.append(prompt)
                    return "injected"

                output = io.StringIO()
                with patcher, contextlib.redirect_stdout(output):
                    thread = threading.Thread(
                        target=wrapper._queue_watcher,
                        args=(lambda: ("worker", self.queue), inject),
                        kwargs={
                            "stop_event": self.stop,
                            "poll_seconds": 0.01,
                            "fetch_role_fn": self._role,
                            "fetch_rules_fn": self._rules,
                            "report_sync_fn": lambda *_a, **_k: None,
                        },
                        daemon=True,
                    )
                    thread.start()
                    self.assertFalse(self.stop.wait(0.18))
                    self.stop.set()
                    thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(calls, [])
                self.assertEqual(
                    wrapper._read_queue_cursor(
                        self.queue, self.queue.read_bytes()
                    ),
                    0,
                )
                if name == "initial-marker":
                    # If the fence itself cannot be written, the corrupt live
                    # journal remains the fail-closed admission evidence.
                    self.assertTrue(corrupt.exists())
                else:
                    self.assertTrue(
                        wrapper._delivery_block_marker_path(self.queue).exists()
                    )

    def _assert_marker_race_blocks(self, *, rules=None, append_patch=None):
        self.write_events({
            "event_id": "evt-marker-race", "channel": "lane-a",
        })
        calls = []
        thread = threading.Thread(
            target=wrapper._queue_watcher,
            args=(
                lambda: ("worker", self.queue),
                lambda prompt: calls.append(prompt) or "injected",
            ),
            kwargs={
                "stop_event": self.stop,
                "poll_seconds": 0.01,
                "fetch_role_fn": self._role,
                "fetch_rules_fn": rules or self._rules,
                "report_sync_fn": lambda *_a, **_k: None,
            },
            daemon=True,
        )
        context = append_patch or contextlib.nullcontext()
        with context:
            thread.start()
            self.assertFalse(self.stop.wait(0.18))
            self.stop.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(calls, [])
        self.assertTrue(wrapper._delivery_is_blocked(self.queue))
        self.assertEqual(
            wrapper._read_queue_cursor(self.queue, self.queue.read_bytes()), 0
        )

    def test_marker_published_during_rules_fetch_blocks_before_attempt(self):
        def rules(*_args, **_kwargs):
            wrapper._write_delivery_block_marker(
                self.queue, "published during rules fetch"
            )
            return self._rules()

        self._assert_marker_race_blocks(rules=rules)
        self.assertFalse(wrapper._delivery_journal_path(self.queue).exists())

    def test_marker_published_after_attempt_blocks_before_bounded_inject(self):
        original = wrapper._append_delivery_transition

        def append_and_fence(queue, state, events, **kwargs):
            result = original(queue, state, events, **kwargs)
            if state == "attempting":
                wrapper._write_delivery_block_marker(
                    queue, "published after attempting"
                )
            return result

        self._assert_marker_race_blocks(append_patch=mock.patch.object(
            wrapper, "_append_delivery_transition",
            side_effect=append_and_fence,
        ))
        self.assertEqual(
            wrapper._read_delivery_states(self.queue)["evt-marker-race"]["state"],
            "attempting",
        )

    def test_repeated_quarantine_never_overwrites_prior_evidence(self):
        journal = wrapper._delivery_journal_path(self.queue)
        with mock.patch.object(delivery_io.time, "time_ns", return_value=123), \
                mock.patch.object(delivery_io.os, "getpid", return_value=456), \
                mock.patch.object(delivery_io.time, "strftime", return_value="STAMP"):
            journal.write_bytes(b"first-corruption")
            first = wrapper._quarantine_delivery_journal(self.queue)
            journal.write_bytes(b"second-corruption")
            second = wrapper._quarantine_delivery_journal(self.queue)
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), b"first-corruption")
        self.assertEqual(second.read_bytes(), b"second-corruption")

    def test_consumer_lease_spans_injection_but_not_producer_append(self):
        self.write_events({"event_id": "evt-one-consumer", "channel": "lane-a"})
        injecting = threading.Event()
        release = threading.Event()
        accepted = threading.Event()
        calls = []

        def inject(_prompt):
            calls.append(threading.get_ident())
            injecting.set()
            release.wait(5)
            return "injected"

        def start_watcher():
            return threading.Thread(
                target=wrapper._queue_watcher,
                args=(lambda: ("worker", self.queue), inject),
                kwargs={
                    "stop_event": self.stop,
                    "poll_seconds": 0.005,
                    "fetch_role_fn": self._role,
                    "fetch_rules_fn": self._rules,
                    "report_sync_fn": lambda *_a, **_k: None,
                },
                daemon=True,
            )

        first = start_watcher()
        second = start_watcher()
        first.start()
        self.assertTrue(injecting.wait(5))
        second.start()

        # A consumer must own its separate lease while driving input, but it
        # must not pin the producer/append lock for that duration.
        producer_done = threading.Event()

        def append_torn_later_record():
            with delivery_io.queue_file_lock(self.queue, timeout=1):
                delivery_io.append_bytes_durable(
                    self.queue, b'{"event_id":"later"'
                )
            producer_done.set()

        producer = threading.Thread(target=append_torn_later_record, daemon=True)
        producer.start()
        try:
            self.assertTrue(producer_done.wait(2))
        finally:
            release.set()
        producer.join(5)

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                state = wrapper._read_delivery_states(self.queue).get(
                    "evt-one-consumer", {}
                ).get("state")
            except ValueError:
                state = None
            if state == "accepted":
                accepted.set()
                break
            time.sleep(0.01)
        self.assertTrue(accepted.is_set())
        self.stop.set()
        first.join(5)
        second.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(len(calls), 1)


    def test_journal_limit_blocks_before_injection_without_deleting(self):
        event = {"event_id": "evt-full", "channel": "lane-a"}
        self.write_events(event)
        calls = {"count": 0}

        def inject(_prompt):
            calls["count"] += 1
            return "injected"

        output = io.StringIO()
        with mock.patch.object(wrapper, "_MAX_DELIVERY_JOURNAL_BYTES", 1):
            with contextlib.redirect_stdout(output):
                thread = threading.Thread(
                    target=wrapper._queue_watcher,
                    args=(lambda: ("worker", self.queue), inject),
                    kwargs={
                        "stop_event": self.stop,
                        "poll_seconds": 0.02,
                        "fetch_role_fn": self._role,
                        "fetch_rules_fn": self._rules,
                        "report_sync_fn": lambda *_a, **_k: None,
                    },
                    daemon=True,
                )
                thread.start()
                self.assertFalse(self.stop.wait(0.12))
                self.stop.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(calls["count"], 0)
        self.assertEqual(
            wrapper._read_queue_cursor(self.queue, self.queue.read_bytes()), 0
        )
        marker = self.queue.with_name(self.queue.name + ".backpressure.json")
        self.assertEqual(
            json.loads(marker.read_text("utf-8"))["component"],
            "delivery-journal",
        )
        self.assertIn("injection blocked", output.getvalue())


class CrossProcessConsumerLeaseTests(unittest.TestCase):
    def test_consumer_lease_is_interprocess_and_independent_of_producer_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = Path(tmp) / "worker_queue.jsonl"
            ready = Path(tmp) / "ready"
            release = Path(tmp) / "release"
            code = (
                "import sys,time; from pathlib import Path; "
                "from delivery_io import queue_consumer_lease; "
                "q,r,x=map(Path,sys.argv[1:]); "
                "cm=queue_consumer_lease(q,2); cm.__enter__(); "
                "r.write_text('ready'); "
                "deadline=time.monotonic()+10; "
                "\nwhile not x.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                "cm.__exit__(None,None,None)"
            )
            child = subprocess.Popen(
                [sys.executable, "-c", code, str(queue), str(ready), str(release)],
                cwd=str(Path(__file__).resolve().parents[1]),
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                with self.assertRaises(TimeoutError):
                    with delivery_io.queue_consumer_lease(queue, timeout=0):
                        pass
                # Producer and consumer lock paths are intentionally distinct.
                with delivery_io.queue_file_lock(queue, timeout=0):
                    delivery_io.append_bytes_durable(queue, b"record\n")
            finally:
                release.write_text("release", encoding="utf-8")
                try:
                    child.wait(5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(5)
                    self.fail("consumer-lease child did not release promptly")
            self.assertEqual(child.returncode, 0)


class UnixInjectorContractTests(unittest.TestCase):
    @mock.patch.object(wrapper_unix.time, "sleep")
    @mock.patch.object(wrapper_unix.subprocess, "run")
    def test_returns_explicit_success_only_after_text_and_enter(self, run, _sleep):
        run.side_effect = [
            mock.Mock(returncode=0), mock.Mock(returncode=0),
            mock.Mock(returncode=0), mock.Mock(returncode=1),
        ]
        self.assertEqual(
            wrapper_unix.inject("task", tmux_session="s"), "injected"
        )
        self.assertEqual(
            wrapper_unix.inject("task", tmux_session="s"),
            "injected-uncertain",
        )

    @mock.patch.object(wrapper_unix.subprocess, "run")
    def test_text_rejection_is_retryable_and_timeout_is_uncertain(self, run):
        run.return_value = mock.Mock(returncode=1)
        self.assertEqual(
            wrapper_unix.inject("task", tmux_session="s"), "deferred"
        )
        run.side_effect = wrapper_unix.subprocess.TimeoutExpired("tmux", 1)
        self.assertEqual(
            wrapper_unix.inject("task", tmux_session="s"),
            "injected-uncertain",
        )


if __name__ == "__main__":
    unittest.main()
