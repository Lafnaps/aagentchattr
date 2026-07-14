"""Focused coverage for API/MCP-created channel discovery in the web UI."""

import asyncio
import copy
import json
import io
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app
import archive as archive_module
import mcp_bridge
from store import MessageStore
from rules import RuleStore
from summaries import SummaryStore
from jobs import JobStore
from schedules import ScheduleStore
from session_store import SessionStore


class _RestRequest:
    headers = {"authorization": "Bearer rest-token"}

    def __init__(self, channel: str):
        self._channel = channel

    async def json(self):
        return {"text": "from REST", "channel": self._channel}


class _RestRegistry:
    def resolve_token(self, token):
        return {"name": "rest-agent"} if token == "rest-token" else None

    def get_all_names(self):
        return []


class _JsonRequest:
    headers = {}

    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


class _Upload:
    filename = "history.zip"

    def __init__(self, payload: bytes):
        self._payload = payload

    async def read(self):
        return self._payload


class _NoTargetsRouter:
    def get_targets(self, sender, text, channel):
        return []

    def is_paused(self, channel):
        return False


class ChannelAutodiscoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._saved = {
            "store": app.store,
            "registry": app.registry,
            "router": app.router,
            "agents": app.agents,
            "session_engine": app.session_engine,
            "session_store": app.session_store,
            "jobs": app.jobs,
            "schedules": app.schedules,
            "summaries": app.summaries,
            "rules": app.rules,
            "config": app.config,
            "room_settings": app.room_settings,
            "broadcast": app.broadcast,
            "broadcast_settings": app.broadcast_settings,
            "structured_broadcast_suspended": app._structured_broadcast_suspended,
            "event_loop": app._event_loop,
            "pending_transaction_events": copy.deepcopy(app._pending_transaction_events),
            "last_active_channel": app._last_active_channel,
            "agent_last_channel": dict(app._agent_last_channel),
            "mcp_store": mcp_bridge.store,
            "mcp_registry": mcp_bridge.registry,
            "mcp_channel_message_writer": mcp_bridge.channel_message_writer,
            "mcp_channel_state_mutator": mcp_bridge.channel_state_mutator,
            "mcp_room_settings": mcp_bridge.room_settings,
            "mcp_rules": mcp_bridge.rules,
            "mcp_summaries": mcp_bridge.summaries,
            "mcp_presence": dict(mcp_bridge._presence),
            "mcp_cursors": {name: dict(cursors) for name, cursors in mcp_bridge._cursors.items()},
            "mcp_last_read_channel": dict(mcp_bridge._last_read_channel),
            "mcp_last_read_job_id": dict(mcp_bridge._last_read_job_id),
        }
        app.config = {"server": {"data_dir": self._tmp.name}}
        app.room_settings = {
            "channels": ["general"],
            "max_channels": 64,
            "max_discovered_channels": 128,
            "catalogue_revision": 0,
        }
        app._save_settings()
        app._catalogue_broadcast_pending.clear()
        app.store = MessageStore(str(Path(self._tmp.name) / "messages.jsonl"))
        app.registry = _RestRegistry()
        app.router = _NoTargetsRouter()
        app.agents = None
        app.session_engine = None
        app.session_store = None
        app.jobs = None
        app.schedules = None
        app.summaries = SummaryStore(str(Path(self._tmp.name) / "summaries.json"))
        app.rules = RuleStore(str(Path(self._tmp.name) / "rules.json"))
        app._last_active_channel = "general"
        app._agent_last_channel.clear()
        app._pending_transaction_events.clear()
        mcp_bridge.store = app.store
        # A simple non-family sender works without an authenticated registry in
        # this unit test; production MCP calls are authenticated by the bridge.
        mcp_bridge.registry = None
        mcp_bridge.channel_message_writer = app.store_channel_message
        mcp_bridge.channel_state_mutator = app._run_channel_state_transaction
        mcp_bridge.room_settings = app.room_settings
        mcp_bridge.rules = app.rules
        mcp_bridge.summaries = app.summaries

    def _build_import_payload(self, channel="lane-archive"):
        source_root = Path(self._tmp.name) / "source"
        source_root.mkdir(exist_ok=True)
        source_messages = MessageStore(str(source_root / "messages.jsonl"))
        source_jobs = JobStore(str(source_root / "jobs.json"))
        source_rules = RuleStore(str(source_root / "rules.json"))
        source_summaries = SummaryStore(str(source_root / "summaries.json"))
        source_messages.add("archive", "import me", channel=channel)
        source_jobs.create("imported", "job", channel, "archive")
        source_rules.propose("Imported rule", "archive")
        source_summaries.write(channel, "Imported summary", "archive")
        return archive_module.build_export(
            source_messages, source_jobs, source_rules, source_summaries,
        )

    @staticmethod
    def _bytes_or_none(path):
        path = Path(path)
        return path.read_bytes() if path.exists() else None

    def tearDown(self):
        app.store = self._saved["store"]
        app.registry = self._saved["registry"]
        app.router = self._saved["router"]
        app.agents = self._saved["agents"]
        app.session_engine = self._saved["session_engine"]
        app.session_store = self._saved["session_store"]
        app.jobs = self._saved["jobs"]
        app.schedules = self._saved["schedules"]
        app.summaries = self._saved["summaries"]
        app.rules = self._saved["rules"]
        app.config = self._saved["config"]
        app.room_settings = self._saved["room_settings"]
        app.broadcast = self._saved["broadcast"]
        app.broadcast_settings = self._saved["broadcast_settings"]
        app._structured_broadcast_suspended = self._saved["structured_broadcast_suspended"]
        app._event_loop = self._saved["event_loop"]
        app._pending_transaction_events.clear()
        app._pending_transaction_events.update(self._saved["pending_transaction_events"])
        app._last_active_channel = self._saved["last_active_channel"]
        app._agent_last_channel.clear()
        app._agent_last_channel.update(self._saved["agent_last_channel"])
        mcp_bridge.store = self._saved["mcp_store"]
        mcp_bridge.registry = self._saved["mcp_registry"]
        mcp_bridge.channel_message_writer = self._saved["mcp_channel_message_writer"]
        mcp_bridge.channel_state_mutator = self._saved["mcp_channel_state_mutator"]
        mcp_bridge.room_settings = self._saved["mcp_room_settings"]
        mcp_bridge.rules = self._saved["mcp_rules"]
        mcp_bridge.summaries = self._saved["mcp_summaries"]
        app._catalogue_broadcast_pending.clear()
        with mcp_bridge._presence_lock:
            mcp_bridge._presence.clear()
            mcp_bridge._presence.update(self._saved["mcp_presence"])
        with mcp_bridge._cursors_lock:
            mcp_bridge._cursors.clear()
            mcp_bridge._cursors.update(self._saved["mcp_cursors"])
        with mcp_bridge._last_read_lock:
            mcp_bridge._last_read_channel.clear()
            mcp_bridge._last_read_channel.update(self._saved["mcp_last_read_channel"])
            mcp_bridge._last_read_job_id.clear()
            mcp_bridge._last_read_job_id.update(self._saved["mcp_last_read_job_id"])
        self._tmp.cleanup()

    def test_store_reports_channels_in_first_seen_order(self):
        app.store.add("a", "one", channel="lane-two")
        app.store.add("a", "two", channel="general")
        app.store.add("a", "three", channel="lane-two")
        app.store.add("a", "four", channel="lane-one")

        self.assertEqual(
            app.store.get_channels(),
            ["lane-two", "general", "lane-one"],
        )

    def test_startup_reconciliation_preserves_configured_order_and_adds_history(self):
        app.room_settings["channels"] = ["general", "manually-created"]
        app.room_settings["max_channels"] = 1  # discovery must not be truncated
        app.store.add("a", "one", channel="lane-two")
        app.store.add("a", "two", channel="general")
        app.store.add("a", "three", channel="lane-one")
        app.store.add("a", "ignored", channel="INVALID CHANNEL")

        added = app._reconcile_message_channels()

        self.assertEqual(added, ["lane-two", "lane-one"])
        self.assertEqual(
            app.room_settings["channels"],
            ["general", "manually-created", "lane-two", "lane-one"],
        )
        persisted = json.loads((Path(self._tmp.name) / "settings.json").read_text("utf-8"))
        self.assertEqual(persisted["channels"], app.room_settings["channels"])

    def test_startup_reconciliation_batches_save_and_broadcast(self):
        app.store.add("a", "one", channel="lane-one")
        app.store.add("a", "two", channel="lane-two")

        with mock.patch.object(app, "_save_settings") as save_settings, \
                mock.patch.object(app, "_queue_settings_broadcast") as queue_broadcast:
            added = app._reconcile_message_channels()

        self.assertEqual(added, ["lane-one", "lane-two"])
        save_settings.assert_called_once_with()
        queue_broadcast.assert_called_once_with()

    def test_discovery_ceiling_is_configurable_but_hard_bounded(self):
        app.room_settings["max_discovered_channels"] = 100000
        self.assertEqual(app._channel_discovery_limit(), 256)
        self.assertEqual(app.room_settings["max_discovered_channels"], 256)

    def test_loading_settings_moves_general_first_without_reordering_other_channels(self):
        settings_path = Path(self._tmp.name) / "settings.json"
        settings_path.write_text(
            json.dumps({"channels": ["lane-two", "general", "lane-one"]}),
            "utf-8",
        )

        app._load_settings()

        self.assertEqual(
            app.room_settings["channels"],
            ["general", "lane-two", "lane-one"],
        )

    async def test_live_message_broadcasts_catalogue_before_first_message(self):
        events = []

        async def fake_broadcast_settings():
            events.append(("settings", list(app.room_settings["channels"])))

        async def fake_broadcast(message):
            events.append(("message", message["channel"]))

        app.broadcast_settings = fake_broadcast_settings
        app.broadcast = fake_broadcast

        message = app.store.add(
            "system",
            "first",
            msg_type="system",
            channel="lane-live",
        )
        await app._handle_new_message({
            **message,
            "sender": "system",
            "text": "first",
            "type": "system",
            "channel": "lane-live",
        })

        self.assertEqual(
            events,
            [
                ("settings", ["general", "lane-live"]),
                ("message", "lane-live"),
            ],
        )

    async def test_rest_and_mcp_messages_both_register_live_channels(self):
        pending = []
        app.store.on_message(pending.append)

        mcp_result = mcp_bridge.chat_send(
            sender="mcp-worker",
            message="from MCP",
            channel="lane-mcp",
            choices=[],
        )
        rest_response = await app.api_send(_RestRequest("lane-rest"))

        self.assertIn("Sent (id=", mcp_result)
        self.assertEqual(rest_response.status_code, 200)
        self.assertEqual([message["channel"] for message in pending], ["lane-mcp", "lane-rest"])

        async def no_op(*args, **kwargs):
            return None

        app.broadcast_settings = no_op
        app.broadcast = no_op
        for message in pending:
            await app._handle_new_message(message)

        self.assertEqual(
            app.room_settings["channels"],
            ["general", "lane-mcp", "lane-rest"],
        )

    def test_invalid_or_duplicate_channel_does_not_mutate_catalogue(self):
        self.assertFalse(app._register_message_channel("INVALID CHANNEL"))
        self.assertTrue(app._register_message_channel("lane-valid"))
        self.assertFalse(app._register_message_channel("lane-valid"))
        self.assertEqual(app.room_settings["channels"], ["general", "lane-valid"])

    async def test_invalid_rest_and_mcp_channels_are_rejected_before_persistence(self):
        rest_response = await app.api_send(_RestRequest("INVALID CHANNEL"))
        mcp_result = mcp_bridge.chat_send(
            sender="mcp-worker",
            message="must not persist",
            channel="bad/channel",
            choices=[],
        )

        self.assertEqual(rest_response.status_code, 400)
        self.assertIn("invalid channel", rest_response.body.decode("utf-8"))
        self.assertIn("Error: invalid channel", mcp_result)
        self.assertEqual(app.store.get_recent(20), [])
        self.assertEqual(app.room_settings["channels"], ["general"])

    async def test_full_discovery_catalogue_rejects_rest_and_mcp_without_persisting(self):
        app.room_settings.update({
            "channels": ["general", "lane-full"],
            "max_discovered_channels": 2,
        })

        rest_response = await app.api_send(_RestRequest("lane-rest"))
        mcp_result = mcp_bridge.chat_send(
            sender="mcp-worker",
            message="must not persist",
            channel="lane-mcp",
            choices=[],
        )

        self.assertEqual(rest_response.status_code, 409)
        self.assertIn("catalogue is full", rest_response.body.decode("utf-8"))
        self.assertIn("catalogue is full", mcp_result)
        self.assertEqual(app.store.get_recent(20), [])
        self.assertEqual(app.room_settings["channels"], ["general", "lane-full"])

    async def test_deferred_callback_after_channel_delete_cannot_resurrect_or_broadcast(self):
        events = []

        async def fake_broadcast_settings():
            events.append(("settings", list(app.room_settings["channels"])))

        async def fake_broadcast(message):
            events.append(("message", message["id"]))

        app.broadcast_settings = fake_broadcast_settings
        app.broadcast = fake_broadcast
        message, error = app.store_channel_message(
            "worker", "queued", channel="lane-race"
        )
        self.assertIsNone(error)
        self.assertEqual(app._delete_catalogued_channel("lane-race"), (True, None))

        # This simulates the event-loop task that was queued by store.on_message
        # but did not start until after channel_delete completed.
        await app._handle_new_message(message)

        self.assertEqual(events, [])
        self.assertNotIn("lane-race", app.room_settings["channels"])
        self.assertEqual(app.store.get_recent(20, channel="lane-race"), [])

    async def test_stale_callback_may_emit_settings_only_never_message_or_trigger(self):
        events = []

        class Router:
            def __init__(self):
                self.calls = 0

            def get_targets(self, *_args):
                self.calls += 1
                return ["target"]

            def is_paused(self, _channel):
                return False

        routing = Router()
        app.router = routing
        message, error = app.store_channel_message(
            "worker", "@target queued", channel="lane-settings-race",
        )
        self.assertIsNone(error)

        async def settings_then_delete():
            events.append(("settings", list(app.room_settings["channels"])))
            self.assertEqual(
                app._delete_catalogued_channel("lane-settings-race"),
                (True, None),
            )

        async def forbidden_message(_message):
            events.append(("message", None))

        app.broadcast_settings = settings_then_delete
        app.broadcast = forbidden_message
        await app._handle_new_message(message)

        self.assertEqual(events, [
            ("settings", ["general", "lane-settings-race"]),
        ])
        self.assertEqual(routing.calls, 0)
        self.assertNotIn("lane-settings-race", app.room_settings["channels"])

    async def test_outbound_fence_rejects_reused_id_with_different_uid(self):
        frames = []

        class Client:
            async def send_text(self, payload):
                frames.append(json.loads(payload))

        old_message = app.store.add("worker", "old", channel="general")
        snapshot = app.store.snapshot_state()
        app.store.delete([old_message["id"]])
        # Rewind the counter to model archive rollback/reset, then allocate the
        # same numeric id to a distinct durable record.
        snapshot["messages"] = []
        snapshot["next_id"] = old_message["id"]
        snapshot["todos"] = {}
        snapshot["messages_file"] = (True, b"")
        snapshot["todos_file"] = (False, b"")
        app.store.restore_state(snapshot)
        new_message = app.store.add("worker", "new", channel="general")
        self.assertEqual(new_message["id"], old_message["id"])
        self.assertNotEqual(new_message["uid"], old_message["uid"])

        old_clients = app.ws_clients
        app.ws_clients = {Client()}
        try:
            sent = await app.broadcast(old_message)
        finally:
            app.ws_clients = old_clients
        self.assertFalse(sent)
        self.assertEqual(frames, [])
        self.assertEqual(app.store.get_by_id(new_message["id"])["text"], "new")

    async def test_delete_between_optimistic_check_and_catalogue_lock_cannot_resurrect(self):
        events = []

        async def fake_broadcast_settings():
            events.append("settings")

        async def fake_broadcast(message):
            events.append("message")

        app.broadcast_settings = fake_broadcast_settings
        app.broadcast = fake_broadcast
        message, error = app.store_channel_message(
            "worker", "queued", channel="lane-interleave"
        )
        self.assertIsNone(error)

        original_get = app.store.get_by_id
        first_check = True

        def delete_after_first_positive_check(msg_id):
            nonlocal first_check
            found = original_get(msg_id)
            if first_check:
                first_check = False
                self.assertIsNotNone(found)
                self.assertEqual(
                    app._delete_catalogued_channel("lane-interleave"),
                    (True, None),
                )
            return found

        with mock.patch.object(app.store, "get_by_id", side_effect=delete_after_first_positive_check):
            await app._handle_new_message(message)

        self.assertEqual(events, [])
        self.assertNotIn("lane-interleave", app.room_settings["channels"])
        self.assertIsNone(original_get(message["id"]))

    def test_catalogue_revision_is_monotonic_and_persisted(self):
        message, error = app.store_channel_message(
            "worker", "hello", channel="lane-revision"
        )
        self.assertIsNone(error)
        self.assertIsNotNone(message)
        after_create = app.room_settings["catalogue_revision"]
        self.assertGreater(after_create, 0)

        self.assertEqual(
            app._delete_catalogued_channel("lane-revision"),
            (True, None),
        )
        after_delete = app.room_settings["catalogue_revision"]
        self.assertGreater(after_delete, after_create)
        persisted = json.loads(
            (Path(self._tmp.name) / "settings.json").read_text("utf-8")
        )
        self.assertEqual(persisted["catalogue_revision"], after_delete)
        self.assertEqual(list(Path(self._tmp.name).glob(".settings.json.*.tmp")), [])

    async def test_settings_and_message_frames_carry_same_catalogue_fence(self):
        frames = []

        class Client:
            async def send_text(self, payload):
                frames.append(json.loads(payload))

        old_clients = app.ws_clients
        app.ws_clients = {Client()}
        try:
            app._register_message_channel("lane-frame")
            message = app.store.add("worker", "hello", channel="lane-frame")
            await app.broadcast_settings()
            await app.broadcast(message)
        finally:
            app.ws_clients = old_clients

        self.assertEqual([frame["type"] for frame in frames], ["settings", "message"])
        revision = app.room_settings["catalogue_revision"]
        self.assertEqual(frames[0]["catalogue_revision"], revision)
        self.assertEqual(frames[0]["data"]["catalogue_revision"], revision)
        self.assertEqual(frames[1]["catalogue_revision"], revision)

    async def test_failed_settings_publish_keeps_pending_marker_for_retry(self):
        app._register_message_channel("lane-publish-retry")
        with mock.patch.object(
            app, "_broadcast_channel_payload_locked",
            side_effect=OSError("send failed"),
        ):
            with self.assertRaisesRegex(OSError, "send failed"):
                await app._publish_channel_transaction("lane-publish-retry", True)
        self.assertIn("lane-publish-retry", app._catalogue_broadcast_pending)

    async def test_transaction_events_follow_settings_and_share_revision(self):
        frames = []

        class Client:
            async def send_text(self, payload):
                frames.append(json.loads(payload))

        app._event_loop = asyncio.get_running_loop()
        app.rules.on_change(app._on_rule_change)
        app.store.on_message(app._on_store_message)
        old_clients = app.ws_clients
        app.ws_clients = {Client()}
        try:
            state, added, error = app._run_channel_state_transaction(
                "lane-ordered",
                lambda: app._create_rule_proposal_state(
                    "Ordered rule", "worker", "", "lane-ordered",
                    is_human=False,
                ),
                compensator=app._rollback_rule_proposal_state,
            )
            self.assertIsNotNone(state)
            self.assertTrue(added)
            self.assertIsNone(error)
            await app._publish_channel_transaction("lane-ordered", added)
            await asyncio.sleep(0)
        finally:
            app.ws_clients = old_clients

        self.assertEqual(
            [frame["type"] for frame in frames],
            ["settings", "rule", "message"],
        )
        revision = app.room_settings["catalogue_revision"]
        self.assertTrue(all(frame["catalogue_revision"] == revision for frame in frames))

    async def test_outbound_fence_drops_message_deleted_during_final_lookup(self):
        frames = []

        class Client:
            async def send_text(self, payload):
                frames.append(json.loads(payload))

        message, error = app.store_channel_message(
            "worker", "stale", channel="lane-stale"
        )
        self.assertIsNone(error)
        original_get = app.store.get_by_id
        deleted = False

        def delete_at_final_lookup(message_id):
            nonlocal deleted
            found = original_get(message_id)
            if not deleted:
                deleted = True
                self.assertEqual(
                    app._delete_catalogued_channel("lane-stale"),
                    (True, None),
                )
            return found

        old_clients = app.ws_clients
        app.ws_clients = {Client()}
        try:
            with mock.patch.object(
                app.store, "get_by_id", side_effect=delete_at_final_lookup,
            ):
                sent = await app.broadcast(message)
        finally:
            app.ws_clients = old_clients

        self.assertFalse(sent)
        self.assertEqual(frames, [])
        self.assertNotIn("lane-stale", app.room_settings["channels"])

    async def test_outbound_fence_checks_message_channel_not_only_id(self):
        frames = []

        class Client:
            async def send_text(self, payload):
                frames.append(json.loads(payload))

        message, error = app.store_channel_message(
            "worker", "original", channel="lane-original"
        )
        self.assertIsNone(error)
        app._register_message_channel("lane-forged")
        forged = dict(message)
        forged["channel"] = "lane-forged"
        old_clients = app.ws_clients
        app.ws_clients = {Client()}
        try:
            sent = await app.broadcast(forged)
        finally:
            app.ws_clients = old_clients

        self.assertFalse(sent)
        self.assertEqual(frames, [])

    async def test_rename_frames_are_atomic_ordered_and_share_revision(self):
        frames = []

        class Client:
            async def send_text(self, payload):
                frames.append(json.loads(payload))

        message, error = app.store_channel_message(
            "worker", "move me", channel="lane-old"
        )
        self.assertIsNone(error)
        app._last_active_channel = "lane-old"
        app._agent_last_channel.update({"a": "lane-old", "b": "general"})

        old_clients = app.ws_clients
        app.ws_clients = {Client()}
        try:
            renamed, rename_error = await app._rename_channel_and_broadcast(
                "lane-old", "lane-new"
            )
        finally:
            app.ws_clients = old_clients

        self.assertTrue(renamed)
        self.assertIsNone(rename_error)
        self.assertEqual([frame["type"] for frame in frames], ["channel_renamed", "settings"])
        self.assertEqual(frames[0]["catalogue_revision"], frames[1]["catalogue_revision"])
        self.assertEqual(frames[1]["data"]["channels"], ["general", "lane-new"])
        self.assertEqual(app.store.get_by_id(message["id"])["channel"], "lane-new")
        self.assertEqual(app._last_active_channel, "lane-new")
        self.assertEqual(app._agent_last_channel, {"a": "lane-new", "b": "general"})

        client_source = (ROOT / "static" / "chat.js").read_text("utf-8")
        rename_handler = client_source[client_source.index("event.type === 'channel_renamed'"):]
        self.assertIn("channelList[channelIndex] = event.new_name", rename_handler)
        self.assertIn("activeChannel = event.new_name", rename_handler)
        self.assertIn("filterMessagesByChannel();", rename_handler)
        self.assertIn("renderChannelTabs();", rename_handler)

    def test_delete_and_rename_restore_messages_when_settings_commit_fails(self):
        delete_message, error = app.store_channel_message(
            "worker", "keep on delete failure", channel="lane-delete-fail",
        )
        self.assertIsNone(error)
        delete_state = app.store.snapshot_state()
        delete_settings = copy.deepcopy(app.room_settings)
        with mock.patch.object(app, "_save_settings", side_effect=OSError("settings failed")), \
                mock.patch.object(app.log, "exception"), \
                self.assertRaisesRegex(OSError, "settings failed"):
            app._delete_catalogued_channel("lane-delete-fail")
        self.assertEqual(app.store.snapshot_state(), delete_state)
        self.assertEqual(app.room_settings, delete_settings)
        self.assertEqual(app.store.get_by_id(delete_message["id"])["uid"], delete_message["uid"])

        rename_message, error = app.store_channel_message(
            "worker", "keep on rename failure", channel="lane-rename-fail",
        )
        self.assertIsNone(error)
        rename_state = app.store.snapshot_state()
        rename_settings = copy.deepcopy(app.room_settings)
        with mock.patch.object(app, "_save_settings", side_effect=OSError("settings failed")), \
                mock.patch.object(app.log, "exception"), \
                self.assertRaisesRegex(OSError, "settings failed"):
            app._rename_catalogued_channel("lane-rename-fail", "lane-renamed")
        self.assertEqual(app.store.snapshot_state(), rename_state)
        self.assertEqual(app.room_settings, rename_settings)
        self.assertEqual(app.store.get_by_id(rename_message["id"])["channel"], "lane-rename-fail")

    def test_delete_migrates_all_activity_pointers_to_general(self):
        app._register_message_channel("lane-delete")
        app._last_active_channel = "lane-delete"
        app._agent_last_channel.update({"a": "lane-delete", "b": "general"})

        self.assertEqual(app._delete_catalogued_channel("lane-delete"), (True, None))
        self.assertEqual(app._last_active_channel, "general")
        self.assertEqual(app._agent_last_channel, {"a": "general", "b": "general"})

    def test_mcp_last_read_fallbacks_migrate_for_every_sender(self):
        with mcp_bridge._last_read_lock:
            mcp_bridge._last_read_channel.update({
                "worker-a": "lane-old", "worker-b": "lane-old",
                "worker-c": "general",
            })
        mcp_bridge.migrate_cursors_rename("lane-old", "lane-new")
        with mcp_bridge._last_read_lock:
            self.assertEqual(mcp_bridge._last_read_channel["worker-a"], "lane-new")
            self.assertEqual(mcp_bridge._last_read_channel["worker-b"], "lane-new")
            self.assertEqual(mcp_bridge._last_read_channel["worker-c"], "general")

        renamed_result = mcp_bridge.chat_send(
            sender="worker-a", message="renamed fallback", choices=[],
        )
        self.assertIn("Sent (id=", renamed_result)
        self.assertEqual(app.store.get_recent(1)[0]["channel"], "lane-new")

        self.assertEqual(app._delete_catalogued_channel("lane-new"), (True, None))
        mcp_bridge.migrate_cursors_delete("lane-new")
        with mcp_bridge._last_read_lock:
            self.assertEqual(mcp_bridge._last_read_channel["worker-a"], "general")
            self.assertEqual(mcp_bridge._last_read_channel["worker-b"], "general")
        deleted_result = mcp_bridge.chat_send(
            sender="worker-b", message="deleted fallback", choices=[],
        )
        self.assertIn("Sent (id=", deleted_result)
        self.assertEqual(app.store.get_recent(1)[0]["channel"], "general")
        self.assertNotIn("lane-new", app.room_settings["channels"])

    def test_rename_and_delete_reject_every_structured_dependency(self):
        app._register_message_channel("lane-busy")
        app.jobs = mock.Mock()
        app.jobs.list_all.return_value = [{"channel": "lane-busy"}]
        app.schedules = mock.Mock()
        app.schedules.list_all.return_value = [{"channel": "lane-busy"}]
        app.summaries = mock.Mock()
        app.summaries.get.return_value = {"text": "summary"}
        app.session_store = mock.Mock()
        app.session_store.list_all.return_value = [
            {"channel": "lane-busy", "state": "complete"},
        ]

        snapshot, rename_error = app._rename_catalogued_channel(
            "lane-busy", "lane-renamed"
        )
        deleted, delete_error = app._delete_catalogued_channel("lane-busy")

        self.assertIsNone(snapshot)
        self.assertFalse(deleted)
        for dependency in ("jobs (1)", "schedules (1)", "summary", "sessions (1)"):
            self.assertIn(dependency, rename_error)
            self.assertIn(dependency, delete_error)
        self.assertEqual(app.room_settings["channels"], ["general", "lane-busy"])

    def test_dependency_inspection_failure_is_fail_closed(self):
        app._register_message_channel("lane-unknown-deps")
        app.jobs = mock.Mock()
        app.jobs.list_all.side_effect = OSError("jobs unavailable")
        with mock.patch.object(app.log, "exception"):
            snapshot, rename_error = app._rename_catalogued_channel(
                "lane-unknown-deps", "lane-new"
            )
            deleted, delete_error = app._delete_catalogued_channel(
                "lane-unknown-deps"
            )
        self.assertIsNone(snapshot)
        self.assertFalse(deleted)
        self.assertIn("dependency check failed", rename_error)
        self.assertIn("dependency check failed", delete_error)
        self.assertEqual(app.room_settings["channels"], ["general", "lane-unknown-deps"])

    async def test_structured_creation_failure_rolls_back_reservation_and_revision(self):
        starting_revision = app.room_settings["catalogue_revision"]
        app.schedules = mock.Mock()
        app.schedules.create.side_effect = OSError("schedule disk failed")
        with mock.patch.object(app.log, "exception"):
            schedule_response = await app.create_schedule(_JsonRequest({
                "prompt": "run", "targets": ["worker"], "spec": "every 5m",
                "channel": "lane-schedule-fail",
            }))
        self.assertEqual(schedule_response.status_code, 500)
        self.assertNotIn("lane-schedule-fail", app.room_settings["channels"])
        self.assertEqual(app.room_settings["catalogue_revision"], starting_revision)

        app.jobs = mock.Mock()
        app.jobs.create.side_effect = OSError("job disk failed")
        with mock.patch.object(app.log, "exception"):
            job_response = await app.create_job(_JsonRequest({
                "title": "work", "channel": "lane-job-fail",
            }))
        self.assertEqual(job_response.status_code, 500)
        self.assertNotIn("lane-job-fail", app.room_settings["channels"])
        self.assertEqual(app.room_settings["catalogue_revision"], starting_revision)
        persisted = json.loads((Path(self._tmp.name) / "settings.json").read_text("utf-8"))
        self.assertEqual(persisted["channels"], ["general"])
        self.assertEqual(persisted["catalogue_revision"], starting_revision)

    async def test_job_breadcrumb_failure_rolls_back_job_and_channel(self):
        app.jobs = JobStore(str(Path(self._tmp.name) / "jobs.json"))
        starting_revision = app.room_settings["catalogue_revision"]
        with mock.patch.object(app.store, "add", side_effect=OSError("timeline failed")), \
                mock.patch.object(app.log, "exception"):
            response = await app.create_job(_JsonRequest({
                "title": "transactional job", "channel": "lane-job-partial",
            }))

        self.assertEqual(response.status_code, 500)
        self.assertEqual(app.jobs.list_all(), [])
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual(app.room_settings["catalogue_revision"], starting_revision)

    async def test_final_settings_failure_compensates_schedule_and_job(self):
        app.schedules = ScheduleStore(str(Path(self._tmp.name) / "schedules.json"))
        app.jobs = JobStore(str(Path(self._tmp.name) / "jobs.json"))
        settings_before = (Path(self._tmp.name) / "settings.json").read_bytes()

        with mock.patch.object(app, "_save_settings", side_effect=OSError("settings failed")), \
                mock.patch.object(app.log, "exception"):
            schedule_response = await app.create_schedule(_JsonRequest({
                "prompt": "run", "targets": ["worker"], "spec": "every 5m",
                "channel": "lane-sched-set",
            }))
            job_response = await app.create_job(_JsonRequest({
                "title": "work", "channel": "lane-job-set",
            }))

        self.assertEqual(schedule_response.status_code, 500)
        self.assertEqual(job_response.status_code, 500)
        self.assertEqual(app.schedules.list_all(), [])
        self.assertEqual(app.jobs.list_all(), [])
        self.assertEqual(app.store.get_recent(20), [])
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual((Path(self._tmp.name) / "settings.json").read_bytes(), settings_before)

    def test_final_settings_failure_compensates_mcp_rule_and_summary(self):
        settings_before = (Path(self._tmp.name) / "settings.json").read_bytes()
        with mock.patch.object(app, "_save_settings", side_effect=OSError("settings failed")), \
                mock.patch.object(app.log, "exception"):
            rule_result = mcp_bridge.chat_rules(
                action="propose", sender="worker", rule="Be exact",
                channel="lane-rule-set",
            )
            summary_result = mcp_bridge.chat_summary(
                action="write", sender="worker", text="Exact summary",
                channel="lane-sum-set",
            )

        self.assertIn("failed to create rule proposal", rule_result)
        self.assertIn("failed to write summary", summary_result)
        self.assertEqual(app.rules.list_all(), [])
        self.assertEqual(app.summaries.get_all(), {})
        self.assertEqual(app.store.get_recent(20), [])
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual((Path(self._tmp.name) / "settings.json").read_bytes(), settings_before)

    def test_ws_rule_proposal_final_settings_failure_has_no_partial_state(self):
        settings_before = (Path(self._tmp.name) / "settings.json").read_bytes()
        with mock.patch.object(app, "_save_settings", side_effect=OSError("settings failed")), \
                mock.patch.object(app.log, "exception"), \
                self.assertRaisesRegex(OSError, "settings failed"):
            app._run_channel_state_transaction(
                "lane-ws-rule-set",
                lambda: app._create_rule_proposal_state(
                    "Review carefully", "worker", "", "lane-ws-rule-set",
                    is_human=False,
                ),
                compensator=app._rollback_rule_proposal_state,
            )

        self.assertEqual(app.rules.list_all(), [])
        self.assertEqual(app.store.get_recent(20), [])
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual((Path(self._tmp.name) / "settings.json").read_bytes(), settings_before)

    async def test_failed_rule_transaction_emits_no_transient_runtime_frames(self):
        frames = []

        class Client:
            async def send_text(self, payload):
                frames.append(json.loads(payload))

        app._event_loop = asyncio.get_running_loop()
        app.rules.on_change(app._on_rule_change)
        app.store.on_message(app._on_store_message)
        old_clients = app.ws_clients
        app.ws_clients = {Client()}
        try:
            with mock.patch.object(
                app, "_save_settings", side_effect=OSError("settings failed"),
            ), mock.patch.object(app.log, "exception"), self.assertRaises(OSError):
                app._run_channel_state_transaction(
                    "lane-no-transient",
                    lambda: app._create_rule_proposal_state(
                        "No transient", "worker", "", "lane-no-transient",
                        is_human=False,
                    ),
                    compensator=app._rollback_rule_proposal_state,
                )
            await asyncio.sleep(0)
        finally:
            app.ws_clients = old_clients

        self.assertEqual(frames, [])
        self.assertEqual(app._pending_transaction_events, {})

    async def test_final_settings_failure_compensates_session_and_draft_request(self):
        template = {
            "id": "valid", "name": "Valid", "roles": ["reviewer"],
            "phases": [{
                "name": "Review", "participants": ["reviewer"],
                "prompt": "Review", "is_output": True,
            }],
        }
        app.session_store = SessionStore(str(Path(self._tmp.name) / "session-runs.json"))
        app.session_store._templates["valid"] = template

        class Engine:
            def __init__(self):
                self.banners = 0
                self.triggers = 0

            def get_active(self, _channel):
                return None

            def emit_current_phase_banner(self, _session):
                self.banners += 1

            def _trigger_current(self, _session):
                self.triggers += 1

        engine = Engine()
        app.session_engine = engine
        settings_before = (Path(self._tmp.name) / "settings.json").read_bytes()
        with mock.patch.object(app, "_save_settings", side_effect=OSError("settings failed")), \
                mock.patch.object(app.log, "exception"):
            session_response = await app.start_session(_JsonRequest({
                "template_id": "valid", "channel": "lane-session-set",
                "cast": {"reviewer": "worker"},
            }))
            draft_response = await app.request_session_draft(_JsonRequest({
                "agent": "worker", "description": "design",
                "channel": "lane-draft-set",
            }))

        self.assertEqual(session_response.status_code, 500)
        self.assertEqual(draft_response.status_code, 500)
        self.assertEqual(app.session_store.list_all(), [])
        self.assertEqual(engine.banners, 0)
        self.assertEqual(engine.triggers, 0)
        self.assertEqual(app.store.get_recent(20), [])
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual((Path(self._tmp.name) / "settings.json").read_bytes(), settings_before)

    def test_failed_mutation_compensates_or_retains_channel_fail_closed(self):
        app.jobs = JobStore(str(Path(self._tmp.name) / "jobs.json"))
        holder = {}
        compensation_calls = []

        def create_then_raise(channel):
            state = {"job": app.jobs.create("partial", "job", channel, "worker")}
            holder[channel] = state
            exc = RuntimeError("after durable write")
            exc._channel_transaction_state = state
            raise exc

        def compensate(state):
            compensation_calls.append(state["job"]["id"])
            app.jobs.delete(state["job"]["id"])

        with self.assertRaisesRegex(RuntimeError, "after durable write"):
            app._run_channel_state_transaction(
                "lane-compensated",
                lambda: create_then_raise("lane-compensated"),
                compensator=compensate,
            )
        self.assertEqual(len(compensation_calls), 1)
        self.assertNotIn("lane-compensated", app.room_settings["channels"])
        self.assertEqual(app.jobs.list_all(), [])

        with mock.patch.object(app.log, "exception"), \
                self.assertRaisesRegex(RuntimeError, "after durable write"):
            app._run_channel_state_transaction(
                "lane-retained",
                lambda: create_then_raise("lane-retained"),
                compensator=lambda _state: (_ for _ in ()).throw(OSError("rollback failed")),
            )
        self.assertIn("lane-retained", app.room_settings["channels"])
        self.assertEqual(len(app.jobs.list_all(channel="lane-retained")), 1)

    def test_store_message_commits_after_append_and_retains_durable_recovery(self):
        settings_path = Path(self._tmp.name) / "settings.json"
        settings_before = settings_path.read_bytes()
        with mock.patch.object(app.store, "add", side_effect=OSError("append failed")), \
                mock.patch.object(app, "_save_settings") as save_settings, \
                self.assertRaisesRegex(OSError, "append failed"):
            app.store_channel_message("worker", "no record", channel="lane-append-fail")
        save_settings.assert_not_called()
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual(settings_path.read_bytes(), settings_before)

        with mock.patch.object(app, "_save_settings", side_effect=OSError("settings failed")), \
                mock.patch.object(app.log, "exception"):
            message, error = app.store_channel_message(
                "worker", "durable", channel="lane-durable",
            )
        self.assertIsNone(error)
        self.assertIsNotNone(message)
        self.assertIn("lane-durable", app.room_settings["channels"])
        self.assertEqual(app.store.get_by_id(message["id"])["uid"], message["uid"])
        self.assertEqual(settings_path.read_bytes(), settings_before)

    async def test_session_prevalidation_and_failed_start_do_not_reserve_channel(self):
        valid_template = {
            "id": "valid",
            "name": "Valid",
            "roles": ["reviewer"],
            "phases": [{
                "name": "Review", "participants": ["reviewer"],
                "prompt": "Review", "is_output": True,
            }],
        }

        class SessionStore:
            def __init__(self):
                self._templates = {"valid": valid_template}
                self.create_calls = 0

            def get_template(self, template_id):
                return self._templates.get(template_id)

            def create(self, **_kwargs):
                self.create_calls += 1
                return None

            def delete(self, _session_id):
                return None

        class SessionEngine:
            def __init__(self, active=None):
                self.active = active

            def get_active(self, channel):
                return self.active

        session_store = SessionStore()
        app.session_store = session_store
        engine = SessionEngine()
        app.session_engine = engine
        starting_revision = app.room_settings["catalogue_revision"]

        unknown = await app.start_session(_JsonRequest({
            "template_id": "missing", "channel": "lane-unknown",
            "cast": {"reviewer": "worker"},
        }))
        invalid_cast = await app.start_session(_JsonRequest({
            "template_id": "valid", "channel": "lane-cast",
            "cast": {"other": "worker"},
        }))
        engine.active = {"id": 1}
        active = await app.start_session(_JsonRequest({
            "template_id": "valid", "channel": "lane-active",
            "cast": {"reviewer": "worker"},
        }))
        engine.active = None
        failed = await app.start_session(_JsonRequest({
            "template_id": "valid", "channel": "lane-start-fail",
            "cast": {"reviewer": "worker"},
        }))

        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(invalid_cast.status_code, 400)
        self.assertEqual(active.status_code, 409)
        self.assertEqual(failed.status_code, 409)
        self.assertEqual(session_store.create_calls, 1)
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual(app.room_settings["catalogue_revision"], starting_revision)

    def test_mcp_structured_writes_reserve_first_and_roll_back_failure(self):
        app.room_settings.update({
            "channels": ["general"],
            "max_discovered_channels": 1,
        })
        mcp_bridge.room_settings = app.room_settings
        mcp_bridge.rules = mock.Mock()
        mcp_bridge.summaries = mock.Mock()

        rule_result = mcp_bridge.chat_rules(
            action="propose", sender="worker", rule="Do it",
            channel="lane-full",
        )
        summary_result = mcp_bridge.chat_summary(
            action="write", sender="worker", text="Summary",
            channel="lane-full",
        )
        self.assertIn("catalogue is full", rule_result)
        self.assertIn("catalogue is full", summary_result)
        mcp_bridge.rules.propose.assert_not_called()
        mcp_bridge.summaries.write.assert_not_called()

        app.room_settings["max_discovered_channels"] = 128
        starting_revision = app.room_settings["catalogue_revision"]
        mcp_bridge.rules.propose.side_effect = OSError("rules disk failed")
        failed_rule = mcp_bridge.chat_rules(
            action="propose", sender="worker", rule="Do it",
            channel="lane-rule-fail",
        )
        mcp_bridge.summaries.get.return_value = None
        mcp_bridge.summaries.write.return_value = None
        failed_summary = mcp_bridge.chat_summary(
            action="write", sender="worker", text="Summary",
            channel="lane-summary-fail",
        )
        self.assertIn("failed to create rule proposal", failed_rule)
        self.assertIn("failed to write summary", failed_summary)
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual(app.room_settings["catalogue_revision"], starting_revision)

    def test_mcp_structured_downstream_write_failure_removes_partial_state(self):
        starting_revision = app.room_settings["catalogue_revision"]
        original_writer = mcp_bridge.channel_message_writer
        mcp_bridge.rules = app.rules
        mcp_bridge.summaries = app.summaries

        def fail_timeline(*_args, **_kwargs):
            raise OSError("timeline disk failed")

        mcp_bridge.channel_message_writer = fail_timeline
        try:
            rule_result = mcp_bridge.chat_rules(
                action="propose", sender="worker", rule="Be exact",
                channel="lane-rule-partial",
            )
            summary_result = mcp_bridge.chat_summary(
                action="write", sender="worker", text="No partial state",
                channel="lane-summary-partial",
            )
        finally:
            mcp_bridge.channel_message_writer = original_writer

        self.assertIn("failed to create rule proposal", rule_result)
        self.assertIn("failed to write summary", summary_result)
        self.assertEqual(app.rules.list_all(), [])
        self.assertIsNone(app.summaries.get("lane-summary-partial"))
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual(app.room_settings["catalogue_revision"], starting_revision)

    async def test_channel_bearing_state_ingress_rejects_before_mutation(self):
        fake_schedules = mock.Mock()
        fake_jobs = mock.Mock()
        invalid = "INVALID CHANNEL"

        with mock.patch.object(app, "schedules", fake_schedules):
            schedule_response = await app.create_schedule(_JsonRequest({
                "prompt": "run", "targets": ["worker"], "spec": "every 5m",
                "channel": invalid,
            }))
        with mock.patch.object(app, "jobs", fake_jobs):
            job_response = await app.create_job(_JsonRequest({
                "title": "work", "channel": invalid,
            }))
        with mock.patch.object(app, "session_engine", object()), \
                mock.patch.object(app, "session_store", object()):
            session_response = await app.start_session(_JsonRequest({
                "template_id": "x", "channel": invalid,
            }))
        request_response = await app.request_session_draft(_JsonRequest({
            "agent": "worker", "description": "design", "channel": invalid,
        }))

        self.assertEqual(schedule_response.status_code, 400)
        self.assertEqual(job_response.status_code, 400)
        self.assertEqual(session_response.status_code, 400)
        self.assertEqual(request_response.status_code, 400)
        fake_schedules.create.assert_not_called()
        fake_jobs.create.assert_not_called()
        self.assertEqual(app.store.get_recent(20), [])
        self.assertEqual(app.room_settings["channels"], ["general"])

    async def test_archive_invalid_channel_is_rejected_before_import_mutation(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps({"schema_version": 1}))
            zf.writestr("messages.jsonl", json.dumps({
                "sender": "worker", "text": "hidden", "channel": "bad/channel",
            }) + "\n")
            zf.writestr("jobs.json", "[]")
            zf.writestr("rules.json", "[]")
            zf.writestr("summaries.json", "[]")

        response = await app.import_history(_Upload(payload.getvalue()))

        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid channel", response.body.decode("utf-8"))
        self.assertEqual(app.store.get_recent(20), [])
        self.assertEqual(app.room_settings["channels"], ["general"])

    async def test_archive_mid_store_failure_restores_every_store_and_file(self):
        app.jobs = JobStore(str(Path(self._tmp.name) / "jobs.json"))
        app.store.add("baseline", "keep", channel="general")
        app.jobs.create("keep", "job", "general", "baseline")
        app.rules.propose("Keep rule", "baseline")
        app.summaries.write("general", "Keep summary", "baseline")
        before = app._snapshot_import_stores()
        settings_before = (Path(self._tmp.name) / "settings.json").read_bytes()
        payload = self._build_import_payload()
        original_save = app.rules._save
        calls = 0

        def fail_once():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("rule import failed")
            return original_save()

        with mock.patch.object(app.rules, "_save", side_effect=fail_once), \
                mock.patch.object(app.log, "exception"):
            response = await app.import_history(_Upload(payload))

        self.assertEqual(response.status_code, 500)
        self.assertEqual(app._snapshot_import_stores(), before)
        self.assertEqual((Path(self._tmp.name) / "settings.json").read_bytes(), settings_before)
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual(app._structured_broadcast_suspended, 0)

    async def test_archive_settings_failure_rolls_back_all_imported_sections(self):
        app.jobs = JobStore(str(Path(self._tmp.name) / "jobs.json"))
        app.store.add("baseline", "keep", channel="general")
        app.jobs.create("keep", "job", "general", "baseline")
        app.rules.propose("Keep rule", "baseline")
        app.summaries.write("general", "Keep summary", "baseline")
        before = app._snapshot_import_stores()
        settings_path = Path(self._tmp.name) / "settings.json"
        settings_before = settings_path.read_bytes()

        with mock.patch.object(app, "_save_settings", side_effect=OSError("settings failed")), \
                mock.patch.object(app.log, "exception"):
            response = await app.import_history(_Upload(self._build_import_payload()))

        self.assertEqual(response.status_code, 500)
        self.assertEqual(app._snapshot_import_stores(), before)
        self.assertEqual(settings_path.read_bytes(), settings_before)
        self.assertEqual(app.room_settings["channels"], ["general"])
        self.assertEqual(app._structured_broadcast_suspended, 0)

    async def test_archive_mutation_barrier_preserves_concurrent_direct_write(self):
        app.jobs = JobStore(str(Path(self._tmp.name) / "jobs.json"))
        writer_started = threading.Event()
        writer_done = threading.Event()
        writer = None

        def fake_import(*_args, **_kwargs):
            nonlocal writer

            def write_concurrently():
                writer_started.set()
                app.store.add("concurrent", "must survive", channel="general")
                writer_done.set()

            writer = threading.Thread(target=write_concurrently)
            writer.start()
            self.assertTrue(writer_started.wait(1))
            self.assertFalse(writer_done.wait(0.05))
            raise OSError("forced import failure")

        payload = self._build_import_payload()
        with mock.patch.object(archive_module, "import_archive", side_effect=fake_import), \
                mock.patch.object(app.log, "exception"):
            response = await app.import_history(_Upload(payload))
        writer.join(2)

        self.assertEqual(response.status_code, 500)
        self.assertTrue(writer_done.is_set())
        self.assertEqual(
            [item["text"] for item in app.store.get_recent(20)],
            ["must survive"],
        )

    async def test_valid_state_ingress_auto_registers_channel_before_mutation(self):
        fake_schedules = mock.Mock()
        fake_schedules.create.return_value = {"id": "schedule-1", "channel": "lane-scheduled"}

        with mock.patch.object(app, "schedules", fake_schedules):
            response = await app.create_schedule(_JsonRequest({
                "prompt": "run", "targets": ["worker"], "spec": "every 5m",
                "channel": "lane-scheduled",
            }))

        self.assertEqual(response.status_code, 200)
        self.assertIn("lane-scheduled", app.room_settings["channels"])
        fake_schedules.create.assert_called_once()

    async def test_structured_ws_channel_error_contains_authoritative_rollback(self):
        frames = []

        class WebSocket:
            async def send_text(self, payload):
                frames.append(json.loads(payload))

        app._register_message_channel("lane-old")
        await app._send_ws_channel_error(
            WebSocket(),
            "channel_rename",
            "collision",
            restore_channel="lane-old",
        )

        self.assertEqual(len(frames), 1)
        frame = frames[0]
        self.assertEqual(frame["type"], "error")
        self.assertEqual(frame["code"], "channel_rejected")
        self.assertEqual(frame["operation"], "channel_rename")
        self.assertEqual(frame["restore_channel"], "lane-old")
        self.assertEqual(frame["catalogue_revision"], frame["settings"]["catalogue_revision"])
        self.assertIn("lane-old", frame["settings"]["channels"])


if __name__ == "__main__":
    unittest.main()
