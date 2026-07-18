"""Hermetic coverage for the Telegram owner route (L-CHATT 5-6).

Everything runs against TEMP-only stores and the real security middleware via
``starlette``'s ``TestClient`` (or the repository's accepted delivery seams).
No external network, no live process, no live registry.

Contract proven here:
  * actual request/response shapes for inbound send and outbound fetch on the
    port-independent loopback app surface;
  * the two-factor gate (route bearer + Telegram user/chat allowlist), incl.
    every one-factor-only negative case, rejecting before persistence/wake;
  * ``#owner-telegram`` channel normalization and invalid-channel refusal;
  * canonical ``codex-sol`` with the ``@codex`` compatibility alias and no
    legacy ``codex`` identity ever emitted;
  * offline persistence, restart, later registration and exactly-one
    injection/replay through the accepted delivery journal;
  * correlation id and monotonic cursor preserved; echo-loop source excluded;
  * zero bearer/body/user/chat/correlation leak into logs/errors/queue/store.
"""

import concurrent.futures
import io
import json
import logging
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app
import telegram_route
import telegram_route_contract as contract
import wrapper
from delivery_io import DeliveryBackpressureError
from store import MessageStore
from agents import AgentTrigger


BEARER = "ROUTE-BEARER-SENTINEL-9z9z"
USER_ID = 771234567
CHAT_ID = 889876543
TELEGRAM_MESSAGE_ID = 4242
ALLOWLIST = [(USER_ID, CHAT_ID)]
AUTH = {"Authorization": f"Bearer {BEARER}"}


# --------------------------------------------------------------------------- #
# Pure helpers (canonicalization / normalization / addressing)
# --------------------------------------------------------------------------- #
class RouteHelperTests(unittest.TestCase):
    def test_recipient_alias_resolves_only_to_canonical_never_legacy(self):
        for token in ("codex-sol", "@codex-sol", "codex", "@codex", "CODEX",
                      " @Codex ", None, ""):
            self.assertEqual(
                telegram_route.canonicalize_recipient(token),
                telegram_route.CANONICAL_RESPONDER,
            )
        # The map can only ever yield "codex-sol"; it never yields "codex".
        self.assertNotEqual(telegram_route.CANONICAL_RESPONDER, "codex")

    def test_unknown_recipient_is_invalid(self):
        for token in ("claude", "gemini", "owner-telegram", "codex-2", 7, object()):
            self.assertIsNone(telegram_route.canonicalize_recipient(token))

    def test_channel_normalization_and_refusal(self):
        for token in ("owner-telegram", "#owner-telegram", " #Owner-Telegram ",
                      None, ""):
            self.assertEqual(
                telegram_route.normalize_route_channel(token),
                telegram_route.ROUTE_CHANNEL,
            )
        for token in ("general", "#general", "random", "codex-sol", 7):
            self.assertIsNone(telegram_route.normalize_route_channel(token))

    def test_stable_action_id_is_generation_independent_and_deterministic(self):
        first = telegram_route.stable_inbound_action_id("cid-1", "uid-a")
        self.assertEqual(
            first, telegram_route.stable_inbound_action_id("cid-1", "uid-a")
        )
        self.assertTrue(first.startswith("act-"))
        self.assertNotEqual(
            first, telegram_route.stable_inbound_action_id("cid-1", "uid-b")
        )
        self.assertNotEqual(
            first, telegram_route.stable_inbound_action_id("cid-2", "uid-a")
        )

    def test_addressing_and_correlation_resolution(self):
        owner = {
            "id": 1, "sender": telegram_route.OWNER_IDENTITY,
            "metadata": {"recipient": "codex-sol", "correlation_id": "cid-x",
                         "telegram_message_id": TELEGRAM_MESSAGE_ID},
        }
        store = {1: owner}

        def resolve(mid):
            return store.get(mid)

        explicit = {"id": 2, "sender": "codex-sol",
                    "metadata": {"recipient": "owner-telegram",
                                 "correlation_id": "cid-explicit"}}
        replied = {"id": 3, "sender": "codex-sol", "reply_to": 1}
        mentioned = {"id": 4, "sender": "codex-sol",
                     "text": "done @owner-telegram"}
        unrelated = {"id": 5, "sender": "codex-sol", "text": "chatter"}

        self.assertTrue(telegram_route.is_addressed_to_owner(explicit, resolve))
        self.assertTrue(telegram_route.is_addressed_to_owner(replied, resolve))
        self.assertTrue(telegram_route.is_addressed_to_owner(mentioned, resolve))
        self.assertFalse(telegram_route.is_addressed_to_owner(unrelated, resolve))

        self.assertEqual(
            telegram_route.resolve_correlation(explicit, resolve), "cid-explicit"
        )
        # A reply inherits the correlation id of the owner message it answers.
        self.assertEqual(
            telegram_route.resolve_correlation(replied, resolve), "cid-x"
        )
        self.assertIsNone(
            telegram_route.resolve_correlation(mentioned, resolve)
        )
        self.assertEqual(
            telegram_route.resolve_telegram_reply_to(replied, resolve),
            TELEGRAM_MESSAGE_ID,
        )
        self.assertEqual(
            telegram_route.resolve_telegram_reply_to(
                unrelated, resolve, preceding_request=owner
            ),
            TELEGRAM_MESSAGE_ID,
        )

    def test_telegram_message_id_normalization_is_positive_integer_only(self):
        for value in (1, TELEGRAM_MESSAGE_ID, " 4242 "):
            self.assertEqual(
                telegram_route.normalize_tg_message_id(value), int(value)
            )
        for value in (None, True, False, 0, -1, "", "-1", "1.2", object()):
            self.assertIsNone(telegram_route.normalize_tg_message_id(value))


# --------------------------------------------------------------------------- #
# Two-factor guard unit (secret-safe at rest)
# --------------------------------------------------------------------------- #
class RouteGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "telegram_route.json"

    def _guard(self):
        return telegram_route.TelegramRouteGuard(str(self.path))

    def test_unprovisioned_rejects_everything(self):
        guard = self._guard()
        self.assertFalse(guard.is_provisioned())
        self.assertFalse(guard.verify_bearer(BEARER))
        self.assertFalse(guard.verify_inbound(BEARER, USER_ID, CHAT_ID))

    def test_provision_persists_digest_not_raw_bearer(self):
        guard = self._guard()
        guard.provision(BEARER, ALLOWLIST)
        self.assertTrue(guard.is_provisioned())
        raw = self.path.read_text("utf-8")
        self.assertNotIn(BEARER, raw)
        stored = json.loads(raw)
        self.assertIn("bearer_salt", stored)
        self.assertIn("bearer_hash", stored)
        self.assertNotIn("bearer", stored)  # no raw bearer key
        # Allowlist pairs are config (not a log); ids are stored as strings.
        self.assertEqual(
            stored["allowlist"], [{"user_id": str(USER_ID), "chat_id": str(CHAT_ID)}]
        )

    def test_two_factor_and_every_one_factor_case(self):
        guard = self._guard()
        guard.provision(BEARER, ALLOWLIST)
        # Both correct.
        self.assertTrue(guard.verify_inbound(BEARER, USER_ID, CHAT_ID))
        self.assertTrue(guard.verify_inbound(BEARER, str(USER_ID), str(CHAT_ID)))
        # Exactly one factor wrong/missing → always False.
        self.assertFalse(guard.verify_inbound("wrong", USER_ID, CHAT_ID))
        self.assertFalse(guard.verify_inbound("", USER_ID, CHAT_ID))
        self.assertFalse(guard.verify_inbound(BEARER, 999999, CHAT_ID))
        self.assertFalse(guard.verify_inbound(BEARER, USER_ID, 999999))
        self.assertFalse(guard.verify_inbound(BEARER, None, CHAT_ID))
        self.assertFalse(guard.verify_inbound(BEARER, USER_ID, None))
        # Cross pairing (user of one row, chat of another) is refused.
        guard.provision(BEARER, [(1, 2), (3, 4)])
        self.assertTrue(guard.verify_inbound(BEARER, 1, 2))
        self.assertFalse(guard.verify_inbound(BEARER, 1, 4))

    def test_provision_validates_inputs(self):
        guard = self._guard()
        with self.assertRaises(ValueError):
            guard.provision("", ALLOWLIST)
        with self.assertRaises(ValueError):
            guard.provision(BEARER, [])

    def test_reprovision_rotates_salt(self):
        guard = self._guard()
        guard.provision(BEARER, ALLOWLIST)
        first = json.loads(self.path.read_text("utf-8"))
        guard.provision(BEARER, ALLOWLIST)
        second = json.loads(self.path.read_text("utf-8"))
        self.assertNotEqual(first["bearer_salt"], second["bearer_salt"])
        self.assertNotEqual(first["bearer_hash"], second["bearer_hash"])
        # The rotated store still authenticates the same bearer.
        self.assertTrue(self._guard().verify_bearer(BEARER))

    def test_corrupt_store_fails_closed(self):
        self.path.write_text("{ not json", "utf-8")
        guard = self._guard()
        self.assertFalse(guard.is_provisioned())
        self.assertFalse(guard.verify_inbound(BEARER, USER_ID, CHAT_ID))


# --------------------------------------------------------------------------- #
# HTTP contract via the exported real TestClient fixture
# --------------------------------------------------------------------------- #
class RouteHttpContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = contract.build_contract_harness(
            self.tmp.name, bearer=BEARER, allowlist=ALLOWLIST
        )
        self.addCleanup(self.h.close)
        self.client = self.h.client

    def _inbound(self, headers=AUTH, **kwargs):
        kwargs.setdefault("telegram_user_id", USER_ID)
        kwargs.setdefault("telegram_chat_id", CHAT_ID)
        return self.client.post(
            contract.INBOUND_PATH, headers=headers,
            json=contract.example_inbound_request(**kwargs),
        )

    # --- request/response shape ---
    def test_inbound_success_response_shape(self):
        r = self._inbound(correlation_id="tg-1")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(set(body), {"status", "recipient", "channel",
                                     "correlation_id", "cursor"})
        self.assertEqual(body["status"], "queued")
        self.assertEqual(body["recipient"], "codex-sol")
        self.assertEqual(body["channel"], "owner-telegram")
        self.assertEqual(body["correlation_id"], "tg-1")
        self.assertIsInstance(body["cursor"], int)
        # Matches the exported contract example (modulo cursor value).
        expected = contract.example_inbound_response(
            correlation_id="tg-1", cursor=body["cursor"]
        )
        self.assertEqual(body, expected)

    def test_outbound_success_response_shape(self):
        self._inbound(correlation_id="tg-9")
        inbound_id = 0
        app.store.add("codex-sol", "reply body", channel=contract.ROUTE_CHANNEL,
                      reply_to=inbound_id)
        r = self.client.get(contract.OUTBOUND_PATH, headers=AUTH)
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(set(body), {"messages", "cursor"})
        self.assertEqual(len(body["messages"]), 1)
        entry = body["messages"][0]
        self.assertEqual(set(entry), {"id", "sender", "recipient",
                                      "correlation_id", "reply_to_message_id",
                                      "text", "channel"})
        self.assertEqual(entry["recipient"], "owner-telegram")
        self.assertEqual(entry["sender"], "codex-sol")
        self.assertEqual(entry["correlation_id"], "tg-9")
        self.assertEqual(entry["reply_to_message_id"], TELEGRAM_MESSAGE_ID)
        self.assertEqual(body["cursor"], entry["id"])

    # --- two-factor gate + every one-factor negative ---
    def test_valid_two_factor_persists_and_wakes(self):
        r = self._inbound(correlation_id="tg-ok")
        self.assertEqual(r.status_code, 200)
        # Persisted exactly one owner message in the route channel.
        msgs = app.store.get_recent(10, channel="owner-telegram")
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["sender"], "owner-telegram")
        # Durable wake enqueued to the canonical responder queue.
        self.assertTrue(self.h.responder_queue_path().exists())
        wake = json.loads(
            self.h.responder_queue_path().read_text("utf-8").splitlines()[0]
        )
        self.assertIn("chat_read_exact", wake["prompt"])
        self.assertIn(f"message_id={r.json()['cursor']}", wake["prompt"])
        self.assertIn(f"reply_to={r.json()['cursor']}", wake["prompt"])
        self.assertNotIn("What is the current task status", wake["prompt"])

    def test_every_one_factor_only_case_is_rejected_before_effect(self):
        cases = {
            "wrong-bearer": ({"Authorization": "Bearer WRONG"},
                             dict(telegram_user_id=USER_ID, telegram_chat_id=CHAT_ID)),
            "missing-bearer": ({}, dict(telegram_user_id=USER_ID,
                                        telegram_chat_id=CHAT_ID)),
            "wrong-user": (AUTH, dict(telegram_user_id=1, telegram_chat_id=CHAT_ID)),
            "wrong-chat": (AUTH, dict(telegram_user_id=USER_ID, telegram_chat_id=1)),
            "missing-user": (AUTH, dict(telegram_user_id=None,
                                        telegram_chat_id=CHAT_ID)),
            "missing-chat": (AUTH, dict(telegram_user_id=USER_ID,
                                        telegram_chat_id=None)),
        }
        for name, (headers, ids) in cases.items():
            with self.subTest(case=name):
                r = self._inbound(headers=headers, correlation_id=f"cid-{name}",
                                  **ids)
                self.assertEqual(r.status_code, 403)
                # Generic body only: no factor/route/registry disclosure.
                self.assertEqual(r.json(), {"error": "forbidden"})
                # Nothing persisted and nothing woken by a rejected request.
                self.assertEqual(app.store.get_recent(50, channel="owner-telegram"), [])
                self.assertFalse(self.h.responder_queue_path().exists())

    def test_unprovisioned_guard_rejects(self):
        self.h.guard._bearer_hash = None  # simulate de-provisioned at runtime
        r = self._inbound()
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json(), {"error": "forbidden"})

    # --- channel + recipient validation (post-auth) ---
    def test_channel_normalization_hash_prefix_accepted(self):
        r = self._inbound(channel="#owner-telegram", correlation_id="c-hash")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["channel"], "owner-telegram")

    def test_invalid_channel_refused_after_auth(self):
        r = self._inbound(channel="general", correlation_id="c-bad")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json(), {"error": "invalid channel"})
        self.assertEqual(app.store.get_recent(50, channel="general"), [])

    def test_invalid_recipient_refused(self):
        r = self._inbound(recipient="claude", correlation_id="c-badrcpt")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json(), {"error": "invalid recipient"})

    def test_missing_or_invalid_telegram_message_id_refused_before_effect(self):
        for value in (None, True, 0, -1, "", "bad"):
            with self.subTest(value=value):
                r = self._inbound(
                    correlation_id=f"bad-mid-{value!r}",
                    telegram_message_id=value,
                )
                self.assertEqual(r.status_code, 400)
                self.assertEqual(r.json(), {"error": "invalid request"})
        self.assertEqual(app.store.get_recent(10, channel="owner-telegram"), [])
        self.assertFalse(self.h.responder_queue_path().exists())

    def test_missing_fields_refused(self):
        r = self.client.post(contract.INBOUND_PATH, headers=AUTH,
                             json={"telegram_user_id": USER_ID,
                                   "telegram_chat_id": CHAT_ID,
                                   "correlation_id": "c1"})
        self.assertEqual(r.status_code, 400)  # missing text
        r = self.client.post(contract.INBOUND_PATH, headers=AUTH,
                             json={"telegram_user_id": USER_ID,
                                   "telegram_chat_id": CHAT_ID, "text": "hi"})
        self.assertEqual(r.status_code, 400)  # missing correlation_id

    # --- canonical route + alias, no legacy identity emitted ---
    def test_codex_alias_wakes_canonical_not_legacy(self):
        r = self._inbound(recipient="@codex", correlation_id="c-alias")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["recipient"], "codex-sol")
        # The wake lands on the canonical responder queue, never a legacy one.
        self.assertTrue((self.h.data_dir / "codex-sol_queue.jsonl").exists())
        self.assertFalse((self.h.data_dir / "codex_queue.jsonl").exists())

    def test_no_legacy_codex_identity_in_receipt_or_message(self):
        r = self._inbound(recipient="codex", correlation_id="c-noleg")
        body = r.json()
        # Receipt names only the canonical identity.
        self.assertEqual(body["recipient"], "codex-sol")
        self.assertNotIn("codex\"", json.dumps(body))  # never bare "codex"
        # Persisted message metadata records the canonical recipient.
        msg = app.store.get_recent(1, channel="owner-telegram")[0]
        self.assertEqual(msg["metadata"]["recipient"], "codex-sol")
        self.assertNotEqual(msg["sender"], "codex")

    # --- outbound correlation, cursor, echo exclusion ---
    def test_outbound_excludes_echo_and_preserves_correlation_and_cursor(self):
        self._inbound(correlation_id="tg-corr")   # owner message id 0
        # codex-sol replies via reply_to and via @mention.
        app.store.add("codex-sol", "answer one", channel="owner-telegram",
                      reply_to=0)
        app.store.add("codex-sol", "aside @owner-telegram fyi",
                      channel="owner-telegram")
        # An unrelated agent message that is NOT addressed to the owner.
        app.store.add("claude", "unrelated chatter", channel="owner-telegram")
        r = self.client.get(contract.OUTBOUND_PATH, headers=AUTH)
        entries = r.json()["messages"]
        senders = [e["sender"] for e in entries]
        # Echo excluded: the owner's own inbound is never returned.
        self.assertNotIn("owner-telegram", senders)
        # Unrelated message excluded.
        texts = [e["text"] for e in entries]
        self.assertNotIn("unrelated chatter", texts)
        # Reply preserves the inbound correlation id; ids are monotonic.
        reply = next(e for e in entries if e["text"] == "answer one")
        self.assertEqual(reply["correlation_id"], "tg-corr")
        ids = [e["id"] for e in entries]
        self.assertEqual(ids, sorted(ids))
        self.assertTrue(all(i > 0 for i in ids))  # after inbound id 0

    def test_outbound_since_id_cursor_advances(self):
        self._inbound(correlation_id="c-a")               # id 0 (owner)
        app.store.add("codex-sol", "first", channel="owner-telegram", reply_to=0)   # id 1
        r1 = self.client.get(contract.OUTBOUND_PATH, headers=AUTH)
        cursor = r1.json()["cursor"]
        self.assertEqual(cursor, 1)
        app.store.add("codex-sol", "second", channel="owner-telegram", reply_to=0)  # id 2
        r2 = self.client.get(
            f"{contract.OUTBOUND_PATH}?since_id={cursor}", headers=AUTH
        )
        entries = r2.json()["messages"]
        self.assertEqual([e["text"] for e in entries], ["second"])
        self.assertEqual(r2.json()["cursor"], 2)

    def test_outbound_wrong_bearer_rejected(self):
        r = self.client.get(contract.OUTBOUND_PATH,
                            headers={"Authorization": "Bearer WRONG"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json(), {"error": "forbidden"})


# --------------------------------------------------------------------------- #
# Loopback transport gate
# --------------------------------------------------------------------------- #
class RouteLoopbackTests(unittest.TestCase):
    def test_non_loopback_source_is_refused_before_handler(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        h = contract.build_contract_harness(
            tmp.name, bearer=BEARER, allowlist=ALLOWLIST,
            client_addr=("203.0.113.7", 5000),
        )
        self.addCleanup(h.close)
        r = h.client.post(contract.INBOUND_PATH, headers=AUTH,
                          json=contract.example_inbound_request(
                              telegram_user_id=USER_ID, telegram_chat_id=CHAT_ID))
        self.assertEqual(r.status_code, 403)
        # Rejected at the loopback gate: nothing persisted.
        self.assertEqual(app.store.get_recent(50, channel="owner-telegram"), [])


# --------------------------------------------------------------------------- #
# Durable route: offline persistence, restart, exactly-one injection
# --------------------------------------------------------------------------- #
class DurableRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name)
        self.queue = self.data_dir / f"{telegram_route.CANONICAL_RESPONDER}_queue.jsonl"

    def _enqueue_inbound_while_offline(self):
        """Drive the inbound path while codex-sol is unregistered/offline."""
        h = contract.build_contract_harness(
            self.data_dir, bearer=BEARER, allowlist=ALLOWLIST
        )
        try:
            r = h.client.post(
                contract.INBOUND_PATH, headers=AUTH,
                json=contract.example_inbound_request(
                    correlation_id="durable-1",
                    telegram_user_id=USER_ID, telegram_chat_id=CHAT_ID),
            )
            self.assertEqual(r.status_code, 200)
        finally:
            h.close()

    def _run_watcher_once(self, injector, done, stop):
        thread = threading.Thread(
            target=wrapper._queue_watcher,
            args=(lambda: (telegram_route.CANONICAL_RESPONDER, self.queue),
                  injector),
            kwargs={
                "stop_event": stop,
                "poll_seconds": 0.01,
                "fetch_role_fn": lambda *_a, **_k: (True, ""),
                "fetch_rules_fn": lambda *_a, **_k: (
                    True, {"epoch": 1, "rules": [], "refresh_interval": 10}),
                "report_sync_fn": lambda *_a, **_k: None,
            },
            daemon=True,
        )
        with mock.patch.object(wrapper.time, "sleep"):
            thread.start()
            self.assertTrue(done.wait(5))
            stop.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_offline_inbound_persists_and_survives_restart_then_injects_once(self):
        # 1) Inbound while codex-sol is offline: durable message + queue record.
        self._enqueue_inbound_while_offline()
        self.assertTrue(self.queue.exists())
        records = self.queue.read_text("utf-8").splitlines()
        self.assertEqual(len(records), 1)
        rec = json.loads(records[0])
        self.assertEqual(rec["channel"], "owner-telegram")
        self.assertEqual(rec.get("text"), "")           # NO body in the wake
        self.assertIn("action_id", rec)
        self.assertIn("chat_read_exact", rec["prompt"])
        self.assertIn("message_id=0", rec["prompt"])
        self.assertIn("reply_to=0", rec["prompt"])

        # 2) Simulate a server restart: the durable message store reopens from
        #    the same data dir with the owner message intact.
        reopened = MessageStore(str(self.data_dir / "messages.jsonl"))
        owner_msgs = reopened.get_recent(10, channel="owner-telegram")
        self.assertEqual(len(owner_msgs), 1)
        self.assertEqual(owner_msgs[0]["sender"], "owner-telegram")
        self.assertEqual(owner_msgs[0]["metadata"]["correlation_id"], "durable-1")
        # The pending wake also survived the restart.
        self.assertTrue(self.queue.exists())

        # 3) codex-sol finally comes online: its wrapper injects EXACTLY once.
        prompts = []
        done = threading.Event()

        def inject(prompt):
            prompts.append(prompt)
            done.set()
            return "injected"

        self._run_watcher_once(inject, done, threading.Event())
        self.assertEqual(len(prompts), 1)
        self.assertIn("channel='owner-telegram'", prompts[0])
        self.assertIn("chat_read_exact", prompts[0])
        self.assertIn("message_id=0", prompts[0])
        self.assertIn("reply_to=0", prompts[0])
        # The injected wake carries no owner body — only the exact pointer.
        self.assertNotIn("What is the current task status", prompts[0])

        # 4) A second run (e.g. another restart) replays nothing: exactly-once.
        def must_not_inject(_prompt):
            self.fail("durable wake injected twice")

        advanced = threading.Event()

        def watch_cursor():
            raw = self.queue.read_bytes()
            while wrapper._read_queue_cursor(self.queue, raw) != len(raw):
                if advanced.wait(0.01):
                    return
            advanced.set()

        threading.Thread(target=watch_cursor, daemon=True).start()
        self._run_watcher_once(must_not_inject, advanced, threading.Event())


# --------------------------------------------------------------------------- #
# Privacy: no secret / high-cardinality leak into logs / errors / queue / store
# --------------------------------------------------------------------------- #
class RoutePrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = contract.build_contract_harness(
            self.tmp.name, bearer=BEARER, allowlist=ALLOWLIST
        )
        self.addCleanup(self.h.close)

    def test_no_bearer_body_user_chat_correlation_leak(self):
        secret_body = "SECRET-OWNER-BODY-SENTINEL-42"
        correlation = "CORRELATION-SENTINEL-77"
        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setLevel(logging.DEBUG)
        root = logging.getLogger()
        root.addHandler(handler)
        previous_level = root.level
        root.setLevel(logging.DEBUG)
        try:
            ok = self.h.client.post(
                contract.INBOUND_PATH, headers=AUTH,
                json=contract.example_inbound_request(
                    text=secret_body, correlation_id=correlation,
                    telegram_user_id=USER_ID, telegram_chat_id=CHAT_ID),
            )
            self.assertEqual(ok.status_code, 200)
            reject = self.h.client.post(
                contract.INBOUND_PATH,
                headers={"Authorization": f"Bearer {BEARER}"},
                json=contract.example_inbound_request(
                    text=secret_body, correlation_id=correlation,
                    telegram_user_id=USER_ID, telegram_chat_id=1),  # wrong chat
            )
            self.assertEqual(reject.status_code, 403)
        finally:
            root.removeHandler(handler)
            root.setLevel(previous_level)

        logs = buffer.getvalue()
        sensitive = [BEARER, secret_body, correlation, str(USER_ID), str(CHAT_ID)]
        for value in sensitive:
            self.assertNotIn(value, logs, f"leaked {value!r} into logs")

        # The reject response body discloses nothing.
        for value in sensitive:
            self.assertNotIn(value, reject.text)

        # The durable wake queue carries no owner body / bearer / ids.
        queue = self.h.responder_queue_path()
        queue_raw = queue.read_text("utf-8")
        for value in (BEARER, secret_body, correlation, str(USER_ID), str(CHAT_ID)):
            self.assertNotIn(value, queue_raw)

        # The route config store never persists the raw bearer.
        store_raw = (self.h.data_dir / "telegram_route.json").read_text("utf-8")
        self.assertNotIn(BEARER, store_raw)
        # The owner body DOES live in the message store (that is the message
        # store, not a log/metric/audit) so the responder can read it.
        msg = app.store.get_recent(1, channel="owner-telegram")[0]
        self.assertEqual(msg["text"], secret_body)


# --------------------------------------------------------------------------- #
# C1 — authenticated inbound is idempotent (retry / concurrent / restart / 503)
# --------------------------------------------------------------------------- #
class InboundIdempotencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name)
        self.h = contract.build_contract_harness(
            self.data_dir, bearer=BEARER, allowlist=ALLOWLIST
        )
        self.addCleanup(lambda: self.h.close())
        self.client = self.h.client
        self.queue = self.h.responder_queue_path()

    def _post(self, client=None, **kwargs):
        kwargs.setdefault("telegram_user_id", USER_ID)
        kwargs.setdefault("telegram_chat_id", CHAT_ID)
        return (client or self.client).post(
            contract.INBOUND_PATH, headers=AUTH,
            json=contract.example_inbound_request(**kwargs),
        )

    def _owner_messages(self):
        return app.store.get_recent(50, channel="owner-telegram")

    def _wake_records(self):
        if not self.queue.exists():
            return []
        return [json.loads(line) for line
                in self.queue.read_text("utf-8").splitlines() if line.strip()]

    def test_same_request_twice_yields_one_message_and_one_wake(self):
        r1 = self._post(correlation_id="dup-1", text="same body")
        r2 = self._post(correlation_id="dup-1", text="same body")
        self.assertEqual((r1.status_code, r2.status_code), (200, 200))
        # One durable owner message; identical, stable receipt (same cursor).
        self.assertEqual(len(self._owner_messages()), 1)
        self.assertEqual(r1.json(), r2.json())
        # One logical wake carrying one stable action_id.
        recs = self._wake_records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(len({r.get("action_id") for r in recs}), 1)
        self.assertIn("message_id=0", recs[0]["prompt"])
        self.assertIn("reply_to=0", recs[0]["prompt"])

    def test_same_correlation_with_different_telegram_message_id_conflicts(self):
        first = self._post(
            correlation_id="mid-conflict", text="same body",
            telegram_message_id=100,
        )
        second = self._post(
            correlation_id="mid-conflict", text="same body",
            telegram_message_id=101,
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)
        self.assertEqual(second.json(), {"error": "conflict"})
        self.assertEqual(len(self._owner_messages()), 1)
        self.assertEqual(len(self._wake_records()), 1)

    def test_concurrent_same_request_yields_one_message_and_one_wake(self):
        barrier = threading.Barrier(2)

        def call():
            barrier.wait(timeout=5)
            return self._post(correlation_id="cc-1", text="concurrent body")

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            results = [f.result() for f in
                       [ex.submit(call), ex.submit(call)]]
        self.assertTrue(all(r.status_code == 200 for r in results))
        self.assertEqual({r.json()["cursor"] for r in results}, {0})
        self.assertEqual(len(self._owner_messages()), 1)
        self.assertEqual(len(self._wake_records()), 1)

    def test_restart_then_retry_yields_one_message_and_one_wake(self):
        r1 = self._post(correlation_id="rs-1", text="restart body")
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(len(self._wake_records()), 1)
        # Simulate a server restart: rebuild the app on the SAME data dir.
        self.h.close()
        self.h = contract.build_contract_harness(
            self.data_dir, bearer=BEARER, allowlist=ALLOWLIST
        )
        self.client = self.h.client
        r2 = self._post(correlation_id="rs-1", text="restart body")
        self.assertEqual(r2.status_code, 200)
        # Same durable message + stable receipt; the wake deduped (one record).
        self.assertEqual(r1.json()["cursor"], r2.json()["cursor"])
        self.assertEqual(len(self._owner_messages()), 1)
        self.assertEqual(len(self._wake_records()), 1)

    def test_backpressure_after_persist_then_retry_recovers(self):
        real = app.agents.trigger_sync
        state = {"n": 0}

        def flaky(*a, **k):
            state["n"] += 1
            if state["n"] == 1:
                raise DeliveryBackpressureError("injected after persistence")
            return real(*a, **k)

        with mock.patch.object(app.agents, "trigger_sync", side_effect=flaky):
            r1 = self._post(correlation_id="bp-1", text="bp body")
            self.assertEqual(r1.status_code, 503)
            # The message persisted; NO wake was enqueued for the failed append.
            self.assertEqual(len(self._owner_messages()), 1)
            self.assertEqual(self._wake_records(), [])
            # The natural bridge retry re-attaches to the same message and
            # safely re-attempts the same logical wake.
            r2 = self._post(correlation_id="bp-1", text="bp body")
            self.assertEqual(r2.status_code, 200)
        self.assertEqual(len(self._owner_messages()), 1)
        self.assertEqual(len(self._wake_records()), 1)

    def test_conflicting_envelope_same_correlation_fails_closed(self):
        r1 = self._post(correlation_id="conf-1", text="first body")
        self.assertEqual(r1.status_code, 200)
        r2 = self._post(correlation_id="conf-1", text="DIFFERENT body")
        self.assertEqual(r2.status_code, 409)
        # Generic body only: no correlation / body / route disclosure.
        self.assertEqual(r2.json(), {"error": "conflict"})
        self.assertNotIn("conf-1", r2.text)
        self.assertNotIn("DIFFERENT body", r2.text)
        # No second persistence, no second wake.
        self.assertEqual(len(self._owner_messages()), 1)
        self.assertEqual(len(self._wake_records()), 1)


# --------------------------------------------------------------------------- #
# C2 — an ordinary canonical response is selected without fabricated metadata
# --------------------------------------------------------------------------- #
class OutboundOrdinaryResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name)
        self.h = contract.build_contract_harness(
            self.data_dir, bearer=BEARER, allowlist=ALLOWLIST
        )
        self.addCleanup(lambda: self.h.close())
        self.client = self.h.client

    def _inbound(self, correlation_id, telegram_message_id=TELEGRAM_MESSAGE_ID):
        r = self.client.post(
            contract.INBOUND_PATH, headers=AUTH,
            json=contract.example_inbound_request(
                correlation_id=correlation_id,
                telegram_user_id=USER_ID, telegram_chat_id=CHAT_ID,
                telegram_message_id=telegram_message_id),
        )
        self.assertEqual(r.status_code, 200)
        return r

    def _outbound(self, since_id=0, limit=50):
        return self.client.get(
            f"{contract.OUTBOUND_PATH}?since_id={since_id}&limit={limit}",
            headers=AUTH,
        ).json()

    def test_ordinary_reply_selected_without_fabricated_metadata(self):
        self._inbound("tg-ord")                                        # id 0
        # Exactly how an ordinary mcp chat_send stores a reply: no reply_to,
        # no metadata, no @mention.
        app.store.add("codex-sol", "plain answer", channel="owner-telegram")  # 1
        entries = self._outbound()["messages"]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["sender"], "codex-sol")
        self.assertEqual(entry["recipient"], "owner-telegram")
        self.assertEqual(entry["text"], "plain answer")
        # Correlation inherited from the preceding owner request.
        self.assertEqual(entry["correlation_id"], "tg-ord")
        self.assertEqual(entry["reply_to_message_id"], TELEGRAM_MESSAGE_ID)

    def test_multiple_sequential_pairs_map_deterministically(self):
        self._inbound("q1", 5101)                                      # id 0
        app.store.add("codex-sol", "ans1", channel="owner-telegram")   # id 1
        self._inbound("q2", 5102)                                      # id 2
        app.store.add("codex-sol", "ans2", channel="owner-telegram")   # id 3
        got = {e["text"]: e["correlation_id"]
               for e in self._outbound()["messages"]}
        self.assertEqual(got, {"ans1": "q1", "ans2": "q2"})
        reply_targets = {e["text"]: e["reply_to_message_id"]
                         for e in self._outbound()["messages"]}
        self.assertEqual(reply_targets, {"ans1": 5101, "ans2": 5102})

    def test_explicit_reply_takes_precedence_over_sequential_rule(self):
        self._inbound("e1", 5201)                                      # id 0
        self._inbound("e2", 5202)                                      # id 1
        # Reply explicitly to the FIRST question even though the second is the
        # most recent preceding owner request.
        app.store.add("codex-sol", "ans", channel="owner-telegram",
                      reply_to=0)                                      # id 2
        entry = next(e for e in self._outbound()["messages"]
                     if e["text"] == "ans")
        self.assertEqual(entry["correlation_id"], "e1")
        self.assertEqual(entry["reply_to_message_id"], 5201)

    def test_unrelated_sender_owner_echo_and_foreign_recipient_excluded(self):
        self._inbound("f1")                                            # id 0 echo
        app.store.add("claude", "chatter", channel="owner-telegram")   # id 1
        app.store.add("codex-sol", "to-someone-else", channel="owner-telegram",
                      metadata={"recipient": "claude"})                # id 2
        app.store.add("codex-sol", "for owner", channel="owner-telegram")  # id 3
        entries = self._outbound()["messages"]
        self.assertEqual([e["text"] for e in entries], ["for owner"])
        senders = {e["sender"] for e in entries}
        self.assertNotIn("owner-telegram", senders)  # echo excluded
        self.assertNotIn("claude", senders)          # unrelated excluded

    def test_cursor_advances_across_filtered_records(self):
        self._inbound("cf")                                            # id 0 echo
        app.store.add("claude", "chatter", channel="owner-telegram")   # id 1
        app.store.add("codex-sol", "x", channel="owner-telegram",
                      metadata={"recipient": "claude"})                # id 2
        body = self._outbound()
        self.assertEqual(body["messages"], [])
        self.assertEqual(body["cursor"], 2)  # past every filtered record

    def test_restart_forward_poll_has_no_duplicates(self):
        self._inbound("rr")                                            # id 0
        app.store.add("codex-sol", "the answer", channel="owner-telegram")  # 1
        body1 = self._outbound(since_id=0)
        self.assertEqual([e["text"] for e in body1["messages"]], ["the answer"])
        cursor = body1["cursor"]
        # Restart, then resume strictly after the covered cursor.
        self.h.close()
        self.h = contract.build_contract_harness(
            self.data_dir, bearer=BEARER, allowlist=ALLOWLIST
        )
        self.client = self.h.client
        body2 = self._outbound(since_id=cursor)
        self.assertEqual(body2["messages"], [])   # no duplicate after restart


# --------------------------------------------------------------------------- #
# C3 — outbound pagination is lossless (complete, ordered, exactly-once)
# --------------------------------------------------------------------------- #
class OutboundPaginationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = contract.build_contract_harness(
            Path(self.tmp.name), bearer=BEARER, allowlist=ALLOWLIST
        )
        self.addCleanup(lambda: self.h.close())
        self.client = self.h.client

    def test_backlog_beyond_limit_paged_completely_in_order(self):
        r = self.client.post(
            contract.INBOUND_PATH, headers=AUTH,
            json=contract.example_inbound_request(
                correlation_id="bk",
                telegram_user_id=USER_ID, telegram_chat_id=CHAT_ID),
        )
        self.assertEqual(r.status_code, 200)                           # id 0
        for i in range(1, 6):                                          # ids 1..5
            app.store.add("codex-sol", f"r{i}", channel="owner-telegram")

        collected, since = [], 0
        for _ in range(20):                       # bounded page loop, limit=2
            body = self.client.get(
                f"{contract.OUTBOUND_PATH}?since_id={since}&limit=2",
                headers=AUTH,
            ).json()
            texts = [e["text"] for e in body["messages"]]
            collected += texts
            cursor = body["cursor"]
            if cursor == since and not texts:
                break
            since = cursor
        # Every reply delivered exactly once, in order, none dropped/reordered.
        self.assertEqual(collected, ["r1", "r2", "r3", "r4", "r5"])
        self.assertEqual(len(collected), len(set(collected)))


# --------------------------------------------------------------------------- #
# F4 — provisioning entrypoint is operationally deliverable and secret-safe
# --------------------------------------------------------------------------- #
class ProvisioningCliTests(unittest.TestCase):
    def test_provision_cli_is_secret_safe(self):
        with tempfile.TemporaryDirectory() as d:
            store = str(Path(d) / "telegram_route.json")
            argv = ["provision", "--store", store, "--allow", f"{USER_ID}:{CHAT_ID}"]
            with mock.patch("getpass.getpass", side_effect=[BEARER, BEARER]) as gp:
                rc = telegram_route.main(list(argv))
            self.assertEqual(rc, 0)
            self.assertEqual(gp.call_count, 2)   # hidden entry + confirm
            # The bearer never travelled through argv or the environment.
            self.assertNotIn(BEARER, " ".join(argv))
            self.assertTrue(all(BEARER not in v for v in os.environ.values()))
            # At rest: salted digest only; no raw bearer, no bearer key.
            raw = Path(store).read_text("utf-8")
            self.assertNotIn(BEARER, raw)
            data = json.loads(raw)
            self.assertIn("bearer_hash", data)
            self.assertIn("bearer_salt", data)
            self.assertNotIn("bearer", data)
            # The provisioned guard authenticates the bearer + allowlist pair.
            guard = telegram_route.TelegramRouteGuard(store)
            self.assertTrue(guard.verify_inbound(BEARER, USER_ID, CHAT_ID))

    def test_provision_cli_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            store = str(Path(d) / "telegram_route.json")
            with mock.patch("getpass.getpass", side_effect=["A", "B"]):
                rc = telegram_route.main(
                    ["provision", "--store", store, "--allow", "1:2"]
                )
            self.assertEqual(rc, 2)
            self.assertFalse(Path(store).exists())

    def test_provision_cli_requires_allowlist(self):
        with self.assertRaises(SystemExit):
            telegram_route.main(["provision", "--store", "unused.json"])


if __name__ == "__main__":
    unittest.main()
