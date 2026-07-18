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

import io
import json
import logging
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
from store import MessageStore
from agents import AgentTrigger


BEARER = "ROUTE-BEARER-SENTINEL-9z9z"
USER_ID = 771234567
CHAT_ID = 889876543
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
            "metadata": {"recipient": "codex-sol", "correlation_id": "cid-x"},
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
                                      "correlation_id", "text", "channel"})
        self.assertEqual(entry["recipient"], "owner-telegram")
        self.assertEqual(entry["sender"], "codex-sol")
        self.assertEqual(entry["correlation_id"], "tg-9")
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
        self.assertIn("#owner-telegram", prompts[0])
        # The injected wake carries no owner body — only the channel pointer.
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


if __name__ == "__main__":
    unittest.main()
