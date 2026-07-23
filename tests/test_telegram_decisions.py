"""Telegram decision route: bounded wire shape and exactly-once resolution."""

import concurrent.futures
import tempfile
import unittest
from pathlib import Path

import app
import telegram_route_contract as contract


BEARER = "DECISION-ROUTE-BEARER-TEST"
USER_ID = 771234567
CHAT_ID = 889876543
AUTH = {"Authorization": f"Bearer {BEARER}"}


class TelegramDecisionRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name)
        self.harness = contract.build_contract_harness(
            self.data_dir, BEARER, [(USER_ID, CHAT_ID)]
        )
        self.addCleanup(lambda: self.harness.close())

    def _decision(self):
        return app.store.add(
            contract.CANONICAL_RESPONDER,
            "Choose the deployment window",
            msg_type="decision",
            metadata={"choices": ["Morning", "Evening"], "resolved": False},
            channel=contract.ROUTE_CHANNEL,
        )

    def _resolve(self, decision_id, choice_index=0, *, headers=AUTH, **overrides):
        body = contract.example_decision_request(
            decision_id=decision_id,
            choice_index=choice_index,
            telegram_user_id=USER_ID,
            telegram_chat_id=CHAT_ID,
        )
        body.update(overrides)
        return self.harness.client.post(
            contract.DECISION_RESOLVE_PATH, headers=headers, json=body
        )

    def test_unresolved_decision_choices_are_exported_on_the_bounded_wire(self):
        decision = self._decision()
        response = self.harness.client.get(contract.OUTBOUND_PATH, headers=AUTH)
        self.assertEqual(response.status_code, 200)
        entries = response.json()["messages"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(
            entries[0],
            {
                "id": decision["id"],
                "sender": contract.CANONICAL_RESPONDER,
                "recipient": contract.OWNER_IDENTITY,
                "correlation_id": None,
                "reply_to_message_id": None,
                "text": "Choose the deployment window",
                "channel": contract.ROUTE_CHANNEL,
                "type": "decision",
                "decision_id": decision["id"],
                "choices": ["Morning", "Evening"],
            },
        )

    def test_choice_index_resolves_once_and_appends_explicit_owner_reply(self):
        decision = self._decision()
        first = self._resolve(decision["id"], 1)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), {"status": "resolved"})

        stored = app.store.get_by_id(decision["id"])
        self.assertTrue(stored["metadata"]["resolved"])
        self.assertEqual(stored["metadata"]["chosen"], "Evening")
        replies = [
            message for message in app.store.get_since(-1, channel=contract.ROUTE_CHANNEL)
            if message.get("sender") == contract.OWNER_IDENTITY
            and message.get("reply_to") == decision["id"]
        ]
        self.assertEqual(len(replies), 1)
        self.assertIn("Evening", replies[0]["text"])

        stale = self._resolve(decision["id"], 0)
        self.assertEqual(stale.status_code, 200)
        self.assertEqual(stale.json(), {"status": "already_resolved"})
        replies_after = [
            message for message in app.store.get_since(-1, channel=contract.ROUTE_CHANNEL)
            if message.get("sender") == contract.OWNER_IDENTITY
            and message.get("reply_to") == decision["id"]
        ]
        self.assertEqual(len(replies_after), 1)

    def test_restart_replay_is_an_idempotent_noop(self):
        decision = self._decision()
        self.assertEqual(self._resolve(decision["id"], 0).json(), {"status": "resolved"})

        self.harness.close()
        self.harness = contract.build_contract_harness(
            self.data_dir, BEARER, [(USER_ID, CHAT_ID)]
        )
        replay = self._resolve(decision["id"], 0)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), {"status": "already_resolved"})
        replies = [
            message for message in app.store.get_since(-1, channel=contract.ROUTE_CHANNEL)
            if message.get("sender") == contract.OWNER_IDENTITY
            and message.get("reply_to") == decision["id"]
        ]
        self.assertEqual(len(replies), 1)

    def test_concurrent_taps_append_exactly_one_owner_reply(self):
        decision = self._decision()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(
                lambda index: self._resolve(decision["id"], index), (0, 1)
            ))
        self.assertEqual(sorted(r.status_code for r in responses), [200, 200])
        self.assertEqual(
            sorted(r.json()["status"] for r in responses),
            ["already_resolved", "resolved"],
        )
        replies = [
            message for message in app.store.get_since(-1, channel=contract.ROUTE_CHANNEL)
            if message.get("sender") == contract.OWNER_IDENTITY
            and message.get("reply_to") == decision["id"]
        ]
        self.assertEqual(len(replies), 1)

    def test_two_factor_and_malformed_shapes_fail_closed_without_effect_or_echo(self):
        decision = self._decision()
        cases = [
            self._resolve(decision["id"], headers={"Authorization": "Bearer WRONG"}),
            self._resolve(decision["id"], telegram_chat_id=999),
            self._resolve(decision["id"], choice_index=100),
            self._resolve(decision["id"], telegram_user_id=str(USER_ID)),
            self._resolve(decision["id"], choice_text="Evening"),
        ]
        self.assertEqual(
            [response.status_code for response in cases], [403, 403, 400, 400, 400]
        )
        forbidden = (BEARER, str(decision["id"]), "Morning", "Evening")
        for response in cases:
            rendered = response.text
            for value in forbidden:
                self.assertNotIn(value, rendered)
        self.assertFalse(app.store.get_by_id(decision["id"])["metadata"]["resolved"])
        self.assertEqual(
            [m for m in app.store.get_since(-1, channel=contract.ROUTE_CHANNEL)
             if m.get("sender") == contract.OWNER_IDENTITY],
            [],
        )


if __name__ == "__main__":
    unittest.main()
