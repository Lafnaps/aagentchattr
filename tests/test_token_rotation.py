"""Atomic, durable token rotation (wrapper-restart prerequisite).

Contract: chat id1076; fault/concurrency/ASGI rework per id1097 (B1 durability,
B2 snapshot race) and id1098 (E1 normative ASGI status, E2 runtime no-resolve
side effect, E3 exact response shape, E4 patch scope in the evidence, not here).

Every pin names the mutant it kills. Registry-level pins cover semantics; the
ASGI pins drive the REAL Starlette app through the security middleware so the
middleware/endpoint interaction (not just the handler in isolation) is exercised.
"""

import asyncio
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app
from registry import RuntimeRegistry


def _registry(tmp: str) -> RuntimeRegistry:
    registry = RuntimeRegistry(data_dir=tmp)
    registry.seed({"claude": {"label": "Claude", "color": "#da7756"}})
    return registry


# --------------------------------------------------------------------------- #
# Registry semantics + durability (id1097)
# --------------------------------------------------------------------------- #
class RotateTokenRegistryTests(unittest.TestCase):
    def test_rotation_returns_new_token_and_old_is_immediately_stale(self):
        # Kills the no-rotate mutant (token not replaced / old returned).
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]

            rotated = registry.rotate_token(old)

            self.assertIsInstance(rotated, dict)
            self.assertEqual("claude", rotated["name"])
            self.assertNotEqual(old, rotated["token"])
            self.assertGreaterEqual(len(rotated["token"]), 32)
            self.assertIsNone(registry.resolve_token(old))
            self.assertEqual("claude", registry.resolve_token(rotated["token"])["name"])

    def test_identity_fields_are_unchanged_by_rotation(self):
        # Kills any mutant that touches identity besides the token.
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            created = registry.register("claude")
            before = registry.get_instance("claude")

            registry.rotate_token(created["token"])

            after = registry.get_instance("claude")
            self.assertEqual(before, after)  # _inst_dict excludes the token
            self.assertEqual(created["identity_id"], after["identity_id"])
            self.assertEqual("active", after["state"])

    def test_rotated_token_is_persisted_across_registry_restart(self):
        # Kills the persistence-skip mutant (_write_instances_snapshot not called).
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]
            rotated = registry.rotate_token(old)

            reloaded = _registry(tmp)  # fresh instance, same data dir

            self.assertIsNone(reloaded.resolve_token(old))
            self.assertEqual("claude", reloaded.resolve_token(rotated["token"])["name"])

    def test_persist_failure_rolls_back_and_old_token_survives_restart(self):
        # id1097 B1: if the durable write fails, rotation must NOT report success,
        # must roll the in-memory token back, and the OLD token must remain the
        # valid one on disk (the exposed-token-revived-after-restart bug).
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]

            boom_calls = []

            def boom(data):
                boom_calls.append(1)
                raise OSError("synthetic replace failure")

            registry._write_snapshot_to_disk = boom  # inject durable-write fault
            result = registry.rotate_token(old)

            self.assertEqual("persist-failed", result)
            self.assertTrue(boom_calls)
            # In-memory rollback: old token still resolves, no new token exists.
            self.assertEqual("claude", registry.resolve_token(old)["name"])
            # Disk still holds the OLD token — a restart must not revive a ghost
            # and must not invalidate the still-valid old credential.
            del registry._write_snapshot_to_disk
            reloaded = _registry(tmp)
            self.assertEqual("claude", reloaded.resolve_token(old)["name"])

    def test_success_only_after_durable_write_ordering(self):
        # The snapshot that persists the new token must be written BEFORE the
        # caller receives it (durability ordering, id1097 B1).
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]
            order = []
            real = registry._write_snapshot_to_disk

            def traced(data):
                real(data)
                order.append("persisted")

            registry._write_snapshot_to_disk = traced
            rotated = registry.rotate_token(old)
            order.append("returned")

            self.assertIsInstance(rotated, dict)
            self.assertEqual(["persisted", "returned"], order)

    def test_concurrent_same_old_token_yields_exactly_one_success(self):
        # id1097 B2: two racing rotations of the same old token — exactly one
        # succeeds; the loser sees a stale token (None), never a second mint.
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]
            barrier = threading.Barrier(8)
            results = []
            lock = threading.Lock()

            def worker():
                barrier.wait()
                r = registry.rotate_token(old)
                with lock:
                    results.append(r)

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            successes = [r for r in results if isinstance(r, dict)]
            self.assertEqual(1, len(successes))
            self.assertTrue(all(r is None for r in results if not isinstance(r, dict)))
            # The one persisted token is the live one after the storm.
            reloaded = _registry(tmp)
            self.assertEqual("claude", reloaded.resolve_token(successes[0]["token"])["name"])
            self.assertIsNone(reloaded.resolve_token(old))

    def _barriered_rotate(self, registry, token):
        """Start rotate_token(token) in a thread whose durable write blocks on a
        test-injected barrier (monkeypatched _write_snapshot_to_disk — id1144#2,
        no production hook). Returns (thread, entered_evt, release_evt, out, mode)
        where mode controls whether the write ultimately fails or succeeds.
        """
        entered = threading.Event()
        release = threading.Event()
        out = {}
        real_write = registry._write_snapshot_to_disk
        mode = {"fail": False}

        def blocking_write(data):
            entered.set()
            release.wait(5)
            if mode["fail"]:
                raise OSError("synthetic late replace failure")
            real_write(data)

        registry._write_snapshot_to_disk = blocking_write

        def run():
            out["result"] = registry.rotate_token(token)

        t = threading.Thread(target=run)
        return t, entered, release, out, mode

    def test_late_fault_concurrent_lookup_is_atomic_no_op(self):
        # id1142 BLOCKER #1 + id1144#1: while the durable write is in flight the
        # rotation holds _lock, so a concurrent resolve_token(old) MUST block and
        # not complete until the rotation resolves. On a late write-failure the
        # rotation rolls back under the lock, so old stays continuously valid and
        # the new token was never handed out (no tentative credential).
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]
            t, entered, release, out, mode = self._barriered_rotate(registry, old)
            mode["fail"] = True
            t.start()
            self.assertTrue(entered.wait(5))  # rotation now holds _lock, blocked

            look = {}
            done = threading.Event()

            def do_lookup():
                look["old"] = registry.resolve_token(old)
                done.set()

            tb = threading.Thread(target=do_lookup)
            tb.start()
            # The lookup must NOT complete while the rotation holds _lock.
            self.assertFalse(done.wait(0.5), "resolve_token(old) must block on _lock")

            release.set()  # let the write fail -> rollback under _lock
            t.join(5)
            self.assertTrue(done.wait(5))
            tb.join(5)

            self.assertEqual("persist-failed", out["result"])
            self.assertIsNotNone(look["old"])  # old valid after rollback
            self.assertEqual("claude", look["old"]["name"])
            # Disk + a fresh restart still hold ONLY the old token (no ghost new).
            reloaded = _registry(tmp)
            self.assertEqual("claude", reloaded.resolve_token(old)["name"])

    def test_success_concurrent_lookup_waits_for_commit(self):
        # id1144#1 success symmetry: the lookup blocks until the rotation commits,
        # then the new token is valid and the old is stale.
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]
            t, entered, release, out, mode = self._barriered_rotate(registry, old)
            mode["fail"] = False
            t.start()
            self.assertTrue(entered.wait(5))

            look = {}
            done = threading.Event()

            def do_lookup():
                look["old"] = registry.resolve_token(old)
                done.set()

            tb = threading.Thread(target=do_lookup)
            tb.start()
            self.assertFalse(done.wait(0.5), "resolve_token(old) must block until commit")

            release.set()  # let the write succeed -> commit under _lock
            t.join(5)
            self.assertTrue(done.wait(5))
            tb.join(5)

            self.assertIsInstance(out["result"], dict)
            new = out["result"]["token"]
            self.assertIsNone(look["old"])  # old stale post-commit
            self.assertEqual("claude", registry.resolve_token(new)["name"])
            reloaded = _registry(tmp)
            self.assertEqual("claude", reloaded.resolve_token(new)["name"])
            self.assertIsNone(reloaded.resolve_token(old))

    def test_persist_lock_serializes_saves_against_stale_overwrite(self):
        # id1142#2: _persist_lock must serialize a best-effort save's whole
        # snapshot→write against a rotation, so a laggard stale snapshot can never
        # land after a newer durable write. Deterministic via a test barrier on the
        # save's write; removing _persist_lock lets the rotation's write interleave
        # and the stale save clobbers it. With the lock, the rotation blocks on
        # _persist_lock until the save's write completes, and its own write lands last.
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]
            entered = threading.Event()
            release = threading.Event()
            real_write = registry._write_snapshot_to_disk
            first = {"done": False}

            def barriered_write(data):
                # Block only the FIRST writer (the best-effort save) mid-flight.
                if not first["done"]:
                    first["done"] = True
                    entered.set()
                    release.wait(5)
                real_write(data)

            registry._write_snapshot_to_disk = barriered_write

            save_thread = threading.Thread(target=registry._save_instances)
            save_thread.start()
            self.assertTrue(entered.wait(5))  # save holds _persist_lock, mid-write

            rot = {}

            def do_rotate():
                rot["r"] = registry.rotate_token(old)

            rt = threading.Thread(target=do_rotate)
            rt.start()
            # The rotation must block on _persist_lock while the save writes.
            rt.join(0.5)
            self.assertTrue(rt.is_alive(), "rotation must wait for the in-flight save")

            release.set()
            save_thread.join(5)
            rt.join(5)

            self.assertIsInstance(rot["r"], dict)
            new = rot["r"]["token"]
            # The rotation's newer write is the durable one — not clobbered by the save.
            reloaded = _registry(tmp)
            self.assertEqual("claude", reloaded.resolve_token(new)["name"])
            self.assertIsNone(reloaded.resolve_token(old))

    def test_concurrent_rotations_do_not_lose_the_last_write(self):
        # id1097 B2 snapshot-race: rotate A, then rotate B with A's new token;
        # after a restart B's token (the last durable write) must be the live one,
        # never a stale earlier snapshot.
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            t0 = registry.register("claude")["token"]
            t1 = registry.rotate_token(t0)["token"]
            t2 = registry.rotate_token(t1)["token"]

            reloaded = _registry(tmp)
            self.assertEqual("claude", reloaded.resolve_token(t2)["name"])
            self.assertIsNone(reloaded.resolve_token(t0))
            self.assertIsNone(reloaded.resolve_token(t1))

    def test_second_rotation_with_the_old_token_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            old = registry.register("claude")["token"]
            first = registry.rotate_token(old)

            self.assertIsInstance(first, dict)
            self.assertIsNone(registry.rotate_token(old))

    def test_reclaimable_token_is_not_rotatable_and_not_reactivated(self):
        # Kills the resolve_token-style reactivation mutant.
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            token = registry.register("claude")["token"]
            self.assertIsNotNone(registry.deregister("claude"))

            self.assertIsNone(registry.rotate_token(token))
            self.assertFalse(registry.is_registered("claude"))
            self.assertEqual("claude", registry.resolve_token(token)["name"])

    def test_pending_instance_is_not_rotatable(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            token = registry.register("claude")["token"]
            with registry._lock:
                registry._instances["claude"].state = "pending"
            self.assertIsNone(registry.rotate_token(token))

    def test_unknown_token_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = _registry(tmp)
            registry.register("claude")
            self.assertIsNone(registry.rotate_token("f" * 32))
            self.assertIsNone(registry.rotate_token(""))


# --------------------------------------------------------------------------- #
# Real ASGI endpoint through the security middleware (id1098 E1/E2/E3)
# --------------------------------------------------------------------------- #
class RotateTokenAsgiTests(unittest.TestCase):
    def setUp(self):
        from starlette.testclient import TestClient

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = _registry(self.tmp.name)

        self._saved = {k: getattr(app, k) for k in ("registry",)}
        app.registry = self.registry
        # Install the real security middleware with a known session token so the
        # bearer path and the session-token fallback are both exercised. The app
        # may already have a built stack (a prior TestClient); reset it so
        # add_middleware is allowed, then let TestClient rebuild.
        self._saved_mw = app.app.user_middleware[:]
        app.app.middleware_stack = None
        app._install_security_middleware(
            "SESSION-TOKEN", {"server": {"allowed_origins": []}}
        )

        def _restore():
            app.registry = self._saved["registry"]
            app.app.user_middleware[:] = self._saved_mw
            app.app.middleware_stack = None

        self.addCleanup(_restore)
        self.client = TestClient(app.app)

    def _post(self, name, headers=None):
        return self.client.post(f"/api/rotate-token/{name}", headers=headers or {})

    def test_no_auth_is_normative_403_through_real_middleware(self):
        # id1098 E1: with no bearer, the middleware session-token check 403s
        # before the handler. Assert the real ASGI status, not the direct call.
        r = self._post("claude")
        self.assertEqual(403, r.status_code)
        # No credential VALUE is minted or echoed on the no-auth path.
        self.assertNotIn('"token":', r.text)

    def test_valid_rotation_returns_exact_shape_once(self):
        # id1098 E3: body is EXACTLY {"name","token"} — kills a mutant that adds
        # old_token or any extra key to the response.
        old = self.registry.register("claude")["token"]
        r = self._post("claude", {"Authorization": f"Bearer {old}"})
        self.assertEqual(200, r.status_code)
        body = r.json()
        self.assertEqual({"name", "token"}, set(body.keys()))
        self.assertEqual("claude", body["name"])
        self.assertNotEqual(old, body["token"])
        self.assertNotIn(old, r.text)  # retired token never echoed
        self.assertIsNone(self.registry.resolve_token(old))

    def test_retired_token_is_normative_403_on_exact_messages_probe(self):
        """Pin the status consumed by the rolling-restart helper.

        Security middleware rejects the retired bearer before `/api/messages`
        is dispatched, so this is 403 (not an endpoint-level 409).
        """
        old = self.registry.register("claude")["token"]
        rotated = self._post("claude", {"Authorization": f"Bearer {old}"})
        self.assertEqual(200, rotated.status_code)

        response = self.client.get(
            "/api/messages?limit=1&channel=general",
            headers={"Authorization": f"Bearer {old}"},
        )

        self.assertEqual(403, response.status_code)
        self.assertNotIn(old, response.text)
        self.assertNotIn(rotated.json()["token"], response.text)

    def test_bad_bearer_is_403_and_token_free(self):
        # id1142#3: 403 body must carry no credential — kills a mutant that echoes
        # the presented bearer (or any token) back in the response body.
        bad = "0" * 32
        live = self.registry.register("claude")["token"]
        r = self._post("claude", {"Authorization": f"Bearer {bad}"})
        self.assertEqual(403, r.status_code)
        self.assertNotIn('"token"', r.text)
        self.assertNotIn(bad, r.text)
        self.assertNotIn(live, r.text)

    def test_reclaimable_token_via_asgi_does_not_reactivate(self):
        # id1098 E2 runtime pin: a reclaimable (deregistered) token driven through
        # the real middleware+endpoint must 403 AND leave the identity dormant. A
        # mutant that calls resolve_token before the middleware bypass would
        # reactivate it here (and mint on rotate) — this catches it at runtime.
        token = self.registry.register("claude")["token"]
        self.registry.deregister("claude")

        r = self._post("claude", {"Authorization": f"Bearer {token}"})

        self.assertEqual(403, r.status_code)
        self.assertFalse(self.registry.is_registered("claude"))

    def test_path_name_spoof_is_ignored_identity_from_token(self):
        # id1076: rotating A's token via B's path segment rotates A, not B.
        self.registry.seed({"codex": {"label": "Codex", "color": "#10a37f"}})
        claude_token = self.registry.register("claude")["token"]
        codex_token = self.registry.register("codex")["token"]

        r = self._post("codex", {"Authorization": f"Bearer {claude_token}"})

        self.assertEqual(200, r.status_code)
        self.assertEqual("claude", r.json()["name"])
        self.assertIsNone(self.registry.resolve_token(claude_token))
        self.assertEqual("codex", self.registry.resolve_token(codex_token)["name"])

    def test_persist_failure_is_token_free_500(self):
        # id1097 B1 at the endpoint: durable-write failure surfaces a generic 500
        # with no token in the body.
        old = self.registry.register("claude")["token"]

        def boom(data):
            raise OSError("synthetic replace failure")

        self.registry._write_snapshot_to_disk = boom
        r = self._post("claude", {"Authorization": f"Bearer {old}"})

        self.assertEqual(500, r.status_code)
        self.assertNotIn(old, r.text)
        self.assertEqual("claude", self.registry.resolve_token(old)["name"])


if __name__ == "__main__":
    unittest.main()
