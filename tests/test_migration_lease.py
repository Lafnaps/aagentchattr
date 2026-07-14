"""Crash-safety and fail-closed tests for wrapper migration leases."""

import asyncio
import copy
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app
from migration_lease import (
    LEASE_TTL_MAX,
    LEASE_TTL_MIN,
    RECOVERY_PROTECTION_TTL,
    TOMBSTONE_TTL,
    MigrationLeaseError,
    MigrationLeaseStore,
)
from registry import Instance, RuntimeRegistry


class Clock:
    def __init__(self, value=1_800_000_000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeRequest:
    def __init__(self, token="", body=None, raw=None, content_length=None):
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        if content_length is not None:
            self.headers["content-length"] = str(content_length)
        if raw is None and body is not None:
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
        elif isinstance(raw, str):
            raw = raw.encode("utf-8")
        self._raw = raw

    async def stream(self):
        if self._raw is None:
            raise ValueError("no body")
        yield self._raw


class LeaseFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()
        self.store = MigrationLeaseStore(self.tmp.name, clock=self.clock)
        self.registry = RuntimeRegistry(self.tmp.name)
        self.registry.seed({
            "claude": {"label": "Claude", "color": "#da7756"},
            "codex": {"label": "Codex", "color": "#10a37f"},
        })
        self.registry.attach_migration_leases(self.store)

    def register(self, base="claude"):
        result = self.registry.register(base)
        self.assertIsInstance(result, dict)
        return result

    def exact(self, token):
        result = self.registry.resolve_token(token)
        self.assertIsNotNone(result)
        return {key: result[key] for key in ("name", "base", "slot", "identity_id", "epoch")}

    def body(self, token, nonce="a" * 32, lease_id="b" * 32, ttl=900):
        return {
            **self.exact(token),
            "lease_nonce": nonce,
            "lease_id": lease_id,
            "ttl_seconds": ttl,
        }

    def acquire(self, token, **kwargs):
        body = self.body(token, **kwargs)
        return self.store.acquire(self.registry, token, body), body

    @staticmethod
    def release_body(body):
        result = dict(body)
        result.pop("ttl_seconds")
        return result


class MigrationLeaseLifecycleTests(LeaseFixture):
    def test_acquire_response_loss_retry_is_exactly_idempotent_and_token_free_on_disk(self):
        inst = self.register()
        first, body = self.acquire(inst["token"])
        on_disk = (Path(self.tmp.name) / "migration_leases.json").read_text("ascii")
        second = self.store.acquire(self.registry, inst["token"], body)

        self.assertEqual(first, second)
        self.assertEqual("held", first["state"])
        self.assertEqual(set(first), {
            "ok", "name", "base", "slot", "identity_id", "epoch",
            "lease_nonce", "lease_id", "expires_at", "state",
            "route_fingerprint", "family_fingerprint",
        })
        self.assertNotIn(inst["token"], on_disk)
        self.assertNotIn(body["lease_nonce"], on_disk)
        self.assertIn(body["lease_id"], on_disk)

    def test_restart_restores_exact_live_identity_and_durable_route(self):
        inst = self.register()
        renamed = self.registry.rename("claude", "claude-profile", "Profile")
        self.assertIsInstance(renamed, dict)
        body = self.body(inst["token"])
        acquired = self.store.acquire(self.registry, inst["token"], body)
        route_before = dict(self.registry._renames)
        self.assertFalse(self.registry.clean_renames_for("claude"))
        self.assertEqual(route_before, self.registry._renames)

        restarted_store = MigrationLeaseStore(self.tmp.name, clock=self.clock)
        restarted_registry = RuntimeRegistry(self.tmp.name)
        restarted_registry.seed({"claude": {"label": "Claude", "color": "#da7756"}})
        restarted_registry.attach_migration_leases(restarted_store)
        restored = restarted_store.reconcile_registry(restarted_registry)

        self.assertEqual(["claude-profile"], restored)
        exact = restarted_registry.get_instance("claude-profile")
        self.assertEqual(body["identity_id"], exact["identity_id"])
        self.assertEqual(body["epoch"], exact["epoch"])
        self.assertEqual("active", exact["state"])
        self.assertEqual("claude-profile", restarted_registry.resolve_name("claude"))
        self.assertIsInstance(restarted_registry.register("claude"), str)
        status = restarted_store.status(restarted_registry, inst["token"], body["lease_nonce"])
        self.assertEqual(acquired["route_fingerprint"], status["route_fingerprint"])

    def test_restart_restores_entire_same_family_live_snapshot(self):
        first = self.register()
        second = self.register()
        body = self.body(first["token"])
        self.store.acquire(self.registry, first["token"], body)
        live_before = set(self.registry.get_all_names())

        restarted_store = MigrationLeaseStore(self.tmp.name, clock=self.clock)
        restarted_registry = RuntimeRegistry(self.tmp.name)
        restarted_registry.seed({"claude": {"label": "Claude", "color": "#da7756"}})
        restarted_registry.attach_migration_leases(restarted_store)
        restored = restarted_store.reconcile_registry(restarted_registry)

        self.assertEqual(live_before, set(restored))
        self.assertEqual(live_before, set(restarted_registry.get_all_names()))
        self.assertIsNotNone(restarted_registry.resolve_token(second["token"]))
        status = restarted_store.status(
            restarted_registry, first["token"], body["lease_nonce"]
        )
        self.assertEqual("held", status["state"])

    def test_restart_after_ttl_restores_protected_family_route_and_exact_token(self):
        inst = self.register()
        self.assertIsInstance(
            self.registry.rename("claude", "claude-profile", "Profile"), dict
        )
        acquired, body = self.acquire(inst["token"], ttl=LEASE_TTL_MIN)
        self.clock.advance(LEASE_TTL_MIN + 1)

        restarted_store = MigrationLeaseStore(self.tmp.name, clock=self.clock)
        restarted_registry = RuntimeRegistry(self.tmp.name)
        restarted_registry.seed({
            "claude": {"label": "Claude", "color": "#da7756"},
        })
        restarted_registry.attach_migration_leases(restarted_store)
        self.assertNotIn("claude-profile", restarted_registry._instances)
        self.assertIn("claude-profile", restarted_registry._reclaimable)

        restored = restarted_store.reconcile_registry(restarted_registry)

        self.assertEqual(["claude-profile"], restored)
        self.assertEqual(
            body["identity_id"],
            restarted_registry.resolve_token(inst["token"])["identity_id"],
        )
        self.assertEqual("claude-profile", restarted_registry.resolve_name("claude"))
        blocked = restarted_registry.deregister("claude-profile")
        self.assertEqual("migration_lease_active", blocked["error"])
        self.assertFalse(restarted_registry.clean_renames_for("claude"))
        with self.assertRaises(MigrationLeaseError) as expired:
            restarted_store.status(
                restarted_registry, inst["token"], body["lease_nonce"]
            )
        self.assertEqual(409, expired.exception.status_code)

        revived = restarted_store.acquire(
            restarted_registry, inst["token"], body
        )
        self.assertEqual(acquired["route_fingerprint"], revived["route_fingerprint"])
        self.assertEqual(acquired["family_fingerprint"], revived["family_fingerprint"])
        self.assertGreater(revived["expires_at"], int(self.clock.value))

    def test_expired_lease_protects_timeout_and_route_until_fixed_horizon(self):
        inst = self.register()
        self.assertIsInstance(
            self.registry.rename("claude", "claude-profile", "Profile"), dict
        )
        _acquired, body = self.acquire(inst["token"], ttl=LEASE_TTL_MIN)
        self.clock.advance(16)

        blocked = self.registry.deregister("claude-profile")
        self.assertEqual({"ok": False, "error": "migration_lease_active"}, blocked)
        self.assertIsNotNone(self.registry.get_instance("claude-profile"))
        self.assertFalse(self.registry.clean_renames_for("claude"))

        self.clock.advance(LEASE_TTL_MIN)
        with self.assertRaises(MigrationLeaseError) as expired:
            self.store.status(self.registry, inst["token"], body["lease_nonce"])
        self.assertEqual(409, expired.exception.status_code)
        still_blocked = self.registry.deregister("claude-profile")
        self.assertEqual("migration_lease_active", still_blocked["error"])
        self.assertEqual("migration_lease_active", self.registry.register("claude"))
        self.assertEqual(
            "migration_lease_active",
            self.registry.rename("claude-profile", "claude-other"),
        )

        created_at = next(iter(self.store._records.values()))["created_at"]
        self.clock.value = created_at + RECOVERY_PROTECTION_TTL
        removed = self.registry.deregister("claude-profile")
        self.assertTrue(removed["ok"])
        self.assertIsNone(self.registry.get_instance("claude-profile"))
        self.assertTrue(self.registry.clean_renames_for("claude"))

    def test_rotation_preserves_binding_and_only_new_exact_token_renews_and_releases(self):
        inst = self.register()
        _acquired, body = self.acquire(inst["token"])
        rotated = self.registry.rotate_token(inst["token"])
        self.assertIsInstance(rotated, dict)

        with self.assertRaises(MigrationLeaseError) as stale:
            self.store.renew(self.registry, inst["token"], body)
        self.assertEqual(403, stale.exception.status_code)

        self.clock.advance(10)
        renewed = self.store.renew(self.registry, rotated["token"], body)
        self.assertEqual(self.clock.value + body["ttl_seconds"], renewed["expires_at"])
        released = self.store.release(
            self.registry, rotated["token"], self.release_body(body)
        )
        self.assertTrue(released["released"])
        self.assertEqual("released", released["state"])
        self.assertEqual(0, released["expires_at"])

    def test_release_retry_and_status_survive_restart_via_bounded_tombstone(self):
        inst = self.register()
        _acquired, body = self.acquire(inst["token"])
        release_body = self.release_body(body)
        first = self.store.release(self.registry, inst["token"], release_body)
        self.assertTrue(first["released"])

        restarted_store = MigrationLeaseStore(self.tmp.name, clock=self.clock)
        restarted_registry = RuntimeRegistry(self.tmp.name)
        restarted_registry.seed({"claude": {"label": "Claude", "color": "#da7756"}})
        restarted_registry.attach_migration_leases(restarted_store)
        self.assertEqual([], restarted_store.reconcile_registry(restarted_registry))

        status = restarted_store.status(
            restarted_registry, inst["token"], body["lease_nonce"]
        )
        retry = restarted_store.release(
            restarted_registry, inst["token"], release_body
        )
        self.assertEqual("released", status["state"])
        self.assertFalse(retry["released"])
        self.assertEqual(0, retry["expires_at"])

        self.clock.advance(TOMBSTONE_TTL + 1)
        path = Path(self.tmp.name) / "migration_leases.json"
        before = path.read_bytes()
        expired_tombstone = restarted_store.release(
            restarted_registry, inst["token"], release_body
        )
        self.assertFalse(expired_tombstone["released"])
        self.assertEqual("released", expired_tombstone["state"])
        self.assertEqual(before, path.read_bytes())
        with self.assertRaises(MigrationLeaseError) as absent_status:
            restarted_store.status(
                restarted_registry, inst["token"], body["lease_nonce"]
            )
        self.assertEqual(404, absent_status.exception.status_code)

    def test_same_ids_recover_unobserved_or_held_acquire_after_ttl(self):
        inst = self.register()
        first, body = self.acquire(
            inst["token"], ttl=LEASE_TTL_MIN
        )
        nonce_hash = hashlib.sha256(body["lease_nonce"].encode("ascii")).hexdigest()
        original = copy.deepcopy(self.store._records[nonce_hash])
        self.clock.advance(LEASE_TTL_MIN + 1)

        revived = self.store.acquire(self.registry, inst["token"], body)

        current = self.store._records[nonce_hash]
        self.assertEqual("held", revived["state"])
        self.assertEqual(int(self.clock.value) + LEASE_TTL_MIN, revived["expires_at"])
        self.assertEqual(first["route_fingerprint"], revived["route_fingerprint"])
        self.assertEqual(first["family_fingerprint"], revived["family_fingerprint"])
        self.assertEqual(original["created_at"], current["created_at"])
        self.assertEqual(int(self.clock.value), current["updated_at"])
        self.assertEqual(original["family_snapshot"], current["family_snapshot"])
        self.assertEqual(original["route_snapshot"], current["route_snapshot"])
        self.assertEqual(1, len(self.store._records))

    def test_active_revive_crossing_horizon_stays_protected_only_until_expiry(self):
        inst = self.register()
        _first, body = self.acquire(inst["token"], ttl=LEASE_TTL_MIN)
        nonce_hash = hashlib.sha256(body["lease_nonce"].encode("ascii")).hexdigest()
        created_at = self.store._records[nonce_hash]["created_at"]
        self.clock.value = created_at + RECOVERY_PROTECTION_TTL - 60

        revived = self.store.acquire(self.registry, inst["token"], body)
        self.assertEqual(created_at, self.store._records[nonce_hash]["created_at"])
        self.assertGreater(
            revived["expires_at"], created_at + RECOVERY_PROTECTION_TTL
        )
        self.clock.advance(10)
        renewed = self.store.renew(self.registry, inst["token"], body)
        self.assertEqual(created_at, self.store._records[nonce_hash]["created_at"])
        self.assertGreater(renewed["expires_at"], revived["expires_at"])

        self.clock.value = created_at + RECOVERY_PROTECTION_TTL + 1
        blocked = self.registry.deregister("claude")
        self.assertEqual("migration_lease_active", blocked["error"])
        self.clock.value = renewed["expires_at"] + 1
        self.assertTrue(self.registry.deregister("claude")["ok"])

    def test_same_ids_after_prune_are_a_fully_validated_fresh_acquire(self):
        inst = self.register()
        _first, body = self.acquire(inst["token"], ttl=LEASE_TTL_MIN)
        nonce_hash = hashlib.sha256(body["lease_nonce"].encode("ascii")).hexdigest()
        created_at = self.store._records[nonce_hash]["created_at"]
        self.clock.advance(RECOVERY_PROTECTION_TTL + 1)

        reacquired = self.store.acquire(self.registry, inst["token"], body)

        self.assertEqual("held", reacquired["state"])
        self.assertGreater(self.store._records[nonce_hash]["created_at"], created_at)
        self.assertEqual(int(self.clock.value), self.store._records[nonce_hash]["created_at"])
        self.assertEqual(1, len(self.store._records))

    def test_expired_reacquire_rejects_snapshot_drift_and_binding_mismatch(self):
        inst = self.register()
        _first, body = self.acquire(inst["token"], ttl=LEASE_TTL_MIN)
        nonce_hash = hashlib.sha256(body["lease_nonce"].encode("ascii")).hexdigest()
        original = copy.deepcopy(self.store._records[nonce_hash])
        self.clock.advance(LEASE_TTL_MIN + 1)

        wrong_id = dict(body)
        wrong_id["lease_id"] = "c" * 32
        with self.assertRaises(MigrationLeaseError) as mismatch:
            self.store.acquire(self.registry, inst["token"], wrong_id)
        self.assertEqual(409, mismatch.exception.status_code)

        with self.registry._lock:
            self.registry._renames["claude-old"] = "claude"
        with self.assertRaises(MigrationLeaseError) as drift:
            self.store.acquire(self.registry, inst["token"], body)
        self.assertEqual(409, drift.exception.status_code)
        self.assertEqual(original, self.store._records[nonce_hash])

    def test_expired_protection_rejects_other_nonce_then_allows_exact_revival(self):
        first = self.register()
        second = self.register()
        first_body = self.body(
            first["token"], nonce="a" * 32, lease_id="b" * 32,
            ttl=LEASE_TTL_MIN,
        )
        second_body = self.body(
            second["token"], nonce="c" * 32, lease_id="d" * 32,
            ttl=LEASE_TTL_MIN,
        )
        self.store.acquire(self.registry, first["token"], first_body)
        self.clock.advance(LEASE_TTL_MIN + 1)

        with self.assertRaises(MigrationLeaseError) as conflict:
            self.store.acquire(self.registry, second["token"], second_body)
        self.assertEqual(409, conflict.exception.status_code)
        revived = self.store.acquire(self.registry, first["token"], first_body)
        self.assertEqual("held", revived["state"])
        self.assertGreater(revived["expires_at"], int(self.clock.value))

    def test_expired_revival_repersists_registry_and_rolls_back_lease_failure(self):
        inst = self.register()
        _first, body = self.acquire(inst["token"], ttl=LEASE_TTL_MIN)
        nonce_hash = hashlib.sha256(body["lease_nonce"].encode("ascii")).hexdigest()
        original = copy.deepcopy(self.store._records[nonce_hash])
        path = Path(self.tmp.name) / "migration_leases.json"
        original_disk = path.read_bytes()
        self.clock.advance(LEASE_TTL_MIN + 1)
        calls = {"registry": 0, "renames": 0}
        real_registry_write = self.registry._write_snapshot_to_disk
        real_renames_write = self.registry._write_renames_snapshot_to_disk
        real_lease_write = self.store._write_strict_locked

        def registry_write(data):
            calls["registry"] += 1
            return real_registry_write(data)

        def renames_write(data):
            calls["renames"] += 1
            return real_renames_write(data)

        def fail_lease_write():
            raise MigrationLeaseError(500, "synthetic lease persistence failure")

        self.registry._write_snapshot_to_disk = registry_write
        self.registry._write_renames_snapshot_to_disk = renames_write
        self.store._write_strict_locked = fail_lease_write
        try:
            with self.assertRaises(MigrationLeaseError) as failed:
                self.store.acquire(self.registry, inst["token"], body)
            self.assertEqual(500, failed.exception.status_code)
        finally:
            self.registry._write_snapshot_to_disk = real_registry_write
            self.registry._write_renames_snapshot_to_disk = real_renames_write
            self.store._write_strict_locked = real_lease_write

        self.assertEqual({"registry": 1, "renames": 1}, calls)
        self.assertEqual(original, self.store._records[nonce_hash])
        self.assertEqual(original_disk, path.read_bytes())

    def test_expired_existing_release_accepts_reclaimable_exact_owner(self):
        inst = self.register()
        first, body = self.acquire(inst["token"], ttl=LEASE_TTL_MIN)
        self.clock.advance(RECOVERY_PROTECTION_TTL + 1)
        self.assertTrue(self.registry.deregister("claude")["ok"])

        released = self.store.release(
            self.registry, inst["token"], self.release_body(body)
        )

        self.assertTrue(released["released"])
        self.assertEqual("released", released["state"])
        self.assertEqual(0, released["expires_at"])
        self.assertEqual(first["route_fingerprint"], released["route_fingerprint"])
        self.assertEqual(first["family_fingerprint"], released["family_fingerprint"])
        status = self.store.status(
            self.registry, inst["token"], body["lease_nonce"]
        )
        self.assertEqual("released", status["state"])

    def test_expired_existing_release_rolls_back_persistence_failure(self):
        inst = self.register()
        _first, body = self.acquire(inst["token"], ttl=LEASE_TTL_MIN)
        nonce_hash = hashlib.sha256(body["lease_nonce"].encode("ascii")).hexdigest()
        original = copy.deepcopy(self.store._records[nonce_hash])
        path = Path(self.tmp.name) / "migration_leases.json"
        original_disk = path.read_bytes()
        self.clock.advance(LEASE_TTL_MIN + 1)
        real_write = self.store._write_strict_locked

        def fail_write():
            raise MigrationLeaseError(500, "synthetic release persistence failure")

        self.store._write_strict_locked = fail_write
        try:
            with self.assertRaises(MigrationLeaseError) as failed:
                self.store.release(
                    self.registry, inst["token"], self.release_body(body)
                )
            self.assertEqual(500, failed.exception.status_code)
        finally:
            self.store._write_strict_locked = real_write

        self.assertEqual(original, self.store._records[nonce_hash])
        self.assertEqual(original_disk, path.read_bytes())

    def test_pruned_release_is_repeatable_noop_and_rejects_conflicts(self):
        claude = self.register()
        _first, body = self.acquire(
            claude["token"], nonce="a" * 32, lease_id="b" * 32,
            ttl=LEASE_TTL_MIN,
        )
        self.clock.advance(RECOVERY_PROTECTION_TTL + 1)
        self.assertTrue(self.registry.deregister("claude")["ok"])

        codex = self.register("codex")
        codex_body = self.body(
            codex["token"], nonce="c" * 32, lease_id="d" * 32,
        )
        self.store.acquire(self.registry, codex["token"], codex_body)
        nonce_hash = hashlib.sha256(body["lease_nonce"].encode("ascii")).hexdigest()
        self.assertNotIn(nonce_hash, self.store._records)
        path = Path(self.tmp.name) / "migration_leases.json"
        before_disk = path.read_bytes()
        before_records = copy.deepcopy(self.store._records)

        first = self.store.release(
            self.registry, claude["token"], self.release_body(body)
        )
        second = self.store.release(
            self.registry, claude["token"], self.release_body(body)
        )
        self.assertEqual(first, second)
        self.assertFalse(first["released"])
        self.assertEqual("released", first["state"])
        self.assertEqual(before_records, self.store._records)
        self.assertEqual(before_disk, path.read_bytes())

        wrong_nonce = self.release_body(body)
        wrong_nonce["lease_id"] = codex_body["lease_id"]
        with self.assertRaises(MigrationLeaseError) as mismatch:
            self.store.release(self.registry, claude["token"], wrong_nonce)
        self.assertEqual(409, mismatch.exception.status_code)

        conflicting = self.release_body(codex_body)
        conflicting["lease_nonce"] = "e" * 32
        conflicting["lease_id"] = "f" * 32
        with self.assertRaises(MigrationLeaseError) as active:
            self.store.release(self.registry, codex["token"], conflicting)
        self.assertEqual(409, active.exception.status_code)

    def test_ttl_is_strictly_bounded(self):
        inst = self.register()
        for ttl in (LEASE_TTL_MIN - 1, LEASE_TTL_MAX + 1, True, 900.0):
            with self.subTest(ttl=ttl):
                with self.assertRaises(MigrationLeaseError) as caught:
                    self.store.acquire(
                        self.registry, inst["token"], self.body(inst["token"], ttl=ttl)
                    )
                self.assertEqual(400, caught.exception.status_code)

    def test_pending_and_reclaimable_credentials_cannot_acquire(self):
        pending = self.register()
        with self.registry._lock:
            self.registry._instances["claude"].state = "pending"
        with self.assertRaises(MigrationLeaseError) as pending_error:
            self.store.acquire(
                self.registry, pending["token"], self.body(pending["token"])
            )
        self.assertEqual(403, pending_error.exception.status_code)

        with self.registry._lock:
            self.registry._instances["claude"].state = "active"
        self.registry.deregister("claude")
        exact = {
            key: pending[key]
            for key in ("name", "base", "slot", "identity_id", "epoch")
        }
        reclaim_body = {
            **exact, "lease_nonce": "c" * 32, "lease_id": "d" * 32,
            "ttl_seconds": 900,
        }
        with self.assertRaises(MigrationLeaseError) as reclaim_error:
            self.store.acquire(self.registry, pending["token"], reclaim_body)
        self.assertEqual(403, reclaim_error.exception.status_code)


class MigrationLeaseConflictTests(LeaseFixture):
    def test_held_family_blocks_dormant_sibling_reactivation_and_claim(self):
        survivor = self.register()
        sibling = self.register()
        sibling_name = self.exact(sibling["token"])["name"]
        self.assertTrue(self.registry.deregister(sibling_name)["ok"])
        survivor_body = self.body(survivor["token"])
        self.store.acquire(self.registry, survivor["token"], survivor_body)

        self.assertIsNone(self.registry.resolve_token(sibling["token"]))
        self.assertEqual(
            "migration_lease_active", self.registry.claim(sibling_name, sibling_name)
        )
        self.assertIsNone(self.registry.get_instance(sibling_name))
        self.store.status(
            self.registry, survivor["token"], survivor_body["lease_nonce"]
        )

    def test_family_lease_rejects_sibling_acquire_register_deregister_and_rename(self):
        first = self.register()
        second = self.register()
        first_body = self.body(first["token"])
        self.store.acquire(self.registry, first["token"], first_body)
        renames_before = dict(self.registry._renames)

        sibling_body = self.body(
            second["token"], nonce="c" * 32, lease_id="d" * 32
        )
        with self.assertRaises(MigrationLeaseError) as sibling:
            self.store.acquire(self.registry, second["token"], sibling_body)
        self.assertEqual(409, sibling.exception.status_code)
        self.assertIsInstance(self.registry.register("claude"), str)
        self.assertEqual(
            "migration_lease_active",
            self.registry.deregister(self.exact(second["token"])["name"])["error"],
        )
        self.assertIsInstance(
            self.registry.rename(self.exact(second["token"])["name"], "claude-other"),
            str,
        )
        self.assertEqual(renames_before, self.registry._renames)
        self.store.status(self.registry, first["token"], first_body["lease_nonce"])

    def test_other_family_cannot_inject_into_held_rename_route(self):
        owner = self.register("claude")
        other = self.register("codex")
        self.assertIsInstance(self.registry.rename("claude", "mid"), dict)
        self.assertIsInstance(self.registry.rename("mid", "final"), dict)
        body = self.body(owner["token"])
        self.store.acquire(self.registry, owner["token"], body)
        renames_before = dict(self.registry._renames)

        self.assertEqual(
            "migration_lease_route_active",
            self.registry.rename("codex", "mid"),
        )
        self.assertEqual(
            "migration_lease_route_active",
            self.registry.claim("codex", "mid"),
        )
        self.assertEqual(renames_before, self.registry._renames)
        self.assertIsNotNone(self.registry.get_instance("codex"))
        self.store.status(self.registry, owner["token"], body["lease_nonce"])

    def test_wrong_token_identity_epoch_nonce_and_id_fail_closed(self):
        owner = self.register("claude")
        other = self.register("codex")
        body = self.body(owner["token"])

        with self.assertRaises(MigrationLeaseError) as wrong_token:
            self.store.acquire(self.registry, other["token"], body)
        self.assertEqual(409, wrong_token.exception.status_code)

        for field, value in (
            ("name", "claude-wrong"),
            ("base", "codex"),
            ("slot", 2),
            ("identity_id", "f" * 32),
            ("epoch", body["epoch"] + 1),
        ):
            malformed = dict(body)
            malformed[field] = value
            with self.subTest(field=field), self.assertRaises(MigrationLeaseError) as caught:
                self.store.acquire(self.registry, owner["token"], malformed)
            self.assertEqual(409, caught.exception.status_code)

        self.store.acquire(self.registry, owner["token"], body)
        wrong_nonce = dict(body, lease_nonce="c" * 32)
        with self.assertRaises(MigrationLeaseError) as nonce_error:
            self.store.renew(self.registry, owner["token"], wrong_nonce)
        self.assertEqual(409, nonce_error.exception.status_code)
        wrong_id = dict(body, lease_id="d" * 32)
        with self.assertRaises(MigrationLeaseError) as id_error:
            self.store.renew(self.registry, owner["token"], wrong_id)
        self.assertEqual(409, id_error.exception.status_code)

    def test_same_nonce_retry_converges_and_concurrent_distinct_acquire_has_one_winner(self):
        inst = self.register()
        body = self.body(inst["token"])
        barrier = threading.Barrier(3)
        results = []

        def same_worker():
            barrier.wait()
            try:
                results.append(("ok", self.store.acquire(self.registry, inst["token"], body)))
            except MigrationLeaseError as exc:
                results.append(("error", exc.status_code))

        threads = [threading.Thread(target=same_worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(3)
            self.assertFalse(thread.is_alive(), "same-nonce acquire deadlocked")
        self.assertEqual(["ok", "ok"], sorted(item[0] for item in results))
        self.assertEqual(results[0][1], results[1][1])

        # Release and use a fresh fixture identity so two distinct leases race.
        self.store.release(self.registry, inst["token"], self.release_body(body))
        codex = self.register("codex")
        bodies = [
            self.body(codex["token"], nonce="e" * 32, lease_id="1" * 32),
            self.body(codex["token"], nonce="f" * 32, lease_id="2" * 32),
        ]
        barrier2 = threading.Barrier(3)
        outcomes = []

        def distinct_worker(candidate):
            barrier2.wait()
            try:
                self.store.acquire(self.registry, codex["token"], candidate)
                outcomes.append("ok")
            except MigrationLeaseError as exc:
                outcomes.append(f"error-{exc.status_code}")

        threads = [
            threading.Thread(target=distinct_worker, args=(candidate,))
            for candidate in bodies
        ]
        for thread in threads:
            thread.start()
        barrier2.wait()
        for thread in threads:
            thread.join(3)
            self.assertFalse(thread.is_alive(), "distinct acquire deadlocked")
        self.assertEqual(["error-409", "ok"], sorted(outcomes))

    def test_acquire_vs_deregister_is_atomic_and_deadlock_free(self):
        inst = self.register()
        body = self.body(inst["token"])
        barrier = threading.Barrier(3)
        result = {}

        def do_acquire():
            barrier.wait()
            try:
                result["acquire"] = self.store.acquire(
                    self.registry, inst["token"], body
                )["state"]
            except MigrationLeaseError as exc:
                result["acquire"] = exc.status_code

        def do_deregister():
            barrier.wait()
            result["deregister"] = self.registry.deregister("claude")

        threads = [threading.Thread(target=do_acquire), threading.Thread(target=do_deregister)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(3)
            self.assertFalse(thread.is_alive(), "lease/registry lock order deadlocked")

        if result["acquire"] == "held":
            self.assertEqual("migration_lease_active", result["deregister"]["error"])
            self.assertIsNotNone(self.registry.get_instance("claude"))
        else:
            self.assertEqual(403, result["acquire"])
            self.assertTrue(result["deregister"]["ok"])


class MigrationLeaseStoreSafetyTests(unittest.TestCase):
    def _registered_registry(self, root):
        registry = RuntimeRegistry(root)
        registry.seed({"claude": {"label": "Claude", "color": "#da7756"}})
        inst = registry.register("claude")
        return registry, inst

    def test_corrupt_and_torn_stores_freeze_topology_and_surface_503(self):
        for mode in ("corrupt", "torn"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                registry, inst = self._registered_registry(tmp)
                path = Path(tmp) / (
                    "migration_leases.json" if mode == "corrupt" else "migration_leases.tmp"
                )
                path.write_text('{"version":1,"records":', encoding="utf-8")
                store = MigrationLeaseStore(tmp)
                registry.attach_migration_leases(store)

                self.assertFalse(store.healthy)
                self.assertEqual(
                    "migration_lease_store_unhealthy",
                    registry.deregister("claude")["error"],
                )
                self.assertIsInstance(registry.register("claude"), str)
                exact = {key: inst[key] for key in ("name", "base", "slot", "identity_id", "epoch")}
                body = {
                    **exact, "lease_nonce": "a" * 32, "lease_id": "b" * 32,
                    "ttl_seconds": 900,
                }
                with self.assertRaises(MigrationLeaseError) as unhealthy:
                    store.acquire(registry, inst["token"], body)
                self.assertEqual(503, unhealthy.exception.status_code)

    def test_duplicate_key_and_nonfinite_json_are_rejected_strictly(self):
        payloads = (
            '{"version":1,"version":1,"records":{}}',
            '{"version":1,"records":{"x":NaN}}',
        )
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "migration_leases.json").write_text(payload, "utf-8")
                self.assertFalse(MigrationLeaseStore(tmp).healthy)

    def test_structurally_valid_conflicting_protected_records_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = Clock()
            registry, inst = self._registered_registry(tmp)
            store = MigrationLeaseStore(tmp, clock=clock)
            registry.attach_migration_leases(store)
            exact = registry.get_instance("claude")
            body = {
                **{key: exact[key] for key in ("name", "base", "slot", "identity_id", "epoch")},
                "lease_nonce": "a" * 32, "lease_id": "b" * 32,
                "ttl_seconds": 900,
            }
            store.acquire(registry, inst["token"], body)
            path = Path(tmp) / "migration_leases.json"
            payload = json.loads(path.read_text("ascii"))
            original = next(iter(payload["records"].values()))
            nonce = "c" * 32
            duplicate = dict(original)
            duplicate["nonce_hash"] = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            duplicate["lease_id"] = "d" * 32
            payload["records"][duplicate["nonce_hash"]] = duplicate
            path.write_text(json.dumps(payload), "utf-8")
            clock.advance(body["ttl_seconds"] + 1)

            self.assertFalse(MigrationLeaseStore(tmp, clock=clock).healthy)

    def test_registry_or_route_persist_failure_cannot_publish_a_lease(self):
        for writer_name in ("_write_snapshot_to_disk", "_write_renames_snapshot_to_disk"):
            with self.subTest(writer=writer_name), tempfile.TemporaryDirectory() as tmp:
                registry, inst = self._registered_registry(tmp)
                store = MigrationLeaseStore(tmp)
                registry.attach_migration_leases(store)
                exact = registry.get_instance("claude")
                body = {
                    **{key: exact[key] for key in ("name", "base", "slot", "identity_id", "epoch")},
                    "lease_nonce": "a" * 32, "lease_id": "b" * 32,
                    "ttl_seconds": 900,
                }
                original = getattr(registry, writer_name)

                def fail_write(_data):
                    raise OSError("synthetic durable identity failure")

                setattr(registry, writer_name, fail_write)
                try:
                    with self.assertRaises(MigrationLeaseError) as failed:
                        store.acquire(registry, inst["token"], body)
                    self.assertEqual(500, failed.exception.status_code)
                finally:
                    setattr(registry, writer_name, original)

                self.assertEqual({}, store._records)
                self.assertTrue(store.healthy)
                self.assertTrue(registry.deregister("claude")["ok"])

    def test_oversized_family_is_rejected_before_store_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = RuntimeRegistry(tmp)
            registry.seed({"claude": {"label": "Claude", "color": "#da7756"}})
            for slot in range(1, 66):
                name = "claude" if slot == 1 else f"claude-{slot}"
                registry._instances[name] = Instance(
                    name=name, base="claude", slot=slot,
                    label=name, color="#da7756",
                    identity_id=f"{slot:032x}", state="active",
                )
            store = MigrationLeaseStore(tmp)
            registry.attach_migration_leases(store)
            target = registry._instances["claude"]
            body = {
                "name": target.name, "base": target.base, "slot": target.slot,
                "identity_id": target.identity_id, "epoch": target.epoch,
                "lease_nonce": "a" * 32, "lease_id": "b" * 32,
                "ttl_seconds": 900,
            }

            with self.assertRaises(MigrationLeaseError) as bounded:
                store.acquire(registry, target.token, body)
            self.assertEqual(409, bounded.exception.status_code)
            self.assertEqual({}, store._records)
            self.assertFalse((Path(tmp) / "migration_leases.json").exists())

    def test_failed_lease_persist_rolls_back_and_freezes_future_topology(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry, inst = self._registered_registry(tmp)
            store = MigrationLeaseStore(tmp)
            registry.attach_migration_leases(store)
            exact = registry.get_instance("claude")
            body = {
                **{key: exact[key] for key in ("name", "base", "slot", "identity_id", "epoch")},
                "lease_nonce": "a" * 32, "lease_id": "b" * 32,
                "ttl_seconds": 900,
            }

            real_write = store._write_strict_locked

            def fail_write():
                store._mark_unhealthy("synthetic failure")
                raise MigrationLeaseError(500, "migration lease could not be persisted")

            store._write_strict_locked = fail_write
            with self.assertRaises(MigrationLeaseError):
                store.acquire(registry, inst["token"], body)
            store._write_strict_locked = real_write

            self.assertEqual({}, store._records)
            self.assertFalse(store.healthy)
            self.assertEqual(
                "migration_lease_store_unhealthy",
                registry.deregister("claude")["error"],
            )

    def test_attached_empty_store_and_legacy_unattached_registry_have_no_regression(self):
        for attached in (False, True):
            with self.subTest(attached=attached), tempfile.TemporaryDirectory() as tmp:
                registry = RuntimeRegistry(tmp)
                registry.seed({"claude": {"label": "Claude", "color": "#da7756"}})
                if attached:
                    registry.attach_migration_leases(MigrationLeaseStore(tmp))
                first = registry.register("claude")
                second = registry.register("claude")
                self.assertEqual("claude-1", registry.resolve_token(first["token"])["name"])
                self.assertEqual("claude-2", second["name"])
                self.assertTrue(registry.deregister("claude-1")["ok"])
                self.assertEqual("claude", registry.resolve_token(second["token"])["name"])


class MigrationLeaseEndpointTests(LeaseFixture):
    def setUp(self):
        super().setUp()
        self.saved = (app.registry, app.migration_leases)
        app.registry = self.registry
        app.migration_leases = self.store
        self.addCleanup(self._restore)

    def _restore(self):
        app.registry, app.migration_leases = self.saved

    @staticmethod
    def payload(response):
        return json.loads(response.body.decode("utf-8"))

    def test_api_acquire_status_renew_release_and_auth_failures(self):
        inst = self.register()
        body = self.body(inst["token"])

        missing = asyncio.run(app.acquire_migration_lease(FakeRequest(body=body)))
        self.assertEqual(403, missing.status_code)
        non_ascii = asyncio.run(
            app.acquire_migration_lease(FakeRequest("é", body))
        )
        self.assertEqual(403, non_ascii.status_code)
        acquired = asyncio.run(
            app.acquire_migration_lease(FakeRequest(inst["token"], body))
        )
        self.assertEqual(200, acquired.status_code)
        self.assertEqual("held", self.payload(acquired)["state"])
        status = asyncio.run(
            app.migration_lease_status(
                body["lease_nonce"], FakeRequest(inst["token"])
            )
        )
        self.assertEqual(200, status.status_code)
        renewed = asyncio.run(
            app.renew_migration_lease(FakeRequest(inst["token"], body))
        )
        self.assertEqual(200, renewed.status_code)
        released = asyncio.run(
            app.release_migration_lease(
                FakeRequest(inst["token"], self.release_body(body))
            )
        )
        self.assertTrue(self.payload(released)["released"])

    def test_pathological_content_length_is_bounded_before_integer_conversion(self):
        inst = self.register()
        response = asyncio.run(
            app.acquire_migration_lease(
                FakeRequest(
                    inst["token"], self.body(inst["token"]),
                    content_length="0" * 5000,
                )
            )
        )
        self.assertEqual(413, response.status_code)

    def test_real_asgi_middleware_accepts_only_current_bearer_without_echoing_it(self):
        from starlette.testclient import TestClient

        inst = self.register()
        body = self.body(inst["token"])
        saved_middleware = app.app.user_middleware[:]
        app.app.middleware_stack = None
        app._install_security_middleware(
            "SESSION-TOKEN", {"server": {"port": 8300}}
        )
        try:
            with TestClient(app.app) as client:
                missing = client.post("/api/migration-lease/acquire", json=body)
                wrong = client.post(
                    "/api/migration-lease/acquire", json=body,
                    headers={"Authorization": f"Bearer {'f' * 32}"},
                )
                acquired = client.post(
                    "/api/migration-lease/acquire", json=body,
                    headers={"Authorization": f"Bearer {inst['token']}"},
                )
                self.assertEqual(403, missing.status_code)
                self.assertEqual(403, wrong.status_code)
                self.assertEqual(200, acquired.status_code)
                self.assertNotIn(inst["token"], acquired.text)

                rotated = self.registry.rotate_token(inst["token"])
                stale = client.post(
                    "/api/migration-lease/renew", json=body,
                    headers={"Authorization": f"Bearer {inst['token']}"},
                )
                current = client.post(
                    "/api/migration-lease/renew", json=body,
                    headers={"Authorization": f"Bearer {rotated['token']}"},
                )
                self.assertEqual(403, stale.status_code)
                self.assertEqual(200, current.status_code)
                self.assertNotIn(inst["token"], stale.text + current.text)
                self.assertNotIn(rotated["token"], stale.text + current.text)
        finally:
            app.app.user_middleware[:] = saved_middleware
            app.app.middleware_stack = None

    def test_real_asgi_rejects_non_strict_or_oversized_json_before_acquire(self):
        from starlette.testclient import TestClient

        inst = self.register()
        body = self.body(inst["token"])
        encoded = json.dumps(body, separators=(",", ":"))
        duplicate = (
            encoded[:-1] + f',"lease_id":"{"c" * 32}"' + "}"
        ).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {inst['token']}",
            "Content-Type": "application/json",
        }
        saved_middleware = app.app.user_middleware[:]
        app.app.middleware_stack = None
        app._install_security_middleware(
            "SESSION-TOKEN", {"server": {"port": 8300}}
        )
        try:
            with TestClient(app.app) as client:
                responses = [
                    client.post(
                        "/api/migration-lease/acquire", content=duplicate,
                        headers=headers,
                    ),
                    client.post(
                        "/api/migration-lease/acquire",
                        content=encoded.encode("utf-16"), headers=headers,
                    ),
                    client.post(
                        "/api/migration-lease/acquire", content=b"\xff",
                        headers=headers,
                    ),
                    client.post(
                        "/api/migration-lease/acquire",
                        content=json.dumps({**body, "ttl_seconds": float("nan")}),
                        headers=headers,
                    ),
                ]
                self.assertTrue(all(response.status_code == 400 for response in responses))
                oversized = client.post(
                    "/api/migration-lease/acquire",
                    content=b'{"padding":"' + b"x" * 4096 + b'"}',
                    headers=headers,
                )
                self.assertEqual(413, oversized.status_code)

                acquired = client.post(
                    "/api/migration-lease/acquire", json=body, headers=headers,
                )
                self.assertEqual(200, acquired.status_code)
                self.assertEqual("held", acquired.json()["state"])
        finally:
            app.app.user_middleware[:] = saved_middleware
            app.app.middleware_stack = None


if __name__ == "__main__":
    unittest.main()
