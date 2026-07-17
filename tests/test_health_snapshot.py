import asyncio
import json
import unittest

import app
import httpx
from health_snapshot import (
    HEALTH_COUNT_LIMIT,
    HEALTH_SCHEMA,
    HEALTH_SCHEMA_VERSION,
    HEALTH_STATES,
    build_health_snapshot,
)


class HealthyMessageStore:
    _write_blocked_reason = None
    last_id = 17


class HealthyMigrationLeases:
    healthy = True


class FakeRegistry:
    def __init__(self, instances):
        self.instances = instances

    def get_all(self):
        return self.instances


class BrokenComponent:
    def __getattr__(self, _name):
        raise RuntimeError("SECRET raw exception C:\\private\\registry.json")


class HealthSnapshotTests(unittest.TestCase):
    def test_healthy_snapshot_has_exact_fixed_contract(self):
        registry = FakeRegistry({
            "first-secret-name": {"state": "active"},
            "second-secret-name": {"state": "active"},
            "pending-secret-name": {"state": "pending"},
        })

        snapshot = build_health_snapshot(
            HealthyMessageStore(), registry, HealthyMigrationLeases()
        )

        self.assertEqual(
            {
                "schema",
                "schema_version",
                "status",
                "components",
                "counts",
                "count_limit",
            },
            set(snapshot),
        )
        self.assertEqual(HEALTH_SCHEMA, snapshot["schema"])
        self.assertEqual(HEALTH_SCHEMA_VERSION, snapshot["schema_version"])
        self.assertEqual("healthy", snapshot["status"])
        self.assertEqual(
            {
                "message_store": "healthy",
                "runtime_registry": "healthy",
                "migration_leases": "healthy",
            },
            snapshot["components"],
        )
        self.assertEqual(
            {
                "registered_instances": 3,
                "active_instances": 2,
                "pending_instances": 1,
            },
            snapshot["counts"],
        )
        self.assertEqual(HEALTH_COUNT_LIMIT, snapshot["count_limit"])
        self.assertTrue(
            {snapshot["status"], *snapshot["components"].values()}
            <= HEALTH_STATES
        )

    def test_failed_inspection_is_degraded_without_error_detail(self):
        snapshot = build_health_snapshot(
            BrokenComponent(), BrokenComponent(), BrokenComponent()
        )

        self.assertEqual("degraded", snapshot["status"])
        self.assertEqual(
            {"message_store", "runtime_registry", "migration_leases"},
            set(snapshot["components"]),
        )
        self.assertTrue(
            all(state == "degraded" for state in snapshot["components"].values())
        )
        self.assertEqual(
            {
                "registered_instances": 0,
                "active_instances": 0,
                "pending_instances": 0,
            },
            snapshot["counts"],
        )
        serialized = json.dumps(snapshot, sort_keys=True)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("registry.json", serialized)
        self.assertNotIn("raw exception", serialized)

    def test_counts_saturate_at_fixed_bound_and_degrade_registry(self):
        instances = {
            f"private-active-{index}": {"state": "active"}
            for index in range(HEALTH_COUNT_LIMIT + 5)
        }
        instances.update({
            f"private-pending-{index}": {"state": "pending"}
            for index in range(9)
        })

        snapshot = build_health_snapshot(
            HealthyMessageStore(), FakeRegistry(instances), HealthyMigrationLeases()
        )

        self.assertEqual("degraded", snapshot["status"])
        self.assertEqual("degraded", snapshot["components"]["runtime_registry"])
        self.assertEqual(
            {
                "registered_instances": HEALTH_COUNT_LIMIT,
                "active_instances": HEALTH_COUNT_LIMIT,
                "pending_instances": 9,
            },
            snapshot["counts"],
        )
        self.assertTrue(
            all(0 <= value <= HEALTH_COUNT_LIMIT for value in snapshot["counts"].values())
        )

    def test_serialized_output_excludes_identity_content_and_secrets(self):
        forbidden = {
            "name": "PRIVATE-AGENT-NAME",
            "identity_id": "PRIVATE-IDENTITY-ID",
            "message": "PRIVATE-MESSAGE-TEXT",
            "prompt": "PRIVATE-PROMPT",
            "token": "PRIVATE-TOKEN",
            "bearer": "PRIVATE-BEARER",
            "command_line": "PRIVATE-COMMAND-LINE",
            "pid": "PRIVATE-PID",
            "path": "PRIVATE-PATH",
            "hash": "PRIVATE-HASH",
            "revision": "PRIVATE-REVISION",
            "exception": "PRIVATE-EXCEPTION",
        }
        record = {"state": "active", **forbidden}
        snapshot = build_health_snapshot(
            HealthyMessageStore(),
            FakeRegistry({forbidden["name"]: record}),
            HealthyMigrationLeases(),
        )

        serialized = json.dumps(snapshot, sort_keys=True)
        for value in forbidden.values():
            self.assertNotIn(value, serialized)
        self.assertLess(len(serialized), 512)


class HealthRouteTests(unittest.TestCase):
    def setUp(self):
        self.saved_globals = {
            name: getattr(app, name)
            for name in ("store", "registry", "migration_leases")
        }
        app.store = HealthyMessageStore()
        app.registry = FakeRegistry({"private-name": {"state": "active"}})
        app.migration_leases = HealthyMigrationLeases()

        self.saved_middleware = app.app.user_middleware[:]
        app.app.user_middleware[:] = []
        app.app.middleware_stack = None
        app._install_security_middleware(
            "PRIVATE-SESSION-TOKEN", {"server": {"port": 8300}}
        )

    def tearDown(self):
        for name, value in self.saved_globals.items():
            setattr(app, name, value)
        app.app.user_middleware[:] = self.saved_middleware
        app.app.middleware_stack = None

    def request(self, host, headers=None):
        async def send():
            transport = httpx.ASGITransport(
                app=app.app, client=(host, 50000)
            )
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.get("/api/health", headers=headers)

        return asyncio.run(send())

    def test_loopback_route_needs_no_token(self):
        response = self.request("127.0.0.1")

        self.assertEqual(200, response.status_code)
        self.assertEqual("healthy", response.json()["status"])
        self.assertEqual("no-store", response.headers["cache-control"])
        self.assertNotIn("PRIVATE-SESSION-TOKEN", response.text)
        self.assertNotIn("private-name", response.text)

    def test_remote_peer_is_denied_even_with_forwarded_loopback_headers(self):
        headers = {
            "Forwarded": "for=127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
        }
        response = self.request("203.0.113.8", headers=headers)

        self.assertEqual(403, response.status_code)
        self.assertEqual({"error": "forbidden"}, response.json())
        self.assertNotIn("203.0.113.8", response.text)


if __name__ == "__main__":
    unittest.main()
