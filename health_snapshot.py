"""Bounded, privacy-safe service health for localhost monitoring."""

from __future__ import annotations

import ipaddress


HEALTH_SCHEMA = "agentchattr.health"
HEALTH_SCHEMA_VERSION = 1
HEALTH_STATES = frozenset({"healthy", "degraded"})
HEALTH_COUNT_LIMIT = 1000

_HEALTHY = "healthy"
_DEGRADED = "degraded"


def is_loopback_peer(host: object) -> bool:
    """Return true only for a numeric loopback socket peer."""
    if not isinstance(host, str):
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _message_store_health(message_store: object) -> str:
    try:
        if message_store is None:
            return _DEGRADED
        if getattr(message_store, "_write_blocked_reason", None) is not None:
            return _DEGRADED
        last_id = getattr(message_store, "last_id")
        if isinstance(last_id, bool) or not isinstance(last_id, int) or last_id < -1:
            return _DEGRADED
        return _HEALTHY
    except Exception:
        return _DEGRADED


def _bounded_count(value: int) -> tuple[int, bool]:
    if value < 0:
        return 0, True
    if value > HEALTH_COUNT_LIMIT:
        return HEALTH_COUNT_LIMIT, True
    return value, False


def _registry_health(runtime_registry: object) -> tuple[str, dict[str, int]]:
    counts = {
        "registered_instances": 0,
        "active_instances": 0,
        "pending_instances": 0,
    }
    try:
        if runtime_registry is None:
            return _DEGRADED, counts
        instances = runtime_registry.get_all()
        if not isinstance(instances, dict):
            return _DEGRADED, counts

        active = 0
        pending = 0
        valid = True
        for instance in instances.values():
            if not isinstance(instance, dict):
                valid = False
                continue
            state = instance.get("state")
            if state == "active":
                active += 1
            elif state == "pending":
                pending += 1
            else:
                valid = False

        bounded = False
        for key, value in (
            ("registered_instances", len(instances)),
            ("active_instances", active),
            ("pending_instances", pending),
        ):
            counts[key], was_bounded = _bounded_count(value)
            bounded = bounded or was_bounded

        state = _HEALTHY if valid and not bounded else _DEGRADED
        return state, counts
    except Exception:
        return _DEGRADED, counts


def _migration_lease_health(migration_lease_store: object) -> str:
    try:
        if migration_lease_store is None:
            return _DEGRADED
        return _HEALTHY if migration_lease_store.healthy is True else _DEGRADED
    except Exception:
        return _DEGRADED


def degraded_health_snapshot() -> dict:
    """Return the fixed fail-safe envelope without inspecting components."""
    return {
        "schema": HEALTH_SCHEMA,
        "schema_version": HEALTH_SCHEMA_VERSION,
        "status": _DEGRADED,
        "components": {
            "message_store": _DEGRADED,
            "runtime_registry": _DEGRADED,
            "migration_leases": _DEGRADED,
        },
        "counts": {
            "registered_instances": 0,
            "active_instances": 0,
            "pending_instances": 0,
        },
        "count_limit": HEALTH_COUNT_LIMIT,
    }


def build_health_snapshot(
    message_store: object,
    runtime_registry: object,
    migration_lease_store: object,
) -> dict:
    """Inspect fixed components without exposing their values or failures."""
    registry_state, counts = _registry_health(runtime_registry)
    components = {
        "message_store": _message_store_health(message_store),
        "runtime_registry": registry_state,
        "migration_leases": _migration_lease_health(migration_lease_store),
    }
    status = (
        _HEALTHY
        if all(state == _HEALTHY for state in components.values())
        else _DEGRADED
    )
    return {
        "schema": HEALTH_SCHEMA,
        "schema_version": HEALTH_SCHEMA_VERSION,
        "status": status,
        "components": components,
        "counts": counts,
        "count_limit": HEALTH_COUNT_LIMIT,
    }
