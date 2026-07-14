"""Durable, bounded wrapper-migration leases.

A lease freezes one exact runtime identity and its family routing topology while a
wrapper is deliberately stopped for repair.  The store never persists bearer
tokens.  Callers supply two independent 128-bit client nonces so a lost HTTP
response can be reconciled without minting a second lease.

Lock order is deliberately strict: ``MigrationLeaseStore._lock`` before the
registry persistence lock (when needed), then ``RuntimeRegistry._lock``.  The
registry uses the same order for every topology mutation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path


LEASE_TTL_MIN = 120
LEASE_TTL_DEFAULT = 900
LEASE_TTL_MAX = 1800
# A durable repair authority lives for one day. An expired held lease keeps its
# exact identity/route protected for the same fixed interval from first acquire.
RECOVERY_PROTECTION_TTL = 86400
TOMBSTONE_TTL = 3600
MAX_RECORDS = 256
MAX_FAMILY_MEMBERS = 64
MAX_ROUTE_EDGES = 256
MAX_STORE_BYTES = 1024 * 1024

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_IDENTITY_KEYS = {"name", "base", "slot", "identity_id", "epoch"}
_FAMILY_MEMBER_KEYS = _IDENTITY_KEYS | {"live", "state"}
_RECORD_KEYS = {
    "state", "name", "base", "slot", "identity_id", "epoch",
    "nonce_hash", "lease_id", "created_at", "updated_at", "expires_at",
    "tombstone_expires_at", "route_fingerprint", "family_fingerprint",
    "family_snapshot", "route_snapshot",
}


class MigrationLeaseError(Exception):
    """Expected request/store error with an HTTP-compatible status."""

    def __init__(self, status_code: int, error: str):
        super().__init__(error)
        self.status_code = status_code
        self.error = error


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _canonical_fingerprint(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class MigrationLeaseStore:
    """Strict JSON lease store plus atomic registry coordination."""

    def __init__(self, data_dir: str | Path, *, clock=None):
        self._lock = threading.RLock()
        self._clock = clock or time.time
        self._path = Path(data_dir) / "migration_leases.json"
        self._tmp_path = self._path.with_suffix(".tmp")
        self._records: dict[str, dict] = {}
        self._healthy = True
        self._health_error = ""
        self._load_strict()

    @property
    def healthy(self) -> bool:
        with self._lock:
            return self._healthy

    @property
    def health_error(self) -> str:
        with self._lock:
            return self._health_error

    @contextmanager
    def locked(self):
        with self._lock:
            yield self

    def _mark_unhealthy(self, reason: str):
        self._healthy = False
        self._health_error = reason

    def _load_strict(self):
        with self._lock:
            if self._tmp_path.exists():
                self._mark_unhealthy("torn migration lease store")
                return
            if not self._path.exists():
                return
            try:
                raw = self._path.read_bytes()
                if len(raw) > MAX_STORE_BYTES:
                    raise ValueError("migration lease store is too large")
                data = json.loads(
                    raw.decode("utf-8"), object_pairs_hook=_strict_object,
                    parse_constant=_reject_constant,
                )
                if not isinstance(data, dict) or set(data) != {"version", "records"}:
                    raise ValueError("invalid migration lease store envelope")
                if data["version"] != 1 or not isinstance(data["records"], dict):
                    raise ValueError("unsupported migration lease store version")
                if len(data["records"]) > MAX_RECORDS:
                    raise ValueError("migration lease store exceeds record bound")
                loaded = {}
                for key, record in data["records"].items():
                    self._validate_record(key, record)
                    loaded[key] = dict(record)
                self._validate_record_set(loaded)
                self._records = loaded
            except Exception as exc:
                self._records = {}
                self._mark_unhealthy(f"invalid migration lease store: {exc}")

    def _validate_record(self, key: object, record: object):
        if not isinstance(key, str) or not _HEX64.fullmatch(key):
            raise ValueError("invalid migration lease record key")
        if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
            raise ValueError("invalid migration lease record shape")
        if record["nonce_hash"] != key or not _HEX64.fullmatch(record["nonce_hash"]):
            raise ValueError("invalid migration lease nonce hash")
        if record["state"] not in ("held", "released"):
            raise ValueError("invalid migration lease state")
        if not isinstance(record["name"], str) or not _NAME.fullmatch(record["name"]):
            raise ValueError("invalid migration lease name")
        if not isinstance(record["base"], str) or not _NAME.fullmatch(record["base"]):
            raise ValueError("invalid migration lease base")
        if not _is_int(record["slot"]) or record["slot"] < 1:
            raise ValueError("invalid migration lease slot")
        if not isinstance(record["identity_id"], str) or not _HEX32.fullmatch(record["identity_id"]):
            raise ValueError("invalid migration lease identity_id")
        if not _is_int(record["epoch"]) or record["epoch"] < 1:
            raise ValueError("invalid migration lease epoch")
        if not isinstance(record["lease_id"], str) or not _HEX32.fullmatch(record["lease_id"]):
            raise ValueError("invalid migration lease id")
        route_snapshot = record["route_snapshot"]
        if not isinstance(route_snapshot, list) or len(route_snapshot) > MAX_ROUTE_EDGES:
            raise ValueError("invalid migration lease route snapshot")
        seen_edges = set()
        for edge in route_snapshot:
            if (
                not isinstance(edge, list)
                or len(edge) != 2
                or not all(isinstance(value, str) and _NAME.fullmatch(value) for value in edge)
            ):
                raise ValueError("invalid migration lease route edge")
            edge_key = tuple(edge)
            if edge_key in seen_edges:
                raise ValueError("duplicate migration lease route edge")
            seen_edges.add(edge_key)
        snapshot = record["family_snapshot"]
        if (
            not isinstance(snapshot, list)
            or not snapshot
            or len(snapshot) > MAX_FAMILY_MEMBERS
        ):
            raise ValueError("invalid migration lease family snapshot")
        snapshot_names = set()
        snapshot_coords = set()
        snapshot_ids = set()
        target_seen = False
        for member in snapshot:
            if not isinstance(member, dict) or set(member) != _FAMILY_MEMBER_KEYS:
                raise ValueError("invalid migration lease family member shape")
            if not isinstance(member["name"], str) or not _NAME.fullmatch(member["name"]):
                raise ValueError("invalid migration lease family member name")
            if member["base"] != record["base"]:
                raise ValueError("migration lease family member base mismatch")
            if not _is_int(member["slot"]) or member["slot"] < 1:
                raise ValueError("invalid migration lease family member slot")
            if (
                not isinstance(member["identity_id"], str)
                or not _HEX32.fullmatch(member["identity_id"])
            ):
                raise ValueError("invalid migration lease family member identity")
            if not _is_int(member["epoch"]) or member["epoch"] < 1:
                raise ValueError("invalid migration lease family member epoch")
            if not isinstance(member["live"], bool):
                raise ValueError("invalid migration lease family member liveness")
            if member["state"] not in ("active", "pending"):
                raise ValueError("invalid migration lease family member state")
            coordinate = (member["base"], member["slot"])
            if (
                member["name"] in snapshot_names
                or coordinate in snapshot_coords
                or member["identity_id"] in snapshot_ids
            ):
                raise ValueError("conflicting migration lease family members")
            snapshot_names.add(member["name"])
            snapshot_coords.add(coordinate)
            snapshot_ids.add(member["identity_id"])
            if member["identity_id"] == record["identity_id"]:
                if any(member[key] != record[key] for key in _IDENTITY_KEYS):
                    raise ValueError("leased target differs from family snapshot")
                if not member["live"] or member["state"] != "active":
                    raise ValueError("leased target is not live-active in family snapshot")
                target_seen = True
        if not target_seen:
            raise ValueError("leased target missing from family snapshot")
        for key_name in ("created_at", "updated_at", "expires_at", "tombstone_expires_at"):
            value = record[key_name]
            if not _is_int(value):
                raise ValueError(f"invalid migration lease {key_name}")
            if value < 0:
                raise ValueError(f"invalid migration lease {key_name}")
        for key_name in ("route_fingerprint", "family_fingerprint"):
            value = record[key_name]
            if not isinstance(value, str) or not _HEX64.fullmatch(value):
                raise ValueError(f"invalid migration lease {key_name}")
        if record["state"] == "held":
            if record["expires_at"] <= record["updated_at"]:
                raise ValueError("held migration lease is not future bounded")
            if record["expires_at"] - record["updated_at"] > LEASE_TTL_MAX:
                raise ValueError("held migration lease exceeds TTL bound")
            if record["tombstone_expires_at"] != 0:
                raise ValueError("held migration lease has tombstone expiry")
        else:
            if record["expires_at"] != 0:
                raise ValueError("released migration lease has active expiry")
            if record["tombstone_expires_at"] <= record["updated_at"]:
                raise ValueError("released migration lease tombstone is not bounded")
            if record["tombstone_expires_at"] - record["updated_at"] > TOMBSTONE_TTL:
                raise ValueError("released migration lease tombstone exceeds bound")
        if record["created_at"] > record["updated_at"]:
            raise ValueError("migration lease timestamps are reversed")

    def _validate_record_set(self, records: dict[str, dict]):
        lease_ids = set()
        protected_bases = set()
        protected_names = set()
        protected_coords = set()
        protected_identities = set()
        now = int(self._clock())
        for record in records.values():
            if record["lease_id"] in lease_ids:
                raise ValueError("duplicate migration lease id")
            lease_ids.add(record["lease_id"])
            if not self._held_is_protected(record, now):
                continue
            coordinates = (record["base"], record["slot"])
            if (
                record["base"] in protected_bases
                or record["name"] in protected_names
                or coordinates in protected_coords
                or record["identity_id"] in protected_identities
            ):
                raise ValueError("conflicting protected migration leases")
            protected_bases.add(record["base"])
            protected_names.add(record["name"])
            protected_coords.add(coordinates)
            protected_identities.add(record["identity_id"])

    @staticmethod
    def _held_protection_expires_at(record: dict) -> int:
        return max(
            record["expires_at"],
            record["created_at"] + RECOVERY_PROTECTION_TTL,
        )

    @classmethod
    def _held_is_protected(cls, record: dict, now: int) -> bool:
        return (
            record["state"] == "held"
            and cls._held_protection_expires_at(record) > now
        )

    def _serialized(self) -> bytes:
        return json.dumps(
            {"version": 1, "records": self._records}, ensure_ascii=True,
            allow_nan=False, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")

    def _write_strict_locked(self):
        if not self._healthy:
            raise MigrationLeaseError(503, "migration lease store is unhealthy")
        serialized = self._serialized()
        if len(serialized) > MAX_STORE_BYTES:
            raise MigrationLeaseError(503, "migration lease store is full")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._tmp_path.exists():
            self._mark_unhealthy("torn migration lease store")
            raise MigrationLeaseError(503, "migration lease store is unhealthy")
        try:
            with self._tmp_path.open("xb") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(self._tmp_path, self._path)
            try:
                directory_fd = os.open(
                    str(self._path.parent),
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                # Windows does not expose a portable directory fsync.  The
                # file itself was fsynced before the atomic replace.
                pass
        except Exception as exc:
            try:
                self._tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            self._mark_unhealthy(f"migration lease persistence failed: {type(exc).__name__}")
            raise MigrationLeaseError(500, "migration lease could not be persisted") from exc

    def _require_healthy_locked(self):
        if not self._healthy:
            raise MigrationLeaseError(503, "migration lease store is unhealthy")

    def _stale_record_keys_locked(self, now: int) -> set[str]:
        stale = set()
        for key, record in self._records.items():
            if record["state"] == "released":
                if record["tombstone_expires_at"] <= now:
                    stale.add(key)
            elif self._held_protection_expires_at(record) <= now:
                stale.add(key)
        return stale

    def _publish_record_locked(
        self, nonce_hash: str, record: dict, stale_keys: set[str] | None = None,
    ):
        """Atomically publish one record and optional logical pruning in memory/disk."""
        stale_keys = stale_keys or set()
        removed = {
            key: self._records.pop(key)
            for key in stale_keys
            if key in self._records
        }
        had_prior = nonce_hash in self._records
        prior = self._records.get(nonce_hash)
        self._records[nonce_hash] = record
        try:
            self._write_strict_locked()
        except Exception:
            self._records.pop(nonce_hash, None)
            self._records.update(removed)
            if had_prior:
                self._records[nonce_hash] = prior
            raise

    def _protected_held_records_locked(self, now: int):
        return [
            record for record in self._records.values()
            if self._held_is_protected(record, now)
        ]

    @staticmethod
    def _lease_conflicts_identity(record: dict, identity: dict) -> bool:
        return (
            record["base"] == identity["base"]
            or record["name"] == identity["name"]
            or record["identity_id"] == identity["identity_id"]
            or (record["base"], record["slot"])
            == (identity["base"], identity["slot"])
        )

    def _assert_no_protected_lease_conflict_locked(
        self, identity: dict, now: int, *, exclude_nonce_hash: str | None = None,
    ):
        for key, record in self._records.items():
            if key == exclude_nonce_hash:
                continue
            protected = self._held_is_protected(record, now)
            if protected and self._lease_conflicts_identity(record, identity):
                raise MigrationLeaseError(409, "conflicting migration lease")

    @staticmethod
    def _assert_no_other_identity_conflict_locked(registry, inst):
        for source in (registry._instances, registry._reclaimable):
            for other in source.values():
                if other is inst:
                    continue
                if (
                    other.name == inst.name
                    or other.identity_id == inst.identity_id
                    or (other.base, other.slot) == (inst.base, inst.slot)
                ):
                    raise MigrationLeaseError(
                        409, "conflicting migration identity"
                    )

    def is_family_held_locked(self, base: str) -> bool:
        """Registry guard.  Unhealthy storage freezes every family."""
        if not self._healthy:
            return True
        now = int(self._clock())
        return any(
            record["base"] == base
            for record in self._protected_held_records_locked(now)
        )

    def is_exact_held_locked(self, identity: dict) -> bool:
        if not self._healthy:
            return True
        now = int(self._clock())
        return any(
            record["identity_id"] == identity.get("identity_id")
            and all(record[key] == identity.get(key) for key in _IDENTITY_KEYS)
            for record in self._protected_held_records_locked(now)
        )

    def is_route_name_held_locked(self, name: str) -> bool:
        """Whether a topology mutation would touch any held route namespace."""
        if not self._healthy:
            return True
        now = int(self._clock())
        for record in self._protected_held_records_locked(now):
            protected = {record["base"], record["name"]}
            protected.update(member["name"] for member in record["family_snapshot"])
            for old, new in record["route_snapshot"]:
                protected.update((old, new))
            if name in protected:
                return True
        return False

    def _parse_request(self, body: object, operation: str) -> dict:
        required = set(_IDENTITY_KEYS) | {"lease_nonce", "lease_id"}
        if operation in ("acquire", "renew"):
            required.add("ttl_seconds")
        if not isinstance(body, dict) or set(body) != required:
            raise MigrationLeaseError(400, "invalid migration lease request shape")
        result = dict(body)
        for key in ("name", "base"):
            if not isinstance(result[key], str) or not _NAME.fullmatch(result[key]):
                raise MigrationLeaseError(400, f"invalid {key}")
        if not _is_int(result["slot"]) or result["slot"] < 1:
            raise MigrationLeaseError(400, "invalid slot")
        if not isinstance(result["identity_id"], str) or not _HEX32.fullmatch(result["identity_id"]):
            raise MigrationLeaseError(400, "invalid identity_id")
        if not _is_int(result["epoch"]) or result["epoch"] < 1:
            raise MigrationLeaseError(400, "invalid epoch")
        for key in ("lease_nonce", "lease_id"):
            if not isinstance(result[key], str) or not _HEX32.fullmatch(result[key]):
                raise MigrationLeaseError(400, f"invalid {key}")
        if secrets.compare_digest(result["lease_nonce"], result["lease_id"]):
            raise MigrationLeaseError(400, "lease_nonce and lease_id must be independent")
        if "ttl_seconds" in result:
            ttl = result["ttl_seconds"]
            if not _is_int(ttl) or ttl < LEASE_TTL_MIN or ttl > LEASE_TTL_MAX:
                raise MigrationLeaseError(
                    400, f"ttl_seconds must be {LEASE_TTL_MIN}..{LEASE_TTL_MAX}"
                )
        return result

    @staticmethod
    def _identity_from_instance(inst) -> dict:
        return {
            "name": inst.name, "base": inst.base, "slot": inst.slot,
            "identity_id": inst.identity_id, "epoch": inst.epoch,
        }

    @staticmethod
    def _require_current_token(token: object):
        if not isinstance(token, str) or not _HEX32.fullmatch(token):
            raise MigrationLeaseError(403, "current agent bearer required")

    @staticmethod
    def _find_token_locked(registry, token: str, *, include_reclaimable: bool):
        matches = []
        for inst in registry._instances.values():
            if not isinstance(inst.token, str) or not _HEX32.fullmatch(inst.token):
                raise MigrationLeaseError(409, "registry contains an invalid credential")
            if secrets.compare_digest(inst.token, token):
                matches.append((inst, True))
        if include_reclaimable:
            for inst in registry._reclaimable.values():
                if not isinstance(inst.token, str) or not _HEX32.fullmatch(inst.token):
                    raise MigrationLeaseError(409, "registry contains an invalid credential")
                if secrets.compare_digest(inst.token, token):
                    matches.append((inst, False))
        if len(matches) > 1:
            raise MigrationLeaseError(409, "bearer has conflicting identity ownership")
        return matches[0] if matches else (None, False)

    @staticmethod
    def _family_snapshots_locked(
        registry, identity: dict,
    ) -> tuple[str, str, list[dict], list[list[str]]]:
        base = identity["base"]
        members = {}
        names = set()
        coordinates = set()
        for live, source in (
            (True, registry._instances),
            (False, registry._reclaimable),
        ):
            for inst in source.values():
                if inst.base != base:
                    continue
                member = {
                    "name": inst.name, "base": inst.base, "slot": inst.slot,
                    "identity_id": inst.identity_id, "epoch": inst.epoch,
                    "live": live, "state": inst.state,
                }
                if (
                    not isinstance(inst.name, str)
                    or not _NAME.fullmatch(inst.name)
                    or not isinstance(inst.base, str)
                    or not _NAME.fullmatch(inst.base)
                    or not isinstance(inst.identity_id, str)
                    or not _HEX32.fullmatch(inst.identity_id)
                    or not _is_int(inst.slot)
                    or inst.slot < 1
                    or not _is_int(inst.epoch)
                    or inst.epoch < 1
                    or inst.state not in ("active", "pending")
                ):
                    raise MigrationLeaseError(409, "invalid family identity topology")
                prior = members.get(inst.identity_id)
                coordinate = (inst.base, inst.slot)
                if (
                    prior is not None
                    or inst.name in names
                    or coordinate in coordinates
                ):
                    raise MigrationLeaseError(409, "conflicting family identity topology")
                members[inst.identity_id] = member
                names.add(inst.name)
                coordinates.add(coordinate)

        if not members or len(members) > MAX_FAMILY_MEMBERS:
            raise MigrationLeaseError(409, "agent family exceeds migration lease bound")

        relevant = {base, identity["name"]}
        relevant.update(member["name"] for member in members.values())
        edges = []
        changed = True
        while changed:
            changed = False
            for old, new in registry._renames.items():
                if (
                    not isinstance(old, str)
                    or not isinstance(new, str)
                    or not _NAME.fullmatch(old)
                    or not _NAME.fullmatch(new)
                ):
                    raise MigrationLeaseError(409, "invalid migration route topology")
                if old in relevant or new in relevant:
                    edge = [old, new]
                    if edge not in edges:
                        edges.append(edge)
                    before = len(relevant)
                    relevant.update((old, new))
                    changed = changed or len(relevant) != before
                    if len(edges) > MAX_ROUTE_EDGES:
                        raise MigrationLeaseError(409, "migration route exceeds bound")
        edges.sort()
        for source in (registry._instances, registry._reclaimable):
            for inst in source.values():
                if inst.base != base and inst.name in relevant:
                    raise MigrationLeaseError(
                        409, "leased route collides with another agent family"
                    )
        ordered_members = sorted(
            members.values(), key=lambda item: (item["slot"], item["name"], item["identity_id"])
        )
        route = _canonical_fingerprint({"identity": identity, "renames": edges})
        family = _canonical_fingerprint(
            {"base": base, "members": ordered_members, "renames": edges}
        )
        return route, family, ordered_members, edges

    @staticmethod
    def _assert_exact(request_data: dict, inst):
        actual = MigrationLeaseStore._identity_from_instance(inst)
        if any(request_data[key] != actual[key] for key in _IDENTITY_KEYS):
            raise MigrationLeaseError(409, "exact migration identity mismatch")

    @staticmethod
    def _lease_response(
        identity: dict, nonce: str, lease_id: str, *, expires_at: int,
        state: str, route_fingerprint: str, family_fingerprint: str,
    ) -> dict:
        return {
            "ok": True,
            "name": identity["name"],
            "base": identity["base"],
            "slot": identity["slot"],
            "identity_id": identity["identity_id"],
            "epoch": identity["epoch"],
            "lease_nonce": nonce,
            "lease_id": lease_id,
            "expires_at": expires_at,
            "state": state,
            "route_fingerprint": route_fingerprint,
            "family_fingerprint": family_fingerprint,
        }

    def _record_response(self, record: dict, nonce: str) -> dict:
        return self._lease_response(
            record, nonce, record["lease_id"], expires_at=record["expires_at"],
            state=record["state"],
            route_fingerprint=record["route_fingerprint"],
            family_fingerprint=record["family_fingerprint"],
        )

    def acquire(self, registry, token: str, body: object) -> dict:
        self._require_current_token(token)
        request_data = self._parse_request(body, "acquire")
        nonce_hash = _sha256_text(request_data["lease_nonce"])
        now = int(self._clock())
        with self._lock:
            self._require_healthy_locked()
            # Persist the exact current registry snapshot before publishing the
            # lease, closing the register-save/acquire crash window.
            with registry._persist_lock:
                with registry._renames_persist_lock:
                    with registry._lock:
                        return self._acquire_locked(
                            registry, token, request_data, nonce_hash, now
                        )

    def _acquire_locked(
        self, registry, token: str, request_data: dict, nonce_hash: str, now: int,
    ) -> dict:
        """Acquire body with lease + both persistence + registry locks held."""
        try:
            found = self._find_token_locked(registry, token, include_reclaimable=False)
            inst, live = found
            if inst is None or not live or inst.state != "active":
                raise MigrationLeaseError(403, "current live agent bearer required")
            self._assert_exact(request_data, inst)
            self._assert_no_other_identity_conflict_locked(registry, inst)
            identity = self._identity_from_instance(inst)
            (
                route_fp, family_fp, family_snapshot, route_snapshot,
            ) = self._family_snapshots_locked(
                registry, identity
            )
            stale_keys = self._stale_record_keys_locked(now)
            existing = (
                None if nonce_hash in stale_keys
                else self._records.get(nonce_hash)
            )
            if existing is not None:
                if (
                    not secrets.compare_digest(
                        existing["lease_id"], request_data["lease_id"]
                    )
                    or any(
                        existing[key] != request_data[key]
                        for key in _IDENTITY_KEYS
                    )
                    or existing["state"] != "held"
                ):
                    raise MigrationLeaseError(
                        409, "migration lease nonce is already bound"
                    )
                if (
                    existing["route_fingerprint"] != route_fp
                    or existing["family_fingerprint"] != family_fp
                    or existing["family_snapshot"] != family_snapshot
                    or existing["route_snapshot"] != route_snapshot
                ):
                    raise MigrationLeaseError(409, "leased family topology changed")
                self._assert_no_protected_lease_conflict_locked(
                    identity, now, exclude_nonce_hash=nonce_hash
                )
                if existing["expires_at"] > now:
                    return self._record_response(existing, request_data["lease_nonce"])

                # Exact retained expiry revival: re-durable the unchanged
                # registry route first, then atomically republish the original
                # seal with a fresh bounded lifetime. The client nonce/id and
                # created_at remain stable across an unobserved response.
                registry._write_snapshot_to_disk(registry._snapshot_data_locked())
                registry._write_renames_snapshot_to_disk(dict(registry._renames))
                revived = dict(existing)
                revived["updated_at"] = now
                revived["expires_at"] = now + request_data["ttl_seconds"]
                self._validate_record(nonce_hash, revived)
                self._publish_record_locked(nonce_hash, revived, stale_keys)
                return self._record_response(revived, request_data["lease_nonce"])

            for key, record in self._records.items():
                if key in stale_keys:
                    continue
                if secrets.compare_digest(record["lease_id"], request_data["lease_id"]):
                    raise MigrationLeaseError(409, "migration lease id is already bound")
            self._assert_no_protected_lease_conflict_locked(identity, now)
            if len(self._records) - len(stale_keys) >= MAX_RECORDS:
                raise MigrationLeaseError(503, "migration lease store is full")
            # Both exact identity and its base→profile route must be on
            # disk before the lease can become observable.
            registry._write_snapshot_to_disk(registry._snapshot_data_locked())
            registry._write_renames_snapshot_to_disk(dict(registry._renames))
            record = {
                "state": "held", **identity,
                "nonce_hash": nonce_hash,
                "lease_id": request_data["lease_id"],
                "created_at": now,
                "updated_at": now,
                "expires_at": now + request_data["ttl_seconds"],
                "tombstone_expires_at": 0,
                "route_fingerprint": route_fp,
                "family_fingerprint": family_fp,
                "family_snapshot": family_snapshot,
                "route_snapshot": route_snapshot,
            }
            try:
                self._validate_record(nonce_hash, record)
            except ValueError as exc:
                raise MigrationLeaseError(
                    409, "migration lease snapshot is invalid"
                ) from exc
            self._publish_record_locked(nonce_hash, record, stale_keys)
            return self._record_response(record, request_data["lease_nonce"])
        except MigrationLeaseError:
            raise
        except Exception as exc:
            raise MigrationLeaseError(
                500, "migration identity could not be made durable"
            ) from exc

    def renew(self, registry, token: str, body: object) -> dict:
        self._require_current_token(token)
        request_data = self._parse_request(body, "renew")
        nonce_hash = _sha256_text(request_data["lease_nonce"])
        now = int(self._clock())
        with self._lock:
            self._require_healthy_locked()
            record = self._records.get(nonce_hash)
            if record is None or record["state"] != "held" or record["expires_at"] <= now:
                raise MigrationLeaseError(409, "migration lease is not held")
            with registry._lock:
                inst, live = self._find_token_locked(registry, token, include_reclaimable=False)
                if inst is None or not live or inst.state != "active":
                    raise MigrationLeaseError(403, "current live agent bearer required")
                self._assert_exact(request_data, inst)
                if not secrets.compare_digest(record["lease_id"], request_data["lease_id"]):
                    raise MigrationLeaseError(409, "migration lease id mismatch")
                if any(record[key] != request_data[key] for key in _IDENTITY_KEYS):
                    raise MigrationLeaseError(409, "migration lease identity mismatch")
                (
                    route_fp, family_fp, family_snapshot, route_snapshot,
                ) = self._family_snapshots_locked(
                    registry, self._identity_from_instance(inst)
                )
                if (
                    record["route_fingerprint"] != route_fp
                    or record["family_fingerprint"] != family_fp
                    or record["family_snapshot"] != family_snapshot
                    or record["route_snapshot"] != route_snapshot
                ):
                    raise MigrationLeaseError(409, "leased family topology changed")
                prior = dict(record)
                record["updated_at"] = now
                record["expires_at"] = now + request_data["ttl_seconds"]
                try:
                    self._write_strict_locked()
                except Exception:
                    record.clear()
                    record.update(prior)
                    raise
                return self._record_response(record, request_data["lease_nonce"])

    def release(self, registry, token: str, body: object) -> dict:
        self._require_current_token(token)
        request_data = self._parse_request(body, "release")
        nonce_hash = _sha256_text(request_data["lease_nonce"])
        now = int(self._clock())
        with self._lock:
            self._require_healthy_locked()
            with registry._lock:
                inst, _live = self._find_token_locked(
                    registry, token, include_reclaimable=True
                )
                if inst is None:
                    raise MigrationLeaseError(403, "current agent bearer required")
                self._assert_exact(request_data, inst)
                self._assert_no_other_identity_conflict_locked(registry, inst)
                identity = self._identity_from_instance(inst)
                record = self._records.get(nonce_hash)
                if record is None:
                    # An absent/pruned exact lease is already in the released
                    # target state. Do not let arbitrary release IDs fill the
                    # bounded store; repeat POST is deterministic reconciliation.
                    for other in self._records.values():
                        if secrets.compare_digest(
                            other["lease_id"], request_data["lease_id"]
                        ):
                            raise MigrationLeaseError(
                                409, "migration lease nonce mismatch"
                            )
                    self._assert_no_protected_lease_conflict_locked(identity, now)
                    (
                        route_fp, family_fp, _family_snapshot, _route_snapshot,
                    ) = self._family_snapshots_locked(registry, identity)
                    response = self._lease_response(
                        identity, request_data["lease_nonce"],
                        request_data["lease_id"], expires_at=0,
                        state="released", route_fingerprint=route_fp,
                        family_fingerprint=family_fp,
                    )
                    response["released"] = False
                    return response
                if not secrets.compare_digest(record["lease_id"], request_data["lease_id"]):
                    raise MigrationLeaseError(409, "migration lease id mismatch")
                if any(record[key] != request_data[key] for key in _IDENTITY_KEYS):
                    raise MigrationLeaseError(409, "migration lease identity mismatch")
                first_release = record["state"] == "held"
                if first_release:
                    released = dict(record)
                    released["state"] = "released"
                    released["updated_at"] = now
                    released["expires_at"] = 0
                    released["tombstone_expires_at"] = now + TOMBSTONE_TTL
                    self._validate_record(nonce_hash, released)
                    self._publish_record_locked(nonce_hash, released)
                    record = released
                response = self._record_response(
                    record, request_data["lease_nonce"]
                )
                response["released"] = first_release
                return response

    def status(self, registry, token: str, nonce: str) -> dict:
        self._require_current_token(token)
        if not isinstance(nonce, str) or not _HEX32.fullmatch(nonce):
            raise MigrationLeaseError(400, "invalid lease_nonce")
        nonce_hash = _sha256_text(nonce)
        now = int(self._clock())
        with self._lock:
            self._require_healthy_locked()
            record = self._records.get(nonce_hash)
            if record is None:
                raise MigrationLeaseError(404, "migration lease not found")
            if record["state"] == "held" and record["expires_at"] <= now:
                raise MigrationLeaseError(409, "migration lease has expired")
            if record["state"] == "released" and record["tombstone_expires_at"] <= now:
                raise MigrationLeaseError(404, "migration lease not found")
            with registry._lock:
                inst, live = self._find_token_locked(
                    registry, token, include_reclaimable=True
                )
                if inst is None:
                    raise MigrationLeaseError(403, "current agent bearer required")
                actual = self._identity_from_instance(inst)
                if any(record[key] != actual[key] for key in _IDENTITY_KEYS):
                    raise MigrationLeaseError(403, "bearer does not own migration lease")
                if record["state"] == "held":
                    if not live or inst.state != "active":
                        raise MigrationLeaseError(409, "leased identity is not active")
                    (
                        route_fp, family_fp, family_snapshot, route_snapshot,
                    ) = self._family_snapshots_locked(registry, actual)
                    if (
                        record["route_fingerprint"] != route_fp
                        or record["family_fingerprint"] != family_fp
                        or record["family_snapshot"] != family_snapshot
                        or record["route_snapshot"] != route_snapshot
                    ):
                        raise MigrationLeaseError(409, "leased family topology changed")
                return self._record_response(record, nonce)

    def reconcile_registry(self, registry) -> list[str]:
        """Restore every held family snapshot before background cleanup starts.

        Invalid/torn storage or an identity/topology mismatch marks the store
        unhealthy and leaves registry topology frozen rather than guessing.
        """
        now = int(self._clock())
        restored = []
        with self._lock:
            if not self._healthy:
                return restored
            held = self._protected_held_records_locked(now)
            if not held:
                return restored
            try:
                with registry._persist_lock:
                    with registry._lock:
                        instances_before = dict(registry._instances)
                        reclaimable_before = dict(registry._reclaimable)
                        states_before = {
                            inst.identity_id: inst.state
                            for inst in list(registry._instances.values())
                            + list(registry._reclaimable.values())
                        }
                        for record in held:
                            actual_by_id = {}
                            for live, source in (
                                (True, registry._instances),
                                (False, registry._reclaimable),
                            ):
                                for key, inst in source.items():
                                    if inst.base != record["base"]:
                                        continue
                                    if inst.identity_id in actual_by_id or key != inst.name:
                                        raise MigrationLeaseError(
                                            409, "leased family is duplicated after restart"
                                        )
                                    actual_by_id[inst.identity_id] = (live, key, inst)
                            expected_by_id = {
                                member["identity_id"]: member
                                for member in record["family_snapshot"]
                            }
                            if set(actual_by_id) != set(expected_by_id):
                                raise MigrationLeaseError(
                                    409, "leased family membership changed after restart"
                                )
                            for identity_id, member in expected_by_id.items():
                                _live, _key, inst = actual_by_id[identity_id]
                                actual = self._identity_from_instance(inst)
                                if any(member[field] != actual[field] for field in _IDENTITY_KEYS):
                                    raise MigrationLeaseError(
                                        409, "leased family identity changed after restart"
                                    )
                            target = actual_by_id[record["identity_id"]][2]
                            (
                                route_fp, _family_fp, _snapshot, route_snapshot,
                            ) = self._family_snapshots_locked(
                                registry, self._identity_from_instance(target)
                            )
                            if (
                                record["route_fingerprint"] != route_fp
                                or record["route_snapshot"] != route_snapshot
                            ):
                                raise MigrationLeaseError(
                                    409, "leased family route changed after restart"
                                )

                            # RuntimeRegistry intentionally loads every persisted
                            # identity as reclaimable.  Reapply the lease's exact
                            # live/dormant family snapshot before exposing status.
                            for identity_id, member in expected_by_id.items():
                                live, key, inst = actual_by_id[identity_id]
                                if member["live"] and not live:
                                    del registry._reclaimable[key]
                                    registry._instances[inst.name] = inst
                                elif not member["live"] and live:
                                    del registry._instances[key]
                                    registry._reclaimable[inst.name] = inst
                                inst.state = member["state"]
                                if member["live"]:
                                    restored.append(inst.name)

                            target = registry._instances.get(record["name"])
                            if target is None or target.identity_id != record["identity_id"]:
                                raise MigrationLeaseError(
                                    409, "leased target was not restored live after restart"
                                )
                            route_fp, family_fp, family_snapshot, route_snapshot = (
                                self._family_snapshots_locked(
                                    registry, self._identity_from_instance(target)
                                )
                            )
                            if (
                                record["route_fingerprint"] != route_fp
                                or record["family_fingerprint"] != family_fp
                                or record["family_snapshot"] != family_snapshot
                                or record["route_snapshot"] != route_snapshot
                            ):
                                raise MigrationLeaseError(
                                    409, "leased family snapshot changed after restart"
                                )
                        registry._write_snapshot_to_disk(registry._snapshot_data_locked())
            except Exception as exc:
                if "instances_before" in locals():
                    registry._instances = instances_before
                    registry._reclaimable = reclaimable_before
                    for inst in list(registry._instances.values()) + list(registry._reclaimable.values()):
                        if inst.identity_id in states_before:
                            inst.state = states_before[inst.identity_id]
                self._mark_unhealthy(f"migration lease reconciliation failed: {exc}")
                return []
        if restored:
            registry._notify()
        return restored
