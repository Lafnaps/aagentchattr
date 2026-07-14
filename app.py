"""agentchattr — FastAPI web UI + agent auto-trigger."""

import asyncio
import copy
import json
import os
import re as _re
import sys
import threading
import uuid
import logging
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.requests import Request
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from store import MessageStore, _atomic_write_bytes
from rules import RuleStore
from summaries import SummaryStore
from jobs import JobStore
from schedules import ScheduleStore, parse_schedule_spec
from router import Router
from agents import AgentTrigger
from registry import RuntimeRegistry
from migration_lease import MigrationLeaseError, MigrationLeaseStore
from session_store import SessionStore, validate_session_template
from session_engine import SessionEngine
from channel_policy import (
    CHANNEL_CATALOG_LOCK,
    CHANNEL_NAME_RE,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_DISCOVERED_CHANNELS,
    HARD_MAX_DISCOVERED_CHANNELS,
    bounded_discovery_limit,
    channel_name_error,
)

log = logging.getLogger(__name__)

app = FastAPI(title="agentchattr")

# --- globals (set by configure()) ---
store: MessageStore | None = None
rules: RuleStore | None = None
summaries: SummaryStore | None = None
jobs: JobStore | None = None
schedules: ScheduleStore | None = None
router: Router | None = None
agents: AgentTrigger | None = None
registry: RuntimeRegistry | None = None
migration_leases: MigrationLeaseStore | None = None
session_store: SessionStore | None = None
session_engine: SessionEngine | None = None
config: dict = {}
ws_clients: set[WebSocket] = set()

# --- Security: session token (set by configure()) ---
session_token: str = ""

# Room settings (persisted to data/settings.json)
room_settings: dict = {
    "title": "agentchattr",
    "username": "user",
    "font": "sans",
    "channels": ["general"],
    "max_channels": 64,
    "max_discovered_channels": DEFAULT_MAX_DISCOVERED_CHANNELS,
    "catalogue_revision": 0,
    "history_limit": "all",
    "contrast": "normal",
    "custom_roles": [],
}

# Channel validation and admission.  Manual creation uses ``max_channels``;
# authenticated message discovery has a separate, bounded safety ceiling.
_CHANNEL_NAME_RE = CHANNEL_NAME_RE  # backward-compatible private alias
_channel_catalog_lock = CHANNEL_CATALOG_LOCK
_catalogue_broadcast_pending: set[str] = set()
_channel_outbound_lock = asyncio.Lock()
_structured_broadcast_suspended = 0
_transaction_event_local = threading.local()
_pending_transaction_events: dict[str, list[tuple]] = {}

# Agent hats (persisted to data/hats.json)
agent_hats: dict[str, str] = {}  # { agent_name: svg_string }
_hat_lock = threading.RLock()


def _hats_path() -> Path:
    data_dir = config.get("server", {}).get("data_dir", "./data")
    return Path(data_dir) / "hats.json"


def _load_hats():
    global agent_hats
    p = _hats_path()
    if p.exists():
        try:
            loaded = json.loads(p.read_text("utf-8"))
            with _hat_lock:
                agent_hats = loaded if isinstance(loaded, dict) else {}
        except Exception:
            with _hat_lock:
                agent_hats = {}


def _save_hats(hats: dict | None = None):
    p = _hats_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = agent_hats if hats is None else hats
    _atomic_write_bytes(p, json.dumps(payload).encode("utf-8"))


def _sanitize_svg(svg: str) -> str:
    """Strip dangerous content from SVG string."""
    svg = _re.sub(r'<script[^>]*>.*?</script>', '', svg, flags=_re.DOTALL | _re.IGNORECASE)
    svg = _re.sub(r'\bon\w+\s*=', '', svg, flags=_re.IGNORECASE)
    svg = _re.sub(r'javascript\s*:', '', svg, flags=_re.IGNORECASE)
    return svg


def set_agent_hat(agent: str, svg: str) -> str | None:
    """Validate, sanitize, and store a hat SVG. Returns error string or None."""
    svg = svg.strip()
    if not svg.lower().startswith("<svg"):
        return "Hat must be an SVG element (starts with <svg)."
    if len(svg) > 5120:
        return "Hat SVG too large (max 5KB)."
    svg = _sanitize_svg(svg)
    with _hat_lock:
        updated = dict(agent_hats)
        updated[agent.lower()] = svg
        _save_hats(updated)
        agent_hats.clear()
        agent_hats.update(updated)
    if _event_loop:
        asyncio.run_coroutine_threadsafe(broadcast_hats(), _event_loop)
    return None


def clear_agent_hat(agent: str):
    """Remove an agent's hat."""
    key = agent.lower()
    changed = False
    with _hat_lock:
        if key in agent_hats:
            updated = dict(agent_hats)
            del updated[key]
            _save_hats(updated)
            agent_hats.clear()
            agent_hats.update(updated)
            changed = True
    if changed:
        if _event_loop:
            asyncio.run_coroutine_threadsafe(broadcast_hats(), _event_loop)


def _settings_path() -> Path:
    data_dir = config.get("server", {}).get("data_dir", "./data")
    return Path(data_dir) / "settings.json"


def _load_settings():
    global room_settings
    p = _settings_path()
    saved = {}
    if p.exists():
        try:
            saved = json.loads(p.read_text("utf-8"))
        except Exception:
            saved = {}

    with _channel_catalog_lock:
        if isinstance(saved, dict):
            room_settings.update(saved)
        try:
            revision = max(0, int(room_settings.get("catalogue_revision", 0)))
        except (TypeError, ValueError):
            revision = 0
        room_settings["catalogue_revision"] = revision

        # The discovery ceiling is configurable but cannot exceed the compiled
        # safety bound, even if settings.json is edited by hand.
        discovery_limit = bounded_discovery_limit(
            room_settings.get("max_discovered_channels", DEFAULT_MAX_DISCOVERED_CHANNELS)
        )
        room_settings["max_discovered_channels"] = discovery_limit

        configured = room_settings.get("channels", [])
        original_channels = configured if isinstance(configured, list) else []
        normalized = ["general"]
        for channel in original_channels:
            if channel == "general" or channel_name_error(channel):
                continue
            if channel in normalized:
                continue
            if len(normalized) >= discovery_limit:
                log.error(
                    "channel catalogue exceeds bounded discovery ceiling %d; "
                    "ignoring persisted channel %r",
                    discovery_limit,
                    channel,
                )
                continue
            normalized.append(channel)
        room_settings["channels"] = normalized

        try:
            requested_manual_limit = int(
                room_settings.get("max_channels", DEFAULT_MAX_CHANNELS)
            )
        except (TypeError, ValueError):
            requested_manual_limit = DEFAULT_MAX_CHANNELS
        room_settings["max_channels"] = max(
            1, min(requested_manual_limit, discovery_limit)
        )

        catalogue_normalized = original_channels != normalized
        if catalogue_normalized:
            _bump_catalogue_revision_locked()
        normalization_needed = (
            catalogue_normalized
            or saved.get("catalogue_revision") != room_settings["catalogue_revision"]
            or saved.get("max_discovered_channels") != discovery_limit
            or saved.get("max_channels") != room_settings["max_channels"]
        )
        if normalization_needed:
            _save_settings()


def _bump_catalogue_revision_locked() -> int:
    """Increment the persisted catalogue fence; caller holds the shared RLock."""
    revision = max(0, int(room_settings.get("catalogue_revision", 0))) + 1
    room_settings["catalogue_revision"] = revision
    return revision


def _settings_snapshot_locked() -> dict:
    """Return an isolated settings snapshot; caller holds the shared RLock."""
    return json.loads(json.dumps(room_settings))


def _settings_snapshot() -> dict:
    with _channel_catalog_lock:
        return _settings_snapshot_locked()


def _catalogue_revision() -> int:
    with _channel_catalog_lock:
        return int(room_settings.get("catalogue_revision", 0))


def _channel_discovery_limit() -> int:
    """Return the effective bounded catalogue ceiling."""
    with _channel_catalog_lock:
        limit = bounded_discovery_limit(
            room_settings.get("max_discovered_channels", DEFAULT_MAX_DISCOVERED_CHANNELS)
        )
        room_settings["max_discovered_channels"] = limit
        return limit


def _admit_message_channel(
    channel: object, *, persist: bool = True,
) -> tuple[bool, str | None]:
    """Atomically reserve a channel in the web catalogue.

    Returns ``(added, error)``.  A duplicate is successful with ``added=False``;
    malformed names and a full catalogue fail with an actionable error.
    """
    error = channel_name_error(channel)
    if error:
        return False, error

    with _channel_catalog_lock:
        channels = room_settings.setdefault("channels", ["general"])
        if channel in channels:
            return False, None
        limit = _channel_discovery_limit()
        if len(channels) >= limit:
            return False, (
                f"channel catalogue is full ({len(channels)}/{limit}); "
                "delete an unused channel or raise max_discovered_channels "
                f"(hard maximum {HARD_MAX_DISCOVERED_CHANNELS})"
            )
        channels.append(channel)
        _bump_catalogue_revision_locked()
        _catalogue_broadcast_pending.add(channel)
        if persist:
            try:
                _save_settings()
            except OSError:
                # The durable message log can restore the catalogue on startup.
                log.exception("could not persist discovered channel %s", channel)
        return True, None


def _run_channel_state_transaction(
    channel: object,
    mutation,
    *,
    success=None,
    compensator=None,
) -> tuple[object | None, bool, str | None]:
    """Reserve ``channel`` and run a synchronous structured-state mutation.

    The catalogue lock covers both reservation and mutation, so a concurrent
    full-catalogue race can never leave a job/rule/summary/session referring to
    a channel which was not admitted.  A newly-created, still-unpublished
    reservation is rolled back *including its revision* when the mutation
    raises or reports failure.

    ``success`` defaults to ``result is not None``. ``compensator(result)`` is
    required for mutations that persist state: it removes that state durably if
    the final atomic settings commit fails.  If compensation itself fails, the
    admitted channel is deliberately retained in memory (fail-closed) so the
    runtime never hides still-persisted structured state; startup reconciliation
    repairs its catalogue entry from the durable stores.
    """
    if success is None:
        success = lambda result: result is not None

    def restore_catalogue():
        room_settings.clear()
        room_settings.update(settings_before)
        _catalogue_broadcast_pending.clear()
        _catalogue_broadcast_pending.update(pending_before)

    def retain_catalogue_fail_closed():
        try:
            _save_settings()
        except Exception:
            log.exception(
                "could not persist fail-closed channel reservation %r", channel,
            )

    def durable_state_exists() -> bool | None:
        """True/False when inspectable; None means retain admission safely."""
        try:
            if store is not None and channel in store.get_channels():
                return True
            if jobs is not None and hasattr(jobs, "list_all"):
                job_items = jobs.list_all(channel=channel)
                if isinstance(job_items, list) and job_items:
                    return True
            if schedules is not None and hasattr(schedules, "list_all"):
                schedule_items = schedules.list_all()
                if isinstance(schedule_items, list) and any(
                    item.get("channel", "general") == channel
                    for item in schedule_items
                ):
                    return True
            if summaries is not None and summaries.get(channel) is not None:
                return True
            if session_store is not None and hasattr(session_store, "list_all"):
                session_items = session_store.list_all(channel=channel)
                if isinstance(session_items, list) and session_items:
                    return True
            return False
        except Exception:
            log.exception(
                "could not inspect durable state after failed channel mutation %r",
                channel,
            )
            return None

    previous_events = getattr(_transaction_event_local, "events", None)
    transaction_events: list[tuple] = []
    _transaction_event_local.events = transaction_events
    committed = False
    result = None
    added = False
    mutation_succeeded = False
    outcome = None
    try:
        with _channel_catalog_lock:
            settings_before = _settings_snapshot_locked()
            pending_before = set(_catalogue_broadcast_pending)
            added, error = _admit_message_channel(channel, persist=False)
            if error:
                outcome = (None, False, error)
            else:
                try:
                    result = mutation()
                    mutation_succeeded = bool(success(result))
                except Exception as exc:
                    if added:
                        rollback_state = getattr(
                            exc, "_channel_transaction_state", None,
                        )
                        remaining = durable_state_exists()
                        compensated = False
                        if compensator is not None and (
                            rollback_state is not None or remaining is not False
                        ):
                            try:
                                compensator(rollback_state)
                                compensated = True
                            except Exception:
                                log.exception(
                                    "channel mutation compensation failed for %r; "
                                    "retaining admitted channel fail-closed",
                                    channel,
                                )
                        if compensated:
                            remaining = durable_state_exists()
                        if remaining is False:
                            restore_catalogue()
                        else:
                            retain_catalogue_fail_closed()
                    raise
                if added and not mutation_succeeded:
                    remaining = durable_state_exists()
                    compensated = False
                    if compensator is not None and (
                        result is not None or remaining is not False
                    ):
                        try:
                            compensator(result)
                            compensated = True
                        except Exception:
                            log.exception(
                                "unsuccessful channel mutation compensation failed for %r",
                                channel,
                            )
                    if compensated:
                        remaining = durable_state_exists()
                    if remaining is False:
                        restore_catalogue()
                    else:
                        retain_catalogue_fail_closed()
                elif added:
                    try:
                        _save_settings()
                    except Exception:
                        compensated = False
                        if compensator is not None:
                            try:
                                compensator(result)
                                compensated = True
                            except Exception:
                                log.exception(
                                    "channel transaction compensation failed for %r; "
                                    "retaining admitted channel fail-closed",
                                    channel,
                                )
                        remaining = durable_state_exists()
                        if remaining is False:
                            restore_catalogue()
                        else:
                            retain_catalogue_fail_closed()
                        raise
                committed = mutation_succeeded
                outcome = (result, added and mutation_succeeded, None)
    finally:
        if previous_events is None:
            try:
                del _transaction_event_local.events
            except AttributeError:
                pass
        else:
            _transaction_event_local.events = previous_events

    if committed and transaction_events:
        if previous_events is not None:
            previous_events.extend(transaction_events)
        elif added:
            with _channel_catalog_lock:
                _pending_transaction_events.setdefault(
                    str(channel), [],
                ).extend(transaction_events)
            _schedule_pending_channel_publish(str(channel))
        else:
            _dispatch_transaction_events(transaction_events)
    return outcome


def _rollback_mutation_state(state, compensator):
    """Expose a rollback token when an inner compensation itself fails."""
    try:
        compensator(state)
    except Exception as exc:
        try:
            setattr(exc, "_channel_transaction_state", state)
        except Exception:
            pass
        raise


def _run_buffered_store_transaction(mutation):
    """Suppress store callbacks until a multi-store mutation fully commits."""
    previous_events = getattr(_transaction_event_local, "events", None)
    events: list[tuple] = []
    _transaction_event_local.events = events
    committed = False
    try:
        result = mutation()
        committed = True
    finally:
        if previous_events is None:
            try:
                del _transaction_event_local.events
            except AttributeError:
                pass
        else:
            _transaction_event_local.events = previous_events
    if committed and events:
        if previous_events is not None:
            previous_events.extend(events)
        else:
            _dispatch_transaction_events(events)
    return result


async def _publish_channel_transaction(channel: str, added: bool):
    """Publish a successful reservation before related async callbacks run."""
    if not added:
        return
    await _publish_pending_channel_events(channel)


def _register_message_channel(channel: str) -> bool:
    """Add a valid message channel to the persistent web catalogue.

    Messages can enter through WebSocket, REST, MCP, schedules, and background
    callbacks. Registration is centralized at the store-to-web boundary rather
    than duplicated in every ingress path. Returns True only on a change.
    """
    added, _error = _admit_message_channel(channel)
    return added


def _reconcile_message_channels() -> list[str]:
    """Restore every durable store's channels with one save/broadcast.

    Structured stores are included so a fail-closed transaction whose final
    catalogue persistence could not complete is self-healing on restart even
    when it has no timeline breadcrumb (notably schedules).
    """
    added: list[str] = []
    if not store:
        return added
    durable_channels = list(store.get_channels())
    if jobs is not None:
        durable_channels.extend(item.get("channel", "general") for item in jobs.list_all())
    if schedules is not None:
        durable_channels.extend(item.get("channel", "general") for item in schedules.list_all())
    if summaries is not None:
        durable_channels.extend(summaries.get_all().keys())
    if session_store is not None:
        durable_channels.extend(item.get("channel", "general") for item in session_store.list_all())
    with _channel_catalog_lock:
        channels = room_settings.setdefault("channels", ["general"])
        limit = _channel_discovery_limit()
        for channel in durable_channels:
            if channel_name_error(channel) or channel in channels:
                continue
            if len(channels) >= limit:
                log.error(
                    "cannot discover historical channel %r: catalogue full (%d/%d)",
                    channel,
                    len(channels),
                    limit,
                )
                continue
            channels.append(channel)
            added.append(channel)
        if added:
            _bump_catalogue_revision_locked()
            try:
                _save_settings()
            except OSError:
                log.exception("could not persist reconciled channel catalogue")
    if added:
        _queue_settings_broadcast()
    return added


def _queue_settings_broadcast():
    """Schedule exactly one settings broadcast from sync startup/worker code."""
    if _event_loop is None:
        return
    try:
        loop = asyncio.get_running_loop()
        if loop is _event_loop:
            asyncio.ensure_future(broadcast_settings())
            return
    except RuntimeError:
        pass
    asyncio.run_coroutine_threadsafe(broadcast_settings(), _event_loop)


def store_channel_message(sender: str, text: str, **kwargs) -> tuple[dict | None, str | None]:
    """Validate/admit a channel and persist its message as one transaction.

    MCP worker threads, REST, and WebSocket ingress all use this function so a
    delete cannot slip between catalogue reservation and message persistence.
    """
    channel = kwargs.get("channel", "general")
    with _channel_catalog_lock:
        settings_before = _settings_snapshot_locked()
        pending_before = set(_catalogue_broadcast_pending)
        # Do not publish a catalogue entry before its durable message exists.
        # The message is the recovery source if the final settings commit fails.
        added, error = _admit_message_channel(channel, persist=False)
        if error:
            return None, error
        try:
            message = store.add(sender, text, **kwargs)
        except Exception:
            if added:
                room_settings.clear()
                room_settings.update(settings_before)
                _catalogue_broadcast_pending.clear()
                _catalogue_broadcast_pending.update(pending_before)
            raise
        if added:
            try:
                _save_settings()
            except Exception:
                # The record is already durable.  Retain the channel visibly
                # fail-closed; startup reconciliation can persist it later.
                log.exception(
                    "could not persist channel %s after durable message; "
                    "retaining runtime admission",
                    channel,
                )
        return message, None


def _delete_catalogued_channel(name: str) -> tuple[bool, str | None]:
    """Delete catalogue state and messages without an add/delete race."""
    global _last_active_channel
    with _channel_catalog_lock:
        channels = room_settings.setdefault("channels", ["general"])
        if name == "general":
            return False, "the general channel cannot be deleted"
        if name not in channels:
            return False, f"channel '{name}' does not exist"
        dependency_error = _channel_dependency_error_locked(name)
        if dependency_error:
            return False, dependency_error
        settings_before = _settings_snapshot_locked()
        pending_before = set(_catalogue_broadcast_pending)
        last_before = _last_active_channel
        agent_last_before = dict(_agent_last_channel)
        message_state_before = store.snapshot_state()
        try:
            # Delete messages first. If persistence fails, retaining an empty
            # catalogue entry is safer than hiding messages that may remain.
            store.delete_channel(name)
            channels.remove(name)
            _bump_catalogue_revision_locked()
            _catalogue_broadcast_pending.discard(name)
            _migrate_channel_activity_locked(name, "general")
            _save_settings()
        except Exception:
            room_settings.clear()
            room_settings.update(settings_before)
            _catalogue_broadcast_pending.clear()
            _catalogue_broadcast_pending.update(pending_before)
            _last_active_channel = last_before
            _agent_last_channel.clear()
            _agent_last_channel.update(agent_last_before)
            try:
                store.restore_state(message_state_before)
            except Exception:
                # The old channel remains visible.  This is fail-closed even
                # if message restoration itself cannot be completed.
                log.exception("failed to restore messages after channel delete failure")
            raise
        return True, None


def _rename_catalogued_channel(
    old_name: str, new_name: str,
) -> tuple[dict | None, str | None]:
    """Rename one channel and return the authoritative settings snapshot."""
    global _last_active_channel
    with _channel_catalog_lock:
        channels = room_settings.setdefault("channels", ["general"])
        if old_name == "general":
            return None, "the general channel cannot be renamed"
        if old_name not in channels:
            return None, f"channel '{old_name}' does not exist"
        if new_name in channels:
            return None, f"channel '{new_name}' already exists"
        dependency_error = _channel_dependency_error_locked(old_name)
        if dependency_error:
            return None, dependency_error

        settings_before = _settings_snapshot_locked()
        pending_before = set(_catalogue_broadcast_pending)
        last_before = _last_active_channel
        agent_last_before = dict(_agent_last_channel)
        message_state_before = store.snapshot_state()
        idx = channels.index(old_name)
        channels[idx] = new_name
        try:
            store.rename_channel(old_name, new_name)
            _bump_catalogue_revision_locked()
            _catalogue_broadcast_pending.discard(old_name)
            _catalogue_broadcast_pending.discard(new_name)
            _migrate_channel_activity_locked(old_name, new_name)
            _save_settings()
        except Exception:
            room_settings.clear()
            room_settings.update(settings_before)
            _catalogue_broadcast_pending.clear()
            _catalogue_broadcast_pending.update(pending_before)
            _last_active_channel = last_before
            _agent_last_channel.clear()
            _agent_last_channel.update(agent_last_before)
            try:
                store.restore_state(message_state_before)
            except Exception:
                log.exception(
                    "failed to restore message channel rename %s -> %s; "
                    "exposing every observed message channel fail-closed",
                    old_name,
                    new_name,
                )
                observed = store.get_channels()
                channels = room_settings.setdefault("channels", ["general"])
                for observed_channel in observed:
                    if not channel_name_error(observed_channel) and observed_channel not in channels:
                        channels.append(observed_channel)
                _bump_catalogue_revision_locked()
                try:
                    _save_settings()
                except Exception:
                    log.exception("could not persist fail-closed rename catalogue")
            raise
        return _settings_snapshot_locked(), None


async def _rename_channel_and_broadcast(
    old_name: str, new_name: str,
) -> tuple[bool, str | None]:
    """Commit rename and its two UI frames in one outbound critical section."""
    async with _channel_outbound_lock:
        snapshot, error = _rename_catalogued_channel(old_name, new_name)
        if error:
            return False, error
        import mcp_bridge
        try:
            mcp_bridge.migrate_cursors_rename(old_name, new_name)
        except Exception:
            log.exception("could not migrate MCP cursors for channel rename %s -> %s", old_name, new_name)
        revision = snapshot["catalogue_revision"]

        # Rename first: clients which were actively viewing the old channel
        # migrate their DOM and active pointer before settings removes old_name.
        await _broadcast_channel_payload_locked({
            "type": "channel_renamed",
            "old_name": old_name,
            "new_name": new_name,
            "catalogue_revision": revision,
        })
        await _broadcast_channel_payload_locked({
            "type": "settings",
            "data": snapshot,
            "catalogue_revision": revision,
        })
        return True, None


def _save_settings():
    """Atomically persist a locked settings snapshot with best-effort dir sync."""
    with _channel_catalog_lock:
        p = _settings_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f".{p.name}.{uuid.uuid4().hex}.tmp")
        payload = json.dumps(_settings_snapshot_locked(), indent=2)
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, p)
            try:
                dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                dir_fd = os.open(str(p.parent), dir_flags)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                # Directory fsync is unsupported on some Windows filesystems.
                pass
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass


def _apply_room_settings_update(new: dict):
    """Persist a settings update before applying router side effects."""
    with _channel_catalog_lock:
        settings_before = copy.deepcopy(room_settings)
        router_hops_to_apply = None
        try:
            if "title" in new and isinstance(new["title"], str):
                room_settings["title"] = new["title"].strip() or "agentchattr"
            if "username" in new and isinstance(new["username"], str):
                room_settings["username"] = new["username"].strip() or "user"
            if "font" in new and new["font"] in ("mono", "serif", "sans"):
                room_settings["font"] = new["font"]
            if "max_agent_hops" in new:
                try:
                    hops = max(0, min(int(new["max_agent_hops"]), 50))
                    room_settings["max_agent_hops"] = hops
                    router_hops_to_apply = hops
                except (ValueError, TypeError):
                    pass
            if "contrast" in new and new["contrast"] in ("normal", "high"):
                room_settings["contrast"] = new["contrast"]
            if "rules_refresh_interval" in new:
                try:
                    interval = int(new["rules_refresh_interval"])
                    room_settings["rules_refresh_interval"] = max(0, min(interval, 100))
                except (ValueError, TypeError):
                    pass
            if "history_limit" in new:
                value = str(new["history_limit"]).strip().lower()
                if value == "all":
                    room_settings["history_limit"] = "all"
                else:
                    try:
                        value_int = int(value)
                        room_settings["history_limit"] = max(1, min(value_int, 10000))
                    except (ValueError, TypeError):
                        pass
            if "custom_roles" in new and isinstance(new["custom_roles"], list):
                room_settings["custom_roles"] = [
                    str(role).strip()[:20] for role in new["custom_roles"]
                    if isinstance(role, str) and role.strip()
                ][:20]
            _save_settings()
        except Exception:
            room_settings.clear()
            room_settings.update(settings_before)
            raise
        # Setting zero resets every channel's loop-guard state.  Do it only
        # after the corresponding settings bytes are durable, so a failed save
        # cannot silently release paused channels or erase their hop counters.
        if router_hops_to_apply is not None and router is not None:
            router.max_hops = router_hops_to_apply


def _extract_agent_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-agent-token", "").strip()


def _resolve_authenticated_agent(request: Request) -> dict | None:
    if not registry:
        return None
    token = _extract_agent_token(request)
    if not token:
        return None
    return registry.resolve_token(token)


# --- Security middleware ---
# Paths that don't require the session token (public assets).
_PUBLIC_PREFIXES = ("/", "/static/")


def _install_security_middleware(token: str, cfg: dict):
    """Add token validation and origin checking middleware to the app."""
    import app as _self
    _self.session_token = token
    port = cfg.get("server", {}).get("port", 8300)
    allowed_origins = {
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
    }

    class SecurityMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            path = request.url.path

            # Static assets, index page, and uploaded images are public.
            # The index page injects the token client-side via same-origin script.
            # Uploads use random filenames and have path-traversal protection.
            if path == "/" or path.startswith(("/static/", "/uploads/", "/api/roles")):
                return await call_next(request)

            # Agent registration/heartbeat: loopback only (no remote agent minting).
            if path.startswith(("/api/register", "/api/deregister/", "/api/heartbeat/")):
                client_ip = request.client.host if request.client else ""
                if client_ip not in ("127.0.0.1", "::1", "localhost"):
                    return JSONResponse(
                        {"error": f"forbidden: agent registration is restricted to local loopback. Source {client_ip} is not allowed."},
                        status_code=403,
                    )
                return await call_next(request)

            # --- Origin check (blocks cross-origin / DNS-rebinding attacks) ---
            origin = request.headers.get("origin")
            if origin and origin not in allowed_origins:
                return JSONResponse(
                    {"error": "forbidden: origin not allowed"},
                    status_code=403,
                )

            # --- Token check ---
            # Allow registered agents to authenticate via Bearer token
            # for /api/messages and /api/send (no browser session needed).
            auth_header = request.headers.get("authorization", "")
            # /api/rotate-token authenticates by possession INSIDE the endpoint
            # (live instances only). It must not go through resolve_token here:
            # that call transparently reactivates reclaimable identities, and a
            # dormant token must never mint a fresh credential via rotation.
            if auth_header.lower().startswith("bearer ") and path.startswith("/api/rotate-token/"):
                return await call_next(request)
            # Migration-lease endpoints validate the current bearer and exact
            # identity atomically with the lease/registry lock.  Pre-resolving
            # here would reintroduce a timeout/deregister race.
            if auth_header.lower().startswith("bearer ") and path.startswith("/api/migration-lease/"):
                return await call_next(request)
            if auth_header.lower().startswith("bearer ") and (path in ("/api/messages", "/api/send") or path.startswith("/api/rules/")):
                bearer = auth_header[7:].strip()
                if _self.registry and _self.registry.resolve_token(bearer):
                    return await call_next(request)

            req_token = (
                request.headers.get("x-session-token")
                or request.query_params.get("token")
            )
            if req_token != _self.session_token:
                return JSONResponse(
                    {"error": "forbidden: invalid or missing session token"},
                    status_code=403,
                )

            return await call_next(request)

    app.add_middleware(SecurityMiddleware)


def configure(cfg: dict, session_token: str = ""):
    global store, rules, summaries, jobs, schedules, router, agents, registry, migration_leases, session_store, session_engine, config
    config = cfg
    # --- Security: store the session token and install middleware ---
    _install_security_middleware(session_token, cfg)

    data_dir = cfg.get("server", {}).get("data_dir", "./data")
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    # Load the strict lease store before any registry/background cleanup.  A
    # corrupt or torn store remains attached in an unhealthy fail-closed state,
    # freezing topology until an operator repairs it.
    migration_leases = MigrationLeaseStore(data_dir)

    log_path = Path(data_dir) / "agentchattr_log.jsonl"
    legacy_log_path = Path(data_dir) / "room_log.jsonl"
    if not log_path.exists() and legacy_log_path.exists():
        # Backward compatibility for existing installs.
        log_path = legacy_log_path

    store = MessageStore(str(log_path))
    # Initialize store upload dir from config
    raw_upload_dir = cfg.get("images", {}).get("upload_dir", "./uploads")
    store.upload_dir = Path(raw_upload_dir)
    
    # Rules store — migrates from legacy decisions.json automatically
    rules_path = Path(data_dir) / "rules.json"
    legacy_decisions = Path(data_dir) / "decisions.json"
    if not rules_path.exists() and legacy_decisions.exists():
        legacy_decisions.rename(rules_path)
    rules = RuleStore(str(rules_path))
    rules.on_change(_on_rule_change)

    summaries = SummaryStore(str(Path(data_dir) / "summaries.json"))

    # Migrate legacy activities.json → jobs.json
    jobs_path = Path(data_dir) / "jobs.json"
    legacy_activities = Path(data_dir) / "activities.json"
    if not jobs_path.exists() and legacy_activities.exists():
        legacy_activities.rename(jobs_path)

    jobs = JobStore(str(jobs_path))
    jobs.on_change(_on_job_change)

    schedules = ScheduleStore(str(Path(data_dir) / "schedules.json"))
    schedules.on_change(_on_schedule_change)

    max_hops = cfg.get("routing", {}).get("max_agent_hops", 4)

    # Registry: single source of truth for all live agent state
    registry = RuntimeRegistry(data_dir=data_dir)
    registry.seed(cfg.get("agents", {}))
    registry.attach_migration_leases(migration_leases)
    restored_leases = migration_leases.reconcile_registry(registry)
    if not migration_leases.healthy:
        log.error("Migration lease protection is fail-closed: %s", migration_leases.health_error)
    elif restored_leases:
        # Arm the ordinary crash timeout. While held, atomic deregistration is
        # rejected through the fixed recovery-protection horizon (or a later
        # active expiry); only then can the stale timestamp resume cleanup.
        import time as _lease_time
        import mcp_bridge as _lease_mcp
        with _lease_mcp._presence_lock:
            for restored_name in restored_leases:
                _lease_mcp._presence[restored_name] = _lease_time.time()
    registry.on_change(_on_registry_change)

    # Router starts with base agent names (backward compat for direct MCP users),
    # registry.on_change updates it dynamically when instances register/deregister
    agent_names = list(set(
        list(cfg.get("agents", {}).keys()) + registry.get_active_names()
    ))
    router = Router(
        agent_names=agent_names,
        default_mention=cfg.get("routing", {}).get("default", "none"),
        max_hops=max_hops,
        online_checker=lambda: set(registry.get_active_names()) if registry else set(),
    )
    agents = AgentTrigger(registry, data_dir=data_dir)

    # Sessions
    ROOT = Path(__file__).parent
    session_store = SessionStore(
        str(Path(data_dir) / "session_runs.json"),
        templates_dir=str(ROOT / "session_templates"),
    )
    session_engine = SessionEngine(session_store, store, agents, registry)
    session_store.on_change(_on_session_change)

    # Bridge: when ANY message is added to store (including via MCP),
    # broadcast to all WebSocket clients
    store.on_message(_on_store_message)

    _load_settings()
    # The message log is durable while settings may lag (for example, an
    # MCP-created channel from an older server). Reconcile before the first
    # browser connects so channel tabs and per-channel history are complete.
    _reconcile_message_channels()
    _load_hats()

    # Apply saved loop guard setting
    if "max_agent_hops" in room_settings:
        router.max_hops = room_settings["max_agent_hops"]

    # Background thread: check for wrapper recovery flag files
    _data_dir = Path(data_dir)

    _known_online: set[str] = set()  # agents we've seen join — track for leave messages
    _posted_leave: set[str] = set()  # agents we've already posted a leave for — debounce

    _known_active = set()

    def _background_checks():
        import time as _time
        import mcp_bridge

        while True:
            _time.sleep(3)
            # Recovery flags
            try:
                for flag in _data_dir.glob("*_recovered"):
                    agent_name = flag.read_text("utf-8").strip()
                    flag.unlink()
                    store.add(
                        "system",
                        f"Agent routing for {agent_name} interrupted — auto-recovered. "
                        "If agents aren't responding, try sending your message again."
                    )
            except Exception:
                pass

            # Pending instances (slot 2+) wait for human naming or agent claim.
            # No auto-confirm — identity must be explicitly resolved.

            # Presence expiry — post leave messages (but do NOT deregister).
            # Deregistration only happens via /api/deregister (wrapper shutdown)
            # OR the 60s crash timeout below.
            # Short timeout (10s) prevents slot theft when MCP tool calls are intermittent.
            try:
                now = _time.time()
                with mcp_bridge._presence_lock:
                    currently_online = {
                        name for name, ts in mcp_bridge._presence.items()
                        if now - ts < mcp_bridge.PRESENCE_TIMEOUT
                    }
                    currently_active = set()
                    for name, active in mcp_bridge._activity.items():
                        if active:
                            if now - mcp_bridge._activity_ts.get(name, 0) < mcp_bridge.ACTIVITY_TIMEOUT:
                                currently_active.add(name)
                            else:
                                mcp_bridge._activity[name] = False  # auto-expire

                # Crash timeout: if a wrapper hasn't heartbeated for 60s,
                # it's dead — deregister it to free the slot.
                _CRASH_TIMEOUT = 15
                registered = set(registry.get_all_names())
                for name in registered:
                    with mcp_bridge._presence_lock:
                        last_seen = mcp_bridge._presence.get(name, 0)
                    if last_seen > 0 and now - last_seen > _CRASH_TIMEOUT:
                        result = registry.deregister(name)
                        if result and result.get("ok"):
                            log.info(f"Crash timeout: deregistering {name} (no heartbeat for {_CRASH_TIMEOUT}s)")
                            mcp_bridge.purge_identity(name)
                            registry.clean_renames_for(name)
                            renamed = result.get("_renamed_back")
                            if renamed:
                                mcp_bridge.migrate_identity(renamed["old"], renamed["new"])
                                store.rename_sender(renamed["old"], renamed["new"])
                                _migrate_agent_last_channel(renamed["old"], renamed["new"])
                                if _event_loop:
                                    rename_event = json.dumps({
                                        "type": "agent_renamed",
                                        "old_name": renamed["old"],
                                        "new_name": renamed["new"],
                                    })
                                    asyncio.run_coroutine_threadsafe(_broadcast(rename_event), _event_loop)
                            store.add(name, f"{name} disconnected (timeout)", msg_type="leave", channel=_agent_last_channel.get(name, _last_active_channel))
                            _posted_leave.add(name)

                # Re-fetch registered names (may have changed from crash timeout above)
                registered = set(registry.get_all_names())

                # Detect registered instances going offline (leave message only)
                timed_out = registered - currently_online
                for name in timed_out:
                    inst = registry.get_instance(name)
                    if not inst:
                        continue
                    # Skip names that were just renamed (not actually offline)
                    with mcp_bridge._presence_lock:
                        was_renamed = name in mcp_bridge._renamed_from
                        if was_renamed:
                            mcp_bridge._renamed_from.discard(name)
                    if was_renamed:
                        continue
                    # Post leave message ONCE per offline transition (debounced)
                    if name not in _posted_leave:
                        _posted_leave.add(name)
                        store.add(name, f"{name} disconnected", msg_type="leave", channel=_agent_last_channel.get(name, _last_active_channel))

                # Clear leave debounce for agents that came back online
                _posted_leave -= currently_online

                # Detect other agents (non-registered) going offline
                went_offline = (_known_online - currently_online) - timed_out
                for name in went_offline:
                    # Skip leave messages for names that were just renamed
                    with mcp_bridge._presence_lock:
                        was_renamed = name in mcp_bridge._renamed_from
                        if was_renamed:
                            mcp_bridge._renamed_from.discard(name)
                    if was_renamed:
                        continue
                    if not registry.is_registered(name) and name not in _posted_leave:
                        _posted_leave.add(name)
                        store.add(name, f"{name} disconnected", msg_type="leave", channel=_agent_last_channel.get(name, _last_active_channel))

                if _known_online != currently_online and _event_loop:
                    asyncio.run_coroutine_threadsafe(broadcast_status(), _event_loop)

                # Clear stale activity for agents that went offline
                with mcp_bridge._presence_lock:
                    stale_active = [n for n in mcp_bridge._activity
                                    if mcp_bridge._activity.get(n) and n not in currently_online]
                    for n in stale_active:
                        mcp_bridge._activity[n] = False
                    if stale_active:
                        currently_active -= set(stale_active)

                # Broadcast status on any change (online set or activity set)
                if currently_active != _known_active or _known_online != currently_online:
                    _known_active.clear()
                    _known_active.update(currently_active)
                    if _event_loop:
                        asyncio.run_coroutine_threadsafe(broadcast_status(), _event_loop)
                _known_online.clear()
                _known_online.update(currently_online)
            except Exception:
                pass

    threading.Thread(target=_background_checks, daemon=True).start()

    # --- Schedule runner: fires due scheduled prompts every 30s ---
    def _schedule_runner():
        import time as _time
        while True:
            _time.sleep(30)
            try:
                if not schedules:
                    continue
                due = schedules.run_due()
                for s in due:
                    prompt = s.get("prompt", "")
                    targets = s.get("targets", [])
                    channel = s.get("channel", "general")
                    if not prompt or not targets:
                        schedules.mark_run(s["id"])
                        continue
                    sender = s.get("created_by", "user")
                    mention_str = " ".join(f"@{t}" for t in targets)
                    full_text = f"{mention_str} {prompt}" if mention_str else prompt
                    # store.add triggers _handle_new_message via callback,
                    # which routes @mentions to agents — no manual trigger needed.
                    _msg, channel_error = store_channel_message(
                        sender,
                        full_text,
                        channel=channel,
                    )
                    if channel_error:
                        log.error("scheduled message rejected for channel %r: %s", channel, channel_error)
                        continue
                    if s.get("one_shot"):
                        schedules.delete(s["id"])
                    else:
                        schedules.mark_run(s["id"])
            except Exception:
                log.exception("schedule runner error")

    threading.Thread(target=_schedule_runner, daemon=True).start()


# --- Store → WebSocket bridge ---

_event_loop = None  # set by run.py after starting the event loop
_last_active_channel: str = "general"  # last channel any message was sent in
# Per-agent last channel: where each sender was most recently active. Used to
# route leave/disconnect messages to the channel that agent was talking in,
# instead of the global last-active channel (which is usually #general and made
# leave spam land in the wrong place).
_agent_last_channel: dict[str, str] = {}


def _migrate_channel_activity_locked(old_channel: str, new_channel: str):
    """Migrate all in-memory channel pointers; caller holds catalogue lock."""
    global _last_active_channel
    if _last_active_channel == old_channel:
        _last_active_channel = new_channel
    for agent_name, channel in list(_agent_last_channel.items()):
        if channel == old_channel:
            _agent_last_channel[agent_name] = new_channel


def _channel_dependency_error_locked(channel: str) -> str | None:
    """Reject destructive catalogue changes while structured state refers to it.

    Historical sessions count as dependencies too: their persisted transcript
    and output references must not silently change meaning after a channel
    rename/delete.
    """
    dependencies: list[str] = []
    try:
        if jobs is not None:
            count = len(jobs.list_all(channel=channel))
            if count:
                dependencies.append(f"jobs ({count})")
        if schedules is not None:
            count = sum(1 for item in schedules.list_all() if item.get("channel", "general") == channel)
            if count:
                dependencies.append(f"schedules ({count})")
        if summaries is not None and summaries.get(channel) is not None:
            dependencies.append("summary")
        if session_store is not None:
            count = len(session_store.list_all(channel=channel))
            if count:
                dependencies.append(f"sessions ({count})")
    except Exception:
        log.exception("could not verify dependencies for channel %s", channel)
        return (
            f"channel '{channel}' dependency check failed; destructive change rejected"
        )
    if not dependencies:
        return None
    return (
        f"channel '{channel}' is in use by {', '.join(dependencies)}; "
        "remove or migrate those dependencies first"
    )


def _migrate_agent_last_channel(old_name: str, new_name: str):
    """Re-key _agent_last_channel across an agent rename.

    Without this, a disconnect for the post-rename name misses the map and
    falls back to the global last-active channel — putting the leave message
    back in the wrong channel. Call this beside every migrate_identity /
    rename_sender path (slot-1 rename, renamed-back, websocket rename_agent,
    /api/label)."""
    if old_name == new_name:
        return
    ch = _agent_last_channel.pop(old_name, None)
    if ch is not None:
        _agent_last_channel[new_name] = ch


def set_event_loop(loop):
    global _event_loop
    _event_loop = loop


async def _deliver_transaction_event(event: tuple):
    kind, action, payload = event
    if kind == "message":
        await _handle_new_message(payload)
    elif kind == "rule":
        await broadcast_rule(action, payload)
    elif kind == "job":
        await broadcast_job(action, payload)
    elif kind == "schedule":
        await broadcast_schedule(action, payload)
    elif kind == "session":
        await broadcast_session(action, payload)


async def _deliver_transaction_events(events: list[tuple]):
    for event in events:
        await _deliver_transaction_event(event)


def _schedule_coroutine(coro):
    if _event_loop is None:
        return
    try:
        loop = asyncio.get_running_loop()
        if loop is _event_loop:
            asyncio.ensure_future(coro)
            return
    except RuntimeError:
        pass
    asyncio.run_coroutine_threadsafe(coro, _event_loop)


def _dispatch_transaction_events(events: list[tuple]):
    if events:
        _schedule_coroutine(_deliver_transaction_events(events))


def _buffer_or_dispatch_event(kind: str, action, payload: dict):
    if _event_loop is None or _structured_broadcast_suspended:
        return
    event = (kind, action, copy.deepcopy(payload))
    buffer = getattr(_transaction_event_local, "events", None)
    if buffer is not None:
        buffer.append(event)
    else:
        _dispatch_transaction_events([event])


def _schedule_pending_channel_publish(channel: str):
    if _event_loop is not None:
        _schedule_coroutine(_publish_pending_channel_events(channel))


async def _publish_pending_channel_events(channel: str):
    """Publish one admitted tab, then release its committed runtime events."""
    events: list[tuple] = []
    async with _channel_outbound_lock:
        with _channel_catalog_lock:
            needs_settings = channel in _catalogue_broadcast_pending
            has_events = bool(_pending_transaction_events.get(channel))
            if not needs_settings and not has_events:
                return
            snapshot = _settings_snapshot_locked()
        if needs_settings:
            await _broadcast_channel_payload_locked({
                "type": "settings",
                "data": snapshot,
                "catalogue_revision": snapshot["catalogue_revision"],
            })
        with _channel_catalog_lock:
            _catalogue_broadcast_pending.discard(channel)
            events = _pending_transaction_events.pop(channel, [])
    await _deliver_transaction_events(events)


def _on_store_message(msg: dict):
    """Called from any thread when a message is added to the store."""
    _buffer_or_dispatch_event("message", None, msg)


def _on_rule_change(action: str, rule: dict):
    """Called from any thread when a rule changes."""
    _buffer_or_dispatch_event("rule", action, rule)


def _on_job_change(action: str, data: dict):
    """Called from any thread when a job changes."""
    _buffer_or_dispatch_event("job", action, data)


def _on_schedule_change(action: str, schedule: dict):
    """Called from any thread when a schedule changes."""
    _buffer_or_dispatch_event("schedule", action, schedule)


def _on_session_change(action: str, session: dict):
    """Called from any thread when a session changes."""
    if _event_loop is None:
        return
    # Enrich with computed fields so the frontend gets phase_name, current_agent, etc.
    if session_engine:
        session = session_engine._enrich(dict(session))

    # Add completion/interruption banners to chat timeline
    if action == "complete" and store:
        output_id = session.get("output_message_id")
        # Tag the output message so it renders highlighted on reload
        if output_id:
            msg = store.get_by_id(output_id)
            if msg:
                meta = msg.get("metadata") or {}
                meta["session_output"] = True
                store.update_message(output_id, {"metadata": meta})
        store_channel_message(
            sender="system",
            text=f"Session complete: {session.get('template_name', '?')}",
            msg_type="session_end",
            channel=session.get("channel", "general"),
            metadata={"session_id": session.get("id"), "output_message_id": output_id},
        )
    elif action == "interrupt" and store:
        reason = session.get("interrupt_reason", "interrupted")
        store_channel_message(
            sender="system",
            text=f"Session ended: {session.get('template_name', '?')} ({reason})",
            msg_type="session_end",
            channel=session.get("channel", "general"),
            metadata={"session_id": session.get("id"), "reason": reason},
        )

    _buffer_or_dispatch_event("session", action, session)


_draft_ref_re = _re.compile(r'\[([a-f0-9]{8})\]')

def _resolve_draft_lineage(text: str, channel: str) -> tuple[str, int]:
    """Check if a session draft block is a revision of an existing draft.

    Looks at the agent's own message text for a [draft_id] reference, and also
    scans recent channel messages for "revise session draft [XXXX]" requests.
    Returns (draft_id, revision). New drafts get a fresh id and revision=1.
    """
    # Check the message text itself for a draft_id reference
    ref_match = _draft_ref_re.search(text)
    ref_id = ref_match.group(1) if ref_match else None

    if not ref_id:
        # Also check recent messages for a "revise session draft [XXXX]" request
        recent = store.get_recent(count=20, channel=channel)
        for m in reversed(recent):
            m_text = m.get("text", "")
            if "revise session draft" in m_text.lower():
                ref_match = _draft_ref_re.search(m_text)
                if ref_match:
                    ref_id = ref_match.group(1)
                    break

    if ref_id:
        # Find the highest revision for this draft_id in existing messages
        max_rev = 0
        recent = store.get_recent(count=100, channel=channel)
        for m in recent:
            meta = m.get("metadata") or {}
            if meta.get("draft_id") == ref_id:
                max_rev = max(max_rev, meta.get("revision", 1))
        if max_rev > 0:
            return ref_id, max_rev + 1

    return str(uuid.uuid4())[:8], 1


async def _handle_new_message(msg: dict):
    """Broadcast one live message and route its mentions.

    Race contract: deletion may overtake this callback only after a settings
    frame admitting the channel has already been sent.  That authoritative
    frame is allowed to be observed (the deletion's later settings frame
    converges the UI), but a stale/deleted message must never produce a
    ``message`` frame, mention trigger, notification, or activity-pointer
    update.  The repeated durable-id/channel fences below enforce that split.
    """
    # For broadcast slash commands, suppress the raw message — only the expanded
    # version should appear. Delete from store if it was persisted (MCP path),
    # and skip broadcasting the raw text.
    text = msg.get("text", "")
    msg_type = msg.get("type", "chat")
    sender = msg.get("sender", "")
    channel = msg.get("channel", "general")

    # A store callback can be queued and then overtaken by channel/message
    # deletion.  Never let that stale callback resurrect the channel or emit a
    # deleted message.  Messages without an id are the intentional WebSocket
    # slash-command expansion path and are handled below.
    if "id" in msg and not _persisted_message_matches(msg):
        return

    # Publish the catalogue before its first message.  Checked ingress reserves
    # the channel before persisting; legacy/internal writers are admitted here.
    with _channel_catalog_lock:
        # Repeat the existence check while holding the same lock used by
        # channel deletion.  Without this, deletion between the optimistic
        # check above and catalogue admission could still resurrect the tab.
        if "id" in msg and not _persisted_message_matches(msg):
            return
        added, admission_error = _admit_message_channel(channel)
        if admission_error:
            if "id" in msg and _persisted_message_matches(msg):
                store.delete([msg["id"]])
            log.error("dropping undiscoverable message channel %r: %s", channel, admission_error)
            return
        catalogue_changed = added or channel in _catalogue_broadcast_pending
    if catalogue_changed:
        await broadcast_settings()

        with _channel_catalog_lock:
            _catalogue_broadcast_pending.discard(channel)

        # Deletion can run while a slow WebSocket settings send yields.  Recheck
        # before the message broadcast so a late callback cannot leak stale UI.
        if "id" in msg and not _persisted_message_matches(msg):
            return
        if channel not in _settings_snapshot().get("channels", ["general"]):
            return

    # Strip @mentions to find the slash command (e.g. "@claude @codex /hatmaking")
    stripped = _re.sub(r"@[\w-]+\s*", "", text).strip().lower()
    _broadcast_cmds = ("/hatmaking", "/artchallenge", "/roastreview", "/poetry")
    cmd_word = stripped.split()[0] if stripped else ""
    is_broadcast_cmd = cmd_word in _broadcast_cmds
    known_agents = set(registry.get_all_names()) if registry else set()
    known_agents.update(config.get("agents", {}).keys())
    _session_draft_re = _re.compile(r'```session\s*\n(.*?)\n```', _re.DOTALL)
    draft_match = _session_draft_re.search(text)
    is_agent_session_draft = bool(draft_match and sender in known_agents)
    is_hidden_session_request = msg_type == "session_request"

    is_agent_continue = (stripped == "/continue" and sender in known_agents)
    suppress_broadcast = (
        is_broadcast_cmd
        or is_hidden_session_request
        or is_agent_session_draft
        or is_agent_continue
    )

    if not suppress_broadcast:
        if await broadcast(msg) is False:
            return

    # Only a message which survived the outbound catalogue fence may update
    # routing/presence hints.  Synthetic suppressed commands intentionally
    # continue through this path.
    global _last_active_channel
    if msg_type not in ("system", "leave", "join"):
        with _channel_catalog_lock:
            _last_active_channel = channel
            if sender and sender != "system":
                _agent_last_channel[sender] = channel

    # If the raw slash command was persisted (MCP path), silently remove it.
    # It was never broadcast to WebSocket clients, so no delete event needed.
    if suppress_broadcast and msg.get("id"):
        store.delete([msg["id"]])

    # System messages never trigger routing - prevents infinite callback loops
    if sender == "system":
        return

    # Check for slash commands — use stripped text (sans @mentions)
    if stripped == "/continue":
        if sender in known_agents:
            store.add("system", f"Loop guard: only humans can /continue. {sender} tried to self-resume.", channel=channel)
            return
        router.continue_routing(channel)
        store.add("system", f"Routing resumed by {sender}.", channel=channel)
        await broadcast_status()
        return

    if stripped == "/roastreview":
        agent_names = registry.get_all_names() if registry else list(config.get("agents", {}).keys())
        mentions = " ".join(f"@{a}" for a in agent_names)
        store.add(sender, f"{mentions} Time for a roast review! Inspect each other's work and constructively roast it.", channel=channel)
        return

    if stripped.startswith("/artchallenge"):
        parts = stripped.split(None, 1)
        theme = parts[1] if len(parts) > 1 else "anything you like"
        agent_names = registry.get_all_names() if registry else list(config.get("agents", {}).keys())
        mentions = " ".join(f"@{a}" for a in agent_names)
        store.add(
            sender,
            f"{mentions} Art challenge! Create an SVG artwork with the theme: **{theme}**. "
            "Write your SVG code to a .svg file, then attach it using chat_send(image_path=...). "
            "Make it creative, keep it under 5KB. Let's see what you've got!",
            channel=channel,
        )
        return

    if stripped == "/hatmaking":
        agent_names = registry.get_all_names() if registry else list(config.get("agents", {}).keys())
        mentions = " ".join(f"@{a}" for a in agent_names)
        all_instances = registry.get_all() if registry else {}
        agents_cfg = config.get("agents", {})
        color_parts = ", ".join(
            f"{a}={all_instances[a]['color']}" if a in all_instances
            else f"{a}={agents_cfg.get(a, {}).get('color', '#888')}"
            for a in agent_names
        )
        store.add(
            sender,
            f"{mentions} Hat making time! Design a new hat for your avatar using SVG. "
            "Use viewBox=\"0 0 32 16\" so it fits on top of a 32px avatar circle. "
            f"Background is dark (#0f0f17). Avatar colors: {color_parts}. Design for good contrast! "
            "Call chat_set_hat(sender=your_name, svg='<svg ...>...</svg>') to wear it. "
            "Be creative — top hats, party hats, crowns, propeller beanies, whatever you want!",
            channel=channel,
        )
        return

    if stripped.startswith("/poetry"):
        parts = stripped.split(None, 1)
        form = parts[1] if len(parts) > 1 else "haiku"
        if form not in ("haiku", "limerick", "sonnet"):
            form = "haiku"
        agent_names = registry.get_all_names() if registry else list(config.get("agents", {}).keys())
        mentions = " ".join(f"@{a}" for a in agent_names)
        prompts = {
            "haiku": "Write a haiku about the current state of this codebase.",
            "limerick": "Write a limerick about the current state of this codebase.",
            "sonnet": "Write a sonnet about the current state of this codebase.",
        }
        store.add(sender, f"{mentions} {prompts[form]}", channel=channel)
        return

    # Detect session draft blocks from agents only.
    # The session request prompt contains an example ```session block,
    # so treating every non-system sender as a draft source creates a false
    # invalid-draft card the moment the user asks for a custom session.
    _session_draft_re = _re.compile(r'```session\s*\n(.*?)\n```', _re.DOTALL)
    draft_match = _session_draft_re.search(text)
    known_agents = set(registry.get_all_names()) if registry else set()
    known_agents.update(config.get("agents", {}).keys())
    if draft_match and sender in known_agents:
        # Check if this is a revision of an existing draft
        draft_id, revision = _resolve_draft_lineage(text, channel)

        try:
            draft_json = json.loads(draft_match.group(1))
            errors = validate_session_template(draft_json)
            if errors:
                store.add(
                    "system",
                    f"Session draft from {sender} has errors:\n" + "\n".join(f"- {e}" for e in errors),
                    msg_type="session_draft",
                    channel=channel,
                    metadata={"draft_id": draft_id, "revision": revision, "proposed_by": sender,
                              "template": draft_json, "errors": errors, "valid": False},
                )
            else:
                draft_json.setdefault("id", f"draft-{draft_id}")
                store.add(
                    "system",
                    f"Session draft from {sender}: **{draft_json.get('name', '?')}**",
                    msg_type="session_draft",
                    channel=channel,
                    metadata={"draft_id": draft_id, "revision": revision, "proposed_by": sender,
                              "template": draft_json, "errors": [], "valid": True},
                )
        except json.JSONDecodeError:
            store.add(
                "system",
                f"Session draft from {sender} contains invalid JSON.",
                msg_type="session_draft",
                channel=channel,
                metadata={"draft_id": draft_id, "revision": revision, "proposed_by": sender,
                           "errors": ["Invalid JSON in session block"], "valid": False},
            )

    raw_targets = router.get_targets(sender, text, channel)
    # Resolve base family names to actual registered instances
    # e.g. 'claude' → 'claude-prime' when slot-1 was renamed
    targets = []
    for t in raw_targets:
        if registry:
            targets.extend(registry.resolve_to_instances(t))
        else:
            targets.append(t)
    targets = list(dict.fromkeys(targets))  # dedupe, preserve order

    if router.is_paused(channel):
        # Only emit the loop guard notice once per pause
        if not router.is_guard_emitted(channel):
            router.set_guard_emitted(channel)
            store.add(
                "system",
                f"Loop guard: {router.max_hops} agent-to-agent hops reached. "
                "Type /continue to resume.",
                channel=channel
            )
        return

    # Build a readable message string for the wake prompt
    chat_msg = f"{sender}: {text}" if text else ""
    custom_prompt = text if is_hidden_session_request else ""

    # Session turn guard: if a session is active on this channel and the sender
    # is an agent, only allow triggering the agent whose turn it is.
    # Human @mentions are always allowed (the session engine handles pausing).
    sender_is_agent = sender in known_agents
    allowed_agent = session_engine.get_allowed_agent(channel) if session_engine and sender_is_agent else None

    import mcp_bridge
    for target in targets:
        # Skip pending instances — they haven't been named/claimed yet
        if registry:
            inst = registry.get_instance(target)
            if inst and inst.get("state") == "pending":
                continue
        # Session guard: suppress out-of-turn agent triggers
        if allowed_agent and target != allowed_agent:
            continue
        if not mcp_bridge.is_online(target):
            store.add("system", f"{target} appears offline — message queued.", msg_type="system", channel=channel)
        if agents.is_available(target):
            source_ref = f"{msg.get('id')}:{msg.get('uid', '')}"
            await agents.trigger(
                target, message=chat_msg, channel=channel,
                prompt=custom_prompt,
                action_id=agents.action_id_for("message", source_ref, target),
            )


# --- broadcasting ---

async def _broadcast(raw_json: str):
    """Send a pre-serialized JSON string to all WebSocket clients."""
    dead = set()
    for client in list(ws_clients):
        try:
            await client.send_text(raw_json)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)


def _persisted_message_matches(message: dict) -> bool:
    """Return whether id, uid and channel still identify this exact record."""
    if store is None or "id" not in message:
        return False
    persisted = store.get_by_id(message["id"])
    if persisted is None:
        return False
    if persisted.get("uid") != message.get("uid"):
        return False
    return persisted.get("channel", "general") == message.get("channel", "general")


def _message_frame_is_current_locked(payload: dict) -> bool:
    """Validate a persisted message and its channel at the serialization fence."""
    if payload.get("type") != "message":
        return True
    message = payload.get("data") or {}
    if "id" not in message:
        return True
    if not _persisted_message_matches(message):
        return False
    expected_channel = message.get("channel", "general")
    return expected_channel in room_settings.get("channels", ["general"])


async def _broadcast_channel_payload_locked(payload: dict) -> bool:
    """Send a channel frame while the caller holds the outbound lock."""
    dead = set()
    with _channel_catalog_lock:
        # This is deliberately the last check before synchronous JSON
        # serialization.  A queued callback overtaken by delete/rename must not
        # notify clients or resurrect an obsolete channel.
        if not _message_frame_is_current_locked(payload):
            return False
        if "catalogue_revision" not in payload:
            payload = dict(payload)
            payload["catalogue_revision"] = _catalogue_revision()
        data = json.dumps(payload)
    for client in list(ws_clients):
        try:
            await client.send_text(data)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)
    return True


async def _broadcast_channel_payload(payload: dict) -> bool:
    """Serialize catalogue-sensitive frames and attach their revision fence."""
    async with _channel_outbound_lock:
        return await _broadcast_channel_payload_locked(payload)


async def broadcast(msg: dict):
    return await _broadcast_channel_payload({"type": "message", "data": msg})


async def broadcast_status():
    status = agents.get_status()
    channels = _settings_snapshot().get("channels", ["general"])
    status["paused"] = any(router.is_paused(ch) for ch in channels)
    data = json.dumps({"type": "status", "data": status})
    dead = set()
    for client in list(ws_clients):
        try:
            await client.send_text(data)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)


async def broadcast_typing(agent_name: str, is_typing: bool):
    data = json.dumps({"type": "typing", "agent": agent_name, "active": is_typing})
    dead = set()
    for client in list(ws_clients):
        try:
            await client.send_text(data)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)


async def broadcast_clear(channel: str | None = None):
    payload = {"type": "clear"}
    if channel:
        payload["channel"] = channel
    data = json.dumps(payload)
    dead = set()
    for client in list(ws_clients):
        try:
            await client.send_text(data)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)


async def broadcast_todo_update(msg_id: int, status: str | None):
    data = json.dumps({"type": "todo_update", "data": {"id": msg_id, "status": status}})
    dead = set()
    for client in list(ws_clients):
        try:
            await client.send_text(data)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)


async def broadcast_settings():
    snapshot = _settings_snapshot()
    await _broadcast_channel_payload({
        "type": "settings",
        "data": snapshot,
        "catalogue_revision": snapshot["catalogue_revision"],
    })


async def _send_ws_channel_error(
    websocket: WebSocket,
    operation: str,
    error: str,
    *,
    restore_channel: str | None = None,
):
    """Return an authoritative catalogue snapshot for optimistic UI rollback."""
    snapshot = _settings_snapshot()
    payload = {
        "type": "error",
        "code": "channel_rejected",
        "operation": operation,
        "error": error,
        "settings": snapshot,
        "catalogue_revision": snapshot["catalogue_revision"],
    }
    if restore_channel:
        payload["restore_channel"] = restore_channel
    async with _channel_outbound_lock:
        await websocket.send_text(json.dumps(payload))


async def _admit_channel_ingress(channel: object) -> tuple[bool, str | None]:
    """Admit a channel before non-message state mutation and publish it once."""
    with _channel_catalog_lock:
        settings_before = _settings_snapshot_locked()
        pending_before = set(_catalogue_broadcast_pending)
        added, error = _admit_message_channel(channel, persist=False)
        if added:
            try:
                _save_settings()
            except Exception:
                room_settings.clear()
                room_settings.update(settings_before)
                _catalogue_broadcast_pending.clear()
                _catalogue_broadcast_pending.update(pending_before)
                return False, "could not persist channel catalogue"
    if added:
        await _publish_pending_channel_events(str(channel))
    return added, error


async def broadcast_rule(action: str, rule: dict):
    await _broadcast_channel_payload({
        "type": "rule", "action": action, "data": rule,
    })


async def broadcast_job(action: str, data: dict):
    await _broadcast_channel_payload({
        "type": "job", "action": action, "data": data,
    })


async def broadcast_schedule(action: str, schedule: dict):
    await _broadcast_channel_payload({
        "type": "schedule", "action": action, "data": schedule,
    })


async def broadcast_session(action: str, session: dict):
    await _broadcast_channel_payload({
        "type": "session", "action": action, "data": session,
    })


async def broadcast_hats():
    with _hat_lock:
        hats = copy.deepcopy(agent_hats)
    data = json.dumps({"type": "hats", "data": hats})
    dead = set()
    for client in list(ws_clients):
        try:
            await client.send_text(data)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)


async def broadcast_agents():
    """Send updated agent config (from registry) to all WebSocket clients."""
    agent_cfg = registry.get_agent_config() if registry else {}
    data = json.dumps({"type": "agents", "data": agent_cfg})
    dead = set()
    for client in list(ws_clients):
        try:
            await client.send_text(data)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)


def _on_registry_change():
    """Called from registry (any thread) when instances register/deregister/claim/rename."""
    # Update router with current agent names (base names + registered instances)
    if router and registry:
        base_names = list(registry.get_bases().keys())
        # Only include active instances in routing (pending ones are inert)
        instance_names = registry.get_active_names()
        all_names = list(set(base_names + instance_names))
        router.update_agents(all_names)
    # Broadcast to WebSocket clients
    if _event_loop:
        asyncio.run_coroutine_threadsafe(broadcast_agents(), _event_loop)
        asyncio.run_coroutine_threadsafe(broadcast_status(), _event_loop)


# --- WebSocket ---

def _rollback_rule_proposal_state(state):
    """Remove every durable artifact created for one rule proposal."""
    if not state:
        return
    proposal_message = state.get("message")
    if proposal_message is not None:
        store.delete([proposal_message["id"]])
    proposal = state.get("rule")
    if proposal is not None:
        rules.delete(proposal["id"])


def _create_rule_proposal_state(
    text: str, author: str, reason: str, channel: str, *, is_human: bool,
):
    """Create a rule proposal and its optional timeline card as one state bundle."""
    state = {"rule": None, "message": None}
    try:
        rule = rules.propose(text, author, reason)
        state["rule"] = rule
        if rule is None:
            return None
        if is_human:
            if rules.make_draft(rule["id"]) is None:
                raise RuntimeError("could not move rule proposal to draft")
        else:
            message, write_error = store_channel_message(
                author,
                f"Rule proposal: {text}",
                msg_type="rule_proposal",
                channel=channel,
                metadata={
                    "rule_id": rule["id"],
                    "text": text,
                    "status": "pending",
                },
            )
            if write_error:
                raise RuntimeError(write_error)
            state["message"] = message
        return state
    except Exception:
        _rollback_mutation_state(state, _rollback_rule_proposal_state)
        raise


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # --- Security: validate session token on WebSocket connect ---
    token = websocket.query_params.get("token", "")
    if token != session_token:
        # Must accept before closing so the browser receives the close frame.
        # Code 4003 triggers an auto-reload in the client to pick up the new token.
        await websocket.accept()
        await websocket.close(code=4003, reason="forbidden: invalid session token")
        return

    await websocket.accept()

    # Snapshot catalogue + history under the shared lock, then serialize the
    # whole initial stream against live settings/message broadcasts.
    async with _channel_outbound_lock:
        ws_clients.add(websocket)
        with _channel_catalog_lock:
            settings_snapshot = _settings_snapshot_locked()
            revision = settings_snapshot["catalogue_revision"]
            limit_val = settings_snapshot.get("history_limit", "all")
            count = 10000 if limit_val == "all" else int(limit_val)
            history = []
            for ch in settings_snapshot["channels"]:
                history.extend(store.get_recent(count, channel=ch))
        history.sort(key=lambda m: m.get("timestamp", 0))
        await websocket.send_text(json.dumps({
            "type": "settings", "data": settings_snapshot,
            "catalogue_revision": revision,
        }))
        agent_cfg = registry.get_agent_config() if registry else {}
        await websocket.send_text(json.dumps({"type": "agents", "data": agent_cfg}))
        base_colors = {
            name: {"color": cfg.get("color", "#888"), "label": cfg.get("label", name)}
            for name, cfg in config.get("agents", {}).items()
        }
        await websocket.send_text(json.dumps({"type": "base_colors", "data": base_colors}))
        await websocket.send_text(json.dumps({"type": "todos", "data": store.get_todos()}))
        await websocket.send_text(json.dumps({"type": "rules", "data": rules.list_all()}))
        with _hat_lock:
            hats_snapshot = copy.deepcopy(agent_hats)
        await websocket.send_text(json.dumps({"type": "hats", "data": hats_snapshot}))
        await websocket.send_text(json.dumps({"type": "jobs", "data": jobs.list_all()}))
        await websocket.send_text(json.dumps({"type": "schedules", "data": schedules.list_all()}))
        if registry:
            for inst in registry.get_all().values():
                if inst.get("state") == "pending":
                    await websocket.send_text(json.dumps({
                        "type": "pending_instance",
                        "name": inst["name"],
                        "base": inst.get("base", ""),
                        "label": inst.get("label", inst["name"]),
                        "color": inst.get("color", "#888"),
                    }))
        for msg in history:
            await websocket.send_text(json.dumps({
                "type": "message", "data": msg,
                "catalogue_revision": revision,
            }))

    # Send status
    await broadcast_status()

    try:
        while True:
            raw = await websocket.receive_text()
            event = json.loads(raw)

            if event.get("type") == "message":
                text = event.get("text", "").strip()
                attachments = event.get("attachments", [])
                sender = event.get("sender") or room_settings.get("username", "user")
                channel = event.get("channel", "general")

                if not text and not attachments:
                    continue
                validation_error = channel_name_error(channel)
                if validation_error:
                    await _send_ws_channel_error(websocket, "message", validation_error)
                    continue

                # Command handling
                if text.startswith("/"):
                    cmd_parts = text.split()
                    cmd = cmd_parts[0].lower()
                    if cmd == "/clear":
                        store.clear(channel=channel)
                        await broadcast_clear(channel=channel)
                        continue
                    _added, admission_error = _admit_message_channel(channel)
                    if admission_error:
                        await _send_ws_channel_error(websocket, "message", admission_error)
                        continue
                    if cmd == "/continue":
                        router.continue_routing()
                        store.add("system", "Resuming agent conversation...", msg_type="system", channel=channel)
                        await broadcast_status()
                        continue
                    # Broadcast slash commands — expand without storing the raw command.
                    # _handle_new_message will store the expanded version.
                    if cmd in ("/hatmaking", "/artchallenge", "/roastreview", "/poetry"):
                        await _handle_new_message({"sender": sender, "text": text, "channel": channel})
                        continue

                # Store message — the on_message callback handles broadcast + triggers
                reply_to = event.get("reply_to")
                if reply_to is not None:
                    reply_to = int(reply_to)

                _msg, admission_error = store_channel_message(
                    sender,
                    text,
                    attachments=attachments,
                    reply_to=reply_to,
                    channel=channel,
                )
                if admission_error:
                    await _send_ws_channel_error(websocket, "message", admission_error)

            elif event.get("type") == "delete":
                ids = event.get("ids", [])
                if ids:
                    async with _channel_outbound_lock:
                        deleted = store.delete([int(i) for i in ids])
                        if deleted:
                            data = json.dumps({"type": "delete", "ids": deleted})
                            dead = set()
                            for client in list(ws_clients):
                                try:
                                    await client.send_text(data)
                                except Exception:
                                    dead.add(client)
                            ws_clients.difference_update(dead)
                continue

            elif event.get("type") == "todo_add":
                msg_id = event.get("id")
                if msg_id is not None:
                    store.add_todo(int(msg_id))
                    await broadcast_todo_update(int(msg_id), "todo")
                continue

            elif event.get("type") == "todo_toggle":
                msg_id = event.get("id")
                if msg_id is not None:
                    mid = int(msg_id)
                    status = store.get_todo_status(mid)
                    if status == "todo":
                        store.complete_todo(mid)
                        await broadcast_todo_update(mid, "done")
                    elif status == "done":
                        store.reopen_todo(mid)
                        await broadcast_todo_update(mid, "todo")
                continue

            elif event.get("type") == "todo_remove":
                msg_id = event.get("id")
                if msg_id is not None:
                    store.remove_todo(int(msg_id))
                    await broadcast_todo_update(int(msg_id), None)
                continue

            elif event.get("type") in ("decision_propose", "rule_propose"):
                text = event.get("text") or event.get("decision", "")
                text = text.strip()
                author = event.get("author") or event.get("owner") or room_settings.get("username", "user")
                reason = event.get("reason", "")
                is_human = author.lower() == room_settings.get("username", "user").lower()
                if text:
                    channel = event.get("channel", "general")
                    try:
                        rule_state, added, admission_error = _run_channel_state_transaction(
                            channel,
                            lambda: _create_rule_proposal_state(
                                text, author, reason, channel, is_human=is_human,
                            ),
                            compensator=_rollback_rule_proposal_state,
                        )
                    except Exception:
                        log.exception("rule proposal failed after channel reservation")
                        await _send_ws_channel_error(
                            websocket, "rule_propose", "could not create rule proposal",
                        )
                        continue
                    if admission_error:
                        await _send_ws_channel_error(websocket, "rule_propose", admission_error)
                        continue
                    if rule_state is None:
                        await _send_ws_channel_error(
                            websocket, "rule_propose", "too many rules",
                        )
                        continue
                    await _publish_channel_transaction(channel, added)
                continue

            elif event.get("type") in ("decision_approve", "rule_activate"):
                rid = event.get("id")
                if rid is not None:
                    rules.activate(int(rid))
                continue

            elif event.get("type") in ("decision_unapprove", "rule_deactivate"):
                rid = event.get("id")
                if rid is not None:
                    rules.deactivate(int(rid))
                continue

            elif event.get("type") == "rule_make_draft":
                rid = event.get("id")
                if rid is not None:
                    rules.make_draft(int(rid))
                continue

            elif event.get("type") in ("decision_edit", "rule_edit"):
                rid = event.get("id")
                if rid is not None:
                    rules.edit(
                        int(rid),
                        text=event.get("text") or event.get("decision"),
                        reason=event.get("reason"),
                    )
                continue

            elif event.get("type") in ("decision_delete", "rule_delete"):
                rid = event.get("id")
                if rid is not None:
                    rules.delete(int(rid))
                continue

            elif event.get("type") == "rule_remind":
                rules.set_remind()
                remind_data = json.dumps({"type": "rules_remind", "data": {}})
                for client in list(ws_clients):
                    try:
                        await client.send_text(remind_data)
                    except Exception:
                        pass
                continue

            elif event.get("type") == "update_settings":
                new = event.get("data", {})
                _apply_room_settings_update(new)
                await broadcast_settings()

            elif event.get("type") == "rename_agent":
                agent_name = (event.get("name") or "").strip()
                new_label = (event.get("label") or "").strip()
                if agent_name and new_label and registry:
                    # Derive a sanitized sender ID from the label
                    import re as _re
                    new_id = _re.sub(r'[^a-z0-9-]', '', new_label.lower().replace(' ', '-')).strip('-')
                    if not new_id:
                        new_id = agent_name  # fallback: keep old name, just change label
                    if new_id == agent_name:
                        # Same ID — label-only change
                        registry.set_label(agent_name, new_label)
                    else:
                        result = registry.rename(agent_name, new_id, new_label)
                        if isinstance(result, str):
                            # Rename failed (collision etc.) — fall back to label-only
                            registry.set_label(agent_name, new_label)
                        else:
                            # Migrate presence + cursors to new name
                            import mcp_bridge
                            mcp_bridge.migrate_identity(agent_name, new_id)
                            # Update sender on all historical messages
                            store.rename_sender(agent_name, new_id)
                            _migrate_agent_last_channel(agent_name, new_id)
                            # Notify clients so they can update sender in DOM
                            rename_event = json.dumps({
                                "type": "agent_renamed",
                                "old_name": agent_name,
                                "new_name": new_id,
                            })
                            await _broadcast(rename_event)
                continue

            elif event.get("type") == "name_pending":
                # Human names a pending instance (from lightbox)
                agent_name = (event.get("name") or "").strip()
                new_label = (event.get("label") or "").strip()
                if agent_name and registry:
                    if not new_label:
                        # Accept default name
                        registry.confirm_pending(agent_name)
                    else:
                        import re as _re
                        new_id = _re.sub(r'[^a-z0-9-]', '', new_label.lower().replace(' ', '-')).strip('-')
                        if not new_id:
                            new_id = agent_name
                        if new_id == agent_name:
                            # Same ID — just update label and confirm
                            registry.set_label(agent_name, new_label)
                            registry.confirm_pending(agent_name)
                        else:
                            result = registry.rename(agent_name, new_id, new_label)
                            if isinstance(result, str):
                                # Rename failed — just confirm with label
                                registry.set_label(agent_name, new_label)
                                registry.confirm_pending(agent_name)
                            else:
                                # Rename succeeded — confirm new name
                                registry.confirm_pending(new_id)
                                import mcp_bridge
                                mcp_bridge.migrate_identity(agent_name, new_id)
                                # Update sender on all historical messages
                                store.rename_sender(agent_name, new_id)
                                _migrate_agent_last_channel(agent_name, new_id)
                                rename_event = json.dumps({
                                    "type": "agent_renamed",
                                    "old_name": agent_name,
                                    "new_name": new_id,
                                })
                                await _broadcast(rename_event)
                continue

            elif event.get("type") == "channel_create":
                raw_name = event.get("name", "")
                name = raw_name.strip().lower() if isinstance(raw_name, str) else raw_name
                validation_error = channel_name_error(name)
                if validation_error:
                    await _send_ws_channel_error(websocket, "channel_create", validation_error)
                    continue
                with _channel_catalog_lock:
                    settings_before = _settings_snapshot_locked()
                    pending_before = set(_catalogue_broadcast_pending)
                    channels = room_settings.setdefault("channels", ["general"])
                    if name in channels:
                        admission_error = f"channel '{name}' already exists"
                        _added = False
                    else:
                        manual_limit = min(
                            room_settings.get("max_channels", DEFAULT_MAX_CHANNELS),
                            _channel_discovery_limit(),
                        )
                        if len(channels) >= manual_limit:
                            admission_error = f"manual channel limit reached ({manual_limit})"
                            _added = False
                        else:
                            _added, admission_error = _admit_message_channel(
                                name, persist=False,
                            )
                            if _added:
                                try:
                                    _save_settings()
                                except Exception:
                                    room_settings.clear()
                                    room_settings.update(settings_before)
                                    _catalogue_broadcast_pending.clear()
                                    _catalogue_broadcast_pending.update(pending_before)
                                    admission_error = "could not persist channel catalogue"
                                    _added = False
                if admission_error:
                    await _send_ws_channel_error(websocket, "channel_create", admission_error)
                    continue
                with _channel_catalog_lock:
                    _catalogue_broadcast_pending.discard(name)
                await broadcast_settings()

            elif event.get("type") == "channel_rename":
                raw_old_name = event.get("old_name", "")
                raw_new_name = event.get("new_name", "")
                old_name = raw_old_name.strip().lower() if isinstance(raw_old_name, str) else raw_old_name
                new_name = raw_new_name.strip().lower() if isinstance(raw_new_name, str) else raw_new_name
                old_validation_error = channel_name_error(old_name)
                if old_validation_error:
                    await _send_ws_channel_error(
                        websocket, "channel_rename", old_validation_error,
                    )
                    continue
                if old_name == "general":
                    await _send_ws_channel_error(
                        websocket, "channel_rename", "the general channel cannot be renamed",
                        restore_channel=old_name,
                    )
                    continue
                validation_error = channel_name_error(new_name)
                if validation_error:
                    await _send_ws_channel_error(
                        websocket, "channel_rename", validation_error,
                        restore_channel=old_name,
                    )
                    continue
                renamed, rename_error = await _rename_channel_and_broadcast(
                    old_name, new_name,
                )
                if not renamed:
                    await _send_ws_channel_error(
                        websocket, "channel_rename", rename_error or "rename rejected",
                        restore_channel=old_name,
                    )
                    continue

            elif event.get("type") == "channel_delete":
                raw_name = event.get("name", "")
                name = raw_name.strip().lower() if isinstance(raw_name, str) else raw_name
                validation_error = channel_name_error(name)
                if validation_error:
                    await _send_ws_channel_error(websocket, "channel_delete", validation_error)
                    continue
                async with _channel_outbound_lock:
                    deleted, delete_error = _delete_catalogued_channel(name)
                    if deleted:
                        import mcp_bridge
                        try:
                            mcp_bridge.migrate_cursors_delete(name)
                        except Exception:
                            log.exception("could not migrate MCP cursors for deleted channel %s", name)
                        snapshot = _settings_snapshot()
                        await _broadcast_channel_payload_locked({
                            "type": "settings",
                            "data": snapshot,
                            "catalogue_revision": snapshot["catalogue_revision"],
                        })
                if not deleted:
                    await _send_ws_channel_error(
                        websocket, "channel_delete", delete_error or "delete rejected",
                        restore_channel=name,
                    )
                    continue

    except WebSocketDisconnect:
        ws_clients.discard(websocket)
    except Exception:
        ws_clients.discard(websocket)
        log.exception("WebSocket error")


# --- REST endpoints ---

ALLOWED_UPLOAD_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg'}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB default


@app.post("/api/upload")
async def upload_image(file: UploadFile = File(...)):
    upload_dir = Path(config.get("images", {}).get("upload_dir", "./uploads"))
    upload_dir.mkdir(parents=True, exist_ok=True)

    ext = Path(file.filename).suffix or ".png"
    if ext.lower() not in ALLOWED_UPLOAD_EXTS:
        return JSONResponse({"error": f"unsupported file type: {ext}"}, status_code=400)

    content = await file.read()
    max_bytes = config.get("images", {}).get("max_size_mb", 10) * 1024 * 1024
    if len(content) > max_bytes:
        return JSONResponse({"error": f"file too large (max {max_bytes // 1024 // 1024} MB)"}, status_code=400)

    filename = f"{uuid.uuid4().hex[:8]}{ext}"
    filepath = upload_dir / filename
    filepath.write_bytes(content)

    return JSONResponse({
        "name": file.filename,
        "url": f"/uploads/{filename}",
    })


# --- Export / Import ---

def _snapshot_import_stores():
    """Capture all archive-mutated stores for fail-closed rollback."""
    def file_state(path: Path):
        return (True, path.read_bytes()) if path.exists() else (False, b"")

    snapshot = {"message_store": store.snapshot_state()}
    with jobs._lock:
        snapshot["jobs"] = copy.deepcopy(jobs._jobs)
        snapshot["job_next_id"] = jobs._next_id
        snapshot["jobs_file"] = file_state(jobs._path)
    with rules._lock:
        snapshot["rules"] = copy.deepcopy(rules._rules)
        snapshot["rule_next_id"] = rules._next_id
        snapshot["rule_epoch"] = rules._epoch
        snapshot["rule_agent_sync"] = copy.deepcopy(rules._agent_sync)
        snapshot["rules_file"] = file_state(rules._path)
    with summaries._lock:
        snapshot["summaries"] = copy.deepcopy(summaries._summaries)
        snapshot["summaries_file"] = file_state(summaries._path)
    return snapshot


def _restore_import_stores(snapshot):
    """Restore an archive snapshot in memory and durably, or raise."""
    def restore_file(path: Path, state):
        existed, content = state
        if existed:
            _atomic_write_bytes(path, content)
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    current = _snapshot_import_stores()
    try:
        # Restore every file first, then publish matching memory.  On a
        # transient failure the except branch restores the complete current
        # state rather than leaving a mixed pre/post-import view.
        store.restore_state(snapshot["message_store"])
        restore_file(jobs._path, snapshot["jobs_file"])
        restore_file(rules._path, snapshot["rules_file"])
        restore_file(summaries._path, snapshot["summaries_file"])
        with jobs._lock:
            jobs._jobs = copy.deepcopy(snapshot["jobs"])
            jobs._next_id = snapshot["job_next_id"]
        with rules._lock:
            rules._rules = copy.deepcopy(snapshot["rules"])
            rules._next_id = snapshot["rule_next_id"]
            rules._epoch = snapshot["rule_epoch"]
            rules._agent_sync = copy.deepcopy(snapshot["rule_agent_sync"])
        with summaries._lock:
            summaries._summaries = copy.deepcopy(snapshot["summaries"])
    except Exception:
        try:
            store.restore_state(current["message_store"])
            restore_file(jobs._path, current["jobs_file"])
            restore_file(rules._path, current["rules_file"])
            restore_file(summaries._path, current["summaries_file"])
            with jobs._lock:
                jobs._jobs = current["jobs"]
                jobs._next_id = current["job_next_id"]
            with rules._lock:
                rules._rules = current["rules"]
                rules._next_id = current["rule_next_id"]
                rules._epoch = current["rule_epoch"]
                rules._agent_sync = current["rule_agent_sync"]
            with summaries._lock:
                summaries._summaries = current["summaries"]
        except Exception:
            log.exception("could not restore current stores after rollback failure")
        raise


@app.get("/api/export")
async def export_history():
    """Download a zip archive of project history."""
    import archive as _archive
    import time as _time
    try:
        zip_bytes = _archive.build_export(
            store, jobs, rules, summaries,
            app_version=config.get("server", {}).get("version", ""),
        )
    except Exception as exc:
        return JSONResponse({"error": f"export failed: {exc}"}, status_code=500)
    filename = f"agentchattr-export-{_time.strftime('%Y%m%d-%H%M%S')}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/import")
async def import_history(file: UploadFile = File(...)):
    """Upload a zip archive and merge it into current stores."""
    global _structured_broadcast_suspended
    import archive as _archive
    if not file.filename or not file.filename.lower().endswith(".zip"):
        return JSONResponse({"error": "unsupported file type: expected .zip"}, status_code=400)
    content = await file.read()
    if len(content) > _archive.MAX_IMPORT_SIZE:
        return JSONResponse(
            {"error": f"file too large (max {_archive.MAX_IMPORT_SIZE // 1024 // 1024}MB)"},
            status_code=400,
        )
    archive_channels, inspection_error = _archive.inspect_archive_channels(content)
    if inspection_error:
        return JSONResponse({"error": inspection_error}, status_code=400)
    for archive_channel in archive_channels:
        validation_error = channel_name_error(archive_channel)
        if validation_error:
            return JSONResponse(
                {"error": f"archive channel {archive_channel!r}: {validation_error}"},
                status_code=400,
            )

    # Keep catalogue admission and the synchronous archive merge in one lock
    # window. Lock order is catalogue -> stores, matching message/delete paths.
    with _channel_catalog_lock:
        settings_before = _settings_snapshot_locked()
        pending_before = set(_catalogue_broadcast_pending)
        channel_list = list(room_settings.get("channels", ["general"]))
        max_ch = _channel_discovery_limit()
        new_channels = [ch for ch in archive_channels if ch not in channel_list]
        if len(channel_list) + len(new_channels) > max_ch:
            return JSONResponse(
                {"error": f"archive needs {len(new_channels)} new channels but catalogue "
                          f"has only {max_ch - len(channel_list)} free slots"},
                status_code=409,
            )
        # All archive stores use RLocks.  Holding them as one mutation barrier
        # prevents a legitimate concurrent direct write from being erased by
        # rollback while import helpers safely re-enter on this thread.
        with store._lock, jobs._lock, rules._lock, summaries._lock:
            store_snapshot = _snapshot_import_stores()
            _structured_broadcast_suspended += 1
            try:
                report = _archive.import_archive(
                    content, store, jobs, rules, summaries,
                    channel_list, max_channels=max_ch,
                )
                if not report.get("ok"):
                    _restore_import_stores(store_snapshot)
                elif report["channels"]["created"]:
                    room_settings["channels"] = channel_list
                    _bump_catalogue_revision_locked()
                    _save_settings()
            except Exception as exc:
                try:
                    _restore_import_stores(store_snapshot)
                    room_settings.clear()
                    room_settings.update(settings_before)
                    _catalogue_broadcast_pending.clear()
                    _catalogue_broadcast_pending.update(pending_before)
                except Exception:
                    # Rollback could not be made durable. Keep every discovered
                    # channel visible in memory; restart reconciliation rebuilds
                    # the same fail-closed catalogue from whichever records remain.
                    log.exception("archive rollback failed; retaining imported channels fail-closed")
                    room_settings["channels"] = channel_list
                log.exception("archive import transaction failed")
                return JSONResponse({"error": f"import failed: {exc}"}, status_code=500)
            finally:
                _structured_broadcast_suspended -= 1
    if not report.get("ok"):
        error = report.get("error", "import failed")
        status = 409 if "already running" in error else 400
        return JSONResponse({"error": error}, status_code=status)
    if report["channels"]["created"]:
        await broadcast_settings()
    # Tell all connected clients to reload (picks up imported messages)
    data = json.dumps({"type": "reload"})
    dead = set()
    for client in list(ws_clients):
        try:
            await client.send_text(data)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)
    return JSONResponse(report)


@app.get("/api/messages")
async def get_messages(since_id: int = 0, limit: int = 50, channel: str = ""):
    ch = channel if channel else None
    if since_id:
        return store.get_since(since_id, channel=ch)
    return store.get_recent(limit, channel=ch)


@app.post("/api/send")
async def api_send(request: Request):
    """REST endpoint for API agents to send messages without WebSocket.

    Authenticated via Bearer registration token. Sender is resolved from
    the token — the agent cannot impersonate another identity.
    """
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return JSONResponse({"error": "missing Authorization: Bearer <token>"}, status_code=401)
    token = auth[7:].strip()
    inst = registry.resolve_token(token) if registry else None
    if not inst:
        return JSONResponse({"error": "invalid or expired token"}, status_code=403)

    sender = inst["name"]
    body = await request.json()
    text = body.get("text", "").strip()
    if not text:
        return JSONResponse({"error": "text is required"}, status_code=400)
    channel = body.get("channel", "general")
    msg, admission_error = store_channel_message(sender, text, channel=channel)
    if admission_error:
        status = 409 if "catalogue is full" in admission_error else 400
        return JSONResponse({"error": admission_error}, status_code=status)
    return JSONResponse(msg)


@app.post("/api/rotate-token/{name}")
async def api_rotate_token(name: str, request: Request):
    """Rotate the caller's bearer token (wrapper-restart prerequisite).

    Auth is by possession of the current LIVE token; the rotated identity is
    the one that OWNS the presented token. The `name` path segment is
    informational only and never trusted (spoofing another agent's name in the
    path cannot redirect the rotation). Stale, reclaimable, pending, or
    unknown tokens fail closed; reclaimable identities are NOT reactivated by
    this call. The new token is returned exactly once and never logged.

    Auth failures are a single normative 403 (matching the security middleware,
    which 403s a missing/invalid bearer before this handler — id1098 E1). A
    durable-persistence failure is a token-free generic 500 (id1097 B1); the
    success body is EXACTLY {"name","token"} — no retired token, no extra keys
    (id1098 E3).
    """
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return JSONResponse({"error": "forbidden: missing or invalid bearer token"}, status_code=403)
    token = auth[7:].strip()
    rotated = registry.rotate_token(token) if registry else None
    if rotated == "persist-failed":
        return JSONResponse({"error": "internal error: rotation could not be persisted"}, status_code=500)
    if not isinstance(rotated, dict):
        return JSONResponse(
            {"error": "forbidden: token is stale, unknown, or not rotatable"}, status_code=403
        )
    return JSONResponse({"name": rotated["name"], "token": rotated["token"]})


def _migration_lease_error_response(exc: MigrationLeaseError) -> JSONResponse:
    return JSONResponse({"error": exc.error}, status_code=exc.status_code)


def _migration_lease_bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise MigrationLeaseError(403, "current agent bearer required")
    token = auth[7:].strip()
    if not token:
        raise MigrationLeaseError(403, "current agent bearer required")
    return token


_MIGRATION_LEASE_MAX_BODY_BYTES = 4096


def _migration_lease_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _reject_migration_lease_json_constant(_value: str):
    raise ValueError("non-finite JSON number")


async def _migration_lease_body(request: Request) -> dict:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        if (
            not content_length
            or not content_length.isascii()
            or not content_length.isdigit()
        ):
            raise MigrationLeaseError(400, "invalid JSON")
        if len(content_length) > 20:
            raise MigrationLeaseError(413, "migration lease request body too large")
        if int(content_length) > _MIGRATION_LEASE_MAX_BODY_BYTES:
            raise MigrationLeaseError(413, "migration lease request body too large")

    chunks = []
    size = 0
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > _MIGRATION_LEASE_MAX_BODY_BYTES:
                raise MigrationLeaseError(
                    413, "migration lease request body too large"
                )
            chunks.append(chunk)
    except MigrationLeaseError:
        raise
    except Exception as exc:
        raise MigrationLeaseError(400, "invalid JSON") from exc

    raw = b"".join(chunks)
    try:
        # json.loads(bytes) auto-detects UTF-16/32; decode explicitly so the
        # wire contract remains strict UTF-8. A UTF-8 BOM is not accepted.
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError("UTF-8 BOM is not allowed")
        text = raw.decode("utf-8", errors="strict")
        body = json.loads(
            text,
            object_pairs_hook=_migration_lease_json_object,
            parse_constant=_reject_migration_lease_json_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise MigrationLeaseError(400, "invalid JSON") from exc
    if not isinstance(body, dict):
        raise MigrationLeaseError(400, "invalid migration lease request shape")
    return body


@app.post("/api/migration-lease/acquire")
async def acquire_migration_lease(request: Request):
    """Durably freeze one exact live wrapper identity for a bounded migration."""
    try:
        token = _migration_lease_bearer(request)
        body = await _migration_lease_body(request)
        if not migration_leases or not registry:
            raise MigrationLeaseError(503, "migration lease service unavailable")
        return JSONResponse(migration_leases.acquire(registry, token, body))
    except MigrationLeaseError as exc:
        return _migration_lease_error_response(exc)


@app.post("/api/migration-lease/renew")
async def renew_migration_lease(request: Request):
    """Idempotently extend an unexpired exact-identity migration lease."""
    try:
        token = _migration_lease_bearer(request)
        body = await _migration_lease_body(request)
        if not migration_leases or not registry:
            raise MigrationLeaseError(503, "migration lease service unavailable")
        return JSONResponse(migration_leases.renew(registry, token, body))
    except MigrationLeaseError as exc:
        return _migration_lease_error_response(exc)


@app.post("/api/migration-lease/release")
async def release_migration_lease(request: Request):
    """Durably release a lease, retaining a bounded idempotency tombstone."""
    try:
        token = _migration_lease_bearer(request)
        body = await _migration_lease_body(request)
        if not migration_leases or not registry:
            raise MigrationLeaseError(503, "migration lease service unavailable")
        return JSONResponse(migration_leases.release(registry, token, body))
    except MigrationLeaseError as exc:
        return _migration_lease_error_response(exc)


@app.get("/api/migration-lease/status/{lease_nonce}")
async def migration_lease_status(lease_nonce: str, request: Request):
    """Reconcile a lost acquire/release response using the current bearer."""
    try:
        token = _migration_lease_bearer(request)
        if not migration_leases or not registry:
            raise MigrationLeaseError(503, "migration lease service unavailable")
        return JSONResponse(migration_leases.status(registry, token, lease_nonce))
    except MigrationLeaseError as exc:
        return _migration_lease_error_response(exc)


@app.get("/api/status")
async def get_status():
    status = agents.get_status()
    channels = _settings_snapshot().get("channels", ["general"])
    status["paused"] = any(router.is_paused(ch) for ch in channels)
    return status


@app.get("/api/settings")
async def get_settings():
    return _settings_snapshot()


@app.delete("/api/hat/{agent_name}")
async def delete_hat(agent_name: str):
    """Remove an agent's hat (called by the trash-can UI)."""
    clear_agent_hat(agent_name)
    return JSONResponse({"ok": True})


# --- Jobs API ---

@app.get("/api/schedules")
async def get_schedules():
    return schedules.list_all()


@app.post("/api/schedules")
async def create_schedule(request: Request):
    body = await request.json()
    prompt = body.get("prompt", "")
    targets = body.get("targets", [])
    channel = body.get("channel", "general")
    spec = body.get("spec", "")
    one_shot = body.get("one_shot", False)
    send_at_date = body.get("send_at_date", "")  # "YYYY-MM-DD" for one-shot
    created_by = body.get("created_by", "user")
    if not prompt or not targets or not spec:
        return JSONResponse({"error": "prompt, targets, and spec are required"}, status_code=400)
    interval_sec, daily_at = parse_schedule_spec(spec)
    if interval_sec is None:
        return JSONResponse({"error": f"Invalid schedule spec: {spec}"}, status_code=400)
    # For one-shot, compute exact send_at timestamp from date + daily_at time
    send_at = None
    if one_shot and daily_at and send_at_date:
        import datetime as _dt
        try:
            dt = _dt.datetime.strptime(f"{send_at_date} {daily_at}", "%Y-%m-%d %H:%M")
            send_at = dt.timestamp()
        except ValueError:
            pass
    try:
        s, added, channel_error = _run_channel_state_transaction(
            channel,
            lambda: schedules.create(
                prompt=prompt, targets=targets, channel=channel,
                interval_seconds=interval_sec, daily_at=daily_at,
                one_shot=one_shot, send_at=send_at,
                created_by=created_by,
            ),
            compensator=lambda created: schedules.delete(created["id"]),
        )
    except Exception:
        log.exception("schedule creation failed after channel reservation")
        return JSONResponse({"error": "could not create schedule"}, status_code=500)
    if channel_error:
        status = 409 if "catalogue is full" in channel_error else 400
        return JSONResponse({"error": channel_error}, status_code=status)
    await _publish_channel_transaction(channel, added)
    return JSONResponse(s)


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    removed = schedules.delete(schedule_id)
    if not removed:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"ok": True})


@app.patch("/api/schedules/{schedule_id}/toggle")
async def toggle_schedule(schedule_id: str):
    result = schedules.toggle(schedule_id)
    if not result:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(result)


@app.get("/api/jobs")
async def get_jobs(channel: str = "", status: str = ""):
    """List jobs, optionally filtered."""
    ch = channel if channel else None
    st = status if status else None
    return jobs.list_all(channel=ch, status=st)


@app.post("/api/messages/{msg_id}/demote")
async def demote_proposal(msg_id: int):
    """Demote a proposal-style message back to a regular chat message."""
    msg = store.get_by_id(msg_id)
    if not msg:
        return JSONResponse({"error": "message not found"}, status_code=404)
    msg_type = msg.get("type")
    if msg_type not in {"job_proposal", "session_draft"}:
        return JSONResponse({"error": "not a proposal"}, status_code=400)
    meta = copy.deepcopy(msg.get("metadata") or {})
    updated_fields = {"type": "chat", "metadata": {}}

    if msg_type == "job_proposal":
        body_text = meta.get("body", "")
        title = meta.get("title", "")
        plain_text = f"**{title}**\n\n{body_text}" if title else body_text or msg.get("text", "")
        updated_fields["text"] = plain_text
    else:
        tmpl = meta.get("template")
        errors = meta.get("errors", []) or []
        proposed_by = meta.get("proposed_by") or msg.get("sender", "system")
        parts = []

        if isinstance(tmpl, dict):
            name = str(tmpl.get("name", "")).strip()
            desc = str(tmpl.get("description", "")).strip()
            if name:
                parts.append(f"**{name}**")
            if desc:
                parts.append(desc)
            phases = tmpl.get("phases") or []
            if phases:
                lines = []
                for i, ph in enumerate(phases, 1):
                    ph_name = ph.get("name", f"Round {i}")
                    participants = ", ".join(ph.get("participants", []))
                    line = f"{i}. {ph_name}"
                    if participants:
                        line += f" -- {participants}"
                    prompt = (ph.get("prompt") or "").strip()
                    if prompt:
                        line += f"\n   {prompt}"
                    lines.append(line)
                parts.append("\n".join(lines))
        else:
            label = str(msg.get("text", "")).strip() or "Session draft"
            parts.append(label)
            if errors:
                parts.append("\n".join(f"- {e}" for e in errors))

        updated_fields["sender"] = proposed_by
        updated_fields["text"] = "\n\n".join(p for p in parts if p).strip()

    updated = store.update_message(msg_id, updated_fields)
    if updated:
        # Broadcast the updated message to all clients
        payload = json.dumps({"type": "edit", "message": updated})
        dead = set()
        for client in list(ws_clients):
            try:
                await client.send_text(payload)
            except Exception:
                dead.add(client)
        ws_clients.difference_update(dead)
    return updated or {"ok": True}


@app.post("/api/messages/{msg_id}/resolve_decision")
async def resolve_decision(msg_id: int, request: Request):
    """Resolve an inline decision card by recording the chosen option."""
    body = await request.json()
    chosen = body.get("choice", "")
    if not chosen:
        return JSONResponse({"error": "choice is required"}, status_code=400)
    username = room_settings.get("username", "user")
    updated, _reply, error = store.resolve_decision(msg_id, chosen, username)
    if error:
        return JSONResponse({"error": error[0]}, status_code=error[1])
    # Broadcast updated decision card so the UI swaps buttons to resolved state
    if updated:
        await _broadcast(json.dumps({"type": "message_update", "message": updated}))
    return {"ok": True, "chosen": chosen}


@app.post("/api/messages/{msg_id}/resolve_rule_proposal")
async def resolve_rule_proposal(msg_id: int, request: Request):
    """Activate or dismiss a rule proposal."""
    msg = store.get_by_id(msg_id)
    if not msg:
        return JSONResponse({"error": "message not found"}, status_code=404)
    if msg.get("type") != "rule_proposal":
        return JSONResponse({"error": "not a rule proposal"}, status_code=400)
    body = await request.json()
    action = body.get("action", "")
    meta = copy.deepcopy(msg.get("metadata") or {})
    rule_id = meta.get("rule_id")
    if action not in {"activate", "draft", "dismiss"} or rule_id is None:
        return JSONResponse({"error": "invalid action"}, status_code=400)

    def _resolve():
        with rules._lock:
            snapshot = rules.snapshot_state()
            try:
                if action == "activate":
                    rule_result = rules.activate(int(rule_id), _notify=False)
                    status = "activated"
                    event_action = "activate"
                elif action == "draft":
                    rule_result = rules.make_draft(int(rule_id), _notify=False)
                    status = "drafted"
                    event_action = "edit"
                else:
                    rule_result = rules.delete(int(rule_id), _notify=False)
                    status = "dismissed"
                    event_action = "delete"
                if rule_result is None:
                    return None, None, None
                updated_meta = copy.deepcopy(meta)
                updated_meta["status"] = status
                result = store.update_message(msg_id, {"metadata": updated_meta})
                if result is None:
                    raise RuntimeError("rule proposal message disappeared")
                return result, event_action, rule_result
            except Exception:
                rules.restore_state(snapshot)
                raise

    updated, event_action, rule_result = _run_buffered_store_transaction(_resolve)
    if updated is None:
        return JSONResponse({"error": "rule state could not be changed"}, status_code=409)
    rules._fire(event_action, rule_result)
    if updated:
        # Broadcast the updated message so all clients re-render the card
        payload = json.dumps({"type": "edit", "message": updated})
        dead = set()
        for client in list(ws_clients):
            try:
                await client.send_text(payload)
            except Exception:
                dead.add(client)
        ws_clients.difference_update(dead)
    return updated or {"ok": True}


@app.post("/api/messages/{msg_id}/demote_rule_proposal")
async def demote_rule_proposal(msg_id: int):
    """Demote a rule_proposal message back to a regular chat message and delete the rule."""
    msg = store.get_by_id(msg_id)
    if not msg:
        return JSONResponse({"error": "message not found"}, status_code=404)
    if msg.get("type") != "rule_proposal":
        return JSONResponse({"error": "not a rule proposal"}, status_code=400)
    meta = copy.deepcopy(msg.get("metadata") or {})
    rule_id = meta.get("rule_id")
    text = meta.get("text", msg.get("text", ""))

    def _demote():
        with rules._lock:
            snapshot = rules.snapshot_state()
            try:
                removed_rule = None
                if rule_id is not None:
                    removed_rule = rules.delete(int(rule_id), _notify=False)
                result = store.update_message(msg_id, {
                    "type": "chat",
                    "text": text,
                    "metadata": {},
                })
                if result is None:
                    raise RuntimeError("rule proposal message disappeared")
                return result, removed_rule
            except Exception:
                rules.restore_state(snapshot)
                raise

    updated, removed_rule = _run_buffered_store_transaction(_demote)
    if removed_rule is not None:
        rules._fire("delete", removed_rule)
    if updated:
        payload = json.dumps({"type": "edit", "message": updated})
        dead = set()
        for client in list(ws_clients):
            try:
                await client.send_text(payload)
            except Exception:
                dead.add(client)
        ws_clients.difference_update(dead)
    return updated or {"ok": True}


@app.post("/api/trigger-agent")
async def trigger_agent_silent(request: Request):
    """Silently trigger an agent with a message (no chat message posted)."""
    body = await request.json()
    agent_name = body.get("agent", "").strip()
    message = body.get("message", "").strip()
    channel = body.get("channel", "general")
    source_msg_id = body.get("source_msg_id")
    if not agent_name or not message:
        return JSONResponse({"error": "agent and message required"}, status_code=400)
    _added, channel_error = await _admit_channel_ingress(channel)
    if channel_error:
        status = 409 if "catalogue is full" in channel_error else 400
        return JSONResponse({"error": channel_error}, status_code=status)

    custom_prompt = body.get("prompt", "").strip()
    if not custom_prompt:
        if source_msg_id is not None:
            custom_prompt = (
                f"use mcp to read #{channel} - you're mentioned, take appropriate action and respond "
                f"- conversion request: use chat history to find message #{source_msg_id} "
                f"and use chat_propose_job to propose it as a job with title<=80 chars and body<=500 chars."
            )
        else:
            custom_prompt = (
                f"use mcp to read #{channel} - you're mentioned, take appropriate action and respond "
                f"- conversion request: use chat_propose_job to propose a job from the referenced message."
            )
    # Resolve to instances if multi-instance
    targets = [agent_name]
    if registry:
        resolved = registry.resolve_to_instances(agent_name)
        if resolved:
            targets = resolved
    source_ref = source_msg_id
    if source_ref is None:
        source_ref = body.get("request_id")
    if source_ref is None:
        # Backward-compatible deterministic retry key for callers which have
        # not yet adopted request_id.  Explicit request_id remains preferred
        # when two intentionally separate requests have identical content.
        source_ref = json.dumps(
            [channel, message, custom_prompt],
            ensure_ascii=True, separators=(",", ":"),
        )
    action_ids = {}
    for target in targets:
        if agents.is_available(target):
            action_id = agents.action_id_for(
                "trigger-agent", source_ref, target
            )
            action_ids[target] = action_id
            await agents.trigger(
                target, message=message, channel=channel,
                prompt=custom_prompt, action_id=action_id,
            )
    return {"ok": True, "triggered": targets, "action_ids": action_ids}


@app.post("/api/jobs")
async def create_job(request: Request):
    """Create a new job."""
    body = await request.json()
    title = body.get("title", "").strip()
    if not title:
        return JSONResponse({"error": "title required"}, status_code=400)
    job_type = body.get("type", "job")
    channel = body.get("channel", "general")
    created_by = body.get("created_by", "user")
    anchor_msg_id = body.get("anchor_msg_id")
    assignee = body.get("assignee", "")
    job_body = body.get("body", "")

    def _rollback_job_state(state):
        if not state:
            return
        breadcrumb = state.get("breadcrumb")
        if breadcrumb is not None:
            store.delete([breadcrumb["id"]])
        if state.get("anchor_updated"):
            store.restore_message(state["anchor_before"])
        created = state.get("job")
        if created is not None:
            jobs.delete(created["id"])

    def _create_job_state():
        state = {
            "job": None,
            "anchor_id": anchor_msg_id,
            "anchor_before": None,
            "anchor_updated": False,
            "updated_anchor": None,
            "breadcrumb": None,
        }
        try:
            created = jobs.create(
                title=title, job_type=job_type, channel=channel,
                created_by=created_by, anchor_msg_id=anchor_msg_id,
                assignee=assignee, body=job_body,
            )
            state["job"] = created
            if anchor_msg_id is not None:
                anchor_msg = store.get_by_id(anchor_msg_id)
                if anchor_msg and anchor_msg.get("type") == "job_proposal":
                    state["anchor_before"] = copy.deepcopy(anchor_msg)
                    meta = copy.deepcopy(anchor_msg.get("metadata") or {})
                    meta["status"] = "accepted"
                    state["updated_anchor"] = store.update_message(
                        anchor_msg_id, {"metadata": meta},
                    )
                    state["anchor_updated"] = state["updated_anchor"] is not None
            breadcrumb, write_error = store_channel_message(
                created_by,
                f"Job created: {title}",
                msg_type="job_created",
                channel=channel,
                metadata={"job_id": created["id"]},
            )
            if write_error:
                raise RuntimeError(write_error)
            state["breadcrumb"] = breadcrumb
            return state
        except Exception:
            _rollback_mutation_state(state, _rollback_job_state)
            raise

    try:
        transaction_result, added, channel_error = _run_channel_state_transaction(
            channel, _create_job_state, compensator=_rollback_job_state,
        )
    except Exception:
        log.exception("job creation failed after channel reservation")
        return JSONResponse({"error": "could not create job"}, status_code=500)
    if channel_error:
        status = 409 if "catalogue is full" in channel_error else 400
        return JSONResponse({"error": channel_error}, status_code=status)
    result = transaction_result["job"]
    updated_msg = transaction_result["updated_anchor"]
    await _publish_channel_transaction(channel, added)
    if updated_msg:
        payload = json.dumps({"type": "edit", "message": updated_msg})
        dead = set()
        for client in list(ws_clients):
            try:
                await client.send_text(payload)
            except Exception:
                dead.add(client)
        ws_clients.difference_update(dead)
    return result


@app.patch("/api/jobs/{job_id}")
async def update_job(job_id: int, request: Request):
    """Update a job's status, title, or assignee."""
    body = await request.json()
    result = None
    if "status" in body:
        result = jobs.update_status(job_id, body["status"])
    if "title" in body:
        result = jobs.update_title(job_id, body["title"])
    if "assignee" in body:
        result = jobs.update_assignee(job_id, body["assignee"])
    if result is None:
        return JSONResponse({"error": "not found or invalid"}, status_code=404)
    return result


@app.post("/api/jobs/reorder")
async def reorder_jobs(request: Request):
    """Reorder jobs within a status group (globally, not per-channel)."""
    body = await request.json()
    status = body.get("status", "open")
    ordered_ids = body.get("ordered_ids", [])
    if not isinstance(ordered_ids, list) or len(ordered_ids) == 0:
        return JSONResponse({"error": "ordered_ids required"}, status_code=400)
    updated = jobs.reorder(status=status, ordered_ids=ordered_ids)
    return {"ok": True, "updated": len(updated)}


@app.get("/api/jobs/{job_id}/messages")
async def get_job_messages(job_id: int):
    """Get all messages in a job."""
    msgs = jobs.get_messages(job_id)
    if msgs is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return msgs


@app.post("/api/jobs/{job_id}/messages")
async def post_job_message(job_id: int, request: Request):
    """Post a message to a job."""
    body = await request.json()
    text = body.get("text", "").strip()
    sender = body.get("sender", "user")
    attachments = body.get("attachments", [])
    if not text and not attachments:
        return JSONResponse({"error": "text or attachments required"}, status_code=400)
    msg_type = body.get("type", "chat")
    msg = jobs.add_message(job_id, sender, text,
                           attachments=attachments, msg_type=msg_type)
    if msg is None:
        return JSONResponse({"error": "job not found"}, status_code=404)

    # Route @mentions in job messages to agents (with job_id context)
    job = jobs.get(job_id)
    if job:
        channel = job.get("channel", "general")
        raw_targets = router.get_targets(sender, text, channel)
        targets = []
        for t in raw_targets:
            if registry:
                targets.extend(registry.resolve_to_instances(t))
            else:
                targets.append(t)
        targets = list(dict.fromkeys(targets))

        import mcp_bridge
        chat_msg = f"{sender}: {text}" if text else ""
        for target in targets:
            if registry:
                inst = registry.get_instance(target)
                if inst and inst.get("state") == "pending":
                    continue
            if agents.is_available(target):
                await agents.trigger(
                    target, message=chat_msg, channel=channel, job_id=job_id,
                    action_id=agents.action_id_for(
                        "job-message", f"{job_id}:{msg['id']}", target
                    ),
                )

    return msg


@app.delete("/api/jobs/{job_id}/messages/{msg_id}")
async def delete_job_message(job_id: int, msg_id: int):
    """Soft-delete a message in a job thread."""
    result = jobs.delete_message(job_id, msg_id)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return {"ok": True, **result}


@app.post("/api/jobs/{job_id}/messages/{msg_index}/resolve")
async def resolve_job_message(job_id: int, msg_index: int, request: Request):
    """Resolve a suggestion message (accept/dismiss)."""
    body = await request.json()
    resolution = body.get("resolution", "dismissed")
    job = jobs.get(job_id)
    if not job:
        return JSONResponse({"error": "not found"}, status_code=404)
    msgs = job.get("messages", [])
    if msg_index < 0 or msg_index >= len(msgs):
        return JSONResponse({"error": "invalid message index"}, status_code=400)
    resolved_job = jobs.resolve_message(job_id, msg_index, resolution)
    if resolved_job is None:
        return JSONResponse({"error": "message not found"}, status_code=404)
    msg = resolved_job.get("messages", [])[msg_index]

    # If accepted, trigger the suggesting agent with context
    if resolution == "accepted" and msg.get("sender"):
        agent_name = msg["sender"]
        channel = resolved_job.get("channel", "general")
        if agents.is_available(agent_name):
            await agents.trigger(
                agent_name,
                message=f"Your suggestion was accepted: {msg.get('text', '')}",
                channel=channel, job_id=job_id,
                action_id=agents.action_id_for(
                    "job-resolution",
                    f"{job_id}:{msg.get('id', msg_index)}:{resolution}",
                    agent_name,
                ),
            )

    return {"ok": True, "resolution": resolution}


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: int, request: Request):
    """Delete or archive a job. ?permanent=true for real delete."""
    permanent = request.query_params.get("permanent", "").lower() == "true"
    if permanent:
        result = jobs.delete(job_id)
    else:
        result = jobs.update_status(job_id, "archived")
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return result


@app.get("/api/roles")
async def get_roles():
    """Get all agent roles."""
    import mcp_bridge
    return mcp_bridge.get_all_roles()


@app.post("/api/roles/{agent_name}")
async def set_agent_role(agent_name: str, request: Request):
    """Set or clear an agent's role."""
    import mcp_bridge
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)
    role = body.get("role", "").strip()
    mcp_bridge.set_role(agent_name, role)
    await broadcast_status()
    return JSONResponse({"ok": True, "role": role})


# --- Rules API ---

@app.get("/api/rules")
async def get_rules():
    """Get all rules (all states)."""
    return JSONResponse(rules.list_all())


@app.get("/api/rules/active")
async def get_active_rules():
    """Get compact active rules for agent injection."""
    data = rules.active_list()
    data["refresh_interval"] = room_settings.get("rules_refresh_interval", 10)
    return JSONResponse(data)


@app.post("/api/rules/remind")
async def remind_agents():
    """Set remind flag — agents get rules on next trigger."""
    rules.set_remind()
    remind_data = json.dumps({"type": "rules_remind", "data": {}})
    for client in list(ws_clients):
        try:
            await client.send_text(remind_data)
        except Exception:
            pass
    return JSONResponse({"ok": True})


@app.post("/api/rules/agent_sync/{agent_name}")
async def report_rule_sync(agent_name: str, request: Request):
    """Wrapper reports that an agent has seen rules at a given epoch."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)
    epoch = body.get("epoch", 0)
    rules.report_agent_sync(agent_name, epoch)
    # Clear remind flag once any agent has seen the updated rules
    rules.clear_remind()
    return JSONResponse({"ok": True})


@app.get("/api/rules/freshness")
async def get_rules_freshness():
    """Get per-agent sync status."""
    return JSONResponse(rules.agent_freshness())


@app.post("/api/register")
async def register_agent(request: Request):
    """Wrapper calls this to register a new agent instance."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    base = body.get("base", "")
    label = body.get("label")
    if not base:
        return JSONResponse({"error": "base is required"}, status_code=400)
    result = registry.register(base, label)
    if result is None:
        return JSONResponse({"error": f"unknown base: {base}"}, status_code=400)
    if isinstance(result, str):
        status = 503 if result == "migration_lease_store_unhealthy" else 409
        return JSONResponse({"error": result}, status_code=status)
    # Touch presence so the instance doesn't immediately time out
    import mcp_bridge
    with mcp_bridge._presence_lock:
        mcp_bridge._presence[result["name"]] = __import__("time").time()
    # If slot 1 was renamed (e.g. "claude" → "claude-1"), migrate state
    renamed = result.pop("_renamed_slot1", None)
    if renamed:
        mcp_bridge.migrate_identity(renamed["old"], renamed["new"])
        store.rename_sender(renamed["old"], renamed["new"])
        _migrate_agent_last_channel(renamed["old"], renamed["new"])
        if _event_loop:
            rename_event = json.dumps({
                "type": "agent_renamed",
                "old_name": renamed["old"],
                "new_name": renamed["new"],
            })
            asyncio.run_coroutine_threadsafe(_broadcast(rename_event), _event_loop)
    # Broadcast pending_instance event so UI can show naming lightbox
    if result.get("state") == "pending" and _event_loop:
        pending_event = json.dumps({
            "type": "pending_instance",
            "name": result["name"],
            "base": base,
            "label": result.get("label", result["name"]),
            "color": result.get("color", "#888"),
        })
        asyncio.run_coroutine_threadsafe(_broadcast(pending_event), _event_loop)
    return JSONResponse(result)


@app.post("/api/deregister/{name}")
async def deregister_agent(name: str, request: Request):
    """Wrapper calls this on shutdown to remove its instance."""
    auth_inst = _resolve_authenticated_agent(request)
    presented_token = _extract_agent_token(request)
    if presented_token and not auth_inst:
        return JSONResponse({"error": "stale_session"}, status_code=409)
    if auth_inst:
        name = auth_inst["name"]
    elif registry and registry.is_agent_family(name):
        return JSONResponse({"error": "authenticated agent session required"}, status_code=403)

    result = registry.deregister(name)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    if not result.get("ok"):
        error = result.get("error", "deregister rejected")
        status = 503 if error == "migration_lease_store_unhealthy" else 409
        return JSONResponse({"error": error}, status_code=status)
    # Clean up runtime state (presence, activity, cursors, rename chains)
    import mcp_bridge
    mcp_bridge.purge_identity(name)
    registry.clean_renames_for(name)
    # If the remaining instance was renamed back (e.g. "claude-1" → "claude"), migrate state
    renamed = result.pop("_renamed_back", None)
    if renamed:
        mcp_bridge.migrate_identity(renamed["old"], renamed["new"])
        store.rename_sender(renamed["old"], renamed["new"])
        _migrate_agent_last_channel(renamed["old"], renamed["new"])
        if _event_loop:
            rename_event = json.dumps({
                "type": "agent_renamed",
                "old_name": renamed["old"],
                "new_name": renamed["new"],
            })
            asyncio.run_coroutine_threadsafe(_broadcast(rename_event), _event_loop)
    return JSONResponse({"ok": True})


@app.post("/api/label/{name}")
async def rename_agent_label(name: str, request: Request):
    """Rename an agent (human-initiated from UI). Changes identity + label."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    label = body.get("label", "").strip()
    if not label:
        return JSONResponse({"error": "label is required"}, status_code=400)

    import re as _re
    new_id = _re.sub(r'[^a-z0-9-]', '', label.lower().replace(' ', '-')).strip('-')
    if not new_id:
        new_id = name

    if new_id == name:
        # Same ID — label-only change
        if registry.set_label(name, label):
            return JSONResponse({"ok": True})
        return JSONResponse({"error": "not found"}, status_code=404)

    result = registry.rename(name, new_id, label)
    if isinstance(result, str):
        # Rename failed — try label-only as fallback
        if registry.set_label(name, label):
            return JSONResponse({"ok": True, "warning": result})
        return JSONResponse({"error": result}, status_code=400)

    import mcp_bridge
    mcp_bridge.migrate_identity(name, new_id)
    # Update sender on all historical messages
    store.rename_sender(name, new_id)
    _migrate_agent_last_channel(name, new_id)
    return JSONResponse({"ok": True, "new_name": new_id})


@app.post("/api/heartbeat/{agent_name}")
async def heartbeat(agent_name: str, request: Request):
    """Wrapper calls this to keep presence alive and report activity.

    Returns the canonical name from the registry so the wrapper can
    detect renames (e.g. claim renamed 'claude-2' to 'claude-music').
    """
    import mcp_bridge
    auth_inst = _resolve_authenticated_agent(request)
    presented_token = _extract_agent_token(request)
    if presented_token and not auth_inst:
        return JSONResponse({"error": "stale_session"}, status_code=409)
    if registry and registry.is_agent_family(agent_name) and not auth_inst:
        return JSONResponse({"error": "authenticated agent session required"}, status_code=403)

    current_name = auth_inst["name"] if auth_inst else agent_name
    with mcp_bridge._presence_lock:
        mcp_bridge._presence[current_name] = __import__("time").time()
    # Optional activity report from wrapper's terminal monitor
    _activity_changed = False
    try:
        body = await request.json()
        if "active" in body:
            active_val = bool(body["active"])
            was_active = mcp_bridge._activity.get(current_name, False)
            mcp_bridge.set_active(current_name, active_val)
            _activity_changed = was_active != active_val
    except Exception:
        pass  # No body = plain heartbeat
    # Immediately broadcast on activity state change (don't wait for background checker)
    if _activity_changed:
        await broadcast_status()
    # Return canonical name so wrapper can track renames
    resp = {"ok": True, "name": current_name}
    if registry:
        # Follow rename chain (e.g. claude-2 was renamed to claude-music)
        canonical = registry.resolve_name(current_name)
        inst = registry.get_instance(canonical)
        # If rename chain didn't help, try family-based lookup
        # (handles case where _renames was cleared by server restart but
        # the instance was claimed/renamed via MCP)
        if not inst:
            base = current_name.split("-")[0] if "-" in current_name else current_name
            family_inst = registry.get_family_instance(base)
            if family_inst:
                inst = family_inst
                canonical = inst["name"]
        if inst:
            resp["name"] = inst["name"]
            resp["pending"] = inst.get("state") == "pending"
            # Also update presence under the canonical name
            if canonical != current_name:
                now = __import__("time").time()
                with mcp_bridge._presence_lock:
                    mcp_bridge._presence[canonical] = now
    return resp


# --- Open agent session in terminal ---

@app.get("/api/platform")
async def get_platform():
    """Return the server's platform so the web UI can match path formats."""
    import sys
    return JSONResponse({"platform": sys.platform})


@app.post("/api/open-path")
async def open_path(body: dict):
    """Open a file or directory in the native file manager.

    Cross-platform: Explorer on Windows, Finder on macOS, xdg-open on Linux.

    Security note: This endpoint is intended for local-only use (127.0.0.1).
    Do not expose this server on a public network without additional access controls.
    """
    import subprocess
    import sys

    path = body.get("path", "")
    if not path:
        return JSONResponse({"error": "no path"}, status_code=400)

    p = Path(path)
    try:
        if sys.platform == "win32":
            if p.is_file():
                subprocess.Popen(["explorer", "/select,", str(p)])
            elif p.is_dir():
                subprocess.Popen(["explorer", str(p)])
            else:
                return JSONResponse({"error": "path not found"}, status_code=404)
        elif sys.platform == "darwin":
            if p.is_file():
                subprocess.Popen(["open", "-R", str(p)])
            elif p.is_dir():
                subprocess.Popen(["open", str(p)])
            else:
                return JSONResponse({"error": "path not found"}, status_code=404)
        else:
            # Linux — xdg-open opens the containing folder for files
            if p.is_file():
                subprocess.Popen(["xdg-open", str(p.parent)])
            elif p.is_dir():
                subprocess.Popen(["xdg-open", str(p)])
            else:
                return JSONResponse({"error": "path not found"}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    return JSONResponse({"ok": True})


# Serve uploaded images
# --- Sessions API ---

@app.get("/api/sessions/templates")
async def get_session_templates():
    if not session_store:
        return JSONResponse({"error": "sessions not configured"}, status_code=500)
    return JSONResponse(session_store.get_templates())


@app.get("/api/sessions/active")
async def get_active_session(channel: str = "general"):
    if not session_engine:
        return JSONResponse(None)
    session = session_engine.get_active(channel)
    return JSONResponse(session)


@app.get("/api/sessions/active-all")
async def get_all_active_sessions():
    if not session_engine:
        return JSONResponse([])
    return JSONResponse(session_engine.list_active())


@app.post("/api/sessions/start")
async def start_session(request: Request):
    if not session_engine or not session_store:
        return JSONResponse({"error": "sessions not configured"}, status_code=500)
    body = await request.json()
    template_id = body.get("template_id", "")
    draft_message_id = body.get("draft_message_id")
    channel = body.get("channel", "general")
    cast = body.get("cast", {})
    goal = body.get("goal", "")
    started_by = body.get("started_by", "user")
    channel_error = channel_name_error(channel)
    if channel_error:
        return JSONResponse({"error": channel_error}, status_code=400)

    # If running from a draft, load the inline template from message metadata
    tmpl = None
    temporary_template = False
    if draft_message_id is not None:
        try:
            draft_id = int(draft_message_id)
        except (TypeError, ValueError):
            return JSONResponse({"error": "invalid draft message id"}, status_code=400)
        draft_msg = store.get_by_id(draft_id)
        if not draft_msg:
            return JSONResponse({"error": "draft message not found"}, status_code=404)
        meta = draft_msg.get("metadata", {})
        if not meta.get("valid"):
            return JSONResponse({"error": "draft is not valid"}, status_code=400)
        tmpl = meta.get("template")
        if not tmpl:
            return JSONResponse({"error": "draft has no template"}, status_code=400)
        tmpl = dict(tmpl)
        # A draft gets a runtime-unique template id so it cannot shadow a
        # built-in or saved custom template with the same inline id.
        template_id = f"draft-{draft_id}"
        tmpl["id"] = template_id
        temporary_template = True

    # Validate template exists
    if not tmpl:
        tmpl = session_store.get_template(template_id)
    if not tmpl:
        return JSONResponse({"error": f"unknown template: {template_id}"}, status_code=400)
    try:
        template_errors = validate_session_template(tmpl)
    except (TypeError, ValueError):
        template_errors = ["roles and phases contain invalid values"]
    roles = tmpl.get("roles", [])
    if not isinstance(roles, list) or any(
        not isinstance(role, str) or not role.strip() for role in roles
    ):
        template_errors.append("roles must be non-empty strings")
    if template_errors:
        return JSONResponse(
            {"error": "invalid template: " + "; ".join(template_errors)},
            status_code=400,
        )

    # Auto-fill cast from available agents if not fully provided
    if not isinstance(cast, dict):
        return JSONResponse({"error": "cast must be an object"}, status_code=400)
    if not cast:
        online = registry.get_active_names() if registry else []
        roles = tmpl.get("roles", [])
        cast = _auto_cast(roles, online, started_by)
        if not cast:
            return JSONResponse(
                {"error": "not enough agents online to fill all roles"},
                status_code=400,
            )
    unknown_roles = [role for role in cast if role not in roles]
    if unknown_roles:
        return JSONResponse(
            {"error": "cast contains unknown roles: " + ", ".join(map(str, unknown_roles))},
            status_code=400,
        )
    missing_roles = [
        role for role in roles
        if not isinstance(cast.get(role), str) or not cast.get(role, "").strip()
    ]
    if missing_roles:
        return JSONResponse(
            {"error": "cast is missing roles: " + ", ".join(missing_roles)},
            status_code=400,
        )

    if session_engine.get_active(channel):
        return JSONResponse(
            {"error": "could not start session (one may already be active)"},
            status_code=409,
        )

    def _create_session():
        if temporary_template:
            created = session_store.create_from_template(
                tmpl=tmpl,
                channel=channel,
                cast=cast,
                started_by=started_by,
                goal=goal,
            )
        else:
            created = session_store.create(
                template_id=template_id,
                channel=channel,
                cast=cast,
                started_by=started_by,
                goal=goal,
            )
        return {"session": created} if created is not None else None

    def _rollback_session_state(state):
        created = state.get("session") if state else None
        if created is not None:
            session_store.delete(created["id"])

    try:
        transaction_result, added, channel_error = _run_channel_state_transaction(
            channel, _create_session, compensator=_rollback_session_state,
        )
    except Exception:
        log.exception("session creation failed after channel reservation")
        return JSONResponse({"error": "could not start session"}, status_code=500)
    if channel_error:
        status = 409 if "catalogue is full" in channel_error else 400
        return JSONResponse({"error": channel_error}, status_code=status)
    if not transaction_result:
        return JSONResponse({"error": "could not start session (one may already be active)"}, status_code=409)
    session = transaction_result["session"]
    await _publish_channel_transaction(channel, added)

    # Add start banner to chat (only after confirmed success)
    _banner, write_error = store_channel_message(
        sender="system",
        text=f"Session started: {tmpl.get('name', template_id)}",
        msg_type="session_start",
        channel=channel,
        metadata={"template_id": template_id, "goal": goal, "session_id": session["id"]},
    )
    if write_error:
        return JSONResponse({"error": write_error}, status_code=409)
    session_engine.emit_current_phase_banner(session)
    session_engine._trigger_current(session)

    return JSONResponse(session)


@app.post("/api/sessions/{session_id}/end")
async def end_session(session_id: int):
    if not session_engine:
        return JSONResponse({"error": "sessions not configured"}, status_code=500)
    session = session_engine.end_session(session_id)
    if not session:
        return JSONResponse({"error": "session not found or already ended"}, status_code=404)

    # Banner is added by _on_session_change("interrupt", ...) callback
    return JSONResponse(session)


@app.post("/api/sessions/request-draft")
async def request_session_draft(request: Request):
    """Ask an agent to design a session template. Called by the 'Design a session' UI."""
    body = await request.json()
    agent_name = body.get("agent", "").strip()
    description = body.get("description", "").strip()
    channel = body.get("channel", "general")
    sender = body.get("sender", "user")
    if not agent_name or not description:
        return JSONResponse({"error": "agent and description required"}, status_code=400)
    mention_str = f"@{agent_name}"

    def _rollback_draft_request(messages):
        ids = [message["id"] for message in (messages or []) if message is not None]
        if ids:
            store.delete(ids)

    def _create_draft_request():
        messages = []
        try:
            notice, write_error = store_channel_message(
                "system",
                f"Requested session draft from {mention_str}. Wait for a proposal.",
                channel=channel,
            )
            if write_error:
                raise RuntimeError(write_error)
            messages.append(notice)
            request_message, write_error = store_channel_message(
                sender,
                f"{mention_str} Design a session workflow for: **{description}**\n\n"
                "Respond with a single chat message containing a fenced JSON code block with this exact structure:\n"
                "```session\n"
                '{"name": "...", "description": "...", "roles": ["role1", "role2", ...], '
                '"phases": [{"name": "...", "participants": ["role1"], "prompt": "...", "is_output": false}, ...]}\n'
                "```\n"
                "Rules: max 6 roles, max 6 phases, max 4 participants per phase, max 200 chars per prompt. "
                "Mark exactly one phase as `is_output: true` (the final deliverable). "
                f"Keep it focused and sequential. Use the chat_send tool to post your response in the #{channel} channel. "
                "Do NOT respond only in your terminal.",
                channel=channel,
                msg_type="session_request",
                metadata={"session_request": True, "mentions": [f"@{agent_name}"], "request": description},
            )
            if write_error:
                raise RuntimeError(write_error)
            messages.append(request_message)
            return messages
        except Exception:
            _rollback_mutation_state(messages, _rollback_draft_request)
            raise

    try:
        messages, added, channel_error = _run_channel_state_transaction(
            channel,
            _create_draft_request,
            compensator=_rollback_draft_request,
        )
    except Exception:
        log.exception("session draft request failed after channel reservation")
        return JSONResponse({"error": "could not create session draft request"}, status_code=500)
    if channel_error:
        status = 409 if "catalogue is full" in channel_error else 400
        return JSONResponse({"error": channel_error}, status_code=status)
    await _publish_channel_transaction(channel, added)
    return JSONResponse({"ok": True})


@app.post("/api/sessions/save-draft")
async def save_draft(request: Request):
    if not session_store:
        return JSONResponse({"error": "sessions not configured"}, status_code=500)
    body = await request.json()
    msg_id = body.get("message_id")
    if msg_id is None:
        return JSONResponse({"error": "message_id required"}, status_code=400)
    msg = store.get_by_id(int(msg_id))
    if not msg:
        return JSONResponse({"error": "message not found"}, status_code=404)
    meta = msg.get("metadata", {})
    if not meta.get("valid"):
        return JSONResponse({"error": "draft is not valid"}, status_code=400)
    tmpl = copy.deepcopy(meta.get("template"))
    if not tmpl:
        return JSONResponse({"error": "no template in draft"}, status_code=400)

    tmpl.setdefault("id", f"custom-{msg_id}")
    saved = session_store.save_custom_template(tmpl)
    return JSONResponse({"ok": True, "template_id": saved["id"]})


@app.delete("/api/sessions/templates/{template_id}")
async def delete_session_template(template_id: str):
    if not session_store:
        return JSONResponse({"error": "sessions not configured"}, status_code=500)
    deleted = session_store.delete_custom_template(template_id)
    if not deleted:
        return JSONResponse({"error": "template not found or not custom"}, status_code=404)
    return JSONResponse({"ok": True, "template_id": template_id})


def _auto_cast(roles: list[str], online_agents: list[str], started_by: str) -> dict:
    """Auto-assign roles to available agents. Returns empty dict if not enough agents."""
    cast = {}
    available = list(online_agents)

    for role in roles:
        if not available:
            # Reuse agents if we run out (one agent, multiple roles)
            available = list(online_agents)
        if not available:
            return {}
        agent = available.pop(0)
        cast[role] = agent

    return cast


# --- Version check (GitHub release notifier) ---

_version_cache: dict = {"data": None, "fetched_at": 0.0}
_VERSION_CACHE_TTL = 1800  # 30 minutes


def _read_local_version() -> str:
    """Read version from VERSION file in project root."""
    vfile = Path(__file__).parent / "VERSION"
    try:
        return vfile.read_text().strip()
    except Exception:
        return ""


def _detect_install_kind() -> str:
    """Detect how this copy was installed: official_git, fork, or unknown."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
            cwd=Path(__file__).parent,
        )
        url = result.stdout.strip().lower()
        if "bcurts/agentchattr" in url:
            return "official_git"
        elif url:
            return "fork"
    except Exception:
        pass
    return "unknown"


def _fetch_latest_release() -> dict | None:
    """Fetch latest release from GitHub API, with 30-min cache."""
    import time
    import urllib.request

    now = time.time()
    if _version_cache["data"] and (now - _version_cache["fetched_at"]) < _VERSION_CACHE_TTL:
        return _version_cache["data"]

    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/bcurts/agentchattr/releases/latest",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "agentchattr"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            result = {
                "tag": data.get("tag_name", ""),
                "url": data.get("html_url", ""),
            }
            _version_cache["data"] = result
            _version_cache["fetched_at"] = now
            return result
    except Exception:
        return _version_cache.get("data")


def _compare_versions(current: str, latest_tag: str) -> str:
    """Compare version strings. Returns 'behind', 'current', or 'unknown'."""
    # Strip leading 'v' from tag
    latest = latest_tag.lstrip("v")
    if not current or not latest:
        return "unknown"
    try:
        from packaging.version import Version
        if Version(current) < Version(latest):
            return "behind"
        return "current"
    except Exception:
        return "unknown"


@app.get("/api/version_check")
async def version_check():
    """Check for newer releases on GitHub."""
    current = _read_local_version()
    loop = asyncio.get_event_loop()
    release = await loop.run_in_executor(None, _fetch_latest_release)

    if not release or not release.get("tag"):
        return JSONResponse({"current": current, "latest": "", "state": "unknown", "url": ""})

    latest_tag = release["tag"]
    install_kind = _detect_install_kind()
    comparison = _compare_versions(current, latest_tag)

    if comparison == "behind":
        if install_kind == "official_git":
            state = "update_available"
        elif install_kind == "fork":
            state = "upstream_update"
        else:
            state = "unknown"
    elif comparison == "current":
        state = "current"
    else:
        state = "unknown"

    return JSONResponse({
        "current": current,
        "latest": latest_tag,
        "state": state,
        "url": release.get("url", ""),
    })


@app.get("/uploads/{filename}")
async def serve_upload(filename: str):
    upload_dir = Path(config.get("images", {}).get("upload_dir", "./uploads"))
    filepath = (upload_dir / filename).resolve()
    if not filepath.is_relative_to(upload_dir.resolve()):
        return JSONResponse({"error": "invalid path"}, status_code=400)
    if filepath.exists():
        return FileResponse(filepath)
    return JSONResponse({"error": "not found"}, status_code=404)
