"""Agent trigger — writes to queue files picked up by visible worker terminals."""

import json
import hashlib
import logging
import os
import time
import uuid
from pathlib import Path

from delivery_io import (
    DeliveryBackpressureError,
    append_bytes_durable,
    queue_file_lock,
    require_delivery_fence_clear,
    write_backpressure_marker,
)

log = logging.getLogger(__name__)


def _byte_limit(env_name: str, default: int) -> int:
    try:
        return max(4096, int(os.environ.get(env_name, default)))
    except (TypeError, ValueError):
        return default


_MAX_QUEUE_BYTES = _byte_limit("AGENTCHATTR_MAX_QUEUE_BYTES", 8 << 20)


class AgentTrigger:
    def __init__(self, registry, data_dir: str = "./data"):
        self._registry = registry
        self._data_dir = Path(data_dir)

    def is_available(self, name: str) -> bool:
        return self._registry.is_registered(name)

    def get_status(self) -> dict:
        from mcp_bridge import is_online, is_active, get_role
        instances = self._registry.get_all()
        return {
            name: {
                "available": is_online(name),
                "busy": is_active(name),
                "label": info["label"],
                "color": info["color"],
                "role": get_role(name),
            }
            for name, info in instances.items()
        }

    @staticmethod
    def _build_entry(message: str, channel: str, job_id: int | None,
                     **kwargs) -> dict:
        """Build a v1 delivery envelope while retaining every legacy key.

        `event_id` is producer-assigned so a wrapper can deduplicate a replay
        across restarts.  Consumers which predate the envelope simply ignore
        the additive fields and continue to use sender/text/time/channel.
        """
        entry = {
            "envelope_version": 1,
            "event_id": f"evt-{uuid.uuid4().hex}",
            "created_at_ns": time.time_ns(),
            "sender": message.split(":")[0].strip() if ":" in message else "?",
            "text": message,
            "time": time.strftime("%H:%M:%S"),
            "channel": channel,
        }
        custom_prompt = kwargs.get("prompt", "")
        if isinstance(custom_prompt, str) and custom_prompt.strip():
            entry["prompt"] = custom_prompt.strip()
        if job_id is not None:
            entry["job_id"] = job_id
        action_id = kwargs.get("action_id")
        if isinstance(action_id, str) and action_id.strip():
            entry["action_id"] = action_id.strip()
        return entry

    @staticmethod
    def _queue_contains_action_id(queue_file: Path, action_id: str) -> bool:
        """Check the append-only queue while its producer lock is held.

        Action IDs are optional.  When supplied they are the producer's
        idempotency key: a retry returns success without adding another event,
        even if the first event has already been consumed by the worker.
        """
        if not queue_file.exists():
            return False
        with open(queue_file, "rb") as stream:
            for raw_line in stream:
                # Newline is the record commit marker.  A power-loss tail may
                # contain syntactically complete JSON but is not durable and
                # must never suppress the producer's retry.
                if not raw_line.endswith(b"\n"):
                    break
                try:
                    record = json.loads(raw_line.decode("utf-8", "strict"))
                except Exception:
                    continue
                if isinstance(record, dict) and record.get("action_id") == action_id:
                    return True
        return False

    def action_id_for(self, source_kind: str, source_id, agent_name: str) -> str:
        """Derive a stable logical-delivery key from source + generation."""
        generation = "static:0"
        if self._registry is not None:
            try:
                inst = self._registry.get_instance(agent_name)
            except Exception:
                inst = None
            if inst:
                generation = (
                    f"{inst.get('identity_id', 'unknown')}:{inst.get('epoch', 0)}"
                )
        canonical = json.dumps(
            [str(source_kind), str(source_id), str(agent_name), generation],
            ensure_ascii=True, separators=(",", ":"),
        ).encode("utf-8")
        return "act-" + hashlib.sha256(canonical).hexdigest()

    def _append_entry(self, agent_name: str, entry: dict) -> bool:
        queue_file = self._data_dir / f"{agent_name}_queue.jsonl"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        with queue_file_lock(queue_file):
            require_delivery_fence_clear(queue_file)
            action_id = entry.get("action_id")
            if (
                isinstance(action_id, str)
                and action_id
                and self._queue_contains_action_id(queue_file, action_id)
            ):
                log.info(
                    "Deduplicated @%s producer retry (action_id=%s)",
                    agent_name, action_id,
                )
                return False
            separator = b""
            if queue_file.exists() and queue_file.stat().st_size:
                with open(queue_file, "rb") as stream:
                    stream.seek(-1, os.SEEK_END)
                    if stream.read(1) != b"\n":
                        separator = b"\n"
            encoded = separator + (json.dumps(entry) + "\n").encode("utf-8")
            current_size = queue_file.stat().st_size if queue_file.exists() else 0
            if current_size + len(encoded) > _MAX_QUEUE_BYTES:
                marker = write_backpressure_marker(
                    queue_file, "producer-queue", current_size,
                    _MAX_QUEUE_BYTES,
                )
                message = (
                    f"delivery queue {queue_file.name} reached "
                    f"{current_size}/{_MAX_QUEUE_BYTES} bytes; refusing new "
                    f"event without deletion; reconcile {marker.name}"
                )
                log.error(message)
                raise DeliveryBackpressureError(message)
            append_bytes_durable(queue_file, encoded)
        return True

    async def trigger(self, agent_name: str, message: str = "", channel: str = "general",
                      job_id: int | None = None, **kwargs):
        """Write to the agent's queue file. The worker terminal picks it up."""
        entry = self._build_entry(message, channel, job_id, **kwargs)
        appended = self._append_entry(agent_name, entry)

        if appended:
            log.info("Queued @%s trigger (ch=%s, job=%s): %s", agent_name, channel, job_id, message[:80])
        return appended

    def trigger_sync(self, agent_name: str, message: str = "", channel: str = "general",
                     job_id: int | None = None, **kwargs):
        """Synchronous version of trigger — writes to queue file without async."""
        entry = self._build_entry(message, channel, job_id, **kwargs)
        appended = self._append_entry(agent_name, entry)

        if appended:
            log.info("Queued @%s trigger (ch=%s, job=%s): %s", agent_name, channel, job_id, message[:80])
        return appended
