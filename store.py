"""JSONL message persistence for the chat room with observer callbacks."""

import json
import os
import copy
import tempfile
import time
import threading
import uuid
from pathlib import Path


def _atomic_write_bytes(path: Path, content: bytes):
    """Durably replace a file without exposing a truncated destination."""
    fd = None
    temp_path = None
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent),
        )
        temp_path = Path(temp_name)
        stream = os.fdopen(fd, "wb")
        fd = None
        with stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        temp_path = None
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if fd is not None:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def _atomic_write_text(path: Path, content: str):
    _atomic_write_bytes(path, content.encode("utf-8"))


def _file_snapshot(path: Path) -> tuple[bool, bytes]:
    return (True, path.read_bytes()) if path.exists() else (False, b"")


def _restore_file_snapshot(path: Path, snapshot: tuple[bool, bytes]):
    existed, content = snapshot
    if existed:
        _atomic_write_bytes(path, content)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


class MessageLogCorruptionError(RuntimeError):
    """Raised when committed JSONL bytes cannot be interpreted safely."""


class MessageStoreWriteBlockedError(MessageLogCorruptionError):
    """Raised after an append rollback becomes durability-ambiguous."""


class MessageStore:
    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._todos_path = self._path.parent / "todos.json"
        self._messages: list[dict] = []
        self._next_id: int = 0  # monotonically increasing, survives deletions
        self._todos: dict[int, str] = {}  # msg_id → "todo" | "done"
        # Archive transactions hold all participating store locks while their
        # import helpers re-enter individual stores on the same thread.
        self._lock = threading.RLock()
        self._callbacks: list = []  # called on each new message
        self._todo_callbacks: list = []  # called on todo changes
        self._delete_callbacks: list = []  # called on message deletion
        self.upload_dir = self._path.parent.parent / "uploads"  # Default fallback
        self._append_needs_separator = False
        self._write_block_path = self._path.with_name(
            f"{self._path.name}.write-blocked.json"
        )
        self._write_blocked_reason: str | None = (
            "durable write-block marker exists"
            if self._write_block_path.exists() else None
        )
        self._load()
        self._load_todos()

    def _load(self):
        if not self._path.exists():
            return
        raw = self._path.read_bytes()
        messages, max_id, torn_start = self._parse_log_bytes(raw)
        if torn_start is not None and self._write_blocked_reason is None:
            raw = self._quarantine_and_repair_tail(raw, torn_start)
        self._messages = messages
        self._next_id = max_id + 1
        self._append_needs_separator = bool(raw and not raw.endswith(b"\n"))

    def _parse_log_bytes(self, raw: bytes) -> tuple[list[dict], int, int | None]:
        """Parse committed records and identify only an uncommitted final tail."""
        messages: list[dict] = []
        max_id = -1
        offset = 0
        records = raw.splitlines(keepends=True)
        for index, record in enumerate(records):
            start = offset
            offset += len(record)
            has_lf = record.endswith(b"\n")
            payload = record[:-1] if has_lf else record
            if payload.endswith(b"\r"):
                payload = payload[:-1]
            if not payload.strip():
                continue
            try:
                decoded = payload.decode("utf-8")
                msg = json.loads(decoded)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                if index == len(records) - 1 and not has_lf:
                    return messages, max_id, start
                raise MessageLogCorruptionError(
                    f"malformed committed JSONL record {index + 1} in {self._path}"
                ) from exc
            if not isinstance(msg, dict):
                raise MessageLogCorruptionError(
                    f"non-object JSONL record {index + 1} in {self._path}"
                )
            if "id" not in msg:
                msg["id"] = index
            try:
                message_id = int(msg["id"])
            except (TypeError, ValueError) as exc:
                raise MessageLogCorruptionError(
                    f"invalid message id in JSONL record {index + 1} in {self._path}"
                ) from exc
            msg["id"] = message_id
            max_id = max(max_id, message_id)
            messages.append(msg)
        return messages, max_id, None

    def _quarantine_and_repair_tail(self, raw: bytes, start: int) -> bytes:
        """Preserve a torn suffix as evidence before replacing the live prefix."""
        suffix = raw[start:]
        quarantine = self._path.with_name(
            f"{self._path.name}.quarantine-{time.time_ns()}-"
            f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        )
        try:
            _atomic_write_bytes(quarantine, suffix)
            prefix = raw[:start]
            _atomic_write_bytes(self._path, prefix)
        except Exception as exc:
            raise MessageLogCorruptionError(
                f"could not quarantine and repair torn JSONL tail in {self._path}"
            ) from exc
        return prefix

    def _prepare_append_locked(self) -> bool:
        """Validate current bytes and repair only an uncommitted final suffix."""
        self._assert_writable_locked()
        if not self._path.exists():
            return False
        raw = self._path.read_bytes()
        _messages, _max_id, torn_start = self._parse_log_bytes(raw)
        if torn_start is not None:
            raw = self._quarantine_and_repair_tail(raw, torn_start)
        return bool(raw and not raw.endswith(b"\n"))

    def _assert_writable_locked(self):
        if self._write_blocked_reason is not None:
            raise MessageStoreWriteBlockedError(
                f"message store is write-blocked: {self._write_blocked_reason}"
            )

    def _mark_write_blocked_locked(
        self, append_error: Exception, compensation_error: Exception,
        original_size: int,
    ):
        """Persist a terminal marker without modifying the uncertain log."""
        self._write_blocked_reason = (
            "append persistence failed and rollback could not be made durable"
        )
        marker = json.dumps({
            "version": 1,
            "blocked_at_ns": time.time_ns(),
            "original_size": original_size,
            "append_error": repr(append_error),
            "compensation_error": repr(compensation_error),
        }, ensure_ascii=True, indent=2).encode("utf-8") + b"\n"
        try:
            _atomic_write_bytes(self._write_block_path, marker)
        except Exception:
            # The same storage fault may prevent a durable atomic marker. Keep
            # this process terminally blocked and make one non-destructive,
            # best-effort marker write; the uncertain log remains evidence.
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                fd = os.open(str(self._write_block_path), flags, 0o600)
                try:
                    os.write(fd, marker)
                finally:
                    os.close(fd)
            except Exception:
                pass

    def _reload_blocked_log_locked(self):
        """Reflect only parseable disk records after an uncertain append."""
        try:
            raw = self._path.read_bytes() if self._path.exists() else b""
            messages, max_id, _torn_start = self._parse_log_bytes(raw)
        except Exception:
            return
        self._messages = messages
        self._next_id = max_id + 1
        self._append_needs_separator = False

    def on_message(self, callback):
        """Register a callback(msg) called whenever a message is added."""
        self._callbacks.append(callback)

    def snapshot_state(self) -> dict:
        """Capture exact in-memory and on-disk state for a higher-level transaction."""
        with self._lock:
            return {
                "messages": copy.deepcopy(self._messages),
                "next_id": self._next_id,
                "todos": copy.deepcopy(self._todos),
                "append_needs_separator": self._append_needs_separator,
                "messages_file": _file_snapshot(self._path),
                "todos_file": _file_snapshot(self._todos_path),
            }

    def restore_state(self, snapshot: dict):
        """Restore a snapshot exactly; keep the current state if restore fails."""
        with self._lock:
            self._assert_writable_locked()
            current = {
                "messages": copy.deepcopy(self._messages),
                "next_id": self._next_id,
                "todos": copy.deepcopy(self._todos),
                "append_needs_separator": self._append_needs_separator,
                "messages_file": _file_snapshot(self._path),
                "todos_file": _file_snapshot(self._todos_path),
            }
            self._messages = copy.deepcopy(snapshot["messages"])
            self._next_id = snapshot["next_id"]
            self._todos = copy.deepcopy(snapshot["todos"])
            self._append_needs_separator = snapshot.get("append_needs_separator", False)
            try:
                _restore_file_snapshot(self._path, snapshot["messages_file"])
                _restore_file_snapshot(self._todos_path, snapshot["todos_file"])
            except Exception:
                self._messages = current["messages"]
                self._next_id = current["next_id"]
                self._todos = current["todos"]
                self._append_needs_separator = current["append_needs_separator"]
                try:
                    _restore_file_snapshot(self._path, current["messages_file"])
                    _restore_file_snapshot(self._todos_path, current["todos_file"])
                except Exception:
                    pass
                raise

    def _append_message(self, msg: dict):
        """Durably append one message, restoring the prior file on failure."""
        self._append_needs_separator = self._prepare_append_locked()
        existed = self._path.exists()
        original_size = self._path.stat().st_size if existed else 0
        prefix = b"\n" if self._append_needs_separator and original_size else b""
        record = prefix + (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            with open(self._path, "ab") as f:
                f.write(record)
                f.flush()
                os.fsync(f.fileno())
            self._append_needs_separator = False
        except Exception as append_error:
            # A write/flush/fsync failure can leave a partial JSONL record.
            # Restore the exact pre-append length using low-level I/O so a
            # patched/high-level file object cannot prevent compensation.
            compensation_error = None
            try:
                if self._path.exists():
                    fd = os.open(str(self._path), os.O_RDWR)
                    try:
                        os.ftruncate(fd, original_size)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    if not existed and original_size == 0:
                        self._path.unlink()
            except Exception as exc:
                compensation_error = exc
            if compensation_error is not None:
                self._mark_write_blocked_locked(
                    append_error, compensation_error, original_size,
                )
                raise MessageStoreWriteBlockedError(
                    "append failed and compensating truncate/fsync failed; "
                    "message store is now write-blocked"
                ) from append_error
            raise

    def add(self, sender: str, text: str, msg_type: str = "chat",
            attachments: list | None = None, reply_to: int | None = None,
            channel: str = "general",
            metadata: dict | None = None,
            uid: str | None = None,
            timestamp: float | None = None,
            time_str: str | None = None,
            _bulk: bool = False) -> dict:
        with self._lock:
            self._assert_writable_locked()
            ts = timestamp if timestamp is not None else time.time()
            msg = {
                "id": self._next_id,
                "uid": uid or str(uuid.uuid4()),
                "sender": sender,
                "text": text,
                "type": msg_type,
                "timestamp": ts,
                "time": time_str or time.strftime("%H:%M:%S"),
                "attachments": copy.deepcopy(attachments or []),
                "channel": channel,
            }
            if reply_to is not None:
                msg["reply_to"] = reply_to
            if metadata:
                msg["metadata"] = copy.deepcopy(metadata)
            previous_next_id = self._next_id
            self._next_id += 1
            self._messages.append(msg)
            if not _bulk:
                try:
                    self._append_message(msg)
                except Exception:
                    self._messages.pop()
                    self._next_id = previous_next_id
                    if self._write_blocked_reason is not None:
                        self._reload_blocked_log_locked()
                    raise

        # Fire callbacks outside the lock (skip during bulk import)
        result = copy.deepcopy(msg)
        if not _bulk:
            for cb in self._callbacks:
                try:
                    cb(copy.deepcopy(result))
                except Exception:
                    pass

        return result

    def flush_bulk(self):
        """Write all in-memory messages to disk. Call after bulk add operations."""
        with self._lock:
            self._assert_writable_locked()
            self._rewrite()

    def update_reply_to(self, msg_id: int, reply_to: int):
        """Set reply_to on an existing message (used by import to rebuild links)."""
        with self._lock:
            self._assert_writable_locked()
            for m in self._messages:
                if m["id"] == msg_id:
                    previous = m.get("reply_to")
                    had_previous = "reply_to" in m
                    m["reply_to"] = reply_to
                    try:
                        self._rewrite()
                    except Exception:
                        if had_previous:
                            m["reply_to"] = previous
                        else:
                            m.pop("reply_to", None)
                        raise
                    return

    def _rewrite(self):
        """Rewrite the full JSONL file from memory (used after bulk edits)."""
        self._assert_writable_locked()
        content = "".join(
            json.dumps(message, ensure_ascii=False) + "\n"
            for message in self._messages
        )
        _atomic_write_text(self._path, content)
        self._append_needs_separator = False

    def get_by_id(self, msg_id: int) -> dict | None:
        with self._lock:
            for m in self._messages:
                if m["id"] == msg_id:
                    return copy.deepcopy(m)
            return None

    def get_recent(self, count: int = 50, channel: str | None = None) -> list[dict]:
        with self._lock:
            msgs = self._messages
            if channel:
                msgs = [m for m in msgs if m.get("channel", "general") == channel]
            return copy.deepcopy(msgs[-count:])

    def get_since(self, since_id: int = 0, channel: str | None = None) -> list[dict]:
        with self._lock:
            msgs = [m for m in self._messages if m["id"] > since_id]
            if channel:
                msgs = [m for m in msgs if m.get("channel", "general") == channel]
            return copy.deepcopy(msgs)

    def get_channels(self) -> list[str]:
        """Return message channels in first-seen order.

        The persisted log is the durable source for channels created by API
        and MCP clients.  Keeping this query on the store avoids exposing its
        internal message list to the web layer.
        """
        with self._lock:
            seen: set[str] = set()
            channels: list[str] = []
            for message in self._messages:
                channel = message.get("channel", "general") or "general"
                if not isinstance(channel, str):
                    continue
                if channel not in seen:
                    seen.add(channel)
                    channels.append(channel)
            return channels

    def delete(self, msg_ids: list[int]) -> list[int]:
        """Delete messages by ID. Returns list of IDs actually deleted."""
        deleted = []
        deleted_attachments = []
        with self._lock:
            self._assert_writable_locked()
            messages_before = copy.deepcopy(self._messages)
            todos_before = dict(self._todos)
            messages_file_before = _file_snapshot(self._path)
            todos_file_before = _file_snapshot(self._todos_path)
            for mid in msg_ids:
                for i, m in enumerate(self._messages):
                    if m["id"] == mid:
                        # Collect attachment files for cleanup
                        for att in m.get("attachments", []):
                            url = att.get("url", "")
                            if url.startswith("/uploads/"):
                                deleted_attachments.append(url.split("/")[-1])
                        # Remove any associated todo
                        if mid in self._todos:
                            del self._todos[mid]
                        self._messages.pop(i)
                        deleted.append(mid)
                        break
            if deleted:
                try:
                    self._rewrite_jsonl()
                    self._save_todos()
                except Exception:
                    self._messages = messages_before
                    self._todos = todos_before
                    try:
                        _restore_file_snapshot(self._path, messages_file_before)
                        _restore_file_snapshot(self._todos_path, todos_file_before)
                    except Exception:
                        pass
                    raise

        # Clean up uploaded images outside the lock
        for filename in deleted_attachments:
            filepath = self.upload_dir / filename
            if filepath.exists():
                try:
                    filepath.unlink()
                except Exception:
                    pass

        # Fire callbacks
        for cb in self._delete_callbacks:
            try:
                cb(deleted)
            except Exception:
                pass

        return deleted

    def on_delete(self, callback):
        """Register a callback(ids) called when messages are deleted."""
        self._delete_callbacks.append(callback)

    def update_message(self, msg_id: int, updates: dict) -> dict | None:
        """Update fields on a message in-place. Returns the updated message or None."""
        with self._lock:
            self._assert_writable_locked()
            for m in self._messages:
                if m["id"] == msg_id:
                    previous = copy.deepcopy(m)
                    m.update(updates)
                    try:
                        self._rewrite_jsonl()
                    except Exception:
                        m.clear()
                        m.update(previous)
                        raise
                    return copy.deepcopy(m)
            return None

    def restore_message(self, snapshot: dict) -> dict | None:
        """Replace one message exactly, including absence of optional keys."""
        replacement = copy.deepcopy(snapshot)
        message_id = replacement.get("id")
        with self._lock:
            self._assert_writable_locked()
            for index, message in enumerate(self._messages):
                if message["id"] == message_id:
                    previous = message
                    self._messages[index] = replacement
                    try:
                        self._rewrite_jsonl()
                    except Exception:
                        self._messages[index] = previous
                        raise
                    return copy.deepcopy(replacement)
            return None

    def resolve_decision(self, msg_id: int, chosen: str,
                         username: str) -> tuple[dict | None, dict | None,
                                                  tuple[str, int] | None]:
        """Resolve a decision and append its reply as one durable rewrite."""
        with self._lock:
            self._assert_writable_locked()
            message = next((m for m in self._messages if m["id"] == msg_id), None)
            if message is None:
                return None, None, ("message not found", 404)
            if message.get("type") != "decision":
                return None, None, ("not a decision message", 400)
            metadata = copy.deepcopy(message.get("metadata") or {})
            if metadata.get("resolved"):
                return None, None, ("already resolved", 400)
            valid_choices = metadata.get("choices", [])
            if valid_choices and chosen not in valid_choices:
                return None, None, (f"invalid choice. Valid: {valid_choices}", 400)

            messages_before = copy.deepcopy(self._messages)
            next_id_before = self._next_id
            sender = message.get("sender", "")
            channel = message.get("channel", "general")
            metadata["resolved"] = True
            metadata["chosen"] = chosen
            message["metadata"] = metadata

            timestamp = time.time()
            reply = {
                "id": self._next_id,
                "uid": str(uuid.uuid4()),
                "sender": username,
                "text": f"@{sender} {chosen}" if sender else chosen,
                "type": "chat",
                "timestamp": timestamp,
                "time": time.strftime("%H:%M:%S"),
                "attachments": [],
                "channel": channel,
                "reply_to": msg_id,
            }
            self._next_id += 1
            self._messages.append(reply)
            try:
                self._rewrite_jsonl()
            except Exception:
                self._messages = messages_before
                self._next_id = next_id_before
                raise
            updated = copy.deepcopy(message)
            reply_result = copy.deepcopy(reply)

        for callback in self._callbacks:
            try:
                callback(copy.deepcopy(reply_result))
            except Exception:
                pass
        return updated, reply_result, None

    def _rewrite_jsonl(self):
        """Rewrite the JSONL file from current in-memory messages."""
        self._rewrite()

    def clear(self, channel: str | None = None):
        """Wipe messages and rewrite the log file.
        If channel is given, only clear messages in that channel."""
        with self._lock:
            self._assert_writable_locked()
            messages_before = copy.deepcopy(self._messages)
            todos_before = dict(self._todos)
            messages_file_before = _file_snapshot(self._path)
            todos_file_before = _file_snapshot(self._todos_path)
            try:
                if channel:
                    removed_ids = {
                        m["id"] for m in self._messages
                        if m.get("channel", "general") == channel
                    }
                    self._messages = [
                        m for m in self._messages
                        if m.get("channel", "general") != channel
                    ]
                    if removed_ids:
                        for tid in list(self._todos.keys()):
                            if tid in removed_ids:
                                del self._todos[tid]
                        self._rewrite_jsonl()
                        self._save_todos()
                else:
                    self._messages.clear()
                    self._todos.clear()
                    self._rewrite_jsonl()
                    self._save_todos()
            except Exception:
                self._messages = messages_before
                self._todos = todos_before
                try:
                    _restore_file_snapshot(self._path, messages_file_before)
                    _restore_file_snapshot(self._todos_path, todos_file_before)
                except Exception:
                    pass
                raise

    def rename_channel(self, old_name: str, new_name: str):
        """Migrate all messages from old_name to new_name."""
        with self._lock:
            self._assert_writable_locked()
            modified = False
            changed = []
            for m in self._messages:
                if m.get("channel") == old_name:
                    changed.append(m)
                    m["channel"] = new_name
                    modified = True
            if modified:
                try:
                    self._rewrite_jsonl()
                except Exception:
                    for message in changed:
                        message["channel"] = old_name
                    raise

    def rename_sender(self, old_name: str, new_name: str) -> int:
        """Rename sender on all messages from old_name to new_name. Returns count updated."""
        with self._lock:
            self._assert_writable_locked()
            count = 0
            changed = []
            for m in self._messages:
                if m.get("sender") == old_name:
                    changed.append(m)
                    m["sender"] = new_name
                    count += 1
            if count:
                try:
                    self._rewrite_jsonl()
                except Exception:
                    for message in changed:
                        message["sender"] = old_name
                    raise
        return count

    def delete_channel(self, name: str):
        """Remove all messages belonging to a deleted channel."""
        with self._lock:
            self._assert_writable_locked()
            messages_before = copy.deepcopy(self._messages)
            todos_before = dict(self._todos)
            messages_file_before = _file_snapshot(self._path)
            todos_file_before = _file_snapshot(self._todos_path)
            original_len = len(self._messages)
            # Collect IDs of messages being removed so we can clean up their todos
            removed_ids = {m["id"] for m in self._messages if m.get("channel") == name}
            self._messages = [m for m in self._messages if m.get("channel") != name]
            if len(self._messages) != original_len:
                for tid in list(self._todos.keys()):
                    if tid in removed_ids:
                        del self._todos[tid]
                try:
                    self._rewrite_jsonl()
                    self._save_todos()
                except Exception:
                    self._messages = messages_before
                    self._todos = todos_before
                    try:
                        _restore_file_snapshot(self._path, messages_file_before)
                        _restore_file_snapshot(self._todos_path, todos_file_before)
                    except Exception:
                        pass
                    raise

    # --- Todos ---

    def _load_todos(self):
        # Migrate old pins.json (list of ints) → todos.json (dict of id→status)
        old_pins = self._todos_path.parent / "pins.json"
        if old_pins.exists() and not self._todos_path.exists():
            try:
                ids = json.loads(old_pins.read_text("utf-8"))
                if isinstance(ids, list):
                    self._todos = {int(i): "todo" for i in ids}
                    self._save_todos()
                    old_pins.unlink()
            except Exception:
                pass

        if self._todos_path.exists():
            try:
                raw = json.loads(self._todos_path.read_text("utf-8"))
                self._todos = {int(k): v for k, v in raw.items()}
            except Exception:
                self._todos = {}

    def _save_todos(self):
        self._assert_writable_locked()
        _atomic_write_text(
            self._todos_path,
            json.dumps({str(k): v for k, v in self._todos.items()}, indent=2),
        )

    def on_todo(self, callback):
        """Register a callback(msg_id, status) called on todo changes.
        status is 'todo', 'done', or None (removed)."""
        self._todo_callbacks.append(callback)

    def _fire_todo(self, msg_id: int, status: str | None):
        for cb in self._todo_callbacks:
            try:
                cb(msg_id, status)
            except Exception:
                pass

    def add_todo(self, msg_id: int) -> bool:
        with self._lock:
            self._assert_writable_locked()
            if not any(m["id"] == msg_id for m in self._messages):
                return False
            previous = self._todos.get(msg_id)
            had_previous = msg_id in self._todos
            self._todos[msg_id] = "todo"
            try:
                self._save_todos()
            except Exception:
                if had_previous:
                    self._todos[msg_id] = previous
                else:
                    self._todos.pop(msg_id, None)
                raise
        self._fire_todo(msg_id, "todo")
        return True

    def complete_todo(self, msg_id: int) -> bool:
        with self._lock:
            self._assert_writable_locked()
            if msg_id not in self._todos:
                return False
            previous = self._todos[msg_id]
            self._todos[msg_id] = "done"
            try:
                self._save_todos()
            except Exception:
                self._todos[msg_id] = previous
                raise
        self._fire_todo(msg_id, "done")
        return True

    def reopen_todo(self, msg_id: int) -> bool:
        with self._lock:
            self._assert_writable_locked()
            if msg_id not in self._todos:
                return False
            previous = self._todos[msg_id]
            self._todos[msg_id] = "todo"
            try:
                self._save_todos()
            except Exception:
                self._todos[msg_id] = previous
                raise
        self._fire_todo(msg_id, "todo")
        return True

    def remove_todo(self, msg_id: int) -> bool:
        with self._lock:
            self._assert_writable_locked()
            if msg_id not in self._todos:
                return False
            previous = dict(self._todos)
            self._todos.pop(msg_id)
            try:
                self._save_todos()
            except Exception:
                self._todos = previous
                raise
        self._fire_todo(msg_id, None)
        return True

    def get_todo_status(self, msg_id: int) -> str | None:
        return self._todos.get(msg_id)

    def get_todos(self) -> dict[int, str]:
        """Returns {msg_id: status} for all todos."""
        return dict(self._todos)

    def get_todo_messages(self, status: str | None = None) -> list[dict]:
        """Get todo messages, optionally filtered by status."""
        with self._lock:
            if status:
                ids = {k for k, v in self._todos.items() if v == status}
            else:
                ids = set(self._todos.keys())
            return [m for m in self._messages if m["id"] in ids]

    @property
    def last_id(self) -> int:
        with self._lock:
            return self._messages[-1]["id"] if self._messages else -1
