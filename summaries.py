"""Per-channel summary store — agents write, everyone reads."""

import json
import os
import tempfile
import time
import threading
import uuid
from pathlib import Path


def _atomic_write_text(path: Path, content: str):
    """Replace *path* atomically after flushing file contents."""
    fd = None
    temp_path: Path | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        temp_path = Path(temp_name)
        stream = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        fd = None
        with stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        temp_path = None
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            pass
    finally:
        if fd is not None:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass

MAX_CHARS = 1000


class SummaryStore:
    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._summaries: dict[str, dict] = {}  # channel → summary dict
        self._lock = threading.RLock()
        self._load()

    def _load(self):
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text("utf-8"))
            if isinstance(raw, dict):
                self._summaries = raw
        except (json.JSONDecodeError, KeyError):
            self._summaries = {}

    def _save(self):
        _atomic_write_text(
            self._path,
            json.dumps(self._summaries, indent=2, ensure_ascii=False) + "\n",
        )

    def get(self, channel: str) -> dict | None:
        with self._lock:
            entry = self._summaries.get(channel)
            return dict(entry) if entry else None

    def get_all(self) -> dict:
        with self._lock:
            return {ch: dict(s) for ch, s in self._summaries.items()}

    def write(self, channel: str, text: str, author: str, message_id: int = 0,
              uid: str | None = None, updated_at: float | None = None) -> dict | None:
        text = text.strip()
        if not text:
            return None
        if len(text) > MAX_CHARS:
            return None  # Caller should inform the agent
        with self._lock:
            entry = {
                "uid": uid or str(uuid.uuid4()),
                "text": text,
                "author": author,
                "updated_at": updated_at if updated_at is not None else time.time(),
                "message_id": message_id,
            }
            had_previous = channel in self._summaries
            previous = self._summaries.get(channel)
            self._summaries[channel] = entry
            try:
                self._save()
            except Exception:
                if had_previous:
                    self._summaries[channel] = previous
                else:
                    self._summaries.pop(channel, None)
                raise
            return dict(entry)

    def delete(self, channel: str) -> bool:
        with self._lock:
            if channel in self._summaries:
                previous = dict(self._summaries)
                self._summaries.pop(channel)
                try:
                    self._save()
                except Exception:
                    self._summaries.clear()
                    self._summaries.update(previous)
                    raise
                return True
            return False
