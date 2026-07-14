"""Session store — persists active session runs to JSON."""

import copy
import json
import os
import tempfile
import time
import threading
import logging
from pathlib import Path

log = logging.getLogger(__name__)


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


class SessionStore:
    def __init__(self, path: str, templates_dir: str | None = None):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._sessions: list[dict] = []
        self._next_id = 1
        self._lock = threading.RLock()
        self._callbacks: list = []
        self._templates: dict[str, dict] = {}
        self._load()

        # Warn about legacy file
        legacy = self._path.parent / "sessions.json"
        if legacy.exists() and legacy != self._path:
            log.info("Ignoring legacy sessions.json; Sessions uses %s", self._path.name)

        if templates_dir:
            self._load_templates(Path(templates_dir))

        # Load custom (user/agent-created) templates
        custom_path = self._path.parent / "custom_templates.json"
        if custom_path.exists():
            try:
                custom = json.loads(custom_path.read_text("utf-8"))
                for tmpl in (custom if isinstance(custom, list) else []):
                    tid = tmpl.get("id", "")
                    if tid:
                        tmpl["is_custom"] = True
                        self._templates[tid] = tmpl
                        log.info("Loaded custom template: %s", tid)
            except (json.JSONDecodeError, KeyError) as exc:
                log.warning("Failed to load custom templates: %s", exc)

    # --- Persistence ---

    def _load(self):
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text("utf-8"))
            if isinstance(raw, list):
                self._sessions = raw
                if self._sessions:
                    self._next_id = max(s["id"] for s in self._sessions) + 1
        except (json.JSONDecodeError, KeyError):
            self._sessions = []

    def _save(self):
        _atomic_write_text(
            self._path,
            json.dumps(self._sessions, indent=2, ensure_ascii=False) + "\n",
        )

    # --- Templates ---

    def _load_templates(self, directory: Path):
        if not directory.exists():
            log.warning("Session templates directory not found: %s", directory)
            return
        for f in sorted(directory.glob("*.json")):
            try:
                tmpl = json.loads(f.read_text("utf-8"))
                tid = tmpl.get("id", f.stem)
                tmpl["id"] = tid
                tmpl.setdefault("is_custom", False)
                self._templates[tid] = tmpl
                log.info("Loaded session template: %s", tid)
            except (json.JSONDecodeError, KeyError) as exc:
                log.warning("Failed to load template %s: %s", f.name, exc)

    def get_templates(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy(list(self._templates.values()))

    def get_template(self, template_id: str) -> dict | None:
        with self._lock:
            tmpl = self._templates.get(template_id)
            return copy.deepcopy(tmpl) if tmpl is not None else None

    def get_template_for_session(self, session: dict | int) -> dict | None:
        """Resolve a session's inline template before the global catalogue."""
        with self._lock:
            if isinstance(session, int):
                session_data = self._find(session)
            elif isinstance(session, dict):
                session_data = session
            else:
                session_data = None
            if not session_data:
                return None
            transient = session_data.get("transient_template")
            if isinstance(transient, dict):
                return copy.deepcopy(transient)
            template_id = session_data.get("template_id")
            tmpl = self._templates.get(template_id)
            return copy.deepcopy(tmpl) if tmpl is not None else None

    def save_custom_template(self, tmpl: dict) -> dict:
        custom_path = self._path.parent / "custom_templates.json"
        saved = copy.deepcopy(tmpl)
        template_id = saved.get("id")
        if not isinstance(template_id, str) or not template_id:
            raise ValueError("custom template id is required")
        saved["is_custom"] = True
        with self._lock:
            custom = [
                copy.deepcopy(item) for item in self._templates.values()
                if item.get("is_custom") and item.get("id") != template_id
            ]
            custom.append(saved)
            _atomic_write_text(
                custom_path,
                json.dumps(custom, indent=2, ensure_ascii=False) + "\n",
            )
            self._templates[template_id] = copy.deepcopy(saved)
        return copy.deepcopy(saved)

    def delete_custom_template(self, template_id: str) -> bool:
        custom_path = self._path.parent / "custom_templates.json"
        with self._lock:
            tmpl = self._templates.get(template_id)
            if not tmpl or not tmpl.get("is_custom"):
                return False
            new_custom = [
                copy.deepcopy(item) for item in self._templates.values()
                if item.get("is_custom") and item.get("id") != template_id
            ]
            _atomic_write_text(
                custom_path,
                json.dumps(new_custom, indent=2, ensure_ascii=False) + "\n",
            )
            self._templates.pop(template_id, None)
        return True

    # --- Callbacks ---

    def on_change(self, callback):
        """Register a callback(action, session) on any change.
        action: 'create', 'update', 'complete', 'interrupt', 'delete'."""
        self._callbacks.append(callback)

    def _fire(self, action: str, session: dict):
        for cb in self._callbacks:
            try:
                cb(action, session)
            except Exception:
                pass

    # --- Session lifecycle ---

    def create(self, template_id: str, channel: str, cast: dict,
               started_by: str, goal: str = "") -> dict | None:
        """Create and persist a new session run."""
        with self._lock:
            tmpl = copy.deepcopy(self._templates.get(template_id))
        if not tmpl:
            return None
        return self._create_with_template(
            template_id, tmpl, channel, cast, started_by, goal,
            transient=False,
        )

    def create_from_template(self, tmpl: dict, channel: str, cast: dict,
                             started_by: str, goal: str = "") -> dict | None:
        """Create from an inline template without publishing it as custom."""
        template = copy.deepcopy(tmpl)
        template_id = template.get("id")
        if not isinstance(template_id, str) or not template_id:
            raise ValueError("inline template id is required")
        return self._create_with_template(
            template_id, template, channel, cast, started_by, goal,
            transient=True,
        )

    def _create_with_template(self, template_id: str, tmpl: dict,
                              channel: str, cast: dict, started_by: str,
                              goal: str, *, transient: bool) -> dict | None:
        with self._lock:
            # One active session per channel
            for s in self._sessions:
                if s.get("channel") == channel and s.get("state") in ("active", "waiting", "paused"):
                    return None

            session = {
                "id": self._next_id,
                "template_id": template_id,
                "template_name": tmpl.get("name", template_id),
                "channel": channel,
                "cast": copy.deepcopy(cast),
                "state": "active",
                "current_phase": 0,
                "current_turn": 0,
                "started_by": started_by,
                "started_at": time.time(),
                "updated_at": time.time(),
                "last_message_id": None,
                "output_message_id": None,
                "goal": goal.strip()[:500],
            }
            if transient:
                session["transient_template"] = copy.deepcopy(tmpl)
            previous_next_id = self._next_id
            self._next_id += 1
            self._sessions.append(session)
            try:
                self._save()
            except Exception:
                self._sessions.pop()
                self._next_id = previous_next_id
                raise

        result = copy.deepcopy(session)
        self._fire("create", result)
        return result

    def delete(self, session_id: int) -> dict | None:
        """Delete a session, restoring it if persistence fails."""
        with self._lock:
            for index, session in enumerate(self._sessions):
                if session["id"] == session_id:
                    removed = self._sessions.pop(index)
                    try:
                        self._save()
                    except Exception:
                        self._sessions.insert(index, removed)
                        raise
                    result = copy.deepcopy(removed)
                    break
            else:
                return None
        self._fire("delete", result)
        return result

    def get(self, session_id: int) -> dict | None:
        with self._lock:
            for s in self._sessions:
                if s["id"] == session_id:
                    return copy.deepcopy(s)
            return None

    def get_active(self, channel: str) -> dict | None:
        """Get the active/waiting/paused session for a channel."""
        with self._lock:
            for s in self._sessions:
                if s.get("channel") == channel and s.get("state") in ("active", "waiting", "paused"):
                    return copy.deepcopy(s)
            return None

    def list_all(self, channel: str | None = None) -> list[dict]:
        with self._lock:
            result = copy.deepcopy(self._sessions)
        if channel:
            result = [s for s in result if s.get("channel") == channel]
        return result

    def advance_turn(self, session_id: int, message_id: int | None = None) -> dict | None:
        """Advance to the next turn within the current phase."""
        with self._lock:
            session = self._find(session_id)
            if not session or session["state"] not in ("active", "waiting"):
                return None
            previous = copy.deepcopy(session)
            session["current_turn"] += 1
            session["state"] = "active"
            session["updated_at"] = time.time()
            if message_id is not None:
                session["last_message_id"] = message_id
            try:
                self._save()
            except Exception:
                session.clear()
                session.update(previous)
                raise
            result = copy.deepcopy(session)
        self._fire("update", result)
        return result

    def advance_phase(self, session_id: int, message_id: int | None = None) -> dict | None:
        """Advance to the next phase, resetting turn to 0."""
        with self._lock:
            session = self._find(session_id)
            if not session or session["state"] not in ("active", "waiting"):
                return None
            previous = copy.deepcopy(session)
            session["current_phase"] += 1
            session["current_turn"] = 0
            session["state"] = "active"
            session["updated_at"] = time.time()
            if message_id is not None:
                session["last_message_id"] = message_id
            try:
                self._save()
            except Exception:
                session.clear()
                session.update(previous)
                raise
            result = copy.deepcopy(session)
        self._fire("update", result)
        return result

    def set_waiting(self, session_id: int, agent: str) -> dict | None:
        """Mark session as waiting on a specific agent."""
        with self._lock:
            session = self._find(session_id)
            if not session:
                return None
            previous = copy.deepcopy(session)
            session["state"] = "waiting"
            session["waiting_on"] = agent
            session["updated_at"] = time.time()
            try:
                self._save()
            except Exception:
                session.clear()
                session.update(previous)
                raise
            result = copy.deepcopy(session)
        self._fire("update", result)
        return result

    def pause(self, session_id: int) -> dict | None:
        """Pause session (human interruption)."""
        with self._lock:
            session = self._find(session_id)
            if not session or session["state"] not in ("active", "waiting"):
                return None
            previous = copy.deepcopy(session)
            session["state"] = "paused"
            session["updated_at"] = time.time()
            try:
                self._save()
            except Exception:
                session.clear()
                session.update(previous)
                raise
            result = copy.deepcopy(session)
        self._fire("update", result)
        return result

    def resume(self, session_id: int) -> dict | None:
        """Resume a paused session."""
        with self._lock:
            session = self._find(session_id)
            if not session or session["state"] != "paused":
                return None
            previous = copy.deepcopy(session)
            session["state"] = "active"
            session["updated_at"] = time.time()
            try:
                self._save()
            except Exception:
                session.clear()
                session.update(previous)
                raise
            result = copy.deepcopy(session)
        self._fire("update", result)
        return result

    def complete(self, session_id: int, output_message_id: int | None = None) -> dict | None:
        """Mark session as complete."""
        with self._lock:
            session = self._find(session_id)
            if not session:
                return None
            previous = copy.deepcopy(session)
            session["state"] = "complete"
            session["updated_at"] = time.time()
            if output_message_id is not None:
                session["output_message_id"] = output_message_id
            try:
                self._save()
            except Exception:
                session.clear()
                session.update(previous)
                raise
            result = copy.deepcopy(session)
        self._fire("complete", result)
        return result

    def interrupt(self, session_id: int, reason: str = "ended by user") -> dict | None:
        """End session early."""
        with self._lock:
            session = self._find(session_id)
            if not session or session["state"] in ("complete", "interrupted"):
                return None
            previous = copy.deepcopy(session)
            session["state"] = "interrupted"
            session["interrupt_reason"] = reason
            session["updated_at"] = time.time()
            try:
                self._save()
            except Exception:
                session.clear()
                session.update(previous)
                raise
            result = copy.deepcopy(session)
        self._fire("interrupt", result)
        return result

    def _find(self, session_id: int) -> dict | None:
        """Find session by ID (caller must hold lock)."""
        for s in self._sessions:
            if s["id"] == session_id:
                return s
        return None


def validate_session_template(tmpl: dict) -> list[str]:
    """Validate a session template dict. Returns list of errors (empty = valid)."""
    errors = []

    if not isinstance(tmpl, dict):
        return ["Template must be a JSON object"]

    if not tmpl.get("name") or not isinstance(tmpl.get("name"), str):
        errors.append("Missing or invalid 'name' (string required)")

    roles = tmpl.get("roles", [])
    if not isinstance(roles, list) or len(roles) == 0:
        errors.append("'roles' must be a non-empty array")
    elif len(roles) > 6:
        errors.append(f"Too many roles ({len(roles)}, max 6)")

    phases = tmpl.get("phases", [])
    if not isinstance(phases, list) or len(phases) == 0:
        errors.append("'phases' must be a non-empty array")
    elif len(phases) > 6:
        errors.append(f"Too many phases ({len(phases)}, max 6)")

    roles_set = set(roles) if isinstance(roles, list) else set()
    output_count = 0

    for i, phase in enumerate(phases if isinstance(phases, list) else []):
        if not isinstance(phase, dict):
            errors.append(f"Phase {i + 1}: must be an object")
            continue
        if not phase.get("name"):
            errors.append(f"Phase {i + 1}: missing 'name'")
        participants = phase.get("participants", [])
        if not isinstance(participants, list) or len(participants) == 0:
            errors.append(f"Phase {i + 1}: 'participants' must be a non-empty array")
        elif len(participants) > 4:
            errors.append(f"Phase {i + 1}: too many participants ({len(participants)}, max 4)")
        for p in (participants if isinstance(participants, list) else []):
            if p not in roles_set:
                errors.append(f"Phase {i + 1}: participant '{p}' not in roles list")
        prompt = phase.get("prompt", "")
        if isinstance(prompt, str) and len(prompt) > 200:
            errors.append(f"Phase {i + 1}: prompt too long ({len(prompt)} chars, max 200)")
        if phase.get("is_output"):
            output_count += 1

    if output_count == 0 and isinstance(phases, list) and len(phases) > 0:
        errors.append("No phase marked as 'is_output: true'")
    elif output_count > 1:
        errors.append(f"Multiple phases marked as output ({output_count}, expected 1)")

    return errors
