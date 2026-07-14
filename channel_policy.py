"""Shared channel-name and catalogue-cap policy.

The web server and the MCP bridge run on different threads, so catalogue
admission must use one process-wide lock and one validation rule.  Keeping the
hard ceiling here also prevents a persisted setting from disabling the bound.
"""

from __future__ import annotations

import re
import threading


CHANNEL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,19}$")
DEFAULT_MAX_CHANNELS = 64
DEFAULT_MAX_DISCOVERED_CHANNELS = 128
HARD_MAX_DISCOVERED_CHANNELS = 256

# Shared by FastAPI's event-loop thread and MCP worker threads.
CHANNEL_CATALOG_LOCK = threading.RLock()


def channel_name_error(channel: object) -> str | None:
    """Return an actionable validation error, or ``None`` when valid."""
    if not isinstance(channel, str):
        return "channel must be a string"
    if not CHANNEL_NAME_RE.fullmatch(channel):
        return (
            "invalid channel: use 1-20 lowercase letters, digits, or hyphens; "
            "the first character must be a letter or digit"
        )
    return None


def bounded_discovery_limit(value: object) -> int:
    """Parse the configurable discovery ceiling and clamp it fail-closed."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = DEFAULT_MAX_DISCOVERED_CHANNELS
    return max(1, min(parsed, HARD_MAX_DISCOVERED_CHANNELS))
