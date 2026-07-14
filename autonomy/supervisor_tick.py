"""Harmless deterministic readiness tick for the sealed runner path.

This module is statically required by :mod:`autonomy.runner`, listed in the
dependency manifest, and loaded from bootstrap-verified bytes.  It intentionally
does no work beyond proving the scheduler -> bootstrap -> runner -> supervisor
handoff.  Concrete queue/process orchestration is admitted separately.

Manifest-listed Python is trusted code, not an in-process sandbox payload.
"""

from __future__ import annotations


def run(_context: object) -> int:
    """Return deterministic success without touching external state."""

    return 0
