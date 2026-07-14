"""HALT-first supervisor transaction fence.

This is an isolated, unintegrated component.  It exposes exactly one driver,
:func:`run_halt_first_transaction`, with closed semantics:

1. authenticate the exact queue root and its root marker, retaining raw
   non-inheritable Win32 handles for the root directory, the canonical root
   marker, and the permanent lock for the whole critical section (this
   retention lives inside :class:`~autonomy.control_state.PermanentFileLock`
   and is revalidated at acquisition and immediately before release);
2. acquire the permanent ``supervisor.lock`` fence (non-blocking);
3. read and fully validate the durable ``HALT`` before the caller body is
   inspected or invoked;
4. a valid HALT returns :class:`HaltActive` and the body stays untouched;
5. a missing HALT invokes the trusted body exactly once, with exactly zero
   arguments, while the fence is held;
6. the fence is released after the body has returned or raised, on success,
   ``Exception``, and ``BaseException`` alike;
7. :class:`HaltActive` or :class:`TransactionCompleted` is returned only
   after the fence release itself has succeeded.

Trust boundary: the body is a **trusted, synchronous, zero-argument**
callback and is part of the trusted computing base.  True unforgeable
authority cannot be implemented inside one hostile pure-Python process, so
this driver mints no capability, registry, generation, or other Python
token; no object returned from this API is proof of fence ownership, and
detached work started by the body is outside the contract.  The driver
itself owns and retains the fence for the body's full execution; this API is
mutual exclusion and sequencing, not an in-process sandbox.

Failure precedence is exact: a body or HALT-evidence failure with a
successful release re-raises the same primary object unchanged; a successful
body (or HALT) with a failed release raises the release failure; when both
fail, one ordered ``BaseExceptionGroup`` carries the primary first and the
release failure second, so neither is masked.

The module deliberately consumes no clock, builds no tick plan, publishes no
HALT, and never touches scheduler, queue, process, or network state.  Corrupt,
noncanonical, oversized, reparse, hardlinked, or identity-swapped HALT state
fails closed with :class:`HaltEvidenceError` and the body is never called.
There is no public injection surface for clocks, HALT documents, lock
handles, or already-acquired tokens; test seams are private module
attributes.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from autonomy.control_state import (
    HALT_FILENAME,
    MAX_DOCUMENT_BYTES,
    SUPERVISOR_LOCK_FILENAME,
    LockUnavailableError,
    PermanentFileLock,
    SchemaError,
    parse_halt_document,
)

__all__ = [
    "SUPERVISOR_LOCK_FILENAME",
    "SupervisorFenceError",
    "FenceContentionError",
    "FenceUsageError",
    "HaltEvidenceError",
    "HaltActive",
    "TransactionCompleted",
    "run_halt_first_transaction",
]

_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class SupervisorFenceError(Exception):
    """Base class for every typed supervisor-fence failure."""


class FenceContentionError(SupervisorFenceError):
    """The permanent supervisor fence is exactly held by another owner."""


class FenceUsageError(SupervisorFenceError):
    """The caller supplied an unusable transaction body."""


class HaltEvidenceError(SupervisorFenceError):
    """Durable HALT state exists but cannot be fully validated; fail closed."""


@dataclass(frozen=True)
class HaltActive:
    """A valid durable HALT exists; the body was never inspected or invoked."""

    halt: Mapping[str, Any]


@dataclass(frozen=True)
class TransactionCompleted:
    """The body ran exactly once under the fence and returned ``result``.

    ``result`` is an arbitrary trusted business value returned by the body;
    it carries no framework authority and is not proof of fence ownership.
    """

    result: Any


def _halt_open_seam(path: Path) -> None:
    """Private test seam between named HALT inspection and handle open."""

    return None


def _identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _require_halt_stat(
    info: os.stat_result,
    path: Path,
    *,
    expected_size: int | None = None,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    """Fail closed unless ``info`` describes the one expected regular HALT.

    Every checkpoint requires a regular, non-symlink, non-reparse file with
    link count one and a bounded size; later checkpoints additionally pin
    the exact size and file identity captured earlier.
    """

    if stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_FLAG
    ):
        raise HaltEvidenceError(f"durable HALT is a reparse point: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise HaltEvidenceError(f"durable HALT is not a regular file: {path}")
    if info.st_nlink != 1:
        raise HaltEvidenceError(f"durable HALT link count must be one: {path}")
    if info.st_size > MAX_DOCUMENT_BYTES:
        raise HaltEvidenceError(f"durable HALT is oversized: {path}")
    if expected_size is not None and info.st_size != expected_size:
        raise HaltEvidenceError(f"durable HALT size is unstable: {path}")
    if expected_identity is not None and _identity(info) != expected_identity:
        raise HaltEvidenceError(f"durable HALT identity was swapped: {path}")


def _finalize_halt_descriptor(
    descriptor: int, primary: BaseException | None, path: Path
) -> None:
    """Single close attempt for the pinned HALT descriptor, never masking.

    A close success returns, so the caller's still-active ``except``
    re-raises the same primary object with its original traceback via a bare
    ``raise``.  An ``OSError`` refusal from the close is typed as
    :class:`HaltEvidenceError` with the original cause; paired with a primary
    it becomes one ordered ``BaseExceptionGroup([primary, typed_close])``.
    Any other ``BaseException`` from the close is preserved unchanged and
    ordered after the primary when both exist.  Exactly one close attempt is
    made, so a validated document is never returned past a failed close.
    """

    try:
        os.close(descriptor)
    except OSError as exc:
        typed = HaltEvidenceError(f"durable HALT descriptor close failed: {path}")
        typed.__cause__ = exc
        if primary is not None:
            raise BaseExceptionGroup(
                "durable HALT read and descriptor close both failed",
                [primary, typed],
            )
        raise typed
    except BaseException as exc:
        if primary is not None:
            raise BaseExceptionGroup(
                "durable HALT read and descriptor close both failed",
                [primary, exc],
            )
        raise


def _read_durable_halt(root: Path) -> dict[str, Any] | None:
    """Read the durable HALT through a pinned handle, or None for absence.

    Anything other than clean absence or one fully validated canonical HALT
    document raises :class:`HaltEvidenceError`.  Full regular/non-symlink/
    non-reparse/link-count/size/identity validation runs at the initial
    ``lstat``, at the opened ``fstat``, and again after the read with both a
    fresh ``fstat`` and a fresh ``lstat``.  Descriptor setup after open, both
    full evidence checkpoints, the read, and the canonical HALT parse all run
    inside the descriptor primary/close aggregation scope, so corrupt bytes
    plus a close failure preserve both failures in one ordered group.
    """

    path = root / HALT_FILENAME
    try:
        named = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise HaltEvidenceError(f"durable HALT is uninspectable: {path}") from exc
    _require_halt_stat(named, path)
    _halt_open_seam(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HaltEvidenceError(f"durable HALT cannot be opened: {path}") from exc
    try:
        try:
            os.set_inheritable(descriptor, False)
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise HaltEvidenceError(f"durable HALT is unreadable: {path}") from exc
        _require_halt_stat(
            opened,
            path,
            expected_size=named.st_size,
            expected_identity=_identity(named),
        )
        try:
            raw = os.read(descriptor, MAX_DOCUMENT_BYTES + 1)
        except OSError as exc:
            raise HaltEvidenceError(f"durable HALT is unreadable: {path}") from exc
        if len(raw) != opened.st_size:
            raise HaltEvidenceError(f"durable HALT bytes are unstable: {path}")
        try:
            post_opened = os.fstat(descriptor)
            post_named = os.lstat(path)
        except OSError as exc:
            raise HaltEvidenceError(f"durable HALT is unreadable: {path}") from exc
        for post in (post_opened, post_named):
            _require_halt_stat(
                post,
                path,
                expected_size=opened.st_size,
                expected_identity=_identity(opened),
            )
        try:
            document = parse_halt_document(raw)
        except SchemaError as exc:
            raise HaltEvidenceError(f"durable HALT is corrupt: {path}") from exc
    except BaseException as primary:
        _finalize_halt_descriptor(descriptor, primary, path)
        raise
    _finalize_halt_descriptor(descriptor, None, path)
    return document


def run_halt_first_transaction(
    queue_root: os.PathLike[str] | str,
    body: Callable[[], Any],
) -> HaltActive | TransactionCompleted:
    """Run ``body()`` exactly once under the supervisor fence unless HALT holds.

    A valid durable HALT returns :class:`HaltActive` without inspecting the
    body's callability or touching the body.  With HALT absent, a non-callable
    body is rejected with :class:`FenceUsageError` before any invocation; a
    callable body is invoked exactly once with exactly zero arguments while
    the driver retains the fence.  Exact fence contention raises
    :class:`FenceContentionError`; every other root, lock, or HALT problem
    raises its own typed fail-closed error.

    Release precedence: a primary (body, usage, or HALT-evidence) failure
    with a successful fence release re-raises the same primary object
    unchanged; a failed release after a successful body or HALT decision
    raises the release failure; when both fail, one ordered
    ``BaseExceptionGroup("transaction and fence release both failed",
    [primary, release])`` preserves both.  No outcome object is returned
    until the fence release has succeeded.

    Compounded acquisition failure: exact fence contention paired with an
    acquisition-rollback failure surfaces as the fence constructor's own
    ordered ``BaseExceptionGroup([LockUnavailableError, ...])`` unchanged.
    That group carries integrity evidence, is deliberately never mapped to
    :class:`FenceContentionError`, and must not be treated as retryable
    contention.
    """

    try:
        fence = PermanentFileLock(queue_root, SUPERVISOR_LOCK_FILENAME)
    except LockUnavailableError as exc:
        raise FenceContentionError(
            f"supervisor fence is held by another owner: {queue_root}"
        ) from exc
    primary: BaseException | None = None
    outcome: HaltActive | TransactionCompleted | None = None
    try:
        halt = _read_durable_halt(fence.root)
        if halt is not None:
            outcome = HaltActive(halt=MappingProxyType(dict(halt)))
        else:
            if not callable(body):
                # One literal constant message: never evaluate the untrusted
                # body's repr, str, type name, or metaclass hooks.
                raise FenceUsageError("transaction body must be callable")
            outcome = TransactionCompleted(result=body())
    except BaseException as exc:
        primary = exc
    release_failure: BaseException | None = None
    try:
        fence.close()
    except BaseException as exc:
        release_failure = exc
    if primary is not None and release_failure is not None:
        raise BaseExceptionGroup(
            "transaction and fence release both failed",
            [primary, release_failure],
        )
    if primary is not None:
        raise primary
    if release_failure is not None:
        raise release_failure
    return outcome
