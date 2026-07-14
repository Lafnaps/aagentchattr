"""Minimal HALT-first read-only night tick (S1 R4 component).

This is an isolated, unintegrated S1 component: one public call,
:func:`observe_night_tick`, runs the accepted S0 fence driver
:func:`autonomy.supervisor_transaction.run_halt_first_transaction` exactly
once over a trusted zero-argument body that constructs one
:class:`autonomy.boot_clock.WindowsBootClock` via :func:`_new_clock` and
calls ``sample()`` exactly once.  A valid durable HALT short-circuits
before the body, so a halted queue never constructs or samples a clock.
The component is strictly read-only: it mutates no queue, scheduler,
process, network, or product state and owns no persistence.

``observe_night_tick`` catches nothing and prints nothing.  It returns the
exact S0 outcome object -- exact :class:`HaltActive` or exact
:class:`TransactionCompleted`, never a subclass -- only after the
transaction call has returned (the S0 driver releases the fence before it
returns or raises) and the result has been revalidated against the closed
night-tick output grammar:

* HALT evidence must be exactly a ``MappingProxyType`` with exactly the
  six keys ``attempt``/``created_utc``/``kind``/``nonce``/``task_id``/
  ``version``, exact non-bool integers ``attempt == 0`` and
  ``version == 1``, exact strings ``kind == "halt"`` and
  ``task_id == "root"``, a nonce of exactly 32 lowercase ASCII hex
  characters, and an exactly valid canonical
  ``YYYY-MM-DDTHH:MM:SS.mmmZ`` timestamp;
* a completed observation must carry an exact :class:`ClockReading`
  (never a subclass) whose ``epoch`` is exactly 32 lowercase ASCII hex
  and whose ``now_ns`` is an exact non-bool integer in ``0..2**63-1``,
  because the success JSON grammar publishes exactly those two fields
  and nothing else.

Every revalidation mismatch raises the private
``_NightTickProtocolError("trusted-result-invalid")`` after the S0 fence
release; a hostile trusted-result shape is never serialized.  An ordinary
``Exception`` escaping a forged exact reading's missing slot or an exact
``MappingProxyType`` whose ordinary iteration or key access fails during
the snapshot is the same mismatch: it becomes
``_NightTickProtocolError("trusted-result-invalid")`` at the API and the
``unexpected`` error at the CLI.  Fatal ``BaseException`` raised by a
hostile shape is never swallowed and propagates unchanged.  Field values
are re-snapshotted at serialization time through the same validator, so a
mapping that mutates between validation and serialization can only produce
a still-canonical payload or the ``unexpected`` error, never malformed
output.

The private CLI accepts exactly ``("--root", absolute_nonempty_string)``
with no alternate, abbreviated, help, or equals form; parsing performs no
external observation.  Success and error payloads are canonical compact
ASCII JSON (``ensure_ascii=True``, ``allow_nan=False``, ``sort_keys=True``,
compact separators) plus exactly one trailing LF, at most 512 bytes; an
internal overflow becomes the ``unexpected`` error.  Exit/code mapping:
success ``0``; grammar ``2``/``usage``; exact
:class:`FenceContentionError` ``3``/``fence-contention``; exact
:class:`HaltEvidenceError` or exact :class:`BootClockError`
``4``/``observation-refused``; every other ordinary ``Exception`` --
subclasses of the typed errors, protocol/output errors, and every ordinary
``ExceptionGroup`` -- ``5``/``unexpected``.  Exceptions are never
inspected, stringified, repr'd, flattened, or exposed; fatal
``BaseException`` and any exception group carrying a fatal member
propagate unchanged with identity, member ordering, cause/context, and the
S0 traceback suffix intact.

``_entry`` performs one-buffer sink semantics: it looks up
``sys.stdout.buffer`` exactly once, writes the payload exactly once,
requires an exact non-bool integer write count equal to the payload
length, flushes exactly once, and raises ``SystemExit(code)``.  A
lookup/write/flush failure propagates unchanged; a partial write raises
the private ``_NightTickOutputError("stdout-partial-write")`` with no
retry, no error JSON, and no flush after the partial write.  The module
never writes ``sys.stderr``.

There is no public injection surface and no production sink seam; tests
patch only the private ``_new_clock``, the directly imported transaction
driver, the already accepted S0 private seams, and module
``sys.argv``/``sys.stdout``.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from types import MappingProxyType

from autonomy.boot_clock import BootClockError, ClockReading, WindowsBootClock
from autonomy.supervisor_transaction import (
    FenceContentionError,
    HaltActive,
    HaltEvidenceError,
    TransactionCompleted,
    run_halt_first_transaction,
)

__all__ = ["observe_night_tick"]

_SCHEMA = 1
_MAX_PAYLOAD_BYTES = 512
_MAX_NOW_NS = (2 ** 63) - 1
_ROOT_FLAG = "--root"
_HEX32_RE = re.compile(r"[0-9a-f]{32}")
_UTC_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"
)
_UTC_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_EVIDENCE_KEYS = frozenset(
    {"attempt", "created_utc", "kind", "nonce", "task_id", "version"}
)


class _NightTickProtocolError(Exception):
    """A trusted S0/boot-clock result failed exact revalidation."""


class _NightTickOutputError(Exception):
    """The one-shot stdout sink or the payload byte bound was violated."""


def _new_clock() -> WindowsBootClock:
    return WindowsBootClock()


def _tick_body() -> ClockReading:
    # The whole observation: one clock constructed, one sample taken, both
    # only while the S0 driver holds the supervisor fence.
    return _new_clock().sample()


def _canonical_utc(value: object) -> bool:
    """True only for an exactly valid canonical YYYY-MM-DDTHH:MM:SS.mmmZ str.

    The ASCII regex pins the exact shape (three millisecond digits, literal
    ``T`` and ``Z``); ``strptime`` then rejects calendar-impossible values
    such as month 13 or February 30.
    """

    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, _UTC_FORMAT)
    except ValueError:
        return False
    return True


def _halt_snapshot(evidence: object) -> dict[str, object] | None:
    """Read each evidence field once and return a validated plain snapshot.

    ``None`` means the evidence is not exactly one canonical HALT record.
    The returned dict holds the exact values that were validated, so the
    serializer never re-reads a possibly mutating source mapping.  An
    ordinary ``Exception`` raised by the proxy's underlying mapping during
    iteration, key hashing/comparison, or key access is the same mismatch
    and yields ``None``; fatal ``BaseException`` is never caught.
    """

    if type(evidence) is not MappingProxyType:
        return None
    try:
        if frozenset(evidence) != _EVIDENCE_KEYS:
            return None
        snapshot = {
            "attempt": evidence["attempt"],
            "created_utc": evidence["created_utc"],
            "kind": evidence["kind"],
            "nonce": evidence["nonce"],
            "task_id": evidence["task_id"],
            "version": evidence["version"],
        }
    except Exception:
        # The exact proxy type delegates to a possibly hostile underlying
        # mapping; an ordinary access failure is a protocol mismatch, not
        # an escape.  BaseException (KeyboardInterrupt/SystemExit) passes
        # through unchanged.
        return None
    if type(snapshot["attempt"]) is not int or snapshot["attempt"] != 0:
        return None
    if type(snapshot["version"]) is not int or snapshot["version"] != _SCHEMA:
        return None
    if type(snapshot["kind"]) is not str or snapshot["kind"] != "halt":
        return None
    if type(snapshot["task_id"]) is not str or snapshot["task_id"] != "root":
        return None
    if (
        type(snapshot["nonce"]) is not str
        or _HEX32_RE.fullmatch(snapshot["nonce"]) is None
    ):
        return None
    if not _canonical_utc(snapshot["created_utc"]):
        return None
    return snapshot


def _boot_snapshot(result: object) -> dict[str, object] | None:
    """Validated ``{"epoch", "now_ns"}`` snapshot of one exact ClockReading.

    ``None`` for any non-exact type or any field that cannot appear in the
    closed success JSON grammar: ``epoch`` must be exactly 32 lowercase
    ASCII hex and ``now_ns`` an exact non-bool ``int`` in ``0..2**63-1``
    (a legitimately constructed :class:`ClockReading` always passes its
    own ``__post_init__`` and therefore always passes here).  A forged
    exact instance whose slot access raises an ordinary ``Exception``
    (for example a missing slot's ``AttributeError``) is the same
    mismatch and yields ``None``; fatal ``BaseException`` is never caught.
    """

    if type(result) is not ClockReading:
        return None
    try:
        epoch = result.epoch
        now_ns = result.now_ns
    except Exception:
        # A forged exact-type instance can leave slots unset; the ordinary
        # slot-access failure is a protocol mismatch, not an escape.
        # BaseException passes through unchanged.
        return None
    if type(epoch) is not str or _HEX32_RE.fullmatch(epoch) is None:
        return None
    if type(now_ns) is not int or now_ns < 0 or now_ns > _MAX_NOW_NS:
        return None
    return {"epoch": epoch, "now_ns": now_ns}


def observe_night_tick(
    queue_root: os.PathLike[str] | str,
) -> HaltActive | TransactionCompleted:
    """Observe one HALT-first boot-clock tick under the S0 supervisor fence.

    Exactly one direct call to the imported
    :func:`run_halt_first_transaction`; a valid durable HALT returns before
    the body, so no clock is constructed or sampled.  This function catches
    nothing and prints nothing, and it returns the exact S0 outcome object
    only after the driver has returned (fence already released) and the
    result has been revalidated; every mismatch raises the private
    ``_NightTickProtocolError("trusted-result-invalid")``.
    """

    outcome = run_halt_first_transaction(queue_root, _tick_body)
    if type(outcome) is HaltActive:
        if _halt_snapshot(outcome.halt) is None:
            raise _NightTickProtocolError("trusted-result-invalid")
    elif type(outcome) is TransactionCompleted:
        if _boot_snapshot(outcome.result) is None:
            raise _NightTickProtocolError("trusted-result-invalid")
    else:
        raise _NightTickProtocolError("trusted-result-invalid")
    return outcome


def _serialize(document: dict[str, object]) -> bytes:
    payload = (
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise _NightTickOutputError("payload-overflow")
    return payload


def _error_payload(code: str) -> bytes:
    return _serialize({"error": code, "ok": False, "schema": _SCHEMA, "state": "error"})


def _success_payload(outcome: HaltActive | TransactionCompleted) -> bytes:
    if type(outcome) is HaltActive:
        snapshot = _halt_snapshot(outcome.halt)
        if snapshot is None:
            raise _NightTickProtocolError("trusted-result-invalid")
        return _serialize(
            {"halt": snapshot, "ok": True, "schema": _SCHEMA, "state": "halted"}
        )
    snapshot = _boot_snapshot(outcome.result)
    if snapshot is None:
        raise _NightTickProtocolError("trusted-result-invalid")
    return _serialize(
        {"boot": snapshot, "ok": True, "schema": _SCHEMA, "state": "observed"}
    )


def _cli_result(argv: tuple[str, ...]) -> tuple[int, bytes]:
    """Map one exact CLI invocation to ``(exit_code, payload_bytes)``.

    Grammar is exactly ``("--root", absolute_nonempty_string)`` and is
    checked with pure string logic before any external observation.  Fatal
    ``BaseException`` (and any group carrying a fatal member, which is
    never an ``Exception`` instance) propagates unchanged; ordinary
    exceptions are classified by exact type only and never inspected.
    """

    if (
        type(argv) is not tuple
        or len(argv) != 2
        or type(argv[0]) is not str
        or argv[0] != _ROOT_FLAG
        or type(argv[1]) is not str
        or not argv[1]
        or not os.path.isabs(argv[1])
    ):
        return (2, _error_payload("usage"))
    try:
        payload = _success_payload(observe_night_tick(argv[1]))
    except Exception as exc:
        family = type(exc)
        if family is FenceContentionError:
            return (3, _error_payload("fence-contention"))
        if family is HaltEvidenceError or family is BootClockError:
            return (4, _error_payload("observation-refused"))
        return (5, _error_payload("unexpected"))
    return (0, payload)


def _entry() -> None:
    code, payload = _cli_result(tuple(sys.argv[1:]))
    buffer = sys.stdout.buffer
    written = buffer.write(payload)
    if type(written) is not int or written != len(payload):
        # No retry, no error JSON, and no flush after a partial write.
        raise _NightTickOutputError("stdout-partial-write")
    buffer.flush()
    raise SystemExit(code)


if __name__ == "__main__":
    _entry()
