"""Isolated, fail-closed Windows boot-clock producer (M4 component).

This module is a standalone producer: one ``sample()`` call reads the
kernel's boot-environment identifier twice around exactly one
``time.monotonic_ns()`` observation and returns them as one closed
:class:`ClockReading`.  It is deliberately UNINTEGRATED: nothing in the
autonomy runtime consumes a reading yet, a reading grants no live or deploy
authority, and the pair is NOT a cross-reboot ordering guarantee.  The
rejected clock-epoch integration architecture is not implemented here.

Trust contract:

* stdlib only; there is no cache, wall clock, WMI, uptime subtraction,
  random token, registry, environment or persisted-file fallback of any
  kind -- every failure is a typed refusal, never a substitute value;
* on non-win32 platforms every query fails closed before any WinDLL access;
* on Windows the only source is ``ctypes.WinDLL("ntdll.dll")``'s
  ``NtQuerySystemInformation`` with information class 90
  (SystemBootEnvironmentInformation), called with a zeroed raw 32-byte
  buffer and length 32; the result is trusted only when the signed NTSTATUS
  is exactly 0 AND ReturnLength is exactly 32.  The length check is
  load-bearing: the kernel fills a truncated 20-byte prefix and still
  returns STATUS_SUCCESS for input sizes 20..31;
* the epoch is exactly ``bytes(buffer.raw[:16]).hex()`` -- the raw
  identifier bytes, never a UUID/textual GUID conversion -- and an all-zero
  identifier is refused;
* ``sample()`` is query A -> ``time.monotonic_ns()`` -> query B and
  requires A == B with an exact bounded monotonic value, so a reading can
  never pair a time with an ambiguous boot identifier.

:class:`WindowsBootClock` exposes no constructor, callable, epoch or
reading injection surface; hermetic tests patch this module's private
helpers only.  Every refusal is a :class:`BootClockError` carrying a
stable kebab-case code; validation never uses ``assert``.
"""

from __future__ import annotations

import ctypes
import re
import sys
import time
from dataclasses import dataclass

__all__ = [
    "MAX_NS",
    "ClockReading",
    "BootClockError",
    "WindowsBootClock",
]

MAX_NS = (2 ** 63) - 1

_EPOCH_RE = re.compile(r"[0-9a-f]{32}")
_SYSTEM_BOOT_ENVIRONMENT_INFORMATION = 90
_BOOT_INFO_BYTES = 32
_IDENTIFIER_BYTES = 16


class BootClockError(RuntimeError):
    """Stable, output-free fail-closed refusal at the boot-clock boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ClockReading:
    """One closed (boot epoch, monotonic time) pair.

    Closed by construction: ``epoch`` must be exactly a 32-char lowercase
    hex ``str`` and ``now_ns`` must be an exact non-bool ``int`` in
    ``0..MAX_NS``.  Anything else refuses with a typed error.
    """

    epoch: str
    now_ns: int

    def __post_init__(self) -> None:
        if type(self.epoch) is not str or _EPOCH_RE.fullmatch(self.epoch) is None:
            raise BootClockError("epoch-invalid")
        if type(self.now_ns) is not int or self.now_ns < 0 or self.now_ns > MAX_NS:
            raise BootClockError("now-ns-invalid")


def _platform() -> str:
    return sys.platform


def _monotonic_ns() -> int:
    return time.monotonic_ns()


def _load_ntdll():
    """Load ntdll through exactly ``ctypes.WinDLL``; the only WinDLL touch."""

    try:
        return ctypes.WinDLL("ntdll.dll")
    except BootClockError:
        raise
    except OSError:
        raise BootClockError("ntdll-unavailable") from None
    except Exception:
        # A missing or abnormal ``ctypes.WinDLL`` lookup/constructor
        # (AttributeError, TypeError, RuntimeError, ...) must not escape
        # untyped; BaseException (KeyboardInterrupt/SystemExit) passes through.
        raise BootClockError("ntdll-load-failed") from None


def _query_boot_identifier() -> str:
    """Return the kernel boot-environment identifier as 32 lowercase hex.

    Fail-closed on every ambiguity: unsupported platform (before any WinDLL
    access), missing DLL or export, call failure, any nonzero status, any
    ReturnLength other than 32, and an all-zero identifier.  There is no
    fallback source of any kind.
    """

    if _platform() != "win32":
        raise BootClockError("platform-unsupported")
    ntdll = _load_ntdll()
    try:
        query = ntdll.NtQuerySystemInformation
    except BootClockError:
        raise
    except AttributeError:
        raise BootClockError("ntdll-export-missing") from None
    except Exception:
        # An abnormal export getter (a hostile ``__getattr__`` raising
        # TypeError/RuntimeError/...) is a typed refusal, never an escape.
        raise BootClockError("ntdll-export-failed") from None
    try:
        buffer = ctypes.create_string_buffer(_BOOT_INFO_BYTES)
        returned = ctypes.c_ulong(0)
        query.argtypes = (
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        )
        query.restype = ctypes.c_int32
        status = query(
            ctypes.c_ulong(_SYSTEM_BOOT_ENVIRONMENT_INFORMATION),
            ctypes.cast(buffer, ctypes.c_void_p),
            ctypes.c_ulong(_BOOT_INFO_BYTES),
            ctypes.byref(returned),
        )
    except BootClockError:
        raise
    except Exception:
        # Every ordinary Exception from configuration (argtypes/restype
        # assignment, buffer setup) or the call itself is closed to one typed
        # refusal; BaseException is never caught.
        raise BootClockError("boot-query-call-failed") from None
    if type(status) is not int or status != 0:
        raise BootClockError("boot-query-status")
    if type(returned.value) is not int or returned.value != _BOOT_INFO_BYTES:
        raise BootClockError("boot-query-length")
    identifier = bytes(buffer.raw[:_IDENTIFIER_BYTES])
    if identifier == b"\x00" * _IDENTIFIER_BYTES:
        raise BootClockError("boot-identifier-zero")
    return identifier.hex()


class WindowsBootClock:
    """Producer of one fail-closed :class:`ClockReading` per ``sample()``.

    There is deliberately no constructor parameter, no callable protocol
    and no epoch/reading/time injection surface.  Every call re-queries the
    kernel; no reading, identifier or time is ever cached.
    """

    __slots__ = ()

    def sample(self) -> ClockReading:
        first = _query_boot_identifier()
        try:
            now_ns = _monotonic_ns()
        except BootClockError:
            raise
        except Exception:
            # An ordinary Exception from the monotonic read becomes one typed
            # refusal with no second boot query, no retry and no fallback
            # time source; BaseException is never caught.
            raise BootClockError("monotonic-read-failed") from None
        second = _query_boot_identifier()
        if second != first:
            raise BootClockError("boot-identifier-unstable")
        if type(now_ns) is not int or now_ns < 0 or now_ns > MAX_NS:
            raise BootClockError("monotonic-invalid")
        return ClockReading(epoch=first, now_ns=now_ns)
