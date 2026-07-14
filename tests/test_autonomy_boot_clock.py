"""Hermetic and native tests for the isolated ``autonomy.boot_clock`` producer.

Hermetic tests patch only this module's private helpers (``_platform``,
``_load_ntdll``, ``_query_boot_identifier``, ``_monotonic_ns``) plus, for the
native-boundary closure tests only, the module-level ``ctypes`` entry point;
there is no public injection surface to use.  The mock-WinDLL harness proves the exact
native contract (class 90, argtypes, signed restype, zeroed 32-byte buffer,
status==0 AND ReturnLength==32) without touching the real kernel, and the
native tests prove same-boot and independent-process agreement on Windows,
skipping only when the platform itself is unsupported.
"""

from __future__ import annotations

import ast
import ctypes
import dataclasses
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

import autonomy.boot_clock as boot_clock
from autonomy.boot_clock import MAX_NS, BootClockError, ClockReading, WindowsBootClock

IS_WINDOWS = sys.platform == "win32"
REPO_ROOT = Path(boot_clock.__file__).resolve().parent.parent
EPOCH_A = "0123456789abcdef0123456789abcdef"
EPOCH_B = "f" * 32

_ALLOWED_IMPORT_ROOTS = {"__future__", "ctypes", "dataclasses", "re", "sys", "time"}
_FORBIDDEN_SOURCE_TOKENS = (
    "uuid",
    "winreg",
    "wmi",
    "random",
    "secrets",
    "environ",
    "getenv",
    "tempfile",
    "subprocess",
    "time.time",
    "GetTickCount",
    "QueryUnbiasedInterruptTime",
)


def expect_error(test: unittest.TestCase, code: str):
    return _ErrorContext(test, code)


class _ErrorContext:
    def __init__(self, test: unittest.TestCase, code: str) -> None:
        self.test = test
        self.code = code

    def __enter__(self):
        self.ctx = self.test.assertRaises(BootClockError)
        self.caught = self.ctx.__enter__()
        return self.caught

    def __exit__(self, exc_type, exc, tb):
        suppressed = self.ctx.__exit__(exc_type, exc, tb)
        if suppressed:
            self.test.assertEqual(self.code, self.caught.exception.code)
        return suppressed


class ExportsAndPurityTests(unittest.TestCase):
    def test_public_exports_and_max_ns(self) -> None:
        self.assertEqual(
            ["MAX_NS", "ClockReading", "BootClockError", "WindowsBootClock"],
            boot_clock.__all__,
        )
        self.assertIs(type(MAX_NS), int)
        self.assertEqual((2 ** 63) - 1, MAX_NS)

    def test_stdlib_only_imports_and_no_assert_validation(self) -> None:
        source = Path(boot_clock.__file__).read_text(encoding="ascii")
        tree = ast.parse(source)
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(0, node.level)
                self.assertIsNotNone(node.module)
                roots.add(node.module.split(".", 1)[0])
            self.assertNotIsInstance(node, ast.Assert)
        self.assertTrue(roots.issubset(_ALLOWED_IMPORT_ROOTS), roots)

    def test_no_fallback_sources_in_module(self) -> None:
        source = Path(boot_clock.__file__).read_text(encoding="ascii")
        body = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        # The docstring legitimately *names* the forbidden fallbacks; strip
        # string literals via the AST before scanning code tokens.
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                body = body.replace(repr(node.value), "")
                body = body.replace(node.value, "")
        for token in _FORBIDDEN_SOURCE_TOKENS:
            self.assertNotIn(token, body, token)

    def test_module_is_strict_ascii(self) -> None:
        raw = Path(boot_clock.__file__).read_bytes()
        raw.decode("ascii", "strict")


class ClockReadingTests(unittest.TestCase):
    def test_valid_reading_and_boundaries(self) -> None:
        for now_ns in (0, 1, MAX_NS):
            with self.subTest(now_ns=now_ns):
                reading = ClockReading(epoch=EPOCH_A, now_ns=now_ns)
                self.assertEqual(EPOCH_A, reading.epoch)
                self.assertEqual(now_ns, reading.now_ns)
        self.assertEqual(
            ClockReading(epoch=EPOCH_A, now_ns=7),
            ClockReading(epoch=EPOCH_A, now_ns=7),
        )

    def test_reading_is_frozen_with_slots(self) -> None:
        reading = ClockReading(epoch=EPOCH_A, now_ns=7)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            reading.now_ns = 8  # type: ignore[misc]
        with self.assertRaises((AttributeError, dataclasses.FrozenInstanceError)):
            reading.extra = 1  # type: ignore[attr-defined]
        self.assertFalse(hasattr(reading, "__dict__"))

    def test_epoch_is_closed_by_construction(self) -> None:
        class HexSubclass(str):
            pass

        bad_epochs = (
            None,
            b"0" * 32,
            EPOCH_A.upper(),
            EPOCH_A[:31],
            EPOCH_A + "0",
            "g" + EPOCH_A[1:],
            "0x" + EPOCH_A[2:],
            " " + EPOCH_A[1:],
            123,
            HexSubclass(EPOCH_A),
        )
        for epoch in bad_epochs:
            with self.subTest(epoch=epoch):
                with expect_error(self, "epoch-invalid"):
                    ClockReading(epoch=epoch, now_ns=0)  # type: ignore[arg-type]

    def test_now_ns_is_closed_by_construction(self) -> None:
        bad_values = (True, False, -1, MAX_NS + 1, 1.0, "0", None, 2 ** 64)
        for now_ns in bad_values:
            with self.subTest(now_ns=now_ns):
                with expect_error(self, "now-ns-invalid"):
                    ClockReading(epoch=EPOCH_A, now_ns=now_ns)  # type: ignore[arg-type]


class InjectionSurfaceTests(unittest.TestCase):
    def test_no_constructor_or_callable_injection(self) -> None:
        clock = WindowsBootClock()
        self.assertFalse(callable(clock))
        with self.assertRaises(TypeError):
            WindowsBootClock(EPOCH_A)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            WindowsBootClock(epoch=EPOCH_A)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            WindowsBootClock(reading=object())  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            clock.sample(EPOCH_A)  # type: ignore[call-arg]

    def test_no_state_slots_to_inject(self) -> None:
        clock = WindowsBootClock()
        self.assertEqual((), WindowsBootClock.__slots__)
        self.assertFalse(hasattr(clock, "__dict__"))
        with self.assertRaises(AttributeError):
            clock.epoch = EPOCH_A  # type: ignore[attr-defined]


class HermeticSampleTests(unittest.TestCase):
    def test_sample_orders_query_monotonic_query(self) -> None:
        calls: list[str] = []

        def fake_query() -> str:
            calls.append("query")
            return EPOCH_A

        def fake_now() -> int:
            calls.append("monotonic")
            return 123

        with mock.patch.object(
            boot_clock, "_query_boot_identifier", side_effect=fake_query
        ), mock.patch.object(boot_clock, "_monotonic_ns", side_effect=fake_now):
            reading = WindowsBootClock().sample()
        self.assertEqual(ClockReading(epoch=EPOCH_A, now_ns=123), reading)
        self.assertEqual(["query", "monotonic", "query"], calls)

    def test_identifier_mismatch_between_queries_fails_closed(self) -> None:
        with mock.patch.object(
            boot_clock, "_query_boot_identifier", side_effect=[EPOCH_A, EPOCH_B]
        ), mock.patch.object(boot_clock, "_monotonic_ns", return_value=123):
            with expect_error(self, "boot-identifier-unstable"):
                WindowsBootClock().sample()

    def test_invalid_monotonic_values_fail_closed(self) -> None:
        bad_values = (True, False, -1, MAX_NS + 1, 1.5, "7", None)
        for value in bad_values:
            with self.subTest(value=value):
                with mock.patch.object(
                    boot_clock, "_query_boot_identifier", return_value=EPOCH_A
                ), mock.patch.object(boot_clock, "_monotonic_ns", return_value=value):
                    with expect_error(self, "monotonic-invalid"):
                        WindowsBootClock().sample()

    def test_monotonic_bounds_are_exact(self) -> None:
        for value in (0, MAX_NS):
            with self.subTest(value=value):
                with mock.patch.object(
                    boot_clock, "_query_boot_identifier", return_value=EPOCH_A
                ), mock.patch.object(boot_clock, "_monotonic_ns", return_value=value):
                    self.assertEqual(value, WindowsBootClock().sample().now_ns)

    def test_sample_never_caches(self) -> None:
        query = mock.Mock(side_effect=[EPOCH_A, EPOCH_A, EPOCH_B, EPOCH_B])
        now = mock.Mock(side_effect=[10, 20])
        clock = WindowsBootClock()
        with mock.patch.object(
            boot_clock, "_query_boot_identifier", query
        ), mock.patch.object(boot_clock, "_monotonic_ns", now):
            first = clock.sample()
            second = clock.sample()
        self.assertEqual(4, query.call_count)
        self.assertEqual(2, now.call_count)
        self.assertEqual(EPOCH_A, first.epoch)
        self.assertEqual(EPOCH_B, second.epoch)

    def test_query_error_propagates_without_fallback(self) -> None:
        query = mock.Mock(side_effect=BootClockError("ntdll-unavailable"))
        now = mock.Mock()
        with mock.patch.object(
            boot_clock, "_query_boot_identifier", query
        ), mock.patch.object(boot_clock, "_monotonic_ns", now):
            with expect_error(self, "ntdll-unavailable"):
                WindowsBootClock().sample()
        self.assertEqual(1, query.call_count)
        now.assert_not_called()


class MonotonicFailureClosureTests(unittest.TestCase):
    """Hostile monotonic reads: typed closure, no second query, no retry."""

    def test_ordinary_monotonic_failure_becomes_typed(self) -> None:
        for failure in (OSError("clock read denied"), RuntimeError("clock torn down")):
            with self.subTest(failure=type(failure).__name__):
                query = mock.Mock(return_value=EPOCH_A)
                now = mock.Mock(side_effect=failure)
                with mock.patch.object(
                    boot_clock, "_query_boot_identifier", query
                ), mock.patch.object(boot_clock, "_monotonic_ns", now):
                    with expect_error(self, "monotonic-read-failed"):
                        WindowsBootClock().sample()
                # Exactly one first boot query, zero second boot query, one
                # monotonic attempt: no fallback and no retry of any kind.
                self.assertEqual(1, query.call_count)
                self.assertEqual(1, now.call_count)

    def test_monotonic_boot_clock_error_is_preserved(self) -> None:
        original = BootClockError("monotonic-custom-refusal")
        query = mock.Mock(return_value=EPOCH_A)
        now = mock.Mock(side_effect=original)
        with mock.patch.object(
            boot_clock, "_query_boot_identifier", query
        ), mock.patch.object(boot_clock, "_monotonic_ns", now):
            with self.assertRaises(BootClockError) as caught:
                WindowsBootClock().sample()
        self.assertIs(original, caught.exception)
        self.assertEqual("monotonic-custom-refusal", caught.exception.code)
        self.assertEqual(1, query.call_count)
        self.assertEqual(1, now.call_count)

    def test_monotonic_base_exception_passes_through_untyped(self) -> None:
        for failure in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(failure=type(failure).__name__):
                query = mock.Mock(return_value=EPOCH_A)
                now = mock.Mock(side_effect=failure)
                with mock.patch.object(
                    boot_clock, "_query_boot_identifier", query
                ), mock.patch.object(boot_clock, "_monotonic_ns", now):
                    with self.assertRaises(type(failure)) as caught:
                        WindowsBootClock().sample()
                self.assertIs(failure, caught.exception)
                self.assertNotIsInstance(caught.exception, BootClockError)
                self.assertEqual(1, query.call_count)
                self.assertEqual(1, now.call_count)


class FakeNtQuery:
    """A recording stand-in for ``ntdll.NtQuerySystemInformation``."""

    def __init__(
        self,
        *,
        fill: bytes = b"\x11" * 16 + b"\x22" * 16,
        status: object = 0,
        ret_length: int = 32,
        raise_call: BaseException | None = None,
    ) -> None:
        self.fill = fill
        self.status = status
        self.ret_length = ret_length
        self.raise_call = raise_call
        self.argtypes: object = None
        self.restype: object = None
        self.calls: list[tuple[int, int]] = []
        self.buffer_zeroed_at_call: bool | None = None

    def __call__(self, info_class, buffer_ptr, length, ret_ptr):
        self.calls.append((info_class.value, length.value))
        if self.raise_call is not None:
            raise self.raise_call
        target = ctypes.cast(buffer_ptr, ctypes.POINTER(ctypes.c_char * 32))
        self.buffer_zeroed_at_call = target.contents.raw == b"\x00" * 32
        target.contents.raw = self.fill[: len(self.fill)]
        # ``ret_ptr`` is the byref(...) argument; its target is ``_obj``.
        ret_ptr._obj.value = self.ret_length
        return self.status


class MockWinDllContractTests(unittest.TestCase):
    """Prove the exact native call contract against a recording fake DLL."""

    def query_with(self, fake: FakeNtQuery) -> str:
        dll = types.SimpleNamespace(NtQuerySystemInformation=fake)
        with mock.patch.object(
            boot_clock, "_platform", return_value="win32"
        ), mock.patch.object(boot_clock, "_load_ntdll", return_value=dll):
            return boot_clock._query_boot_identifier()

    def expect_query_error(self, fake: FakeNtQuery, code: str) -> None:
        with expect_error(self, code):
            self.query_with(fake)
        # Fail-closed means exactly one attempt and no fallback source.
        self.assertLessEqual(len(fake.calls), 1)

    def test_success_uses_exact_class_argtypes_restype_and_buffer(self) -> None:
        identifier = bytes(range(1, 17))
        fake = FakeNtQuery(fill=identifier + b"\x00" * 16)
        epoch = self.query_with(fake)
        self.assertEqual(identifier.hex(), epoch)
        self.assertEqual([(90, 32)], fake.calls)
        self.assertIs(True, fake.buffer_zeroed_at_call)
        self.assertEqual(
            (
                ctypes.c_ulong,
                ctypes.c_void_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
            ),
            tuple(fake.argtypes),
        )
        self.assertIs(ctypes.c_int32, fake.restype)

    def test_epoch_is_raw_bytes_hex_never_guid_text(self) -> None:
        identifier = bytes(range(1, 17))
        epoch = self.query_with(FakeNtQuery(fill=identifier + b"\xaa" * 16))
        self.assertEqual(identifier.hex(), epoch)
        self.assertNotIn("-", epoch)
        # The textual GUID rendering byte-swaps the first three fields; the
        # epoch must be the raw in-memory order instead.
        guid_text = (
            identifier[3::-1].hex()
            + identifier[5:3:-1].hex()
            + identifier[7:5:-1].hex()
            + identifier[8:].hex()
        )
        self.assertNotEqual(guid_text, epoch)

    def test_trailing_buffer_bytes_are_excluded_from_epoch(self) -> None:
        identifier = b"\x42" * 16
        epoch = self.query_with(FakeNtQuery(fill=identifier + b"\x99" * 16))
        self.assertEqual(identifier.hex(), epoch)
        self.assertEqual(32, len(epoch))

    def test_status_zero_with_return_length_20_fails(self) -> None:
        # The kernel fills a truncated 20-byte prefix with STATUS_SUCCESS for
        # input sizes 20..31; only ReturnLength == 32 may be trusted.
        fake = FakeNtQuery(fill=b"\x11" * 20, status=0, ret_length=20)
        self.expect_query_error(fake, "boot-query-length")

    def test_other_return_lengths_fail(self) -> None:
        for ret_length in (0, 16, 31, 33, 64):
            with self.subTest(ret_length=ret_length):
                fake = FakeNtQuery(status=0, ret_length=ret_length)
                self.expect_query_error(fake, "boot-query-length")

    def test_nonzero_status_fails(self) -> None:
        for status in (-1073741820, -1, 1, 0xC0000004, True, None, 0.0):
            with self.subTest(status=status):
                self.expect_query_error(
                    FakeNtQuery(status=status), "boot-query-status"
                )

    def test_all_zero_identifier_fails(self) -> None:
        fake = FakeNtQuery(fill=b"\x00" * 16 + b"\x77" * 16)
        self.expect_query_error(fake, "boot-identifier-zero")

    def test_call_failures_fail_closed(self) -> None:
        failures = (
            OSError("access denied"),
            ctypes.ArgumentError("bad argument"),
            TypeError("bad call"),
            ValueError("bad value"),
            RuntimeError("abnormal call"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                self.expect_query_error(
                    FakeNtQuery(raise_call=failure), "boot-query-call-failed"
                )

    def test_call_boot_clock_error_is_preserved(self) -> None:
        original = BootClockError("call-custom-refusal")
        with self.assertRaises(BootClockError) as caught:
            self.query_with(FakeNtQuery(raise_call=original))
        self.assertIs(original, caught.exception)
        self.assertEqual("call-custom-refusal", caught.exception.code)

    def test_call_base_exception_passes_through_untyped(self) -> None:
        for failure in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises(type(failure)) as caught:
                    self.query_with(FakeNtQuery(raise_call=failure))
                self.assertIs(failure, caught.exception)
                self.assertNotIsInstance(caught.exception, BootClockError)

    def test_missing_export_fails_closed(self) -> None:
        dll = types.SimpleNamespace()
        with mock.patch.object(
            boot_clock, "_platform", return_value="win32"
        ), mock.patch.object(boot_clock, "_load_ntdll", return_value=dll):
            with expect_error(self, "ntdll-export-missing"):
                boot_clock._query_boot_identifier()

    def test_missing_dll_fails_closed(self) -> None:
        with mock.patch.object(
            boot_clock, "_platform", return_value="win32"
        ), mock.patch.object(
            boot_clock, "_load_ntdll", side_effect=BootClockError("ntdll-unavailable")
        ):
            with expect_error(self, "ntdll-unavailable"):
                boot_clock._query_boot_identifier()


class _HostileExportDll:
    """A DLL stand-in whose export lookup raises instead of resolving."""

    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def __getattr__(self, name: str):
        raise self._failure


def _hostile_config_query(failure: BaseException):
    """A query stand-in whose ctypes configuration (attribute set) raises."""

    class _HostileConfig:
        def __setattr__(self, name, value):
            raise failure

    return _HostileConfig()


class WinDllLoadClosureTests(unittest.TestCase):
    """Missing/abnormal ``ctypes.WinDLL`` lookup or call is a typed refusal."""

    def load_error(self, fake_ctypes, code: str) -> None:
        with mock.patch.object(boot_clock, "ctypes", fake_ctypes):
            with expect_error(self, code):
                boot_clock._load_ntdll()

    def test_missing_windll_attribute_fails_closed(self) -> None:
        # ctypes without a WinDLL attribute at all (the lookup raises
        # AttributeError) must be a stable typed refusal.
        self.load_error(types.SimpleNamespace(), "ntdll-load-failed")

    def test_abnormal_windll_constructor_fails_closed(self) -> None:
        failures = (
            AttributeError("hostile loader attribute"),
            TypeError("hostile loader call"),
            RuntimeError("loader torn down"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                loader = mock.Mock(side_effect=failure)
                self.load_error(
                    types.SimpleNamespace(WinDLL=loader), "ntdll-load-failed"
                )
                # Exactly one load attempt: no retry and no fallback loader.
                self.assertEqual(1, loader.call_count)

    def test_os_error_keeps_stable_unavailable_code(self) -> None:
        loader = mock.Mock(side_effect=OSError("module not found"))
        self.load_error(types.SimpleNamespace(WinDLL=loader), "ntdll-unavailable")
        self.assertEqual(1, loader.call_count)

    def test_load_boot_clock_error_is_preserved(self) -> None:
        original = BootClockError("ntdll-custom-refusal")
        loader = mock.Mock(side_effect=original)
        with mock.patch.object(
            boot_clock, "ctypes", types.SimpleNamespace(WinDLL=loader)
        ):
            with self.assertRaises(BootClockError) as caught:
                boot_clock._load_ntdll()
        self.assertIs(original, caught.exception)
        self.assertEqual("ntdll-custom-refusal", caught.exception.code)

    def test_load_base_exception_passes_through_untyped(self) -> None:
        for failure in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(failure=type(failure).__name__):
                loader = mock.Mock(side_effect=failure)
                with mock.patch.object(
                    boot_clock, "ctypes", types.SimpleNamespace(WinDLL=loader)
                ):
                    with self.assertRaises(type(failure)) as caught:
                        boot_clock._load_ntdll()
                self.assertIs(failure, caught.exception)
                self.assertNotIsInstance(caught.exception, BootClockError)

    def test_sample_converts_abnormal_windll_before_monotonic(self) -> None:
        loader = mock.Mock(side_effect=RuntimeError("loader torn down"))
        now = mock.Mock()
        with mock.patch.object(
            boot_clock, "_platform", return_value="win32"
        ), mock.patch.object(
            boot_clock, "ctypes", types.SimpleNamespace(WinDLL=loader)
        ), mock.patch.object(boot_clock, "_monotonic_ns", now):
            with expect_error(self, "ntdll-load-failed"):
                WindowsBootClock().sample()
        self.assertEqual(1, loader.call_count)
        now.assert_not_called()


class NativeBoundaryClosureTests(unittest.TestCase):
    """No ordinary Exception escapes the export/configuration boundary."""

    def query_error(self, dll, code: str) -> None:
        with mock.patch.object(
            boot_clock, "_platform", return_value="win32"
        ), mock.patch.object(boot_clock, "_load_ntdll", return_value=dll):
            with expect_error(self, code):
                boot_clock._query_boot_identifier()

    def test_abnormal_export_getter_fails_closed(self) -> None:
        failures = (
            TypeError("hostile getattr"),
            RuntimeError("hostile getattr"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                self.query_error(_HostileExportDll(failure), "ntdll-export-failed")

    def test_export_attribute_error_stays_missing_refusal(self) -> None:
        self.query_error(
            _HostileExportDll(AttributeError("export gone")), "ntdll-export-missing"
        )

    def test_export_boot_clock_error_is_preserved(self) -> None:
        original = BootClockError("export-custom-refusal")
        with mock.patch.object(
            boot_clock, "_platform", return_value="win32"
        ), mock.patch.object(
            boot_clock, "_load_ntdll", return_value=_HostileExportDll(original)
        ):
            with self.assertRaises(BootClockError) as caught:
                boot_clock._query_boot_identifier()
        self.assertIs(original, caught.exception)
        self.assertEqual("export-custom-refusal", caught.exception.code)

    def test_export_base_exception_passes_through_untyped(self) -> None:
        for failure in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(
                    boot_clock, "_platform", return_value="win32"
                ), mock.patch.object(
                    boot_clock, "_load_ntdll", return_value=_HostileExportDll(failure)
                ):
                    with self.assertRaises(type(failure)) as caught:
                        boot_clock._query_boot_identifier()
                self.assertIs(failure, caught.exception)
                self.assertNotIsInstance(caught.exception, BootClockError)

    def test_abnormal_query_configuration_fails_closed(self) -> None:
        failures = (
            RuntimeError("hostile setattr"),
            TypeError("hostile setattr"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                dll = types.SimpleNamespace(
                    NtQuerySystemInformation=_hostile_config_query(failure)
                )
                self.query_error(dll, "boot-query-call-failed")

    def test_query_configuration_base_exception_passes_through(self) -> None:
        failure = KeyboardInterrupt()
        dll = types.SimpleNamespace(
            NtQuerySystemInformation=_hostile_config_query(failure)
        )
        with mock.patch.object(
            boot_clock, "_platform", return_value="win32"
        ), mock.patch.object(boot_clock, "_load_ntdll", return_value=dll):
            with self.assertRaises(KeyboardInterrupt) as caught:
                boot_clock._query_boot_identifier()
        self.assertIs(failure, caught.exception)

    def test_non_callable_export_fails_closed(self) -> None:
        # ``None.argtypes = ...`` raises AttributeError inside the closed
        # configuration path; the refusal stays the stable call-failed code.
        dll = types.SimpleNamespace(NtQuerySystemInformation=None)
        self.query_error(dll, "boot-query-call-failed")


class NonWindowsGuardTests(unittest.TestCase):
    def test_non_win32_fails_before_any_windll_access(self) -> None:
        for platform in ("linux", "darwin", "cygwin", "emscripten", ""):
            with self.subTest(platform=platform):
                loader = mock.Mock(
                    side_effect=AssertionError("WinDLL touched off-Windows")
                )
                with mock.patch.object(
                    boot_clock, "_platform", return_value=platform
                ), mock.patch.object(boot_clock, "_load_ntdll", loader):
                    with expect_error(self, "platform-unsupported"):
                        WindowsBootClock().sample()
                loader.assert_not_called()

    @unittest.skipIf(IS_WINDOWS, "native non-Windows refusal")
    def test_real_non_windows_platform_fails_closed(self) -> None:
        with expect_error(self, "platform-unsupported"):
            WindowsBootClock().sample()


@unittest.skipUnless(IS_WINDOWS, "native boot clock requires Windows")
class NativeWindowsTests(unittest.TestCase):
    def test_same_boot_samples_agree_and_are_bounded(self) -> None:
        clock = WindowsBootClock()
        first = clock.sample()
        second = clock.sample()
        self.assertEqual(first.epoch, second.epoch)
        self.assertIsNotNone(boot_clock._EPOCH_RE.fullmatch(first.epoch))
        self.assertNotEqual("0" * 32, first.epoch)
        for reading in (first, second):
            self.assertIs(type(reading.now_ns), int)
            self.assertGreater(reading.now_ns, 0)
            self.assertLessEqual(reading.now_ns, MAX_NS)
        self.assertGreaterEqual(second.now_ns, first.now_ns)
        self.assertLess(second.now_ns - first.now_ns, 60 * 10 ** 9)

    def test_independent_process_reads_identical_epoch(self) -> None:
        local = WindowsBootClock().sample().epoch
        script = (
            "import sys\n"
            "from autonomy.boot_clock import WindowsBootClock\n"
            "sys.stdout.write(WindowsBootClock().sample().epoch)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(REPO_ROOT),
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        remote = result.stdout.decode("ascii")
        self.assertIsNotNone(boot_clock._EPOCH_RE.fullmatch(remote))
        self.assertEqual(local, remote)


if __name__ == "__main__":
    unittest.main()
