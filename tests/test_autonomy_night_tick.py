from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import tokenize
import unicodedata
import unittest
from pathlib import Path
from types import MappingProxyType
from unittest import mock

import autonomy.night_tick as night_tick
from autonomy.boot_clock import MAX_NS, BootClockError, ClockReading, WindowsBootClock
from autonomy.control_state import (
    ROOT_MARKER,
    SUPERVISOR_LOCK_FILENAME,
    LockUnavailableError,
    PermanentFileLock,
    create_halt,
)
from autonomy.night_tick import observe_night_tick
from autonomy.supervisor_transaction import (
    FenceContentionError,
    FenceUsageError,
    HaltActive,
    HaltEvidenceError,
    SupervisorFenceError,
    TransactionCompleted,
    run_halt_first_transaction,
)
from tests.test_autonomy_supervisor_transaction import driver_binding_violations


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "autonomy" / "night_tick.py"
CANONICAL_ROOT_MARKER = b'{"name":"agentchattr-autonomy-queue","version":1}\n'
NONCE = "c" * 32
STAMP = "2026-07-13T12:34:56.789Z"
EPOCH = "a" * 32
IS_WINDOWS = os.name == "nt"

# An absolute path that is never observed because the transaction driver is
# patched in every test that uses it.
UNUSED_ABSOLUTE_ROOT = os.path.join(tempfile.gettempdir(), "night-tick-unused-root")

HALTED_PAYLOAD = (
    b'{"halt":{"attempt":0,"created_utc":"2026-07-13T12:34:56.789Z",'
    b'"kind":"halt","nonce":"cccccccccccccccccccccccccccccccc",'
    b'"task_id":"root","version":1},"ok":true,"schema":1,"state":"halted"}\n'
)
OBSERVED_PAYLOAD = (
    b'{"boot":{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","now_ns":1},'
    b'"ok":true,"schema":1,"state":"observed"}\n'
)
USAGE_PAYLOAD = b'{"error":"usage","ok":false,"schema":1,"state":"error"}\n'
CONTENTION_PAYLOAD = (
    b'{"error":"fence-contention","ok":false,"schema":1,"state":"error"}\n'
)
REFUSED_PAYLOAD = (
    b'{"error":"observation-refused","ok":false,"schema":1,"state":"error"}\n'
)
UNEXPECTED_PAYLOAD = b'{"error":"unexpected","ok":false,"schema":1,"state":"error"}\n'


def subprocess_environment():
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def run_night_tick_cli(arguments, timeout=120.0):
    """One fully reaped ``python -B -m autonomy.night_tick`` child."""

    return subprocess.run(
        [sys.executable, "-B", "-m", "autonomy.night_tick", *arguments],
        cwd=REPO_ROOT,
        env=subprocess_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
    )


def collect_name_tokens(source_text):
    """Every exact Python NAME token in ``source_text``, NFKC-normalized."""

    names = set()
    for token in tokenize.generate_tokens(io.StringIO(source_text).readline):
        if token.type == tokenize.NAME:
            names.add(unicodedata.normalize("NFKC", token.string))
    return names


def valid_evidence(**overrides):
    document = {
        "attempt": 0,
        "created_utc": STAMP,
        "kind": "halt",
        "nonce": NONCE,
        "task_id": "root",
        "version": 1,
    }
    document.update(overrides)
    return MappingProxyType(document)


def forged_reading(epoch, now_ns):
    """An exact-type ClockReading that bypassed its own validation."""

    reading = ClockReading.__new__(ClockReading)
    object.__setattr__(reading, "epoch", epoch)
    object.__setattr__(reading, "now_ns", now_ns)
    return reading


def forged_partial_reading(**slots):
    """An exact-type ClockReading with only the given slots assigned.

    Reading an unassigned slot raises an ordinary ``AttributeError``, so
    this forges the missing-slot hostile shape the S1 R4 review probed.
    """

    reading = ClockReading.__new__(ClockReading)
    for name, value in slots.items():
        object.__setattr__(reading, name, value)
    return reading


class ExplodingIterationDict(dict):
    """Underlying mapping whose ordinary iteration fails through the proxy."""

    def __iter__(self):
        raise RuntimeError("hostile evidence iteration")


class ExplodingAccessDict(dict):
    """Underlying mapping whose ordinary key access fails through the proxy."""

    def __getitem__(self, key):
        if key == "kind":
            raise KeyError(key)
        return dict.__getitem__(self, key)


class FatalIterationDict(dict):
    """Underlying mapping whose iteration raises a stored fatal sentinel."""

    def __init__(self, base, sentinel):
        super().__init__(base)
        self.sentinel = sentinel

    def __iter__(self):
        raise self.sentinel


class FatalAccessDict(dict):
    """Underlying mapping whose key access raises a stored fatal sentinel."""

    def __init__(self, base, sentinel):
        super().__init__(base)
        self.sentinel = sentinel

    def __getitem__(self, key):
        raise self.sentinel


class HaltActiveSubclass(HaltActive):
    pass


class TransactionCompletedSubclass(TransactionCompleted):
    pass


class ClockReadingSubclass(ClockReading):
    pass


class ContentionSubclass(FenceContentionError):
    pass


class EvidenceSubclass(HaltEvidenceError):
    pass


class BootClockErrorSubclass(BootClockError):
    pass


class RecordingBuffer:
    def __init__(self, write_result=None, write_error=None, flush_error=None):
        self.write_result = write_result
        self.write_error = write_error
        self.flush_error = flush_error
        self.writes = []
        self.flushes = 0

    def write(self, payload):
        self.writes.append(bytes(payload))
        if self.write_error is not None:
            raise self.write_error
        if self.write_result is not None:
            return self.write_result
        return len(payload)

    def flush(self):
        self.flushes += 1
        if self.flush_error is not None:
            raise self.flush_error


class RecordingStdout:
    def __init__(self, buffer):
        self.recorded_buffer = buffer
        self.buffer_lookups = 0

    @property
    def buffer(self):
        self.buffer_lookups += 1
        return self.recorded_buffer


class PoisonedStderr:
    def __getattr__(self, name):
        raise AssertionError(f"stderr was touched: {name}")


class FenceFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ROOT_MARKER).write_bytes(CANONICAL_ROOT_MARKER)


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class HaltShortCircuitTests(FenceFixture):
    def test_valid_halt_returns_exact_halt_active_without_clock(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        clock_sentinel = mock.Mock(
            side_effect=AssertionError("a valid HALT constructed a clock")
        )
        with mock.patch.object(night_tick, "_new_clock", clock_sentinel):
            outcome = observe_night_tick(self.root)
        clock_sentinel.assert_not_called()
        self.assertIs(HaltActive, type(outcome))
        self.assertIs(MappingProxyType, type(outcome.halt))
        self.assertEqual(
            {
                "attempt": 0,
                "created_utc": STAMP,
                "kind": "halt",
                "nonce": NONCE,
                "task_id": "root",
                "version": 1,
            },
            dict(outcome.halt),
        )

    def test_halt_short_circuit_releases_fence_for_next_observer(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        with mock.patch.object(
            night_tick, "_new_clock", mock.Mock(side_effect=AssertionError("clock"))
        ):
            first = observe_night_tick(self.root)
            second = observe_night_tick(self.root)
        self.assertIs(HaltActive, type(first))
        self.assertIs(HaltActive, type(second))

    def test_corrupt_halt_fails_closed_before_any_clock(self):
        (self.root / "HALT").write_bytes(b'{"not":"canonical"}\n')
        clock_sentinel = mock.Mock(
            side_effect=AssertionError("a corrupt HALT constructed a clock")
        )
        with mock.patch.object(night_tick, "_new_clock", clock_sentinel):
            with self.assertRaises(HaltEvidenceError):
                observe_night_tick(self.root)
        clock_sentinel.assert_not_called()


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class HeldFenceSamplingTests(FenceFixture):
    def test_body_constructs_one_clock_and_samples_once_under_held_fence(self):
        log = []
        root = self.root
        reading = ClockReading(epoch=EPOCH, now_ns=1)

        class FenceProbingClock:
            def sample(self):
                log.append("sample")
                try:
                    probe = PermanentFileLock(root, SUPERVISOR_LOCK_FILENAME)
                except LockUnavailableError:
                    log.append("fence-held")
                else:
                    probe.close()
                    log.append("fence-free")
                return reading

        constructor = mock.Mock(side_effect=FenceProbingClock)
        with mock.patch.object(night_tick, "_new_clock", constructor):
            outcome = observe_night_tick(self.root)
        self.assertIs(TransactionCompleted, type(outcome))
        self.assertIs(reading, outcome.result)
        self.assertEqual(1, constructor.call_count)
        self.assertEqual(["sample", "fence-held"], log)

    def test_fence_is_released_after_completed_observation(self):
        with mock.patch.object(
            night_tick,
            "_new_clock",
            mock.Mock(
                side_effect=lambda: mock.Mock(
                    sample=mock.Mock(return_value=ClockReading(epoch=EPOCH, now_ns=1))
                )
            ),
        ):
            observe_night_tick(self.root)
        probe = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        probe.close()

    def test_fence_is_released_after_trusted_result_mismatch(self):
        fake_clock = mock.Mock(sample=mock.Mock(return_value="not-a-reading"))
        with mock.patch.object(
            night_tick, "_new_clock", mock.Mock(return_value=fake_clock)
        ):
            with self.assertRaises(night_tick._NightTickProtocolError) as context:
                observe_night_tick(self.root)
        self.assertEqual(("trusted-result-invalid",), context.exception.args)
        self.assertEqual(1, fake_clock.sample.call_count)
        probe = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        probe.close()

    def test_fence_is_released_after_boot_clock_refusal(self):
        with mock.patch.object(
            night_tick,
            "_new_clock",
            mock.Mock(side_effect=BootClockError("boot-query-status")),
        ):
            with self.assertRaises(BootClockError):
                observe_night_tick(self.root)
        outcome = run_halt_first_transaction(self.root, lambda: "recovered")
        self.assertEqual("recovered", outcome.result)

    def test_real_boot_clock_end_to_end_observation(self):
        outcome = observe_night_tick(self.root)
        self.assertIs(TransactionCompleted, type(outcome))
        self.assertIs(ClockReading, type(outcome.result))
        self.assertRegex(outcome.result.epoch, r"\A[0-9a-f]{32}\Z")
        self.assertIs(int, type(outcome.result.now_ns))
        self.assertGreaterEqual(outcome.result.now_ns, 0)
        self.assertLessEqual(outcome.result.now_ns, MAX_NS)


class BodyAndClockFactoryTests(unittest.TestCase):
    def test_new_clock_returns_exactly_one_windows_boot_clock(self):
        clock = night_tick._new_clock()
        self.assertIs(WindowsBootClock, type(clock))

    def test_tick_body_constructs_once_and_samples_once(self):
        reading = ClockReading(epoch=EPOCH, now_ns=1)
        fake_clock = mock.Mock(sample=mock.Mock(return_value=reading))
        constructor = mock.Mock(return_value=fake_clock)
        with mock.patch.object(night_tick, "_new_clock", constructor):
            result = night_tick._tick_body()
        self.assertIs(reading, result)
        constructor.assert_called_once_with()
        fake_clock.sample.assert_called_once_with()

    def test_observe_calls_driver_exactly_once_with_root_and_body(self):
        outcome = HaltActive(halt=valid_evidence())
        driver = mock.Mock(return_value=outcome)
        with mock.patch.object(night_tick, "run_halt_first_transaction", driver):
            returned = observe_night_tick(UNUSED_ABSOLUTE_ROOT)
        self.assertIs(outcome, returned)
        driver.assert_called_once_with(UNUSED_ABSOLUTE_ROOT, night_tick._tick_body)


class TrustedResultValidationTests(unittest.TestCase):
    def observe_with(self, outcome_or_error):
        if isinstance(outcome_or_error, BaseException):
            driver = mock.Mock(side_effect=outcome_or_error)
        else:
            driver = mock.Mock(return_value=outcome_or_error)
        with mock.patch.object(night_tick, "run_halt_first_transaction", driver):
            return observe_night_tick(UNUSED_ABSOLUTE_ROOT)

    def assert_rejected(self, outcome):
        with self.assertRaises(night_tick._NightTickProtocolError) as context:
            self.observe_with(outcome)
        self.assertEqual(("trusted-result-invalid",), context.exception.args)

    def test_valid_halt_active_is_returned_with_identity(self):
        outcome = HaltActive(halt=valid_evidence())
        self.assertIs(outcome, self.observe_with(outcome))

    def test_valid_transaction_completed_is_returned_with_identity(self):
        outcome = TransactionCompleted(result=ClockReading(epoch=EPOCH, now_ns=1))
        self.assertIs(outcome, self.observe_with(outcome))

    def test_non_outcome_objects_are_rejected(self):
        for hostile in (None, object(), "halt", 0, True, {}, (), ClockReading, [1]):
            with self.subTest(hostile=hostile):
                self.assert_rejected(hostile)

    def test_outcome_subclasses_are_rejected(self):
        self.assert_rejected(HaltActiveSubclass(halt=valid_evidence()))
        self.assert_rejected(
            TransactionCompletedSubclass(result=ClockReading(epoch=EPOCH, now_ns=1))
        )

    def test_halt_evidence_must_be_exactly_a_mapping_proxy(self):
        document = dict(valid_evidence())

        class DictSubclass(dict):
            pass

        for hostile in (document, DictSubclass(document), None, [("attempt", 0)]):
            with self.subTest(hostile=type(hostile).__name__):
                self.assert_rejected(HaltActive(halt=hostile))

    def test_halt_evidence_key_set_must_be_exact(self):
        missing = dict(valid_evidence())
        del missing["nonce"]
        extra = dict(valid_evidence())
        extra["generation"] = 1
        renamed = dict(valid_evidence())
        renamed["Nonce"] = renamed.pop("nonce")
        for document in (missing, extra, renamed, {}):
            with self.subTest(keys=sorted(document)):
                self.assert_rejected(HaltActive(halt=MappingProxyType(document)))

    def test_halt_attempt_and_version_must_be_exact_non_bool_integers(self):
        for overrides in (
            {"attempt": False},
            {"attempt": True},
            {"attempt": 1},
            {"attempt": -1},
            {"attempt": "0"},
            {"attempt": 0.0},
            {"attempt": None},
            {"version": True},
            {"version": 2},
            {"version": 0},
            {"version": "1"},
            {"version": 1.0},
            {"version": None},
        ):
            with self.subTest(overrides=overrides):
                self.assert_rejected(HaltActive(halt=valid_evidence(**overrides)))

    def test_halt_kind_and_task_id_must_be_exact_strings(self):
        for overrides in (
            {"kind": "HALT"},
            {"kind": "halt "},
            {"kind": b"halt"},
            {"kind": None},
            {"task_id": "Root"},
            {"task_id": "root2"},
            {"task_id": b"root"},
            {"task_id": None},
        ):
            with self.subTest(overrides=overrides):
                self.assert_rejected(HaltActive(halt=valid_evidence(**overrides)))

    def test_halt_nonce_must_be_exactly_32_lowercase_ascii_hex(self):
        hostile_unicode = "\N{MATHEMATICAL SANS-SERIF SMALL C}" + "c" * 31
        for nonce in (
            NONCE.upper(),
            "c" * 31,
            "c" * 33,
            "g" * 32,
            "c" * 31 + " ",
            hostile_unicode,
            b"c" * 32,
            None,
            0xC,
        ):
            with self.subTest(nonce=nonce):
                self.assert_rejected(HaltActive(halt=valid_evidence(nonce=nonce)))

    def test_halt_created_utc_valid_canonical_values_are_accepted(self):
        for created_utc in (
            "2026-07-13T12:34:56.789Z",
            "2024-02-29T00:00:00.000Z",
            "1999-12-31T23:59:59.999Z",
        ):
            with self.subTest(created_utc=created_utc):
                outcome = HaltActive(halt=valid_evidence(created_utc=created_utc))
                self.assertIs(outcome, self.observe_with(outcome))

    def test_halt_created_utc_invalid_values_are_rejected(self):
        for created_utc in (
            "2026-02-30T12:34:56.789Z",
            "2025-02-29T12:34:56.789Z",
            "2026-13-01T00:00:00.000Z",
            "2026-00-01T00:00:00.000Z",
            "2026-01-00T00:00:00.000Z",
            "2026-07-13T24:00:00.000Z",
            "2026-07-13T12:60:00.000Z",
            "2026-07-13T12:34:60.000Z",
            "0000-01-01T00:00:00.000Z",
            "2026-07-13T12:34:56.78Z",
            "2026-07-13T12:34:56.7890Z",
            "2026-07-13T12:34:56Z",
            "2026-07-13 12:34:56.789Z",
            "2026-07-13T12:34:56.789z",
            "2026-07-13T12:34:56.789+00:00",
            "2026-07-13T12:34:56.789Z ",
            " 2026-07-13T12:34:56.789Z",
            "\N{ARABIC-INDIC DIGIT TWO}026-07-13T12:34:56.789Z",
            "",
            None,
            20260713,
            b"2026-07-13T12:34:56.789Z",
        ):
            with self.subTest(created_utc=created_utc):
                self.assert_rejected(
                    HaltActive(halt=valid_evidence(created_utc=created_utc))
                )

    def test_completed_result_must_be_exact_clock_reading(self):
        for hostile in (
            None,
            "reading",
            (EPOCH, 1),
            {"epoch": EPOCH, "now_ns": 1},
            ClockReadingSubclass(epoch=EPOCH, now_ns=1),
        ):
            with self.subTest(hostile=type(hostile).__name__):
                self.assert_rejected(TransactionCompleted(result=hostile))

    def test_forged_clock_reading_fields_are_rejected(self):
        for epoch, now_ns in (
            (EPOCH.upper(), 1),
            ("a" * 31, 1),
            ("a" * 33, 1),
            ("g" * 32, 1),
            (b"a" * 32, 1),
            (None, 1),
            (EPOCH, True),
            (EPOCH, False),
            (EPOCH, "1"),
            (EPOCH, 1.0),
            (EPOCH, None),
        ):
            with self.subTest(epoch=epoch, now_ns=now_ns):
                self.assert_rejected(
                    TransactionCompleted(result=forged_reading(epoch, now_ns))
                )

    def test_forged_now_ns_out_of_range_is_rejected(self):
        for now_ns in (-1, MAX_NS + 1, -(2 ** 80), 2 ** 100, 10 ** 600):
            with self.subTest(now_ns=str(now_ns)[:32]):
                self.assert_rejected(
                    TransactionCompleted(result=forged_reading(EPOCH, now_ns))
                )

    def test_boundary_now_ns_values_are_accepted(self):
        for now_ns in (0, MAX_NS):
            with self.subTest(now_ns=now_ns):
                outcome = TransactionCompleted(
                    result=ClockReading(epoch=EPOCH, now_ns=now_ns)
                )
                self.assertIs(outcome, self.observe_with(outcome))

    def test_forged_reading_with_missing_slots_is_rejected(self):
        for slots in ({"now_ns": 1}, {"epoch": EPOCH}, {}):
            with self.subTest(assigned=sorted(slots)):
                self.assert_rejected(
                    TransactionCompleted(result=forged_partial_reading(**slots))
                )

    def test_evidence_ordinary_access_failures_are_rejected(self):
        for underlying in (
            ExplodingIterationDict(dict(valid_evidence())),
            ExplodingAccessDict(dict(valid_evidence())),
        ):
            with self.subTest(underlying=type(underlying).__name__):
                self.assert_rejected(
                    HaltActive(halt=MappingProxyType(underlying))
                )

    def test_evidence_fatal_access_failures_propagate_with_identity(self):
        for underlying_type in (FatalIterationDict, FatalAccessDict):
            with self.subTest(underlying=underlying_type.__name__):
                sentinel = KeyboardInterrupt("fatal evidence")
                evidence = MappingProxyType(
                    underlying_type(dict(valid_evidence()), sentinel)
                )
                with self.assertRaises(KeyboardInterrupt) as context:
                    self.observe_with(HaltActive(halt=evidence))
                self.assertIs(sentinel, context.exception)

    def test_driver_exceptions_pass_through_uncaught(self):
        sentinel = HaltEvidenceError("durable HALT is corrupt")
        with self.assertRaises(HaltEvidenceError) as context:
            self.observe_with(sentinel)
        self.assertIs(sentinel, context.exception)


class CliGrammarTests(unittest.TestCase):
    def cli_with_sentinels(self, argv):
        driver = mock.Mock(side_effect=AssertionError("grammar reached the driver"))
        clock = mock.Mock(side_effect=AssertionError("grammar constructed a clock"))
        with mock.patch.object(night_tick, "run_halt_first_transaction", driver):
            with mock.patch.object(night_tick, "_new_clock", clock):
                result = night_tick._cli_result(argv)
        driver.assert_not_called()
        clock.assert_not_called()
        return result

    def test_every_rejected_argv_maps_to_exit_2_usage(self):
        absolute = UNUSED_ABSOLUTE_ROOT
        hostile_flag = "--roo\N{MATHEMATICAL SANS-SERIF SMALL T}"
        rejected = (
            (),
            ("--root",),
            ("--root", absolute, absolute),
            ("-r", absolute),
            (f"--root={absolute}",),
            ("--help",),
            ("--Root", absolute),
            ("--ROOT", absolute),
            ("root", absolute),
            (absolute, "--root"),
            (" --root", absolute),
            ("--root ", absolute),
            (hostile_flag, absolute),
            ("--root", ""),
            ("--root", "relative-root"),
            ("--root", "relative\\path"),
            ("--root", "."),
            ("--root", ".."),
            ("--root", "C:relative") if IS_WINDOWS else ("--root", "relative"),
            ("--root", 5),
            ("--root", None),
            ("--root", b"C:\\queue"),
            ("--root", Path(absolute)),
            (b"--root", absolute),
            (None, absolute),
        )
        for argv in rejected:
            with self.subTest(argv=argv):
                self.assertEqual((2, USAGE_PAYLOAD), self.cli_with_sentinels(argv))

    def test_non_tuple_argv_maps_to_exit_2_usage(self):
        absolute = UNUSED_ABSOLUTE_ROOT
        for argv in ([absolute], ["--root", absolute], "--root", None, 2):
            with self.subTest(argv=argv):
                self.assertEqual((2, USAGE_PAYLOAD), self.cli_with_sentinels(argv))

    def test_exact_grammar_reaches_the_driver(self):
        driver = mock.Mock(return_value=HaltActive(halt=valid_evidence()))
        with mock.patch.object(night_tick, "run_halt_first_transaction", driver):
            code, payload = night_tick._cli_result(("--root", UNUSED_ABSOLUTE_ROOT))
        self.assertEqual(0, code)
        self.assertEqual(HALTED_PAYLOAD, payload)
        driver.assert_called_once_with(UNUSED_ABSOLUTE_ROOT, night_tick._tick_body)


class CliTaxonomyAndPayloadTests(unittest.TestCase):
    GOOD_ARGV = ("--root", UNUSED_ABSOLUTE_ROOT)

    def cli_with_driver(self, outcome_or_error):
        if isinstance(outcome_or_error, BaseException):
            driver = mock.Mock(side_effect=outcome_or_error)
        else:
            driver = mock.Mock(return_value=outcome_or_error)
        with mock.patch.object(night_tick, "run_halt_first_transaction", driver):
            return night_tick._cli_result(self.GOOD_ARGV)

    def test_success_payloads_are_exact_deterministic_bytes(self):
        halted = HaltActive(halt=valid_evidence())
        observed = TransactionCompleted(result=ClockReading(epoch=EPOCH, now_ns=1))
        self.assertEqual((0, HALTED_PAYLOAD), self.cli_with_driver(halted))
        self.assertEqual((0, HALTED_PAYLOAD), self.cli_with_driver(halted))
        self.assertEqual((0, OBSERVED_PAYLOAD), self.cli_with_driver(observed))
        self.assertEqual((0, OBSERVED_PAYLOAD), self.cli_with_driver(observed))

    def test_every_payload_is_ascii_single_lf_and_within_512_bytes(self):
        maximal = TransactionCompleted(result=ClockReading(epoch=EPOCH, now_ns=MAX_NS))
        payloads = [
            self.cli_with_driver(HaltActive(halt=valid_evidence()))[1],
            self.cli_with_driver(maximal)[1],
            USAGE_PAYLOAD,
            CONTENTION_PAYLOAD,
            REFUSED_PAYLOAD,
            UNEXPECTED_PAYLOAD,
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertLessEqual(len(payload), 512)
                self.assertTrue(payload.endswith(b"\n"))
                self.assertEqual(1, payload.count(b"\n"))
                text = payload.decode("ascii")
                document = json.loads(text)
                recoded = json.dumps(
                    document,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                self.assertEqual(recoded + "\n", text)

    def test_exact_fence_contention_maps_to_exit_3(self):
        self.assertEqual(
            (3, CONTENTION_PAYLOAD),
            self.cli_with_driver(FenceContentionError("held")),
        )

    def test_exact_evidence_and_boot_clock_errors_map_to_exit_4(self):
        self.assertEqual(
            (4, REFUSED_PAYLOAD), self.cli_with_driver(HaltEvidenceError("corrupt"))
        )
        self.assertEqual(
            (4, REFUSED_PAYLOAD),
            self.cli_with_driver(BootClockError("boot-query-status")),
        )

    def test_typed_error_subclasses_map_to_exit_5(self):
        for error in (
            ContentionSubclass("held"),
            EvidenceSubclass("corrupt"),
            BootClockErrorSubclass("boot-query-status"),
        ):
            with self.subTest(error=type(error).__name__):
                self.assertEqual((5, UNEXPECTED_PAYLOAD), self.cli_with_driver(error))

    def test_other_ordinary_exceptions_map_to_exit_5(self):
        for error in (
            ValueError("v"),
            OSError(5, "io"),
            FenceUsageError("body"),
            SupervisorFenceError("base"),
            night_tick._NightTickProtocolError("trusted-result-invalid"),
            night_tick._NightTickOutputError("payload-overflow"),
        ):
            with self.subTest(error=type(error).__name__):
                self.assertEqual((5, UNEXPECTED_PAYLOAD), self.cli_with_driver(error))

    def test_ordinary_exception_groups_map_to_exit_5(self):
        group = ExceptionGroup("both failed", [ValueError("v"), OSError(5, "io")])
        self.assertEqual((5, UNEXPECTED_PAYLOAD), self.cli_with_driver(group))

    def test_hostile_trusted_result_maps_to_exit_5(self):
        self.assertEqual((5, UNEXPECTED_PAYLOAD), self.cli_with_driver(object()))
        self.assertEqual(
            (5, UNEXPECTED_PAYLOAD),
            self.cli_with_driver(HaltActive(halt=valid_evidence(attempt=1))),
        )

    def test_payload_overflow_becomes_exit_5_unexpected(self):
        huge = TransactionCompleted(result=forged_reading(EPOCH, 10**600))
        self.assertEqual((5, UNEXPECTED_PAYLOAD), self.cli_with_driver(huge))

    def test_forged_out_of_range_now_ns_maps_to_exit_5(self):
        for now_ns in (-1, MAX_NS + 1):
            with self.subTest(now_ns=now_ns):
                self.assertEqual(
                    (5, UNEXPECTED_PAYLOAD),
                    self.cli_with_driver(
                        TransactionCompleted(result=forged_reading(EPOCH, now_ns))
                    ),
                )

    def test_forged_missing_slot_readings_map_to_exit_5(self):
        for slots in ({"now_ns": 1}, {"epoch": EPOCH}, {}):
            with self.subTest(assigned=sorted(slots)):
                self.assertEqual(
                    (5, UNEXPECTED_PAYLOAD),
                    self.cli_with_driver(
                        TransactionCompleted(
                            result=forged_partial_reading(**slots)
                        )
                    ),
                )

    def test_evidence_ordinary_access_failures_map_to_exit_5(self):
        for underlying in (
            ExplodingIterationDict(dict(valid_evidence())),
            ExplodingAccessDict(dict(valid_evidence())),
        ):
            with self.subTest(underlying=type(underlying).__name__):
                self.assertEqual(
                    (5, UNEXPECTED_PAYLOAD),
                    self.cli_with_driver(
                        HaltActive(halt=MappingProxyType(underlying))
                    ),
                )

    def test_evidence_fatal_access_failure_propagates_through_cli(self):
        for underlying_type in (FatalIterationDict, FatalAccessDict):
            with self.subTest(underlying=underlying_type.__name__):
                sentinel = KeyboardInterrupt("fatal evidence")
                evidence = MappingProxyType(
                    underlying_type(dict(valid_evidence()), sentinel)
                )
                with self.assertRaises(KeyboardInterrupt) as context:
                    self.cli_with_driver(HaltActive(halt=evidence))
                self.assertIs(sentinel, context.exception)

    def test_fatal_base_exceptions_propagate_with_identity(self):
        for fatal in (KeyboardInterrupt(), SystemExit(9), GeneratorExit()):
            with self.subTest(fatal=type(fatal).__name__):
                with self.assertRaises(type(fatal)) as context:
                    self.cli_with_driver(fatal)
                self.assertIs(fatal, context.exception)

    def test_group_with_fatal_member_propagates_unchanged(self):
        primary = ValueError("primary")
        fatal = KeyboardInterrupt()
        group = BaseExceptionGroup("mixed", [primary, fatal])
        self.assertIsNot(ExceptionGroup, type(group))
        with self.assertRaises(BaseExceptionGroup) as context:
            self.cli_with_driver(group)
        self.assertIs(group, context.exception)
        self.assertIs(primary, context.exception.exceptions[0])
        self.assertIs(fatal, context.exception.exceptions[1])

    def test_fatal_cause_and_context_are_preserved(self):
        cause = OSError(5, "io")
        fatal = KeyboardInterrupt()
        fatal.__cause__ = cause
        with self.assertRaises(KeyboardInterrupt) as context:
            self.cli_with_driver(fatal)
        self.assertIs(fatal, context.exception)
        self.assertIs(cause, context.exception.__cause__)

    def test_evidence_mutating_after_validation_yields_exit_5(self):
        class MutatingDict(dict):
            def __init__(self, base):
                super().__init__(base)
                self.reads = 0

            def __getitem__(self, key):
                self.reads += 1
                if self.reads > 6 and key == "kind":
                    return "HALT"
                return dict.__getitem__(self, key)

        evidence = MappingProxyType(MutatingDict(dict(valid_evidence())))
        self.assertEqual(
            (5, UNEXPECTED_PAYLOAD), self.cli_with_driver(HaltActive(halt=evidence))
        )

    def test_evidence_mutating_to_still_valid_values_stays_canonical(self):
        class MutatingDict(dict):
            def __init__(self, base):
                super().__init__(base)
                self.reads = 0

            def __getitem__(self, key):
                self.reads += 1
                if self.reads > 6 and key == "nonce":
                    return "d" * 32
                return dict.__getitem__(self, key)

        evidence = MappingProxyType(MutatingDict(dict(valid_evidence())))
        code, payload = self.cli_with_driver(HaltActive(halt=evidence))
        self.assertEqual(0, code)
        self.assertEqual(HALTED_PAYLOAD.replace(NONCE.encode(), b"d" * 32), payload)


class EntrySinkTests(unittest.TestCase):
    GOOD_ARGV = ["night_tick", "--root", UNUSED_ABSOLUTE_ROOT]

    def run_entry(self, argv, stdout, driver_outcome=None):
        if driver_outcome is None:
            driver_outcome = HaltActive(halt=valid_evidence())
        if isinstance(driver_outcome, BaseException):
            driver = mock.Mock(side_effect=driver_outcome)
        else:
            driver = mock.Mock(return_value=driver_outcome)
        with mock.patch.object(night_tick, "run_halt_first_transaction", driver):
            with mock.patch.object(sys, "argv", argv):
                with mock.patch.object(sys, "stdout", stdout):
                    with mock.patch.object(sys, "stderr", PoisonedStderr()):
                        night_tick._entry()

    def test_success_writes_once_flushes_once_and_exits_zero(self):
        buffer = RecordingBuffer()
        stdout = RecordingStdout(buffer)
        with self.assertRaises(SystemExit) as context:
            self.run_entry(self.GOOD_ARGV, stdout)
        self.assertEqual(0, context.exception.code)
        self.assertEqual([HALTED_PAYLOAD], buffer.writes)
        self.assertEqual(1, buffer.flushes)
        self.assertEqual(1, stdout.buffer_lookups)

    def test_usage_writes_usage_payload_and_exits_two(self):
        buffer = RecordingBuffer()
        with self.assertRaises(SystemExit) as context:
            self.run_entry(["night_tick"], RecordingStdout(buffer))
        self.assertEqual(2, context.exception.code)
        self.assertEqual([USAGE_PAYLOAD], buffer.writes)
        self.assertEqual(1, buffer.flushes)

    def test_contention_writes_payload_and_exits_three(self):
        buffer = RecordingBuffer()
        with self.assertRaises(SystemExit) as context:
            self.run_entry(
                self.GOOD_ARGV,
                RecordingStdout(buffer),
                driver_outcome=FenceContentionError("held"),
            )
        self.assertEqual(3, context.exception.code)
        self.assertEqual([CONTENTION_PAYLOAD], buffer.writes)

    def test_partial_write_raises_without_flush_or_retry(self):
        buffer = RecordingBuffer(write_result=len(HALTED_PAYLOAD) - 1)
        with self.assertRaises(night_tick._NightTickOutputError) as context:
            self.run_entry(self.GOOD_ARGV, RecordingStdout(buffer))
        self.assertEqual(("stdout-partial-write",), context.exception.args)
        self.assertEqual(1, len(buffer.writes))
        self.assertEqual(0, buffer.flushes)

    def test_bool_write_count_is_a_partial_write(self):
        buffer = RecordingBuffer(write_result=True)
        with self.assertRaises(night_tick._NightTickOutputError) as context:
            self.run_entry(self.GOOD_ARGV, RecordingStdout(buffer))
        self.assertEqual(("stdout-partial-write",), context.exception.args)
        self.assertEqual(0, buffer.flushes)

    def test_non_integer_write_count_is_a_partial_write(self):
        buffer = RecordingBuffer(write_result=float(len(HALTED_PAYLOAD)))
        with self.assertRaises(night_tick._NightTickOutputError):
            self.run_entry(self.GOOD_ARGV, RecordingStdout(buffer))
        self.assertEqual(0, buffer.flushes)

    def test_write_failure_propagates_unchanged_without_flush(self):
        sentinel = OSError(28, "no space")
        buffer = RecordingBuffer(write_error=sentinel)
        with self.assertRaises(OSError) as context:
            self.run_entry(self.GOOD_ARGV, RecordingStdout(buffer))
        self.assertIs(sentinel, context.exception)
        self.assertEqual(1, len(buffer.writes))
        self.assertEqual(0, buffer.flushes)

    def test_flush_failure_propagates_unchanged(self):
        sentinel = OSError(5, "io")
        buffer = RecordingBuffer(flush_error=sentinel)
        with self.assertRaises(OSError) as context:
            self.run_entry(self.GOOD_ARGV, RecordingStdout(buffer))
        self.assertIs(sentinel, context.exception)
        self.assertEqual(1, buffer.flushes)

    def test_missing_buffer_propagates_before_any_write(self):
        class BufferlessStdout:
            pass

        with self.assertRaises(AttributeError):
            self.run_entry(self.GOOD_ARGV, BufferlessStdout())

    def test_buffer_is_looked_up_exactly_once_per_entry(self):
        buffer = RecordingBuffer()
        stdout = RecordingStdout(buffer)
        with self.assertRaises(SystemExit):
            self.run_entry(["night_tick"], stdout)
        self.assertEqual(1, stdout.buffer_lookups)

    def test_fatal_driver_exception_produces_no_output(self):
        buffer = RecordingBuffer()
        with self.assertRaises(KeyboardInterrupt):
            self.run_entry(
                self.GOOD_ARGV,
                RecordingStdout(buffer),
                driver_outcome=KeyboardInterrupt(),
            )
        self.assertEqual([], buffer.writes)
        self.assertEqual(0, buffer.flushes)


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class CliSubprocessTests(FenceFixture):
    def assert_canonical_observed(self, stdout):
        self.assertLessEqual(len(stdout), 512)
        self.assertTrue(stdout.endswith(b"\n"))
        self.assertEqual(1, stdout.count(b"\n"))
        document = json.loads(stdout.decode("ascii"))
        self.assertEqual({"boot", "ok", "schema", "state"}, set(document))
        self.assertEqual(True, document["ok"])
        self.assertEqual(1, document["schema"])
        self.assertEqual("observed", document["state"])
        self.assertEqual({"epoch", "now_ns"}, set(document["boot"]))
        self.assertRegex(document["boot"]["epoch"], r"\A[0-9a-f]{32}\Z")
        self.assertIs(int, type(document["boot"]["now_ns"]))
        recoded = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertEqual((recoded + "\n").encode("ascii"), stdout)

    def test_cli_observes_real_boot_clock_and_exits_zero(self):
        completed = run_night_tick_cli(["--root", os.fspath(self.root)])
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(0, completed.returncode)
        self.assert_canonical_observed(completed.stdout)

    def test_cli_halted_root_emits_exact_halt_payload(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        completed = run_night_tick_cli(["--root", os.fspath(self.root)])
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(0, completed.returncode)
        self.assertEqual(HALTED_PAYLOAD, completed.stdout)

    def test_cli_grammar_failures_exit_two_with_usage_payload(self):
        for arguments in (
            [],
            ["--root"],
            ["--root", os.fspath(self.root), "extra"],
            [f"--root={os.fspath(self.root)}"],
            ["--help"],
            ["--root", "relative-root"],
        ):
            with self.subTest(arguments=arguments):
                completed = run_night_tick_cli(arguments)
                self.assertEqual(b"", completed.stderr)
                self.assertEqual(2, completed.returncode)
                self.assertEqual(USAGE_PAYLOAD, completed.stdout)

    def test_cli_corrupt_halt_exits_four_observation_refused(self):
        (self.root / "HALT").write_bytes(b'{"not":"canonical"}\n')
        completed = run_night_tick_cli(["--root", os.fspath(self.root)])
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(4, completed.returncode)
        self.assertEqual(REFUSED_PAYLOAD, completed.stdout)

    def test_cli_missing_root_marker_exits_five_unexpected(self):
        with tempfile.TemporaryDirectory() as bare:
            completed = run_night_tick_cli(["--root", os.fspath(Path(bare).resolve())])
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(5, completed.returncode)
        self.assertEqual(UNEXPECTED_PAYLOAD, completed.stdout)

    def test_cli_nonexistent_root_exits_five_unexpected(self):
        missing = self.root / "does-not-exist"
        completed = run_night_tick_cli(["--root", os.fspath(missing)])
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(5, completed.returncode)
        self.assertEqual(UNEXPECTED_PAYLOAD, completed.stdout)


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class TwoProcessContentionTests(FenceFixture):
    HOLDER_SCRIPT = (
        "import os\n"
        "import sys\n"
        "import time\n"
        "\n"
        "from autonomy.control_state import ("
        "SUPERVISOR_LOCK_FILENAME, PermanentFileLock)\n"
        "\n"
        "root, ready_path, release_path = sys.argv[1:4]\n"
        "lock = PermanentFileLock(root, SUPERVISOR_LOCK_FILENAME)\n"
        "with open(ready_path + '.tmp', 'w') as handle:\n"
        "    handle.write('held')\n"
        "os.replace(ready_path + '.tmp', ready_path)\n"
        "deadline = time.monotonic() + 60.0\n"
        "while not os.path.exists(release_path):\n"
        "    if time.monotonic() >= deadline:\n"
        "        lock.close()\n"
        "        raise SystemExit(7)\n"
        "    time.sleep(0.01)\n"
        "lock.close()\n"
        "raise SystemExit(0)\n"
    )

    def test_ten_real_two_process_contention_rounds(self):
        # Prewarm the permanent lock file so no round can race its creation.
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        for round_index in range(10):
            with self.subTest(round=round_index):
                self.run_contention_round(round_index)

    def run_contention_round(self, round_index):
        ready = self.root / f"holder-ready-{round_index}"
        release = self.root / f"holder-release-{round_index}"
        holder = subprocess.Popen(
            [
                sys.executable,
                "-B",
                "-c",
                self.HOLDER_SCRIPT,
                os.fspath(self.root),
                os.fspath(ready),
                os.fspath(release),
            ],
            cwd=REPO_ROOT,
            env=subprocess_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(holder.kill)
        try:
            deadline = time.monotonic() + 30.0
            while not ready.exists():
                if holder.poll() is not None:
                    stdout, stderr = holder.communicate(timeout=30)
                    self.fail(f"holder exited early: {stdout}{stderr}")
                if time.monotonic() >= deadline:
                    self.fail("holder never acquired the fence")
                time.sleep(0.01)
            completed = run_night_tick_cli(
                ["--root", os.fspath(self.root)], timeout=60.0
            )
            self.assertEqual(b"", completed.stderr)
            self.assertEqual(3, completed.returncode)
            self.assertEqual(CONTENTION_PAYLOAD, completed.stdout)
        finally:
            release.write_bytes(b"release")
            try:
                stdout, stderr = holder.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.communicate(timeout=30)
                raise
        self.assertEqual(0, holder.returncode, stderr)
        self.assertIsNotNone(holder.returncode)

    def test_contention_leaves_lock_file_bytes_intact(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        lock_path = self.root / SUPERVISOR_LOCK_FILENAME
        self.assertEqual(b"\0", lock_path.read_bytes())
        self.run_contention_round(99)
        self.assertEqual(b"\0", lock_path.read_bytes())
        self.assertEqual(1, os.lstat(lock_path).st_nlink)


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class ReadOnlyInventoryTests(FenceFixture):
    def byte_inventory(self):
        entries = {}
        for path in sorted(self.root.rglob("*")):
            relative = str(path.relative_to(self.root))
            entries[relative] = "<dir>" if path.is_dir() else path.read_bytes()
        return entries

    def test_observation_on_prewarmed_root_changes_no_bytes(self):
        observe_night_tick(self.root)  # Prewarm creates the permanent lock.
        before = self.byte_inventory()
        self.assertIn(SUPERVISOR_LOCK_FILENAME, before)
        outcome = observe_night_tick(self.root)
        self.assertIs(TransactionCompleted, type(outcome))
        self.assertEqual(before, self.byte_inventory())

    def test_halted_observation_on_prewarmed_root_changes_no_bytes(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        observe_night_tick(self.root)
        before = self.byte_inventory()
        outcome = observe_night_tick(self.root)
        self.assertIs(HaltActive, type(outcome))
        self.assertEqual(before, self.byte_inventory())

    def test_cli_on_prewarmed_root_changes_no_bytes(self):
        observe_night_tick(self.root)
        before = self.byte_inventory()
        completed = run_night_tick_cli(["--root", os.fspath(self.root)])
        self.assertEqual(0, completed.returncode)
        self.assertEqual(before, self.byte_inventory())


class StaticGateTests(unittest.TestCase):
    ALLOWED_IMPORT_MODULES = frozenset(
        {
            "__future__",
            "json",
            "os",
            "re",
            "sys",
            "datetime",
            "types",
            "autonomy.boot_clock",
            "autonomy.supervisor_transaction",
        }
    )
    ALLOWED_FROM_IMPORTS = {
        "__future__": frozenset({"annotations"}),
        "datetime": frozenset({"datetime"}),
        "types": frozenset({"MappingProxyType"}),
        "autonomy.boot_clock": frozenset(
            {"BootClockError", "ClockReading", "WindowsBootClock"}
        ),
        "autonomy.supervisor_transaction": frozenset(
            {
                "FenceContentionError",
                "HaltActive",
                "HaltEvidenceError",
                "TransactionCompleted",
                "run_halt_first_transaction",
            }
        ),
    }
    FORBIDDEN_NAME_TOKENS = (
        "create_halt",
        "read_halt",
        "halt_exists",
        "PermanentFileLock",
        "acquire_permanent_lock",
        "getattr",
        "setattr",
        "delattr",
        "eval",
        "exec",
        "__import__",
        "importlib",
        "globals",
        "locals",
        "vars",
        "open",
        "print",
        "input",
        "environ",
        "getenv",
        "putenv",
        "subprocess",
        "socket",
        "ssl",
        "http",
        "urllib",
        "asyncio",
        "threading",
        "multiprocessing",
        "ctypes",
        "time",
        "tempfile",
        "shutil",
        "pathlib",
        "Path",
        "stat",
        "io",
        "stderr",
        "FenceCapability",
        "CapabilityError",
        "require_active",
    )

    def module_source(self):
        return MODULE_PATH.read_text(encoding="utf-8")

    def module_tree(self):
        return ast.parse(self.module_source())

    def test_public_surface_is_exactly_observe_night_tick(self):
        self.assertEqual(["observe_night_tick"], night_tick.__all__)

    def test_import_surface_is_exactly_the_frozen_allowlist(self):
        imported = set()
        from_imports = {}
        for node in ast.walk(self.module_tree()):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(0, node.level, "relative imports are forbidden")
                self.assertIsNotNone(node.module)
                imported.add(node.module)
                names = from_imports.setdefault(node.module, set())
                names.update(alias.name for alias in node.names)
        self.assertEqual(self.ALLOWED_IMPORT_MODULES, frozenset(imported))
        self.assertEqual(
            {module: frozenset(names) for module, names in from_imports.items()},
            self.ALLOWED_FROM_IMPORTS,
        )
        for names in from_imports.values():
            self.assertNotIn("*", names)

    def test_forbidden_name_tokens_are_absent(self):
        tokens = collect_name_tokens(self.module_source())
        for forbidden in self.FORBIDDEN_NAME_TOKENS:
            self.assertNotIn(forbidden, tokens, forbidden)

    def test_exactly_one_direct_transaction_driver_call(self):
        direct_calls = 0
        attribute_calls = 0
        for node in ast.walk(self.module_tree()):
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "run_halt_first_transaction"
                ):
                    direct_calls += 1
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run_halt_first_transaction"
                ):
                    attribute_calls += 1
        self.assertEqual(1, direct_calls)
        self.assertEqual(0, attribute_calls)

    def test_driver_name_is_never_rebound_or_aliased(self):
        for node in ast.walk(self.module_tree()):
            if isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                self.assertNotEqual("run_halt_first_transaction", node.id)

    def test_driver_binding_discipline_has_no_violations(self):
        # Full AST binding analysis: exactly one module-level unaliased
        # import of run_halt_first_transaction from the frozen module and
        # exactly one direct Name call to that imported binding directly
        # inside observe_night_tick, with every other binding or use of
        # the identifier rejected.
        self.assertEqual([], driver_binding_violations(self.module_source()))

    def test_alias_preserving_redefinition_mutant_of_real_module_is_rejected(self):
        # The exact temporary-mirror mutant from the S1 R4 independent
        # review, applied to the real module source: the imported driver
        # survives under an alias, a local function redefines the driver
        # name, and observe_night_tick delegates through the redefinition.
        original = self.module_source()
        aliased = original.replace(
            "    run_halt_first_transaction,\n)",
            "    run_halt_first_transaction as _fenced_driver,\n)",
            1,
        )
        self.assertNotEqual(original, aliased)
        mutant = aliased.replace(
            "def _new_clock()",
            "def run_halt_first_transaction(queue_root, body):\n"
            "    return _fenced_driver(queue_root, body)\n\n\n"
            "def _new_clock()",
            1,
        )
        self.assertNotEqual(aliased, mutant)
        compile(mutant, "<night-tick-mutant>", "exec")
        # The mutant defeats every pre-R4-correction gate: the NAME token
        # is still present, there is still exactly one direct Name call
        # and zero attribute calls, and the driver name is never a plain
        # Name store or delete.
        self.assertIn("run_halt_first_transaction", collect_name_tokens(mutant))
        tree = ast.parse(mutant)
        direct_calls = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "run_halt_first_transaction"
        )
        self.assertEqual(1, direct_calls)
        rebound = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id == "run_halt_first_transaction"
        ]
        self.assertEqual([], rebound)
        # Only the binding validator rejects it.
        violations = driver_binding_violations(mutant)
        self.assertIn("driver-imported-under-alias", violations)
        self.assertIn("driver-name-used-as-function-definition", violations)
        self.assertIn("driver-unaliased-import-count-not-one", violations)

    def test_module_compiles_in_memory(self):
        compile(self.module_source(), os.fspath(MODULE_PATH), "exec")


if __name__ == "__main__":
    unittest.main()
