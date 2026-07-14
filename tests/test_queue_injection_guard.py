"""Deterministic tests for the fail-closed queue-injection admission gate.

Covers CODEX-2-INFRA-INJECT-GUARD-003 incl. the id2098/id2099/id2100 rework:
provider-shaped composer recognition (live Claude marker U+276F + NBSP),
hash-bound durable-queue cursor, append-only startup admission, strict
record parsing with quarantine, full multi-destination prompt representation,
identity-generation capture, exact composer-region Enter verification,
atomic Enter with fail-closed uncertain policy, and compatibility with the
pre-existing Fable safeguard protections. No live console, no live tokens.
"""

import ctypes
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agents
import wrapper

if sys.platform == "win32":
    import wrapper_windows


NBSP = " "

# Screen fixtures. Composer content is synthetic — never real prompt text.
CODEX_IDLE = "\n".join([
    "codex banner",
    "Worked for 2m 10s",
    "",
    "›",
    "  send /help for commands",
])

FABLE_IDLE = "\n".join([
    "✻ transcript output",
    "╭──────────────────────────────────────╮",
    f"│ ❯{NBSP}",
    "╰──────────────────────────────────────╯",
    "  ⏵⏵ bypass permissions on",
])


def _codex_screen_with_text(text: str) -> str:
    return "\n".join([
        "codex banner",
        "Worked for 2m 10s",
        "",
        "› " + text,
        "  send /help for commands",
    ])


def _fable_screen_with_text(text: str) -> str:
    return "\n".join([
        "✻ transcript output",
        "╭──────────────────────────────────────╮",
        f"│ ❯{NBSP}{text}",
        "╰──────────────────────────────────────╯",
        "  ⏵⏵ bypass permissions on",
    ])


SAFEGUARD_MENU = """
Session paused

Fable 5's safeguards flagged this message. The safeguards are intentionally
broad right now and may flag safe and routine coding, cybersecurity, or biology
work. These measures let us bring you Mythos-level capabilities sooner, and
we're working to refine them. Send feedback with /feedback or learn more

❯ 1. Switch to Opus 4.8
  2. Edit prompt and retry with Fable 5
"""


@unittest.skipUnless(sys.platform == "win32", "Windows-only injection gate")
class ComposerStateTests(unittest.TestCase):
    def _state(self, screen, markers=("›",), placeholders=(),
               separator=" ", empty_requires_separator=False):
        state, content, _row = wrapper_windows._composer_state(
            screen, markers, placeholders, separator, empty_requires_separator
        )
        return state, content

    def _claude(self, screen, placeholders=()):
        return self._state(
            screen, markers=("❯",), placeholders=placeholders,
            separator=NBSP, empty_requires_separator=True,
        )

    def test_live_shaped_fable_empty_composer(self):
        self.assertEqual(self._claude(FABLE_IDLE)[0], "empty")

    def test_live_shaped_fable_nonempty_composer(self):
        state, content = self._claude(_fable_screen_with_text("draft text"))
        self.assertEqual(state, "nonempty")
        self.assertEqual(content, "draft text")

    def test_bare_marker_glyph_in_transcript_is_not_claude_composer(self):
        # Provider-shaped proof: live Claude renders marker+NBSP even when
        # empty; a bare "❯" transcript glyph must never be recognized.
        stray = "\n".join(["transcript", "❯", ""])
        self.assertEqual(self._claude(stray)[0], "unrecognized")

    def test_wrong_separator_is_not_claude_composer(self):
        ascii_space = "\n".join(["x", "❯ text typed"])
        self.assertEqual(self._claude(ascii_space)[0], "unrecognized")

    def test_codex_empty_composer_is_positively_recognized(self):
        self.assertEqual(self._state(CODEX_IDLE)[0], "empty")

    def test_codex_nonempty_composer_is_nonempty(self):
        state, content = self._state(_codex_screen_with_text("mixed garbled"))
        self.assertEqual(state, "nonempty")
        self.assertEqual(content, "mixed garbled")

    def test_screen_without_marker_is_unrecognized(self):
        self.assertEqual(
            self._state("ordinary clean screen")[0], "unrecognized"
        )

    def test_no_markers_configured_is_unrecognized(self):
        self.assertEqual(self._state(CODEX_IDLE, markers=())[0], "unrecognized")

    def test_bottom_most_marker_row_wins_over_output_quotes(self):
        screen = "\n".join([
            f"❯{NBSP}quoted old output",
            "╭─────────╮",
            f"│ ❯{NBSP}",
            "╰─────────╯",
        ])
        self.assertEqual(self._claude(screen)[0], "empty")

    def test_allowed_placeholder_counts_as_empty(self):
        screen = _codex_screen_with_text("Ask Codex anything")
        self.assertEqual(
            self._state(screen, placeholders=("Ask Codex anything",))[0],
            "empty",
        )

    def test_trailing_block_cursor_cell_still_empty(self):
        self.assertEqual(self._state(_codex_screen_with_text("▌"))[0], "empty")
        self.assertEqual(
            self._claude(_fable_screen_with_text("▌"))[0], "empty"
        )

    def test_marker_glued_to_text_is_not_a_composer_row(self):
        state, _ = self._state("x\n>>> python prompt", markers=(">",))
        self.assertEqual(state, "unrecognized")


@unittest.skipUnless(sys.platform == "win32", "Windows-only injection gate")
class AdmissionGuardTests(unittest.TestCase):
    def _guard(self, provider="codex", **kwargs):
        return wrapper_windows._ComposerAdmissionGuard(provider, **kwargs)

    def test_two_stable_empty_reads_admit(self):
        guard = self._guard()
        self.assertEqual(guard.classify(CODEX_IDLE), "busy")
        self.assertEqual(guard.classify(CODEX_IDLE), "admit")

    def test_claude_profile_admits_on_live_shaped_screen(self):
        guard = self._guard(provider="claude")
        self.assertEqual(guard.classify(FABLE_IDLE), "busy")
        self.assertEqual(guard.classify(FABLE_IDLE), "admit")

    def test_alternating_status_row_never_admits(self):
        # id2100 P1: a status row changing A->B->A above an empty composer is
        # an ACTIVE child; only composer-row cursor deltas are tolerated.
        guard = self._guard()
        screen_a = CODEX_IDLE.replace("2m 10s", "2m 11s")
        screen_b = CODEX_IDLE.replace("2m 10s", "2m 12s")
        for screen in (screen_a, screen_b, screen_a, screen_b, screen_a):
            self.assertEqual(guard.classify(screen), "busy")

    def test_nonempty_composer_defers_and_resets_stability(self):
        guard = self._guard()
        guard.classify(CODEX_IDLE)
        self.assertEqual(
            guard.classify(_codex_screen_with_text("draft")),
            "nonempty-composer",
        )
        self.assertEqual(guard.classify(CODEX_IDLE), "busy")
        self.assertEqual(guard.classify(CODEX_IDLE), "admit")

    def test_unknown_provider_never_admits(self):
        guard = self._guard(provider="gemini")
        self.assertEqual(guard.classify(CODEX_IDLE), "unrecognized-composer")
        self.assertEqual(guard.classify(CODEX_IDLE), "unrecognized-composer")

    def test_cursor_blink_inside_composer_row_stays_stable(self):
        guard = self._guard(provider="claude")
        blink = FABLE_IDLE.replace(f"│ ❯{NBSP}", f"│ ❯{NBSP}▌")
        self.assertEqual(guard.classify(FABLE_IDLE), "busy")
        self.assertEqual(guard.classify(blink), "admit")

    def test_alert_dedupe_is_per_classification_set(self):
        # id2100 P2: A,B,A must emit A and B once each — never A twice.
        guard = self._guard()
        self.assertTrue(guard.should_alert("busy"))
        self.assertTrue(guard.should_alert("nonempty-composer"))
        self.assertFalse(guard.should_alert("busy"))
        self.assertFalse(guard.should_alert("nonempty-composer"))
        guard.reset_episode()
        self.assertTrue(guard.should_alert("busy"))

    def test_custom_markers_override_bypasses_separator_requirement(self):
        guard = self._guard(provider="claude", markers=("❯",))
        stray = "\n".join(["transcript", "❯"])
        self.assertEqual(guard.classify(stray), "busy")  # operator override

    def test_resolve_provider(self):
        resolve = wrapper_windows._resolve_composer_provider
        self.assertEqual(resolve("codex"), "codex")
        self.assertEqual(resolve("fable-infra"), "claude")
        self.assertEqual(resolve("mystery", r"C:\bin\claude.EXE"), "claude")
        self.assertEqual(resolve("mystery"), "")


@unittest.skipUnless(sys.platform == "win32", "Windows-only injection gate")
class TypedTextVisibleTests(unittest.TestCase):
    """id2098 B3: exact composer-region equality, no tolerance."""

    TEXT = "use mcp to read #lane-test1 - task"

    def _guard(self, provider="codex"):
        return wrapper_windows._ComposerAdmissionGuard(provider)

    def _visible(self, post, provider="codex", pre=CODEX_IDLE, text=None):
        return wrapper_windows._typed_text_visible(
            post, pre, text or self.TEXT, self._guard(provider)
        )

    def test_exact_text_in_composer_passes(self):
        self.assertTrue(self._visible(_codex_screen_with_text(self.TEXT)))

    def test_mutant_one_extra_manual_char_suppresses_enter(self):
        self.assertFalse(
            self._visible(_codex_screen_with_text(self.TEXT + "Z"))
        )
        self.assertFalse(
            self._visible(_codex_screen_with_text("Z" + self.TEXT))
        )

    def test_mutant_prefix_in_composer_tail_in_old_output_suppresses(self):
        # The full text sits in OLD transcript output; the composer holds
        # only a short prefix. Region-bound matching must refuse Enter.
        post = "\n".join([
            "old transcript: " + self.TEXT,
            "Worked for 2m 10s",
            "",
            "› use mcp to read",
            "  send /help for commands",
        ])
        self.assertFalse(self._visible(post))

    def test_wrapped_boxed_composer_reconstructs_exact_text(self):
        post = "\n".join([
            "✻ transcript output",
            "╭──────────────────────────╮",
            f"│ ❯{NBSP}use mcp to read #lane-",
            "│ test1 - task",
            "╰──────────────────────────╯",
        ])
        self.assertTrue(self._visible(post, provider="claude", pre=FABLE_IDLE))

    def test_wrapped_composer_with_extra_wrapped_char_suppresses(self):
        post = "\n".join([
            "✻ transcript output",
            "╭──────────────────────────╮",
            f"│ ❯{NBSP}use mcp to read #lane-",
            "│ test1 - taskZ",
            "╰──────────────────────────╯",
        ])
        self.assertFalse(
            self._visible(post, provider="claude", pre=FABLE_IDLE)
        )

    def test_vanished_text_or_unrecognized_composer_suppresses(self):
        self.assertFalse(self._visible(CODEX_IDLE.replace("2m 10s", "3m")))
        self.assertFalse(self._visible("totally unrelated screen"))

    def test_unchanged_screen_suppresses(self):
        self.assertFalse(self._visible(CODEX_IDLE, pre=CODEX_IDLE))


@unittest.skipUnless(sys.platform == "win32", "Windows-only injection gate")
class InjectAttemptTests(unittest.TestCase):
    """Single-attempt admission + atomic batch + single Enter."""

    @staticmethod
    def _console_writer(calls, *, partial_enter=False):
        def write_console_input(handle, records, count, written_ptr):
            pointer = ctypes.cast(
                records, ctypes.POINTER(wrapper_windows._INPUT_RECORD)
            )
            batch = []
            for index in range(count):
                event = pointer[index].Event.KeyEvent
                batch.append((
                    event.uChar.UnicodeChar,
                    bool(event.bKeyDown),
                    event.wVirtualKeyCode,
                ))
            calls.append(batch)
            written = ctypes.cast(
                written_ptr, ctypes.POINTER(wrapper_windows.wintypes.DWORD)
            )
            is_enter_batch = (
                count == 2
                and batch[0][2] == wrapper_windows.VK_RETURN
            )
            if partial_enter and is_enter_batch:
                written.contents.value = 1
                return 1
            written.contents.value = count
            return 1

        return write_console_input

    def _attempt(self, text, screens, guard, calls, safeguard_guard=False,
                 partial_enter=False):
        with (
            mock.patch.object(
                wrapper_windows.kernel32, "GetStdHandle", return_value=123
            ),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(
                    calls, partial_enter=partial_enter
                ),
            ),
            mock.patch.object(
                wrapper_windows,
                "_read_visible_console_text",
                side_effect=screens,
            ),
            mock.patch.object(wrapper_windows.time, "sleep"),
        ):
            return wrapper_windows._injection_attempt(
                text,
                safeguard_guard=safeguard_guard,
                composer_guard=guard,
            )

    def test_active_child_defers_without_any_input(self):
        guard = wrapper_windows._ComposerAdmissionGuard("codex")
        calls = []
        first = self._attempt(
            "task", [CODEX_IDLE.replace("2m 10s", "2m 11s")], guard, calls
        )
        second = self._attempt("task", [CODEX_IDLE], guard, calls)
        self.assertEqual(first["status"], "deferred")
        self.assertEqual(second["status"], "deferred")
        self.assertEqual(second["classification"], "busy")
        self.assertEqual(calls, [])

    def test_unreadable_screen_defers_without_any_input(self):
        guard = wrapper_windows._ComposerAdmissionGuard("codex")
        calls = []
        result = self._attempt(
            "task", OSError("synthetic read failure"), guard, calls
        )
        self.assertEqual(result["status"], "deferred")
        self.assertEqual(result["classification"], "unreadable")
        self.assertEqual(result["event"]["error_type"], "OSError")
        self.assertEqual(calls, [])

    def test_nonempty_composer_defers_without_any_input(self):
        guard = wrapper_windows._ComposerAdmissionGuard("codex")
        calls = []
        result = self._attempt(
            "task", [_codex_screen_with_text("manual draft")], guard, calls
        )
        self.assertEqual(result["status"], "deferred")
        self.assertEqual(result["classification"], "nonempty-composer")
        self.assertEqual(calls, [])

    def test_safeguard_menu_defers_under_composer_gate(self):
        guard = wrapper_windows._ComposerAdmissionGuard("claude")
        calls = []
        result = self._attempt(
            "task", [SAFEGUARD_MENU], guard, calls, safeguard_guard=True
        )
        self.assertEqual(result["status"], "deferred")
        self.assertEqual(result["classification"], "strict")
        self.assertEqual(calls, [])

    def test_stable_empty_composer_single_batch_single_enter(self):
        text = "use mcp to read #lane-test1 - task"
        guard = wrapper_windows._ComposerAdmissionGuard("codex")
        calls = []
        first = self._attempt(text, [CODEX_IDLE], guard, calls)
        self.assertEqual(first["status"], "deferred")
        typed = _codex_screen_with_text(text)
        second = self._attempt(text, [CODEX_IDLE, typed], guard, calls)
        self.assertEqual(second["status"], "injected")

        # Exactly one atomic text batch, then exactly one atomic Enter batch.
        text_batches = [batch for batch in calls if len(batch) > 2]
        self.assertEqual(len(text_batches), 1)
        typed_chars = "".join(
            char for char, key_down, _vk in text_batches[0] if key_down
        )
        self.assertEqual(typed_chars, text)
        enter_batches = [
            batch for batch in calls
            if batch and batch[0][2] == wrapper_windows.VK_RETURN
        ]
        self.assertEqual(len(enter_batches), 1)
        self.assertEqual(
            [(down) for _c, down, _vk in enter_batches[0]], [True, False]
        )

    def test_redraw_between_text_and_enter_suppresses_enter(self):
        text = "use mcp to read #lane-test1 - task"
        guard = wrapper_windows._ComposerAdmissionGuard("codex")
        calls = []
        self._attempt(text, [CODEX_IDLE], guard, calls)
        result = self._attempt(
            text, [CODEX_IDLE, CODEX_IDLE, CODEX_IDLE], guard, calls
        )
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(
            result["event"]["action"], "injection-enter-cancelled"
        )
        enters = [
            event for batch in calls for event in batch
            if event[2] == wrapper_windows.VK_RETURN
        ]
        self.assertEqual(enters, [])

    def test_partial_enter_is_terminal_uncertain_never_retried(self):
        # Key-down delivered, key-up unconfirmed -> block+alert, never ACK.
        text = "use mcp to read #lane-test1 - task"
        guard = wrapper_windows._ComposerAdmissionGuard("codex")
        calls = []
        self._attempt(text, [CODEX_IDLE], guard, calls)
        typed = _codex_screen_with_text(text)
        result = self._attempt(
            text, [CODEX_IDLE, typed], guard, calls, partial_enter=True
        )
        self.assertEqual(result["status"], "injected-uncertain")
        self.assertEqual(
            result["event"]["action"], "injection-enter-uncertain"
        )
        self.assertNotIn("injected-uncertain", wrapper._CONSUME_RESULTS)
        self.assertEqual(
            wrapper._nonterminal_delivery_state("injected-uncertain"),
            "injected-uncertain",
        )

    def test_admitted_injector_dedupes_alert_set_per_episode(self):
        guard = wrapper_windows._ComposerAdmissionGuard("codex")
        events = []
        injector = wrapper_windows._make_admitted_injector(
            composer_guard=guard, emit=events.append
        )
        nonempty = _codex_screen_with_text("manual draft")
        busy_a = CODEX_IDLE.replace("2m 10s", "2m 11s")
        screens = [nonempty, busy_a, nonempty, nonempty]
        with (
            mock.patch.object(
                wrapper_windows, "_read_visible_console_text",
                side_effect=screens,
            ),
            mock.patch.object(wrapper_windows.time, "sleep"),
        ):
            for _ in screens:
                self.assertEqual(injector("task"), "deferred")
        deferred = [e for e in events if e["action"] == "injection-deferred"]
        classifications = [e["classification"] for e in deferred]
        # A,B,A,A pattern -> each classification alerted exactly once.
        self.assertEqual(
            sorted(classifications), ["busy", "nonempty-composer"]
        )


class QueueCursorTests(unittest.TestCase):
    """id2099 H2: content-bound cursor; strict decode; quarantine."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.queue = Path(self._tmp.name) / "agent_queue.jsonl"

    def test_pending_read_never_truncates_queue(self):
        payload = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(payload)
        status, pending, end, raw = wrapper._read_pending_triggers(self.queue)
        self.assertEqual(status, "ok")
        self.assertIn("lane-test1", pending)
        self.assertEqual(end, len(payload))
        self.assertEqual(self.queue.read_bytes(), payload)

    def test_torn_trailing_line_stays_pending(self):
        self.queue.write_bytes(b'{"channel": "lane-test1"}')
        status, pending, end, _raw = wrapper._read_pending_triggers(self.queue)
        self.assertEqual((status, pending, end), ("ok", "", 0))
        self.queue.write_bytes(b'{"channel": "lane-test1"}\n')
        status, pending, _end, _raw = wrapper._read_pending_triggers(self.queue)
        self.assertIn("lane-test1", pending)

    def test_cursor_consumes_only_committed_prefix(self):
        first = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(first)
        _s, _p, end, raw = wrapper._read_pending_triggers(self.queue)
        wrapper._write_queue_cursor(self.queue, end, raw)
        second = b'{"channel": "orchestration"}\n'
        with open(self.queue, "ab") as fh:
            fh.write(second)
        _s, pending, end, _raw = wrapper._read_pending_triggers(self.queue)
        self.assertIn("orchestration", pending)
        self.assertNotIn("lane-test1", pending)
        self.assertEqual(end, len(first) + len(second))

    def test_replaced_queue_with_plausible_offset_replays_from_start(self):
        # Old cursor offset fits inside the NEW file but the consumed prefix
        # hash no longer matches -> full replay, never a silent skip.
        first = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(first)
        _s, _p, end, raw = wrapper._read_pending_triggers(self.queue)
        wrapper._write_queue_cursor(self.queue, end, raw)
        replacement = b'{"channel": "orchestration", "n": 12345}\n'
        self.assertGreater(len(replacement), end)
        self.queue.write_bytes(replacement)
        _s, pending, _e, _r = wrapper._read_pending_triggers(self.queue)
        self.assertIn("orchestration", pending)

    def test_mid_line_offset_replays_from_start(self):
        payload = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(payload)
        # Forge a sidecar pointing mid-line with a correct prefix hash.
        forged = json.dumps({
            "offset": 5,
            "prefix_sha256": wrapper._sha256_hex(payload[:5]),
        })
        wrapper._queue_cursor_path(self.queue).write_text(forged, "utf-8")
        _s, pending, _e, _r = wrapper._read_pending_triggers(self.queue)
        self.assertIn("lane-test1", pending)

    def test_corrupt_sidecar_replays_from_start(self):
        payload = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(payload)
        wrapper._queue_cursor_path(self.queue).write_text("garbage", "utf-8")
        _s, pending, _e, _r = wrapper._read_pending_triggers(self.queue)
        self.assertIn("lane-test1", pending)

    def test_undecodable_bytes_report_corrupt_not_skipped(self):
        self.queue.write_bytes(b'\xff\xfe broken \xff\n')
        status, pending, end, _raw = wrapper._read_pending_triggers(self.queue)
        self.assertEqual(status, "corrupt")
        self.assertEqual(pending, "")
        self.assertGreater(end, 0)

    def test_quarantine_persists_window_before_cursor_advance(self):
        bad = b'{"channel": "lane-test1"}\nnot-json-at-all\n'
        self.queue.write_bytes(bad)
        _s, _p, end, raw = wrapper._read_pending_triggers(self.queue)
        self.assertTrue(
            wrapper._quarantine_pending_window(self.queue, raw, 0, end)
        )
        quarantined = list(
            self.queue.parent.glob(self.queue.name + ".quarantine-*")
        )
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].read_bytes(), bad)
        # Queue bytes untouched; cursor advanced past the window.
        self.assertEqual(self.queue.read_bytes(), bad)
        _s, pending, _e, _r = wrapper._read_pending_triggers(self.queue)
        self.assertEqual(pending, "")

    def test_parse_counts_malformed_lines(self):
        triggers, malformed = wrapper._parse_trigger_lines(
            '{"channel": "a"}\nnot json\n{"job_id": 3}\n'
        )
        self.assertEqual(len(triggers), 2)
        self.assertEqual(malformed, 1)


class StartupCompactionTests(unittest.TestCase):
    """Startup uses append-only admission — no replace/append race."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.queue = Path(self._tmp.name) / "agent_queue.jsonl"

    def _consume_first_line(self, raw: bytes) -> int:
        end = raw.index(b"\n") + 1
        wrapper._write_queue_cursor(self.queue, end, raw)
        return end

    def test_unconsumed_suffix_survives_and_replays(self):
        consumed = b'{"channel": "lane-test1"}\n'
        pending = b'{"channel": "orchestration"}\n'
        self.queue.write_bytes(consumed + pending)
        self._consume_first_line(consumed + pending)

        wrapper._preserve_stale_queue(self.queue)

        # Active queue is never replaced; the cursor exposes only pending.
        self.assertEqual(self.queue.read_bytes(), consumed + pending)
        _s, replayed, _e, _r = wrapper._read_pending_triggers(self.queue)
        self.assertIn("orchestration", replayed)

    def test_nothing_consumed_keeps_queue_intact_no_archive(self):
        pending = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(pending)
        wrapper._preserve_stale_queue(self.queue)
        self.assertEqual(self.queue.read_bytes(), pending)
        self.assertEqual(
            list(self.queue.parent.glob(self.queue.name + ".recovered-*")),
            [],
        )

    def test_fully_consumed_queue_remains_append_only(self):
        consumed = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(consumed)
        self._consume_first_line(consumed)
        wrapper._preserve_stale_queue(self.queue)
        self.assertEqual(self.queue.read_bytes(), consumed)
        _s, replayed, _e, _r = wrapper._read_pending_triggers(self.queue)
        self.assertEqual(replayed, "")

    def test_identical_pending_prefix_cannot_be_skipped_by_startup(self):
        record = b'{"channel": "lane-test1"}\n'
        payload = record + record
        self.queue.write_bytes(payload)
        self._consume_first_line(payload)
        with mock.patch.object(wrapper.os, "replace") as replace:
            wrapper._preserve_stale_queue(self.queue)
        replace.assert_not_called()
        self.assertEqual(self.queue.read_bytes(), payload)
        _s, still_pending, _e, _raw = wrapper._read_pending_triggers(self.queue)
        self.assertEqual(still_pending.encode("utf-8"), record)

    def test_concurrent_producer_append_waits_and_is_not_lost(self):
        consumed = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(consumed)
        self._consume_first_line(consumed)
        entered = threading.Event()
        release = threading.Event()
        producer_started = threading.Event()
        producer_done = threading.Event()
        real_read_cursor = wrapper._read_queue_cursor

        def paused_read_cursor(queue, raw):
            entered.set()
            self.assertTrue(release.wait(5))
            return real_read_cursor(queue, raw)

        producer = agents.AgentTrigger(mock.Mock(), self.queue.parent)

        def append_concurrently():
            producer_started.set()
            producer.trigger_sync(
                "agent", "owner: concurrent", "lane-new",
                action_id="ACT-CONCURRENT",
            )
            producer_done.set()

        with mock.patch.object(wrapper, "_read_queue_cursor", side_effect=paused_read_cursor):
            maintenance = threading.Thread(
                target=wrapper._preserve_stale_queue, args=(self.queue,)
            )
            maintenance.start()
            self.assertTrue(entered.wait(5))
            append = threading.Thread(
                target=append_concurrently
            )
            append.start()
            self.assertTrue(producer_started.wait(5))
            # Producer is deterministically contending with startup admission.
            self.assertFalse(producer_done.wait(0.05))
            release.set()
            maintenance.join(5)
            append.join(5)
        self.assertFalse(maintenance.is_alive())
        self.assertFalse(append.is_alive())
        records = self.queue.parent / "agent_queue.jsonl"
        self.assertIn(b"ACT-CONCURRENT", records.read_bytes())


class CoalesceRepresentationTests(unittest.TestCase):
    """id2099 H3: every consumed record must be represented in the prompt."""

    def test_single_channel_keeps_legacy_phrasing(self):
        prompt = wrapper._coalesce_trigger_prompt([{"channel": "lane-test1"}])
        self.assertEqual(
            prompt,
            "use mcp to read #lane-test1 - you're mentioned, "
            "take appropriate action and respond",
        )

    def test_single_job_keeps_legacy_phrasing(self):
        prompt = wrapper._coalesce_trigger_prompt([{"job_id": 7}])
        self.assertEqual(
            prompt,
            "use mcp to read job_id=7 - you're mentioned in a job thread, "
            "take appropriate action and respond",
        )

    def test_multiple_channels_all_represented(self):
        prompt = wrapper._coalesce_trigger_prompt(
            [{"channel": "lane-test1"}, {"channel": "orchestration"}]
        )
        self.assertIn("#lane-test1", prompt)
        self.assertIn("#orchestration", prompt)

    def test_channels_jobs_and_customs_all_represented(self):
        prompt = wrapper._coalesce_trigger_prompt([
            {"channel": "lane-test1"},
            {"job_id": 5},
            {"prompt": "custom instruction body"},
            {"channel": "orchestration"},
        ])
        self.assertIn("custom instruction body", prompt)
        self.assertIn("#lane-test1", prompt)
        self.assertIn("#orchestration", prompt)
        self.assertIn("job_id=5", prompt)

    def test_duplicate_channels_deduplicated(self):
        prompt = wrapper._coalesce_trigger_prompt(
            [{"channel": "a"}, {"channel": "a"}]
        )
        self.assertEqual(prompt.count("#a"), 1)


class WatcherDurabilityTests(unittest.TestCase):
    """_queue_watcher: consume-on-success only, coalesce during deferral,
    fetch-failure deferral (H4), identity generation (H5), quarantine (M)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.queue = Path(self._tmp.name) / "agent_queue.jsonl"
        self.stop = threading.Event()

    @staticmethod
    def _rules_ok(*_a, **_k):
        return True, {"epoch": 1, "rules": [], "refresh_interval": 10}

    @staticmethod
    def _role_ok(*_a, **_k):
        return True, ""

    def _run_watcher(self, inject_fn, until: threading.Event, *,
                     identity_fn=None, role_fn=None, rules_fn=None):
        thread = threading.Thread(
            target=wrapper._queue_watcher,
            args=(identity_fn or (lambda: ("agent", self.queue)), inject_fn),
            kwargs={
                "poll_seconds": 0.01,
                "stop_event": self.stop,
                "fetch_role_fn": role_fn or self._role_ok,
                "fetch_rules_fn": rules_fn or self._rules_ok,
                "report_sync_fn": lambda *_a, **_k: None,
            },
            daemon=True,
        )
        with mock.patch.object(wrapper.time, "sleep"):
            thread.start()
            self.assertTrue(until.wait(timeout=5))
            self.stop.set()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

    def _cursor_offset(self) -> int:
        raw = self.queue.read_bytes()
        return wrapper._read_queue_cursor(self.queue, raw)

    def test_deferral_keeps_queue_and_coalesces_new_triggers(self):
        self.queue.write_bytes(b'{"channel": "lane-test1"}\n')
        prompts = []
        done = threading.Event()
        state = {"attempt": 0}

        def inject_fn(prompt):
            prompts.append(prompt)
            state["attempt"] += 1
            if state["attempt"] == 1:
                with open(self.queue, "ab") as fh:
                    fh.write(b'{"channel": "orchestration"}\n')
                return "deferred"
            done.set()
            return "injected"

        self._run_watcher(inject_fn, done)

        self.assertIn("#lane-test1", prompts[0])
        # The deferred batch was rebuilt representing BOTH destinations.
        self.assertIn("#orchestration", prompts[-1])
        self.assertIn("#lane-test1", prompts[-1])
        content = self.queue.read_bytes()
        self.assertIn(b"lane-test1", content)
        self.assertIn(b"orchestration", content)
        self.assertEqual(self._cursor_offset(), len(content))

    def test_crash_during_deferral_leaves_recoverable_queue(self):
        payload = b'{"channel": "lane-test1"}\n'
        self.queue.write_bytes(payload)
        attempted = threading.Event()

        def deferred_inject(_prompt):
            attempted.set()
            return "deferred"

        self._run_watcher(deferred_inject, attempted)
        self.assertEqual(self.queue.read_bytes(), payload)
        self.assertEqual(self._cursor_offset(), 0)

        prompts = []
        done = threading.Event()
        self.stop = threading.Event()

        def recovered_inject(prompt):
            prompts.append(prompt)
            done.set()
            return "injected"

        self._run_watcher(recovered_inject, done)
        self.assertTrue(any("#lane-test1" in p for p in prompts))
        self.assertEqual(self._cursor_offset(), len(payload))

    def test_terminal_results_consume_batch(self):
        for result in (True, "injected", "dead-letter"):
            with self.subTest(result=result):
                self.queue.write_bytes(b'{"channel": "lane-test1"}\n')
                try:
                    wrapper._queue_cursor_path(self.queue).unlink()
                except OSError:
                    pass
                try:
                    wrapper._delivery_journal_path(self.queue).unlink()
                except OSError:
                    pass
                done = threading.Event()
                self.stop = threading.Event()

                def inject_fn(_prompt, _result=result):
                    done.set()
                    return _result

                self._run_watcher(inject_fn, done)
                self.assertEqual(
                    self._cursor_offset(), len(self.queue.read_bytes())
                )

    def test_nonterminal_results_do_not_consume(self):
        for result in (
            False, None, "error", "cancelled", "deferred",
            "injected-uncertain",
        ):
            with self.subTest(result=result):
                self.queue.write_bytes(b'{"channel": "lane-test1"}\n')
                try:
                    wrapper._queue_cursor_path(self.queue).unlink()
                except OSError:
                    pass
                try:
                    wrapper._delivery_journal_path(self.queue).unlink()
                except OSError:
                    pass
                done = threading.Event()
                self.stop = threading.Event()

                def inject_fn(_prompt, _result=result):
                    done.set()
                    return _result

                self._run_watcher(inject_fn, done)
                self.assertEqual(self._cursor_offset(), 0)

    def test_rules_fetch_failure_defers_without_consuming(self):
        # id2099 H4: transport failure => no context-less injection.
        self.queue.write_bytes(b'{"channel": "lane-test1"}\n')
        inject_calls = []
        polled = threading.Event()
        state = {"fail": True, "polls": 0}

        def rules_fn(*_a, **_k):
            state["polls"] += 1
            if state["polls"] >= 3:
                polled.set()
            if state["fail"]:
                return False, None
            return True, {"epoch": 1, "rules": [], "refresh_interval": 10}

        def inject_fn(prompt):
            inject_calls.append(prompt)
            return "injected"

        self._run_watcher(inject_fn, polled, rules_fn=rules_fn)
        self.assertEqual(inject_calls, [])
        self.assertEqual(self._cursor_offset(), 0)

        # Service recovery -> the same durable trigger is delivered.
        state["fail"] = False
        done = threading.Event()
        self.stop = threading.Event()

        def inject_ok(prompt):
            inject_calls.append(prompt)
            done.set()
            return "injected"

        self._run_watcher(inject_ok, done, rules_fn=rules_fn)
        self.assertTrue(any("#lane-test1" in p for p in inject_calls))

    def test_identity_change_mid_iteration_abandons_attempt(self):
        # id2099 H5: rename between snapshot and input aborts the attempt.
        self.queue.write_bytes(b'{"channel": "lane-test1"}\n')
        inject_calls = []
        flipped = threading.Event()
        calls = {"n": 0}

        def identity_fn():
            calls["n"] += 1
            if calls["n"] >= 3:
                flipped.set()
                return ("renamed-agent", self.queue.with_name("other.jsonl"))
            return ("agent", self.queue)

        def inject_fn(prompt):
            inject_calls.append(prompt)
            return "injected"

        self._run_watcher(inject_fn, flipped, identity_fn=identity_fn)
        self.assertEqual(inject_calls, [])
        self.assertEqual(self._cursor_offset(), 0)

    def test_malformed_record_quarantines_instead_of_consuming_past(self):
        bad = b'{"channel": "lane-test1"}\nnot-json\n'
        self.queue.write_bytes(bad)
        inject_calls = []
        quarantined = threading.Event()

        def inject_fn(prompt):
            inject_calls.append(prompt)
            return "injected"

        def wait_for_quarantine():
            while not list(
                self.queue.parent.glob(self.queue.name + ".quarantine-*")
            ):
                if self.stop.wait(0.01):
                    return
            quarantined.set()

        threading.Thread(target=wait_for_quarantine, daemon=True).start()
        self._run_watcher(inject_fn, quarantined)

        self.assertEqual(inject_calls, [])  # bad window never injected
        qfiles = list(
            self.queue.parent.glob(self.queue.name + ".quarantine-*")
        )
        self.assertEqual(len(qfiles), 1)
        self.assertEqual(qfiles[0].read_bytes(), bad)
        self.assertEqual(self.queue.read_bytes(), bad)  # never truncated
        self.assertEqual(self._cursor_offset(), len(bad))

    def test_prompt_is_flattened_and_carries_role_and_rules(self):
        self.queue.write_bytes(b'{"channel": "lane-test1"}\n')
        prompts = []
        done = threading.Event()

        def inject_fn(prompt):
            prompts.append(prompt)
            done.set()
            return "injected"

        self._run_watcher(
            inject_fn, done,
            role_fn=lambda *_a, **_k: (True, "release lane"),
            rules_fn=lambda *_a, **_k: (True, {
                "epoch": 3,
                "rules": ["rule one", "rule two"],
                "refresh_interval": 10,
            }),
        )

        self.assertEqual(len(prompts), 1)
        self.assertNotIn("\n", prompts[0])
        self.assertIn("ROLE: release lane", prompts[0])
        self.assertIn("rule one; rule two", prompts[0])


@unittest.skipUnless(sys.platform == "win32", "Windows-only injection gate")
class RunAgentWiringTests(unittest.TestCase):
    def test_admission_guard_wires_single_attempt_injector(self):
        captured = {}

        class FinishedProcess:
            pid = 999
            returncode = 0

            @staticmethod
            def wait():
                return None

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                mock.patch.object(wrapper_windows, "enable_vt_mode"),
                mock.patch.object(wrapper_windows, "_vt_keepalive_thread"),
                mock.patch.object(wrapper_windows, "_start_safeguard_monitor"),
                mock.patch.object(
                    wrapper_windows.subprocess,
                    "Popen",
                    return_value=FinishedProcess(),
                ),
            ):
                wrapper_windows.run_agent(
                    command=r"C:\bin\codex.exe",
                    extra_args=[],
                    cwd=temp_dir,
                    env={},
                    queue_file=Path(temp_dir) / "queue.jsonl",
                    agent="codex",
                    no_restart=True,
                    start_watcher=lambda fn: captured.setdefault("inject", fn),
                    pid_holder=[None],
                    injection_admission_guard=True,
                )

            text = "use mcp to read #lane-test1 - task"
            screens = iter([
                CODEX_IDLE,                     # attempt 1: stability read 1
                CODEX_IDLE,                     # attempt 2: stable -> admit
                _codex_screen_with_text(text),  # post-type preflight
            ])
            calls = []
            with (
                mock.patch.object(
                    wrapper_windows.kernel32, "GetStdHandle", return_value=123
                ),
                mock.patch.object(
                    wrapper_windows.kernel32,
                    "WriteConsoleInputW",
                    side_effect=InjectAttemptTests._console_writer(calls),
                ),
                mock.patch.object(
                    wrapper_windows,
                    "_read_visible_console_text",
                    side_effect=lambda *a, **k: next(screens),
                ),
                mock.patch.object(wrapper_windows.time, "sleep"),
            ):
                self.assertEqual(captured["inject"](text), "deferred")
                self.assertEqual(captured["inject"](text), "injected")
            self.assertTrue(calls)


if __name__ == "__main__":
    unittest.main()
