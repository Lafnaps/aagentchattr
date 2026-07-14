import ctypes
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import wrapper_windows


MENU = """
Session paused

Fable 5's safeguards flagged this message. The safeguards are intentionally
broad right now and may flag safe and routine coding, cybersecurity, or biology
work. These measures let us bring you Mythos-level capabilities sooner, and
we're working to refine them. Send feedback with /feedback or learn more

❯ 1. Switch to Opus 4.8
  2. Edit prompt and retry with Fable 5
"""

MENU_SECOND = MENU.replace(
    "❯ 1. Switch to Opus 4.8",
    "  1. Switch to Opus 4.8",
).replace(
    "  2. Edit prompt and retry with Fable 5",
    "❯ 2. Edit prompt and retry with Fable 5",
)


class SafeguardScreenTests(unittest.TestCase):
    def test_exact_wrapped_menu_is_strict(self):
        self.assertEqual(
            wrapper_windows._classify_fable_safeguard_screen(MENU), "strict"
        )

    def test_changed_retry_target_is_never_strict(self):
        changed = MENU.replace("retry with Fable 5", "retry with Opus 4.8")
        self.assertEqual(
            wrapper_windows._classify_fable_safeguard_screen(changed),
            "ambiguous",
        )

    def test_missing_paragraph_is_ambiguous(self):
        short = """Session paused
Fable 5's safeguards flagged this message.
❯ 1. Switch to Opus 4.8
  2. Edit prompt and retry with Fable 5
"""
        self.assertEqual(
            wrapper_windows._classify_fable_safeguard_screen(short),
            "ambiguous",
        )

    def test_ordinary_output_is_not_a_menu(self):
        self.assertIsNone(
            wrapper_windows._classify_fable_safeguard_screen("choose 1 or 2")
        )

    def test_second_pointer_is_verified_separately(self):
        self.assertTrue(
            wrapper_windows._is_second_safeguard_option_selected(MENU_SECOND)
        )
        self.assertFalse(
            wrapper_windows._is_second_safeguard_option_selected(MENU)
        )

    def test_full_template_above_blank_lower_viewport_is_not_strict(self):
        quoted_above = MENU + ("\n" * 12)
        self.assertEqual(
            wrapper_windows._classify_fable_safeguard_screen(quoted_above),
            "ambiguous",
        )

    def test_truncated_pointer_menu_is_blocked_for_queue_input(self):
        truncated = """❯ 1. Switch to Opus 4.8
  2. Edit prompt and retry with Fable 5
"""
        self.assertIsNone(
            wrapper_windows._classify_fable_safeguard_screen(truncated)
        )
        self.assertTrue(
            wrapper_windows._screen_may_accept_safeguard_choice(truncated)
        )

    def test_single_low_pointer_row_is_blocked(self):
        pointer_only = "❯ 1. Switch to Opus 4.8"
        self.assertIsNone(
            wrapper_windows._classify_fable_safeguard_screen(pointer_only)
        )
        self.assertTrue(
            wrapper_windows._screen_may_accept_safeguard_choice(pointer_only)
        )

    def test_pause_paragraph_without_options_is_ambiguous(self):
        paragraph_only = "Session paused\n" + wrapper_windows._FABLE_SAFEGUARD_PARAGRAPH
        self.assertEqual(
            wrapper_windows._classify_fable_safeguard_screen(paragraph_only),
            "ambiguous",
        )


class SafeguardRetryControllerTests(unittest.TestCase):
    def setUp(self):
        self.controller = wrapper_windows._SafeguardRetryController(
            max_retries=2, stable_polls=2
        )

    def _stable(self, text=MENU, pid=101):
        self.assertIsNone(self.controller.observe(text, pid))
        return self.controller.observe(text, pid)

    def _clear_episode(self, pid=101):
        self.assertIsNone(self.controller.observe("normal output", pid))
        self.assertIsNone(self.controller.observe("normal output", pid))

    def test_two_retries_then_escalation(self):
        first = self._stable()
        self.assertEqual(first["action"], "retry")
        self.assertEqual(first["attempt"], 1)
        self.assertIsNone(self.controller.observe(MENU, 101))

        self._clear_episode()
        second = self._stable()
        self.assertEqual(second["action"], "retry")
        self.assertEqual(second["attempt"], 2)

        self._clear_episode()
        third = self._stable()
        self.assertEqual(third["action"], "escalate")
        self.assertEqual(third["attempt"], 2)
        self.assertIsNone(self.controller.observe(MENU, 101))

    def test_five_retries_then_sixth_escalates_when_configured(self):
        controller = wrapper_windows._SafeguardRetryController(
            max_retries=5, stable_polls=2
        )

        for attempt in range(1, 6):
            self.assertIsNone(controller.observe(MENU, 202))
            decision = controller.observe(MENU, 202)
            self.assertEqual(decision["action"], "retry")
            self.assertEqual(decision["attempt"], attempt)
            self.assertIsNone(controller.observe("normal output", 202))
            self.assertIsNone(controller.observe("normal output", 202))

        self.assertIsNone(controller.observe(MENU, 202))
        decision = controller.observe(MENU, 202)
        self.assertEqual(decision["action"], "escalate")
        self.assertEqual(decision["attempt"], 5)

    def test_new_child_pid_resets_budget(self):
        self.assertEqual(self._stable(pid=101)["attempt"], 1)
        self.assertEqual(self._stable(pid=202)["attempt"], 1)

    def test_ambiguous_menu_only_alerts_once(self):
        changed = MENU.replace("retry with Fable 5", "retry with Opus 4.8")
        first = self.controller.observe(changed, 101)
        self.assertEqual(first["action"], "ambiguous")
        self.assertIsNone(self.controller.observe(changed, 101))

        # One unread/clean flicker cannot re-arm alert spam.
        self.controller.observe("normal output", 101)
        self.assertIsNone(self.controller.observe(changed, 101))

        # A genuinely clean interval begins a new visible episode.
        self._clear_episode()
        again = self.controller.observe(changed, 101)
        self.assertEqual(again["action"], "ambiguous")

    def test_escalation_rearms_after_two_clean_polls(self):
        self.assertEqual(self._stable()["action"], "retry")
        self._clear_episode()
        self.assertEqual(self._stable()["action"], "retry")
        self._clear_episode()
        self.assertEqual(self._stable()["action"], "escalate")
        self._clear_episode()
        self.assertEqual(self._stable()["action"], "escalate")

    def test_cancelled_redraw_does_not_consume_budget(self):
        self.assertEqual(self._stable()["attempt"], 1)
        self.controller.cancel_retry()
        self.controller.observe("normal output", 101)
        self.assertEqual(self._stable()["attempt"], 1)


class SafeguardInputTests(unittest.TestCase):
    @staticmethod
    def _console_writer(calls, *, fail_call=None, partial_call=None,
                        read_counter=None):
        call_number = 0

        def write_console_input(handle, records, count, written_ptr):
            nonlocal call_number
            call_number += 1
            if read_counter is not None:
                calls.append(("screen_reads", read_counter[0]))
            pointer = ctypes.cast(
                records, ctypes.POINTER(wrapper_windows._INPUT_RECORD)
            )
            for index in range(count):
                event = pointer[index].Event.KeyEvent
                calls.append((
                    event.uChar.UnicodeChar,
                    bool(event.bKeyDown),
                    event.wVirtualKeyCode,
                ))
            written = ctypes.cast(
                written_ptr, ctypes.POINTER(wrapper_windows.wintypes.DWORD)
            )
            if fail_call == call_number:
                written.contents.value = 0
                return 0
            if partial_call == call_number:
                written.contents.value = max(0, count - 1)
                return 1
            written.contents.value = count
            return 1

        return write_console_input

    def test_second_option_marshals_nul_down_then_verified_enter(self):
        calls = []
        with (
            mock.patch.object(
                wrapper_windows.kernel32,
                "GetStdHandle",
                return_value=123,
            ),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls),
            ),
            mock.patch.object(
                wrapper_windows,
                "_read_visible_console_text",
                side_effect=[MENU, MENU_SECOND, MENU_SECOND],
            ),
            mock.patch.object(wrapper_windows.time, "sleep"),
        ):
            selected = wrapper_windows._select_second_menu_option()

        self.assertTrue(selected)
        self.assertEqual(
            calls,
            [
                ("\x00", True, wrapper_windows.VK_DOWN),
                ("\x00", False, wrapper_windows.VK_DOWN),
                ("\r", True, wrapper_windows.VK_RETURN),
                ("\r", False, wrapper_windows.VK_RETURN),
            ],
        )
        self.assertNotIn("2", [char for char, _, _ in calls])

    def test_failed_down_never_sends_enter(self):
        calls = []
        with (
            mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls, fail_call=1),
            ),
            mock.patch.object(
                wrapper_windows, "_read_visible_console_text", return_value=MENU
            ),
        ):
            with self.assertRaises(OSError):
                wrapper_windows._select_second_menu_option()

        self.assertFalse(any(call[2] == wrapper_windows.VK_RETURN for call in calls))

    def test_partial_success_down_never_sends_enter(self):
        calls = []
        with (
            mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls, partial_call=1),
            ),
            mock.patch.object(
                wrapper_windows, "_read_visible_console_text", return_value=MENU
            ),
        ):
            with self.assertRaises(OSError):
                wrapper_windows._select_second_menu_option()

        self.assertFalse(any(call[2] == wrapper_windows.VK_RETURN for call in calls))

    def test_fingerprint_mismatch_suppresses_every_key(self):
        calls = []
        with (
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls),
            ),
            mock.patch.object(
                wrapper_windows, "_read_visible_console_text", return_value=MENU
            ),
        ):
            selected = wrapper_windows._select_second_menu_option(
                expected_fingerprint="0000000000000000"
            )

        self.assertFalse(selected)
        self.assertEqual(calls, [])

    def test_pointer_reset_before_enter_suppresses_enter(self):
        calls = []
        with (
            mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls),
            ),
            mock.patch.object(
                wrapper_windows,
                "_read_visible_console_text",
                side_effect=[MENU, MENU_SECOND, MENU],
            ),
            mock.patch.object(wrapper_windows.time, "sleep"),
        ):
            selected = wrapper_windows._select_second_menu_option()

        self.assertFalse(selected)
        self.assertEqual(
            calls,
            [
                ("\x00", True, wrapper_windows.VK_DOWN),
                ("\x00", False, wrapper_windows.VK_DOWN),
            ],
        )

    def test_visible_menu_defers_all_queue_input_until_clean(self):
        calls = []
        events = []
        reads = [0]
        sleeps = [0]

        def read_screen():
            reads[0] += 1
            return MENU if reads[0] == 1 else "ordinary clean screen"

        def record_event(event):
            self.assertFalse(wrapper_windows._inject_lock._is_owned())
            events.append(event)

        def checked_sleep(_seconds):
            sleeps[0] += 1
            if sleeps[0] == 1:
                self.assertFalse(wrapper_windows._inject_lock._is_owned())

        with (
            mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls, read_counter=reads),
            ),
            mock.patch.object(
                wrapper_windows, "_read_visible_console_text", side_effect=read_screen
            ),
            mock.patch.object(
                wrapper_windows.time, "sleep", side_effect=checked_sleep
            ),
        ):
            delivered = wrapper_windows.inject(
                "queued task",
                safeguard_guard=True,
                guard_event_callback=record_event,
            )

        self.assertTrue(delivered)
        self.assertEqual(events[0]["action"], "injection-deferred")
        first_write = next(call for call in calls if call[0] == "screen_reads")
        self.assertGreaterEqual(first_write[1], 2)

    def test_ambiguous_and_truncated_menus_also_defer_queue_input(self):
        variants = (
            MENU.replace("retry with Fable 5", "retry with a future model"),
            MENU.replace("❯ 1.", "▶ 1."),
            """❯ 1. Switch to Opus 4.8
  2. Edit prompt and retry with Fable 5
""",
            "❯ 1. Switch to Opus 4.8",
        )
        for blocked_screen in variants:
            with self.subTest(screen=blocked_screen.splitlines()[0]):
                calls = []
                events = []
                reads = [0]

                def read_screen():
                    reads[0] += 1
                    return blocked_screen if reads[0] == 1 else "clean"

                with (
                    mock.patch.object(
                        wrapper_windows.kernel32, "GetStdHandle", return_value=123
                    ),
                    mock.patch.object(
                        wrapper_windows.kernel32,
                        "WriteConsoleInputW",
                        side_effect=self._console_writer(
                            calls, read_counter=reads
                        ),
                    ),
                    mock.patch.object(
                        wrapper_windows,
                        "_read_visible_console_text",
                        side_effect=read_screen,
                    ),
                    mock.patch.object(wrapper_windows.time, "sleep"),
                ):
                    self.assertTrue(wrapper_windows.inject(
                        "queued task",
                        safeguard_guard=True,
                        guard_event_callback=events.append,
                    ))

                first_write = next(
                    call for call in calls if call[0] == "screen_reads"
                )
                self.assertGreaterEqual(first_write[1], 2)
                self.assertEqual(events[0]["action"], "injection-deferred")

    def test_unreadable_screen_defers_instead_of_assuming_clean(self):
        calls = []
        events = []
        reads = [0]

        def read_screen():
            reads[0] += 1
            if reads[0] == 1:
                raise OSError("synthetic read failure")
            return "ordinary clean screen"

        with (
            mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls, read_counter=reads),
            ),
            mock.patch.object(
                wrapper_windows, "_read_visible_console_text", side_effect=read_screen
            ),
            mock.patch.object(wrapper_windows.time, "sleep"),
        ):
            delivered = wrapper_windows.inject(
                "queued task",
                safeguard_guard=True,
                guard_event_callback=events.append,
            )

        self.assertTrue(delivered)
        self.assertEqual(events[0]["classification"], "unreadable")
        first_write = next(call for call in calls if call[0] == "screen_reads")
        self.assertGreaterEqual(first_write[1], 2)

    def test_late_menu_suppresses_enter_after_text_batch(self):
        calls = []
        events = []
        changed_pointer = MENU.replace("❯ 1.", "▶ 1.")
        with (
            mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls),
            ),
            mock.patch.object(
                wrapper_windows,
                "_read_visible_console_text",
                side_effect=["clean", changed_pointer, changed_pointer],
            ),
            mock.patch.object(wrapper_windows.time, "sleep"),
        ):
            delivered = wrapper_windows.inject(
                "queued task",
                safeguard_guard=True,
                guard_event_callback=events.append,
            )

        self.assertFalse(delivered)
        self.assertTrue(any(call[2] == 0 for call in calls))
        self.assertFalse(any(call[2] == wrapper_windows.VK_RETURN for call in calls))
        self.assertEqual(events[-1]["action"], "injection-enter-cancelled")

    def test_failed_or_partial_text_batch_suppresses_enter(self):
        calls = []
        events = []
        with (
            mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls, fail_call=1),
            ),
            mock.patch.object(
                wrapper_windows, "_read_visible_console_text", return_value="clean"
            ),
            mock.patch.object(wrapper_windows.time, "sleep"),
        ):
            delivered = wrapper_windows.inject(
                "queued task",
                safeguard_guard=True,
                guard_event_callback=events.append,
            )

        self.assertFalse(delivered)
        self.assertFalse(any(call[2] == wrapper_windows.VK_RETURN for call in calls))
        self.assertEqual(events[-1]["action"], "injection-error")

    def test_partial_success_text_batch_suppresses_enter(self):
        calls = []
        events = []
        with (
            mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
            mock.patch.object(
                wrapper_windows.kernel32,
                "WriteConsoleInputW",
                side_effect=self._console_writer(calls, partial_call=1),
            ),
            mock.patch.object(
                wrapper_windows, "_read_visible_console_text", return_value="clean"
            ),
            mock.patch.object(wrapper_windows.time, "sleep"),
        ):
            delivered = wrapper_windows.inject(
                "queued task",
                safeguard_guard=True,
                guard_event_callback=events.append,
            )

        self.assertFalse(delivered)
        self.assertFalse(any(call[2] == wrapper_windows.VK_RETURN for call in calls))
        self.assertEqual(events[-1]["action"], "injection-error")

    def test_monitor_survives_screen_read_exception(self):
        events = []
        stop = threading.Event()
        reads = [0]

        def read_screen():
            reads[0] += 1
            if reads[0] == 1:
                raise RuntimeError("synthetic screen failure")
            stop.set()
            return "ordinary output"

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            wrapper_windows, "_read_visible_console_text", side_effect=read_screen
        ):
            thread = wrapper_windows._start_safeguard_monitor(
                agent="fable-test",
                pid_holder=[321],
                queue_file=Path(temp_dir) / "queue.jsonl",
                enabled=True,
                max_retries=2,
                enter_backend="console_input",
                event_sink=events.append,
                poll_seconds=0.01,
                stop_event=stop,
            )
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertGreaterEqual(reads[0], 2)
        errors = [event for event in events if event["action"] == "monitor-error"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["error_type"], "RuntimeError")

    def test_fable_queue_guard_stays_on_when_auto_retry_is_off(self):
        captured = {}
        calls = []
        reads = [0]

        class FinishedProcess:
            pid = 777
            returncode = 0

            @staticmethod
            def wait():
                return None

        def start_watcher(inject_fn):
            captured["inject"] = inject_fn

        def read_screen():
            reads[0] += 1
            return MENU if reads[0] == 1 else "ordinary clean screen"

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                mock.patch.object(wrapper_windows, "enable_vt_mode"),
                mock.patch.object(wrapper_windows, "_vt_keepalive_thread"),
                mock.patch.object(
                    wrapper_windows, "_start_safeguard_monitor"
                ) as monitor,
                mock.patch.object(
                    wrapper_windows.subprocess,
                    "Popen",
                    return_value=FinishedProcess(),
                ),
            ):
                queue_file = Path(temp_dir) / "queue.jsonl"
                wrapper_windows.run_agent(
                    command="claude",
                    extra_args=[],
                    cwd=temp_dir,
                    env={},
                    queue_file=queue_file,
                    agent="fable-test",
                    no_restart=True,
                    start_watcher=start_watcher,
                    pid_holder=[None],
                    safeguard_auto_retry=False,
                )
                monitor.assert_called_once()

            with (
                mock.patch.object(wrapper_windows.kernel32, "GetStdHandle", return_value=123),
                mock.patch.object(
                    wrapper_windows.kernel32,
                    "WriteConsoleInputW",
                    side_effect=self._console_writer(calls, read_counter=reads),
                ),
                mock.patch.object(
                    wrapper_windows, "_read_visible_console_text", side_effect=read_screen
                ),
                mock.patch.object(wrapper_windows.time, "sleep"),
            ):
                self.assertTrue(captured["inject"]("queued task"))

        first_write = next(call for call in calls if call[0] == "screen_reads")
        self.assertGreaterEqual(first_write[1], 2)


if __name__ == "__main__":
    unittest.main()
