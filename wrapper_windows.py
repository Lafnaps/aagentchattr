"""Windows agent injection — uses Win32 WriteConsoleInput to type into the agent CLI.

Called by wrapper.py on Windows. Not imported on other platforms.
"""

import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

if sys.platform != "win32":
    raise ImportError("wrapper_windows only works on Windows")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE_FOR_VT = -11  # kept distinct from STD_OUTPUT_HANDLE below to avoid forward-ref
KEY_EVENT = 0x0001
VK_RETURN = 0x0D
VK_ESCAPE = 0x1B
VK_DOWN = 0x28

# Console-mode bits for SetConsoleMode (Windows Console API)
ENABLE_PROCESSED_OUTPUT = 0x0001
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

# Window message constants used by the wm_setfocus Enter backend.
WM_SETFOCUS = 0x0007
WM_ACTIVATE = 0x0006
WA_ACTIVE = 1


def enable_vt_mode(verbose: bool = True):
    """Enable virtual terminal processing on the underlying console (output only).

    Newer TUI agents (codex, claude, etc.) emit ANSI escape sequences directly
    rather than calling SetConsoleMode themselves. Without VT processing enabled,
    sequences like `?2026h` (synchronized output) leak as literal text and the
    UI is unreadable.

    We open CONOUT$ directly via CreateFileW rather than going through the
    inherited STDOUT handle — this way, even if Python's stdio has been
    redirected through pipes (or a Node/Rust child later reopens its own handle
    to the console), the underlying conhost device gets the mode flipped.

    Deliberately does NOT touch CONIN$. Forcing ENABLE_VIRTUAL_TERMINAL_INPUT
    makes conhost translate window focus changes into `ESC[I`/`ESC[O` byte
    sequences instead of native FOCUS_EVENT records. TUIs that read input via
    the Win32 event API (codex/crossterm) then see the sequence as loose
    keystrokes — the lone ESC clears the composer (wiping injected text) and
    `[I` gets typed literally. Injection via WriteConsoleInputW works without
    the bit; CLIs that want VT input set it themselves.

    Safe to call multiple times. Failures are logged but not fatal.
    """
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    # Set explicit signatures so HANDLE doesn't get truncated to 32 bits on x64.
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetConsoleMode.restype = wintypes.BOOL
    kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.SetConsoleMode.restype = wintypes.BOOL

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3

    targets = (
        ("CONOUT$", GENERIC_READ | GENERIC_WRITE,
         ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT, "stdout"),
    )

    for device, access, extra_bits, label in targets:
        handle = kernel32.CreateFileW(
            device, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None,
        )
        if not handle or handle == INVALID_HANDLE_VALUE:
            if verbose:
                print(f"  [wrapper] VT enable ({label}): could not open {device}", flush=True)
            continue
        try:
            mode = wintypes.DWORD(0)
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                if verbose:
                    print(f"  [wrapper] VT enable ({label}): GetConsoleMode failed", flush=True)
                continue
            before = mode.value
            new_mode = before | extra_bits
            if new_mode == before:
                if verbose:
                    print(f"  [wrapper] VT enable ({label}): already 0x{before:04x} (VT bits set)", flush=True)
                continue
            ok = kernel32.SetConsoleMode(handle, new_mode)
            if verbose:
                status = "ok" if ok else "FAILED"
                print(f"  [wrapper] VT enable ({label}): 0x{before:04x} -> 0x{new_mode:04x} [{status}]", flush=True)
        finally:
            kernel32.CloseHandle(handle)


class _CHAR_UNION(ctypes.Union):
    _fields_ = [("UnicodeChar", wintypes.WCHAR), ("AsciiChar", wintypes.CHAR)]


class _KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("bKeyDown", wintypes.BOOL),
        ("wRepeatCount", wintypes.WORD),
        ("wVirtualKeyCode", wintypes.WORD),
        ("wVirtualScanCode", wintypes.WORD),
        ("uChar", _CHAR_UNION),
        ("dwControlKeyState", wintypes.DWORD),
    ]


class _EVENT_UNION(ctypes.Union):
    _fields_ = [("KeyEvent", _KEY_EVENT_RECORD)]


class _INPUT_RECORD(ctypes.Structure):
    _fields_ = [("EventType", wintypes.WORD), ("Event", _EVENT_UNION)]


def _write_key(handle, char: str, key_down: bool, vk: int = 0, scan: int = 0):
    if not isinstance(char, str) or len(char) != 1:
        raise ValueError("console key events require exactly one Unicode character")
    rec = _INPUT_RECORD()
    rec.EventType = KEY_EVENT
    evt = rec.Event.KeyEvent
    evt.bKeyDown = key_down
    evt.wRepeatCount = 1
    evt.uChar.UnicodeChar = char
    evt.wVirtualKeyCode = vk
    evt.wVirtualScanCode = scan
    written = wintypes.DWORD(0)
    ok = kernel32.WriteConsoleInputW(
        handle, ctypes.byref(rec), 1, ctypes.byref(written)
    )
    if not ok or written.value != 1:
        raise OSError(ctypes.get_last_error(), "WriteConsoleInputW failed")


def _send_wm_setfocus():
    """Tell the console window it just received focus — some Node TUIs
    (GitHub Copilot CLI) gate Enter processing on focus state, so this
    makes them accept injected Enter without an actual focus change."""
    hwnd = kernel32.GetConsoleWindow()
    if not hwnd:
        return
    user32.SendMessageW(hwnd, WM_SETFOCUS, 0, 0)
    user32.SendMessageW(hwnd, WM_ACTIVATE, WA_ACTIVE, 0)


_inject_lock = threading.RLock()


def inject(text: str, *, delay: float = 0.3, enter_backend: str = "console_input",
           safeguard_guard: bool = False, guard_event_callback=None,
           guard_poll_seconds: float = 0.25):
    """Inject text + Enter into the current console via WriteConsoleInput.

    Uses batch WriteConsoleInputW for the text (all records in one call)
    then a separate Enter keystroke after a scaled delay.

    `enter_backend` controls how the final Enter is delivered:
      - "console_input" (default): standard WriteConsoleInput + VK_RETURN.
        Works for Claude/Codex/Gemini/Kimi/Qwen/Kilo/etc.
      - "wm_setfocus": fake-focus message (WM_SETFOCUS + WM_ACTIVATE) to
        the console window before sending VK_RETURN. Needed for GitHub
        Copilot CLI, whose Ink-based input layer ignores Enter events
        when the console window is unfocused.
    """
    deferred = False
    while True:
        result = _injection_attempt(
            text,
            delay=delay,
            enter_backend=enter_backend,
            safeguard_guard=safeguard_guard,
        )
        status = result["status"]
        if status == "injected":
            return True
        if status == "injected-uncertain":
            if guard_event_callback:
                guard_event_callback(result["event"])
            # Never claim acceptance or auto-retry: key-down may already have
            # submitted, but the child has not semantically acknowledged it.
            return "injected-uncertain"
        if status in ("error", "cancelled"):
            if guard_event_callback:
                guard_event_callback(result["event"])
            return False
        # deferred
        if not deferred and guard_event_callback:
            guard_event_callback(result["event"])
        deferred = True
        time.sleep(max(0.1, guard_poll_seconds))


def _injection_attempt(text: str, *, delay: float = 0.3,
                       enter_backend: str = "console_input",
                       safeguard_guard: bool = False,
                       composer_guard=None,
                       allow_active: bool = False) -> dict:
    """One fail-closed admission-gated injection attempt.

    Runs entirely under _inject_lock; never invokes callbacks (the caller
    emits outside the lock). Returns {"status": ..., "event": ...} where
    status is one of "injected", "deferred", "cancelled", "error" and event
    is a ready-to-emit alert payload (absent for "injected"). Admission
    order: unreadable screen -> Fable safeguard-menu block -> composer
    admission (stably idle child + positively empty composer). Any
    non-admitted state defers without sending a single key.
    """
    enter_cancelled = False
    cancelled_screen = ""
    read_error_type = None
    injection_error_type = None
    classification = None
    with _inject_lock:
        try:
            screen = (
                _read_visible_console_text()
                if (safeguard_guard or composer_guard is not None) else ""
            )
        except Exception as exc:
            screen = ""
            read_error_type = type(exc).__name__
        if read_error_type:
            classification = "unreadable"
            if composer_guard is not None:
                composer_guard.reset_stability()
        elif safeguard_guard and _screen_blocks_safeguard_input(screen):
            exact_classification = _classify_fable_safeguard_screen(screen)
            classification = (
                "capacity"
                if _classify_fable_capacity_screen(screen) is not None
                else exact_classification or "pointer-like"
            )
            if composer_guard is not None:
                composer_guard.reset_stability()
        elif composer_guard is not None:
            admission = (
                composer_guard.classify_active(screen)
                if allow_active else composer_guard.classify(screen)
            )
            if admission != "admit":
                classification = admission
        if classification is None:
            try:
                outcome = _inject_unlocked(
                    text,
                    delay=delay,
                    enter_backend=enter_backend,
                    abort_enter_if_safeguard=safeguard_guard,
                    composer_guard=composer_guard,
                    pre_screen=screen if composer_guard is not None else None,
                )
                if outcome == "uncertain":
                    # Enter key-down delivered, key-up unconfirmed: terminal.
                    # Consuming (never retrying) avoids a duplicate task.
                    if composer_guard is not None:
                        composer_guard.reset_episode()
                    return {
                        "status": "injected-uncertain",
                        "event": {
                            "action": "injection-enter-uncertain",
                            "fingerprint": _safeguard_screen_fingerprint(""),
                        },
                    }
                if outcome:
                    if composer_guard is not None:
                        composer_guard.reset_episode()
                    return {"status": "injected"}
                enter_cancelled = True
                try:
                    cancelled_screen = _read_visible_console_text()
                except Exception:
                    cancelled_screen = ""
            except Exception as exc:
                injection_error_type = type(exc).__name__
    if injection_error_type:
        return {
            "status": "error",
            "event": {
                "action": "injection-error",
                "error_type": injection_error_type,
                "fingerprint": _safeguard_screen_fingerprint(""),
            },
        }
    if enter_cancelled:
        return {
            "status": "cancelled",
            # Private, in-memory provenance only. Callers emit only `event`;
            # this raw snapshot is never persisted or included in alerts.
            "_owned_cancelled_screen": cancelled_screen,
            "event": {
                "action": "injection-enter-cancelled",
                "classification": (
                    "capacity"
                    if _classify_fable_capacity_screen(cancelled_screen) is not None
                    else _classify_fable_safeguard_screen(cancelled_screen)
                ),
                "fingerprint": _safeguard_screen_fingerprint(
                    cancelled_screen
                ),
            },
        }
    return {
        "status": "deferred",
        "classification": classification,
        "event": {
            "action": "injection-deferred",
            "classification": classification,
            "fingerprint": _safeguard_screen_fingerprint(screen),
            **({"error_type": read_error_type} if read_error_type else {}),
        },
    }


def _probe_injection_admission(*, safeguard_guard: bool,
                               composer_guard,
                               allow_active: bool = False,
                               owned_text: str | None = None,
                               owned_clear_candidate: dict | None = None,
                               owned_paste_proof: dict | None = None) -> dict:
    """Fail-closed recovery probe; never sends wrapper text or Enter.

    The same fail-closed ordering as _injection_attempt is used, but a
    positive stable-empty result is returned to the watcher instead of
    immediately attempting delivery. By default it is read-only. A cancelled
    episode may additionally clear its exact in-memory owned composer batch
    (or a one-shot, cancellation-bound Codex paste pill with the exact Python
    character count) with Escape, but only after two consecutive due probes
    prove the complete screen stable under the normal composer discipline. A
    positively empty redraw is then required. This is the only way a blocked
    cancellation/error episode can become eligible for another attempt.
    """
    read_error_type = None
    owned_cleared = False
    owned_exact = False
    owned_clear_attempted = False
    with _inject_lock:
        try:
            screen = _read_visible_console_text()
        except Exception as exc:
            screen = ""
            read_error_type = type(exc).__name__

        safeguard_blocked = (
            read_error_type is None
            and safeguard_guard
            and _screen_blocks_safeguard_input(screen)
        )
        # A cancelled attempt may have written the complete wrapper batch but
        # withheld Enter after a redraw. A single exact snapshot is not enough:
        # the child may still be producing output. Arm Escape only after two
        # consecutive due probes see both the exact in-memory owned composer
        # and a full screen stable under _stable_against (whose sole tolerance
        # is a cursor-cell delta on the same composer row).
        if (
            read_error_type is None
            and owned_text
            and composer_guard is not None
            and not safeguard_blocked
        ):
            owned_exact, clear_armed = _owned_clear_stability_observation(
                screen,
                owned_text,
                composer_guard,
                owned_clear_candidate,
                owned_paste_proof=owned_paste_proof,
            )
        else:
            clear_armed = False
            if owned_clear_candidate is not None:
                owned_clear_candidate.clear()

        if clear_armed:
            owned_clear_attempted = True
            # Every clear attempt consumes its two-sighting proof. If Escape
            # fails or the redraw is not positively empty, the next attempt
            # must earn two new stable exact observations from scratch.
            if owned_clear_candidate is not None:
                owned_clear_candidate.clear()
            # A cancellation-bound paste-pill proof is single-use. Consume it
            # before the first Escape key event; a failed/uncertain clear can
            # never reuse the same provenance on a later probe.
            if owned_paste_proof is not None:
                owned_paste_proof.clear()
            handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
            clear_error_type = None
            try:
                _write_key(
                    handle, "\x1b", True, vk=VK_ESCAPE, scan=0x01
                )
                _write_key(
                    handle, "\x1b", False, vk=VK_ESCAPE, scan=0x01
                )
            except Exception as exc:
                clear_error_type = type(exc).__name__
            time.sleep(0.05)
            try:
                screen = _read_visible_console_text()
            except Exception as exc:
                screen = ""
                read_error_type = type(exc).__name__
            else:
                state, _content, _row = _composer_state(
                    screen,
                    composer_guard.markers,
                    composer_guard.placeholders,
                    composer_guard.separator,
                    composer_guard.empty_requires_separator,
                )
                if clear_error_type is not None:
                    # The effect of a failed key-down/key-up pair is uncertain.
                    # An empty redraw cannot prove an atomic wrapper clear.
                    read_error_type = clear_error_type
                elif state == "empty":
                    owned_cleared = True
                    composer_guard.reset_stability()

        if read_error_type:
            classification = "unreadable"
            if composer_guard is not None:
                composer_guard.reset_stability()
        elif safeguard_guard and _screen_blocks_safeguard_input(screen):
            classification = (
                "capacity"
                if _classify_fable_capacity_screen(screen) is not None
                else _classify_fable_safeguard_screen(screen) or "pointer-like"
            )
            if composer_guard is not None:
                composer_guard.reset_stability()
        elif composer_guard is None:
            # A blocked episode cannot be recovered by guessing that an
            # unknown composer is empty.
            classification = "unrecognized-composer"
        elif owned_exact and not owned_clear_attempted:
            # Exact ownership has one stable sighting only. Keep the blocked
            # episode armed and wait for the next due probe; never send Escape
            # on the first observation.
            classification = "owned-clear-pending"
        elif owned_clear_attempted and not owned_cleared:
            classification = "owned-clear-unverified"
        else:
            classification = (
                composer_guard.classify_active(screen)
                if allow_active else composer_guard.classify(screen)
            )
    return {
        "ready": classification == "admit",
        "classification": classification,
        "owned_cleared": owned_cleared,
        **({"error_type": read_error_type} if read_error_type else {}),
    }


def _make_admitted_injector(*, delay: float = 0.3,
                            enter_backend: str = "console_input",
                            safeguard_guard: bool = False,
                            composer_guard=None, emit=None,
                            blocked_probe_initial_seconds: float = 2.0,
                            blocked_probe_max_seconds: float = 60.0,
                            monotonic=None):
    """Build the queue-watcher injector for the fail-closed admission gate.

    Single attempt per call (no internal deferral loop): the watcher owns the
    retry cadence and re-coalesces the durable queue between attempts, so
    triggers arriving during a deferral join the next batch instead of being
    lost. Returns the attempt status string; "injected" is the only result
    that lets the watcher consume the batch. Deferral alerts are deduped per
    classification episode via the composer guard.

    If text was typed but Enter was cancelled because a safeguard menu
    appeared, the durable queue remains pending but the injector enters a
    blocked-composer episode. It emits that cancellation/error once, then
    performs fail-closed recovery probes with exponential backoff. No wrapper
    text or Enter is attempted again until the admission guard has positively
    observed a stable empty composer; only an exact in-memory owned cancelled
    batch seen unchanged on two consecutive due probes may receive Escape
    clearing first. The watcher can query
    retry_after() and call recovery_probe() before touching its journal. One
    audit-only watchdog record is emitted per episode; it is not a chat
    notification.
    """

    clock = monotonic or time.monotonic
    probe_initial = min(60.0, max(2.0, float(blocked_probe_initial_seconds)))
    probe_max = min(
        60.0, max(probe_initial, float(blocked_probe_max_seconds))
    )
    blocked_episode = False
    next_probe_at = 0.0
    probe_delay = probe_initial
    episode_fingerprint = ""
    episode_owned_text = None
    owned_clear_candidate = {}
    owned_paste_proof = {}

    def _schedule_probe(now: float, *, first: bool = False) -> None:
        nonlocal next_probe_at, probe_delay
        probe_delay = (
            probe_initial if first else min(probe_max, probe_delay * 2.0)
        )
        next_probe_at = now + probe_delay

    def _reset_blocked_episode() -> None:
        nonlocal blocked_episode, next_probe_at, probe_delay
        nonlocal episode_fingerprint, episode_owned_text
        blocked_episode = False
        next_probe_at = 0.0
        probe_delay = probe_initial
        episode_fingerprint = ""
        episode_owned_text = None
        owned_clear_candidate.clear()
        owned_paste_proof.clear()

    def _retry_after() -> float:
        if not blocked_episode:
            return 0.0
        return max(0.0, next_probe_at - clock())

    def _enter_blocked_episode(result: dict, *, operator_alert: bool = True,
                               owned_text: str | None = None) -> None:
        nonlocal blocked_episode, episode_fingerprint, episode_owned_text
        if blocked_episode:
            return
        blocked_episode = True
        event = result.get("event") or {}
        episode_fingerprint = str(event.get("fingerprint") or "unknown")
        episode_owned_text = (
            owned_text if isinstance(owned_text, str) and owned_text else None
        )
        owned_clear_candidate.clear()
        owned_paste_proof.clear()
        if episode_owned_text is not None:
            pill = _codex_cancelled_owned_paste_pill(
                result.get("_owned_cancelled_screen"),
                episode_owned_text,
                composer_guard,
            )
            if pill is not None:
                owned_paste_proof["pill"] = pill
        _schedule_probe(clock(), first=True)
        if emit:
            # This is the single operator-facing notification for the
            # cancellation/error episode.
            if operator_alert:
                emit(event)
            # The wrapper callback deliberately treats this second record as
            # audit-only.  It proves the bounded watchdog was armed without
            # creating another chat message.
            emit({
                "action": "injection-recovery-watchdog",
                "classification": event.get(
                    "classification", result.get("status", "unknown")
                ),
                "fingerprint": episode_fingerprint,
                "retry_after_seconds": probe_initial,
                "max_retry_seconds": probe_max,
            })

    def _recovery_probe_mode(*, allow_active: bool = False) -> bool:
        """Return True only after due, fail-closed empty admission."""
        nonlocal episode_owned_text
        if not blocked_episode:
            return True
        now = clock()
        if now < next_probe_at:
            return False
        result = _probe_injection_admission(
            safeguard_guard=safeguard_guard,
            composer_guard=composer_guard,
            allow_active=allow_active,
            owned_text=episode_owned_text,
            owned_clear_candidate=owned_clear_candidate,
            owned_paste_proof=owned_paste_proof,
        )
        if result.get("owned_cleared"):
            # The stale exact-owned batch is gone. Keep the episode armed until
            # normal empty-composer admission succeeds; the watcher will then
            # re-coalesce and type the full current durable queue batch.
            episode_owned_text = None
            owned_clear_candidate.clear()
            owned_paste_proof.clear()
        if result["ready"]:
            _reset_blocked_episode()
            return True
        _schedule_probe(clock())
        return False

    def _recovery_probe() -> bool:
        return _recovery_probe_mode()

    def _recovery_probe_active() -> bool:
        # Owner Telegram delivery may interrupt an active Codex turn. Recovery
        # must use the same empty-composer admission mode as that delivery;
        # otherwise one cancelled attempt blocks every later owner wake until
        # the turn ends.
        if composer_guard is None or composer_guard.provider != "codex":
            return _recovery_probe_mode()
        return _recovery_probe_mode(allow_active=True)

    def _run_mode(text: str, *, allow_active: bool = False) -> str:
        # Direct callers are protected too.  The queue watcher normally calls
        # retry_after()/recovery_probe() before beginning its journal
        # transaction; this fallback preserves the same no-retype invariant.
        if blocked_episode:
            recovery_probe = (
                _recovery_probe_active if allow_active else _recovery_probe
            )
            if _retry_after() > 0.0 or not recovery_probe():
                return "deferred"

        result = _injection_attempt(
            text,
            delay=delay,
            enter_backend=enter_backend,
            safeguard_guard=safeguard_guard,
            composer_guard=composer_guard,
            allow_active=allow_active,
        )
        status = result["status"]
        if status == "injected":
            _reset_blocked_episode()
            return status
        if status == "injected-uncertain":
            # Terminal: consumed by the watcher, never retried; alerted for
            # manual confirmation.
            _reset_blocked_episode()
            if emit:
                emit(result["event"])
            return status
        if status == "deferred":
            classification = result.get("classification")
            should_alert = (
                composer_guard.should_alert(classification)
                if composer_guard is not None else True
            )
            # A busy/unsafe composer is a recovery episode too.  Without this
            # transition the watcher retries every poll and appends an
            # attempting/retry pair each second until the durable journal
            # reaches its fail-closed limit.
            _enter_blocked_episode(result, operator_alert=should_alert)
            return status
        if status in ("cancelled", "error"):
            # Both outcomes may leave text in the composer.  They therefore
            # start the same deduped fail-closed episode; no retry is possible
            # until bounded recovery proves stable-empty (or safely clears a
            # twice-observed stable exact-owned cancelled batch first).
            _enter_blocked_episode(
                result,
                owned_text=text if status == "cancelled" else None,
            )
            return status
        if emit:
            emit(result["event"])
        return status

    def _run(text: str) -> str:
        return _run_mode(text)

    def _run_active(text: str) -> str:
        # Telegram owner ingress is canonically routed only to Codex. Keep the
        # active-turn exception unavailable to every other provider.
        if composer_guard is None or composer_guard.provider != "codex":
            return _run_mode(text)
        return _run_mode(text, allow_active=True)

    # Small duck-typed protocol consumed by wrapper._queue_watcher.  Keeping
    # it on the callable preserves compatibility with existing start_watcher
    # and legacy injectors.
    _run.retry_after = _retry_after
    _run.recovery_probe = _recovery_probe
    _run.recovery_probe_active = _recovery_probe_active
    _run.inject_active = _run_active
    return _run


def _write_enter(handle) -> str:
    """Send Enter key-down + key-up as ONE WriteConsoleInputW batch.

    Returns "ok" (both records delivered) or "partial" (only the key-down
    landed — the child may already have submitted, so the caller must treat
    the injection as terminal and never retry it). Raises OSError when the
    call delivered nothing at all (nothing was submitted; a plain error)."""
    records = (_INPUT_RECORD * 2)()
    for slot, key_down in ((0, True), (1, False)):
        rec = records[slot]
        rec.EventType = KEY_EVENT
        evt = rec.Event.KeyEvent
        evt.bKeyDown = key_down
        evt.wRepeatCount = 1
        evt.uChar.UnicodeChar = "\r"
        evt.wVirtualKeyCode = VK_RETURN
        evt.wVirtualScanCode = 0x1C
    written = wintypes.DWORD(0)
    kernel32.WriteConsoleInputW(handle, records, 2, ctypes.byref(written))
    if written.value == 2:
        return "ok"
    if written.value >= 1:
        return "partial"
    raise OSError(ctypes.get_last_error(), "WriteConsoleInputW enter failed")


def _enter_preflight_passes(*, abort_enter_if_safeguard: bool,
                            composer_guard, pre_screen, text: str) -> bool:
    """Post-type / pre-Enter preflight. A failed or unreadable check means the
    single Enter is never sent (fail-closed)."""
    if not abort_enter_if_safeguard and composer_guard is None:
        return True
    try:
        post_screen = _read_visible_console_text()
    except Exception:
        return False
    if abort_enter_if_safeguard and _screen_blocks_safeguard_input(post_screen):
        return False
    if composer_guard is not None and not _typed_text_visible(
        post_screen, pre_screen, text, composer_guard
    ):
        return False
    return True


def _inject_unlocked(text: str, *, delay: float = 0.3,
                     enter_backend: str = "console_input",
                     abort_enter_if_safeguard: bool = False,
                     composer_guard=None, pre_screen=None):
    handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)

    # Build all key events at once (key down + key up per character)
    n_events = len(text) * 2
    if n_events > 0:
        records = (_INPUT_RECORD * n_events)()
        idx = 0
        for ch in text:
            for key_down in (True, False):
                rec = records[idx]
                rec.EventType = KEY_EVENT
                evt = rec.Event.KeyEvent
                evt.bKeyDown = key_down
                evt.wRepeatCount = 1
                evt.uChar.UnicodeChar = ch
                evt.wVirtualKeyCode = 0
                evt.wVirtualScanCode = 0
                idx += 1
        written = wintypes.DWORD(0)
        ok = kernel32.WriteConsoleInputW(
            handle, records, n_events, ctypes.byref(written)
        )
        if not ok or written.value != n_events:
            raise OSError(
                ctypes.get_last_error(), "WriteConsoleInputW text batch failed"
            )

    # Scale delay with text length so longer prompts get more processing time
    scaled_delay = max(delay, len(text) * 0.001)
    time.sleep(scaled_delay)

    if not _enter_preflight_passes(
        abort_enter_if_safeguard=abort_enter_if_safeguard,
        composer_guard=composer_guard, pre_screen=pre_screen, text=text,
    ):
        return False

    if enter_backend == "wm_setfocus":
        _send_wm_setfocus()
        # Tiny pause for the window to process the focus message
        time.sleep(0.05)
        if not _enter_preflight_passes(
            abort_enter_if_safeguard=abort_enter_if_safeguard,
            composer_guard=composer_guard, pre_screen=pre_screen, text=text,
        ):
            return False

    if _write_enter(handle) == "partial":
        # Key-down may have submitted; the outcome is terminal-uncertain and
        # must never be retried (a retry could double-submit the task).
        return "uncertain"
    return True


def _select_second_menu_option(*, delay: float = 0.25,
                               enter_backend: str = "console_input",
                               expected_fingerprint: str | None = None):
    """Select the second item in a verified two-item console menu.

    The safeguard menu initially renders its pointer on item 1.  Sending a
    Down key followed by Enter is safer than typing the character ``2``: a
    digit could leak into the next composer if the menu accepts it eagerly.
    """
    with _inject_lock:
        initial_screen = _read_visible_console_text()
        if _classify_fable_safeguard_screen(initial_screen) != "strict":
            return False
        if (
            expected_fingerprint is not None
            and _safeguard_screen_fingerprint(initial_screen)
            != expected_fingerprint
        ):
            return False
        handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
        _write_key(handle, "\0", True, vk=VK_DOWN, scan=0x50)
        _write_key(handle, "\0", False, vk=VK_DOWN, scan=0x50)

        deadline = time.monotonic() + max(0.25, delay * 4)
        second_selected = False
        while time.monotonic() < deadline:
            time.sleep(0.05)
            if _is_second_safeguard_option_selected(
                _read_visible_console_text()
            ):
                second_selected = True
                break
        if not second_selected:
            return False
        if enter_backend == "wm_setfocus":
            _send_wm_setfocus()
            time.sleep(0.05)
        # The menu may redraw while focus changes.  Enter is allowed only while
        # the approved Fable option is still visibly selected.
        if not _is_second_safeguard_option_selected(
            _read_visible_console_text()
        ):
            return False
        _write_key(handle, "\r", True, vk=VK_RETURN, scan=0x1C)
        _write_key(handle, "\r", False, vk=VK_RETURN, scan=0x1C)
        return True


# ---------------------------------------------------------------------------
# Activity detection — console screen buffer hashing
# ---------------------------------------------------------------------------

STD_OUTPUT_HANDLE = -11


class _COORD(ctypes.Structure):
    _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]


class _SMALL_RECT(ctypes.Structure):
    _fields_ = [
        ("Left", wintypes.SHORT),
        ("Top", wintypes.SHORT),
        ("Right", wintypes.SHORT),
        ("Bottom", wintypes.SHORT),
    ]


class _CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [
        ("dwSize", _COORD),
        ("dwCursorPosition", _COORD),
        ("wAttributes", wintypes.WORD),
        ("srWindow", _SMALL_RECT),
        ("dwMaximumWindowSize", _COORD),
    ]


class _CHAR_INFO(ctypes.Structure):
    _fields_ = [("Char", _CHAR_UNION), ("Attributes", wintypes.WORD)]


kernel32.GetConsoleScreenBufferInfo.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_CONSOLE_SCREEN_BUFFER_INFO),
]
kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL

kernel32.ReadConsoleOutputW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_CHAR_INFO),
    _COORD,
    _COORD,
    ctypes.POINTER(_SMALL_RECT),
]
kernel32.ReadConsoleOutputW.restype = wintypes.BOOL


_FABLE_SAFEGUARD_PARAGRAPH = (
    "Fable 5's safeguards flagged this message. The safeguards are "
    "intentionally broad right now and may flag safe and routine coding, "
    "cybersecurity, or biology work. These measures let us bring you "
    "Mythos-level capabilities sooner, and we're working to refine them. "
    "Send feedback with /feedback or learn more"
)
_FABLE_SAFEGUARD_OPTION_1 = "1. Switch to Opus 4.8"
_FABLE_SAFEGUARD_OPTION_2 = "2. Edit prompt and retry with Fable 5"
_FABLE_CAPACITY_LINE = re.compile(
    r"^(?:"
    r"You(?:'|\u2019)ve reached your (?:Fable|weekly Fable) limit"
    r"(?: \u00b7 resets tomorrow)?"
    r"|(?:\u26a0\s*)?Selected model is at capacity\. "
    r"Please try a different model\."
    r")$"
)
_FABLE_LEGACY_ALIASES = frozenset({
    "fable-main",
    "fable-infra",
    "fable-emu",
    "fable-work",
    "fable-review",
})


def _is_fable_lane(agent: str) -> bool:
    """Return true only for canonical Fable lanes or legacy input aliases."""
    return bool(
        re.fullmatch(
            r"claude(?:-(?:test[123]|work))?-fable(?:-\d+)?",
            agent or "",
        )
        or agent in _FABLE_LEGACY_ALIASES
    )


def _normalize_screen_text(text: str) -> str:
    return " ".join(text.split())


def _screen_lines(text: str) -> list[str]:
    # Preserve physical blank rows: dropping them would make a quoted menu at
    # the top of the viewport look as if it were adjacent to the bottom.
    return [line.strip() for line in text.splitlines()]


def _find_low_exact_option_layout(text: str, selected_option: int):
    """Return the exact option-row span, preserving physical row position."""
    lines = _screen_lines(text)
    if selected_option == 1:
        pointer_values = {
            f"❯ {_FABLE_SAFEGUARD_OPTION_1}",
            f"> {_FABLE_SAFEGUARD_OPTION_1}",
        }
        selected_index = next(
            (i for i, line in enumerate(lines) if line in pointer_values), None
        )
        layout_ok = bool(
            selected_index is not None
            and selected_index + 1 < len(lines)
            and lines[selected_index + 1] == _FABLE_SAFEGUARD_OPTION_2
        )
        first_option = selected_index
        last_option = selected_index + 1 if selected_index is not None else None
    else:
        pointer_values = {
            f"❯ {_FABLE_SAFEGUARD_OPTION_2}",
            f"> {_FABLE_SAFEGUARD_OPTION_2}",
        }
        selected_index = next(
            (i for i, line in enumerate(lines) if line in pointer_values), None
        )
        layout_ok = bool(
            selected_index is not None
            and selected_index > 0
            and lines[selected_index - 1] == _FABLE_SAFEGUARD_OPTION_1
        )
        first_option = selected_index - 1 if selected_index is not None else None
        last_option = selected_index
    if not (
        layout_ok
        and selected_index is not None
        and selected_index >= max(0, len(lines) - 8)
    ):
        return None
    return lines, first_option, last_option


def _extract_exact_safeguard_region(text: str, selected_option: int):
    layout = _find_low_exact_option_layout(text, selected_option)
    if layout is None:
        return None
    lines, first_option, last_option = layout
    session_rows = [
        i for i in range(max(0, first_option - 14), first_option)
        if lines[i] == "Session paused"
    ]
    if not session_rows:
        return None
    session_row = session_rows[-1]
    region = _normalize_screen_text(
        "\n".join(lines[session_row:last_option + 1])
    )
    if not (
        region.startswith("Session paused ")
        and _FABLE_SAFEGUARD_PARAGRAPH in region
        and _FABLE_SAFEGUARD_OPTION_1 in region
        and _FABLE_SAFEGUARD_OPTION_2 in region
    ):
        return None
    return region


def _screen_may_accept_safeguard_choice(text: str) -> bool:
    """Broad fail-closed gate used before queue-triggered Enter.

    It intentionally blocks changed or truncated two-option model menus.  The
    exact classifier remains the stricter gate for automatic option selection.
    """
    lines = _screen_lines(text)
    start = max(0, len(lines) - 8)
    for i in range(start, len(lines)):
        line = lines[i]
        pointer_one = line.startswith(("❯ 1. Switch to ", "> 1. Switch to "))
        pointer_two = line.startswith(("❯ 2. ", "> 2. "))
        if pointer_one or pointer_two:
            return True
    return False


def _screen_blocks_safeguard_input(text: str) -> bool:
    return bool(
        _classify_fable_safeguard_screen(text) is not None
        or _classify_fable_capacity_screen(text) is not None
        or _screen_may_accept_safeguard_choice(text)
    )


def _safeguard_screen_fingerprint(text: str) -> str:
    region = (
        _extract_exact_safeguard_region(text, 1)
        or _extract_exact_safeguard_region(text, 2)
    )
    if region is None:
        region = _normalize_screen_text("\n".join(_screen_lines(text)[-14:]))
    return hashlib.sha256(region.encode("utf-8")).hexdigest()[:16]


def _classify_fable_safeguard_screen(text: str) -> str | None:
    """Return ``strict``, ``ambiguous``, or ``None`` for rendered output.

    Only ``strict`` is eligible for automatic input.  ``ambiguous`` is useful
    for alerting when a future CLI release changes the wording: it must never
    cause a key press.
    """
    normalized = _normalize_screen_text(text)
    basic = (
        "Session paused" in normalized
        and "safeguards flagged this message" in normalized
    )
    if not basic:
        return None
    strict = (
        _FABLE_SAFEGUARD_PARAGRAPH in normalized
        and _FABLE_SAFEGUARD_OPTION_1 in normalized
        and _FABLE_SAFEGUARD_OPTION_2 in normalized
        and _extract_exact_safeguard_region(text, 1) is not None
    )
    return "strict" if strict else "ambiguous"


def _extract_exact_capacity_region(text: str) -> str | None:
    """Return a low, provider-shaped Fable capacity notice or ``None``.

    A matching phrase in old transcript text is insufficient: the notice must
    be close to a positively recognized empty Claude composer.  This mirrors
    the safeguard menu's low-viewport binding and prevents a quoted notice or
    an operator draft from becoming a machine event.
    """
    profile = _COMPOSER_PROFILES["claude"]
    state, _content, composer_row = _composer_state(
        text,
        tuple(profile["markers"]),
        tuple(profile["placeholders"]),
        profile["separator"],
        bool(profile["empty_requires_separator"]),
    )
    if state != "empty" or composer_row < 0:
        return None
    lines = _screen_lines(text)
    first_row = max(0, composer_row - 8)
    for index in range(composer_row - 1, first_row - 1, -1):
        first = lines[index]
        if not first.startswith((
            "You've reached your ",
            "You’ve reached your ",
            "Selected model is at capacity.",
            "⚠ Selected model is at capacity.",
            "⚠Selected model is at capacity.",
        )):
            continue
        # A nearby assistant/user lead-in makes the matching words transcript,
        # not provider chrome. Exact isolated provider rows remain admissible.
        previous = lines[index - 1] if index > 0 else ""
        if (
            previous.startswith(("✻", "●", "⏺", "Assistant:", "User:"))
            or previous.endswith(":")
        ):
            continue
        fragments = [first]
        for continuation in lines[index + 1:min(composer_row, index + 4)]:
            if not continuation or continuation.startswith(("╭", "┌", "❯", ">")):
                break
            fragments.append(continuation)
        region = _normalize_screen_text("\n".join(fragments))
        if _FABLE_CAPACITY_LINE.fullmatch(region):
            return region
    return None


def _classify_fable_capacity_screen(text: str) -> str | None:
    """Return ``strict`` only for an active low Fable capacity notice."""
    return "strict" if _extract_exact_capacity_region(text) is not None else None


def _capacity_screen_fingerprint(text: str) -> str:
    region = _extract_exact_capacity_region(text) or ""
    return hashlib.sha256(region.encode("utf-8")).hexdigest()[:16]


def _is_second_safeguard_option_selected(text: str) -> bool:
    normalized = _normalize_screen_text(text)
    return bool(
        "Session paused" in normalized
        and _FABLE_SAFEGUARD_PARAGRAPH in normalized
        and _FABLE_SAFEGUARD_OPTION_1 in normalized
        and _FABLE_SAFEGUARD_OPTION_2 in normalized
        and _extract_exact_safeguard_region(text, 2) is not None
    )


def _read_visible_console_text(handle=None) -> str:
    if handle is None:
        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    csbi = _CONSOLE_SCREEN_BUFFER_INFO()
    if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(csbi)):
        raise OSError(ctypes.get_last_error(), "GetConsoleScreenBufferInfo failed")
    rect = csbi.srWindow
    width = rect.Right - rect.Left + 1
    height = rect.Bottom - rect.Top + 1
    if width <= 0 or height <= 0:
        raise RuntimeError("console screen buffer has invalid dimensions")
    cells = (_CHAR_INFO * (width * height))()
    read_rect = _SMALL_RECT(rect.Left, rect.Top, rect.Right, rect.Bottom)
    if not kernel32.ReadConsoleOutputW(
        handle, cells, _COORD(width, height), _COORD(0, 0),
        ctypes.byref(read_rect),
    ):
        raise OSError(ctypes.get_last_error(), "ReadConsoleOutputW failed")
    rows = []
    for y in range(height):
        chars = []
        for x in range(width):
            ch = cells[(y * width) + x].Char.UnicodeChar
            chars.append(ch if ch and ch != "\x00" else " ")
        # Strip ASCII-space padding only: NBSP and other painted cells are
        # provider-shaped evidence (e.g. the Claude composer's marker+NBSP)
        # and must survive for the composer admission gate.
        rows.append("".join(chars).rstrip(" "))
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Queue-injection admission gate — fail-closed composer recognition
# ---------------------------------------------------------------------------

# Bottom rows scanned for the provider composer marker. TUIs render the
# composer at the bottom of the viewport; hint/status rows below it do not
# start with a composer marker, so the bottom-most marker row is the composer.
_COMPOSER_SCAN_ROWS = 12

# Exact prompt markers that begin a composer row per provider CLI family.
# Recognition is positive-only: a provider absent from this map can never be
# admitted automatically — its triggers defer with an alert (fail-closed;
# never guessed from CPU or other side channels).
# "❯" (U+276F) followed by NBSP (U+00A0) is the live Claude Code / Fable
# composer shape (verified against a read-only UIA snapshot of a running
# Fable session). `separator` is the exact cell required between marker and
# content; with `empty_requires_separator` even an EMPTY composer must show
# marker+separator, so a bare marker glyph in transcript output can never be
# mistaken for the composer. Custom `composer_markers` config bypasses the
# separator requirement (explicit operator override for future layouts).
_COMPOSER_PROFILES: dict[str, dict] = {
    "claude": {
        "markers": ("❯",),
        "separator": " ",
        "empty_requires_separator": True,
        # Claude Code 2.1.215 renders one rotating suggestion as visible
        # composer text even though the input buffer is empty.  Keep the
        # exact built-in strings here: broad/pattern matching could mistake
        # an operator draft for an empty composer and overwrite it.
        "placeholders": (
            'Try "fix lint errors"',
            'Try "fix typecheck errors"',
            'Try "how does <filepath> work?"',
            'Try "refactor <filepath>"',
            'Try "how do I log an error?"',
            'Try "edit <filepath> to..."',
            'Try "write a test for <filepath>"',
            'Try "create a util logging.py that..."',
        ),
    },
    "codex": {
        # "›" — the Codex TUI prompt marker, plain-space separated
        "markers": ("›",),
        "separator": " ",
        "empty_requires_separator": False,
        # Codex 0.144.x rotates one of these suggestions through an otherwise
        # empty composer. They are static strings embedded in the CLI binary,
        # not user-authored input.
        "placeholders": (
            "Explain this codebase",
            "Summarize recent commits",
            "Implement {feature}",
            "Find and fix a bug in @filename",
            "Write tests for @filename",
            "Improve documentation in @filename",
            "Run /review on my current changes",
            "Use /skills to list available skills",
        ),
    },
}


# Box-drawing edges used by bordered composers (e.g. Claude Code's input box).
_BOX_EDGE_CHARS = "│┃|▌▐"

# Block cells some TUIs paint as a caret. Stripped from composer content so a
# painted cursor cannot make an empty composer look non-empty (a cursor cell
# adjacent to real text keeps the row non-empty as required).
_CURSOR_CELL_CHARS = "▌▐█▉▊▋▍▎▏"


def _resolve_composer_provider(agent: str, command: str = "") -> str:
    """Map a wrapper agent to a composer profile. Empty string = unknown."""
    if agent in _COMPOSER_PROFILES:
        return agent
    if agent.startswith("claude-"):
        return "claude"
    if agent.startswith("codex-"):
        return "codex"
    if agent.startswith("fable"):
        return "claude"  # fable-* wrappers run the Claude Code CLI
    stem = Path(command).stem.lower() if command else ""
    if stem in _COMPOSER_PROFILES:
        return stem
    return ""


def _normalize_activity_screen(screen: str, provider: str) -> str:
    """Remove only a positively empty composer row from activity hashing.

    Rotating provider suggestions change many visible cells while the child is
    idle.  Hashing them verbatim keeps `/api/status` falsely busy forever.
    Replacing the complete row is safe only after the same provider-shaped
    parser used by the injection guard proves it empty; real drafts, paste
    pills, tool output and thinking/status rows remain byte-significant.
    """
    profile = _COMPOSER_PROFILES.get(provider or "")
    if not profile:
        return screen
    state, _content, row = _composer_state(
        screen,
        tuple(profile.get("markers", ())),
        tuple(profile.get("placeholders", ())),
        profile.get("separator", " "),
        bool(profile.get("empty_requires_separator", False)),
    )
    if state != "empty" or row < 0:
        return screen
    lines = screen.split("\n")
    # id4083/id4139 D1: the composer row index comes from splitlines(); when
    # the screen carries splitlines-only breaks (U+2028/U+2029/U+0085/\v/\f
    # in transcript content) the two representations diverge and blanking
    # could hit the wrong row — erasing real status while keeping the rotating
    # suggestion. Fail closed: keep the raw screen (counts as real activity).
    if len(lines) != len(screen.splitlines()):
        return screen
    if row >= len(lines):
        return screen
    lines[row] = " " * len(lines[row])
    return "\n".join(lines)


def _strip_composer_row(line: str) -> str:
    # Strip ASCII space/tab and box edges only — NBSP must survive because it
    # is provider-shaped evidence (the live Claude marker separator).
    return line.strip(" \t").strip(_BOX_EDGE_CHARS).strip(" \t")


def _nospace(text: str) -> str:
    return "".join(text.split())


def _composer_state(screen: str, markers: tuple, placeholders: tuple = (),
                    separator: str = " ",
                    empty_requires_separator: bool = False):
    """Positively classify the provider composer from a screen snapshot.

    Returns (state, content, row_index) where state is one of:
      'empty'        — provider-shaped marker row with nothing (or an
                       explicitly allowed placeholder) after the separator
      'nonempty'     — provider-shaped marker row with other content
      'unrecognized' — no provider-shaped composer row visible
    The exact `separator` cell must follow the marker; when
    `empty_requires_separator` is set even an empty composer must render
    marker+separator, so a bare marker glyph in transcript output is never
    recognized. row_index is the splitlines() index of the composer row
    (or -1). content is used for hashing/equality checks only, never logged.
    """
    if not markers:
        return "unrecognized", "", -1
    lines = screen.splitlines()
    first_scanned = max(0, len(lines) - _COMPOSER_SCAN_ROWS)
    for index in range(len(lines) - 1, first_scanned - 1, -1):
        stripped = _strip_composer_row(lines[index])
        if not stripped:
            continue
        for marker in markers:
            if not stripped.startswith(marker):
                continue
            rest = stripped[len(marker):]
            if rest == "":
                if empty_requires_separator:
                    continue  # bare glyph — not this provider's composer
                return "empty", "", index
            if rest[0] != separator:
                continue  # wrong separator — not this provider's composer
            content = rest[1:].strip().strip(_CURSOR_CELL_CHARS).strip()
            if not content or content in placeholders:
                return "empty", content, index
            return "nonempty", content, index
    return "unrecognized", "", -1


def _typed_text_visible(post_screen: str, pre_screen, text: str,
                        composer_guard) -> bool:
    """Positive post-type preflight: Enter is allowed only when the composer
    region reproduces the injected text EXACTLY.

    The provider-shaped marker row must be visible and its content, extended
    greedily across the wrapped composer rows directly below it, must equal
    the injected text with no extra characters (no tolerance). Whitespace and
    box edges are ignored so line wrapping cannot break the match; matching
    never consults transcript rows outside the composer region, so stale text
    elsewhere on screen can never satisfy the check.
    """
    if pre_screen is not None and post_screen == pre_screen:
        return False
    text_ns = _nospace(text)
    if not text_ns:
        return False
    state, content, row = _composer_state(
        post_screen, composer_guard.markers, composer_guard.placeholders,
        composer_guard.separator, composer_guard.empty_requires_separator,
    )
    if state != "nonempty":
        # empty (batch vanished) or unrecognized (no positive region
        # binding — e.g. marker row scrolled out): never Enter.
        return False

    # Claude Code may collapse one atomic WriteConsoleInputW text batch into
    # an exact paste pill instead of rendering the inserted characters.  The
    # input records were already confirmed as a complete batch by
    # _write_text_batch; when the immediately preceding screen positively
    # showed an empty provider composer, this pill is positive evidence that
    # *our* batch owns the composer.  Keep the match exact and provider-bound:
    # arbitrary bracketed text or a pill present before injection must never
    # authorize Enter.
    if composer_guard.provider == "claude" and re.fullmatch(
        r"\[Pasted text #\d+\]", content
    ):
        pre_state, _pre_content, _pre_row = _composer_state(
            pre_screen or "",
            composer_guard.markers,
            composer_guard.placeholders,
            composer_guard.separator,
            composer_guard.empty_requires_separator,
        )
        return pre_state == "empty"

    accumulated = _nospace(content)
    if not text_ns.startswith(accumulated):
        return False
    lines = post_screen.splitlines()
    for line in lines[row + 1:]:
        piece = _nospace(
            _strip_composer_row(line).strip(_CURSOR_CELL_CHARS)
        )
        if not piece:
            break
        candidate = accumulated + piece
        if not text_ns.startswith(candidate):
            break  # row is not a continuation of our text (border/hints)
        accumulated = candidate
    return accumulated == text_ns


def _owned_composer_text_is_exact(screen: str, text: str,
                                  composer_guard) -> bool:
    """Prove visible composer text exactly equals our in-memory batch.

    Recovery accepts no whitespace normalization, decorated/wrapped-row
    reconstruction, paste pill, prefix, suffix, or digest match. Newlines are
    supported only when each continuation is exposed as the next raw screen
    row byte-for-codepoint; ambiguous TUI indentation or soft wrapping fails
    closed. Live queue delivery is flattened before injection, but this strict
    path also covers direct multiline callers without pretending that layout
    normalization proves ownership.
    """
    if not isinstance(text, str) or not text or "\r" in text:
        return False
    state, content, row = _composer_state(
        screen,
        composer_guard.markers,
        composer_guard.placeholders,
        composer_guard.separator,
        composer_guard.empty_requires_separator,
    )
    logical_lines = text.split("\n")
    if (
        state != "nonempty"
        or row < 0
        or content != logical_lines[0]
    ):
        return False
    if len(logical_lines) == 1:
        return True
    screen_lines = screen.split("\n")
    if len(screen_lines) != len(screen.splitlines()):
        return False
    if row + len(logical_lines) > len(screen_lines):
        return False
    return all(
        screen_lines[row + offset] == expected
        for offset, expected in enumerate(logical_lines[1:], start=1)
    )


_CODEX_PASTED_CONTENT_PILL = re.compile(
    r"\[Pasted Content ([1-9][0-9]*|0) chars\]"
)


def _codex_cancelled_owned_paste_pill(screen, text: str,
                                      composer_guard) -> str | None:
    """Return an exact Codex paste pill bound to this cancelled text batch.

    This helper is intentionally unusable as generic composer ownership. It is
    called on the private screen captured immediately after _injection_attempt
    withheld Enter, and accepts only Codex's exact live shape whose canonical
    decimal character count equals Python len(text).
    """
    if (
        not isinstance(screen, str)
        or not isinstance(text, str)
        or not text
        or composer_guard is None
        or composer_guard.provider != "codex"
    ):
        return None
    state, content, row = _composer_state(
        screen,
        composer_guard.markers,
        composer_guard.placeholders,
        composer_guard.separator,
        composer_guard.empty_requires_separator,
    )
    if state != "nonempty" or row < 0:
        return None
    match = _CODEX_PASTED_CONTENT_PILL.fullmatch(content)
    if match is None or match.group(1) != str(len(text)):
        return None
    return content


def _owned_clear_stability_observation(screen: str, text: str,
                                       composer_guard,
                                       candidate: dict | None,
                                       owned_paste_proof: dict | None = None):
    """Track an exact-owned clear candidate across due recovery probes.

    Return (exact, armed). Arming requires two consecutive exact observations
    whose full screen snapshots satisfy the admission guard's existing
    _stable_against discipline. Generic exact text remains the default; a
    Codex paste pill additionally needs the private, immediate-cancellation
    proof. Any other observation discards the candidate; a changed
    transcript/status becomes the first sighting of a new candidate and
    therefore cannot authorize Escape.
    """
    if candidate is None:
        return False, False
    state, _content, row = _composer_state(
        screen,
        composer_guard.markers,
        composer_guard.placeholders,
        composer_guard.separator,
        composer_guard.empty_requires_separator,
    )
    direct_exact = _owned_composer_text_is_exact(
        screen, text, composer_guard
    )
    current_paste_pill = _codex_cancelled_owned_paste_pill(
        screen, text, composer_guard
    )
    owned_paste_pill = (
        owned_paste_proof.get("pill")
        if owned_paste_proof is not None else None
    )
    proven_paste_exact = (
        owned_paste_pill is not None
        and current_paste_pill == owned_paste_pill
    )
    if owned_paste_pill is not None and not (
        proven_paste_exact or direct_exact
    ):
        # The immediate cancellation-bound pill is no longer the composer.
        # An operator edit/count change destroys that one-shot provenance;
        # seeing the same pill later cannot resurrect it.
        owned_paste_proof.clear()
    if (
        state != "nonempty"
        or row < 0
        or not (direct_exact or proven_paste_exact)
    ):
        candidate.clear()
        return False, False

    previous_screen = candidate.get("screen")
    previous_row = candidate.get("row", -1)
    previous_hits = candidate.get("hits", 0)
    stable = (
        isinstance(previous_screen, str)
        and composer_guard._stable_against(
            previous_screen, previous_row, screen, row
        )
    )
    hits = previous_hits + 1 if stable else 1
    candidate.clear()
    candidate.update({"screen": screen, "row": row, "hits": hits})
    return True, hits >= 2


class _ComposerAdmissionGuard:
    """Stateful fail-closed admission: the child must be stably idle and the
    provider composer positively recognized as empty.

    classify() consumes one screen snapshot per call and tracks stability
    across consecutive calls. The ONLY tolerated difference between two
    consecutive reads is a proven cursor-cell delta inside the composer row
    itself (same row index, identical canonical content, both positively
    empty). Any change anywhere else — including status rows adjacent to the
    composer — reads as an active child. States that defer:
      'busy'                  — screen changed since the previous read (or
                                first read of an episode)
      'nonempty-composer'     — composer has content
      'unrecognized-composer' — no positive composer recognition for this
                                provider/screen
    """

    def __init__(self, provider: str, markers=None, placeholders=None,
                 stable_reads: int = 2):
        profile = _COMPOSER_PROFILES.get(provider or "", {})
        self.provider = provider or ""
        if markers:
            # Explicit operator override: custom markers use a plain-space
            # separator and allow bare-marker empty rows.
            self.markers = tuple(markers)
            self.separator = " "
            self.empty_requires_separator = False
        else:
            self.markers = tuple(profile.get("markers", ()))
            self.separator = profile.get("separator", " ")
            self.empty_requires_separator = bool(
                profile.get("empty_requires_separator", False)
            )
        self.placeholders = tuple(
            placeholders if placeholders is not None
            else profile.get("placeholders", ())
        )
        self.stable_reads = max(2, int(stable_reads))
        self._last_screen = None
        self._last_row = -1
        self._stable_hits = 0
        self._alerted = set()

    def reset_stability(self):
        self._last_screen = None
        self._last_row = -1
        self._stable_hits = 0

    def reset_episode(self):
        self.reset_stability()
        self._alerted = set()

    def should_alert(self, classification) -> bool:
        """Dedupe deferral alerts: each classification is emitted at most
        once per episode (the alerted-set is bounded by the classification
        enum; episodes end on injection or reset_episode). An alternating
        A,B,A sequence emits A and B once each — never A twice."""
        if classification in self._alerted:
            return False
        self._alerted.add(classification)
        return True

    def _composer_row_canonical(self, line: str) -> str:
        return _strip_composer_row(line).strip(_CURSOR_CELL_CHARS)

    def _stable_against(self, prev: str, prev_row: int, screen: str,
                        row: int) -> bool:
        if prev == screen:
            return True
        if row < 0 or row != prev_row:
            return False
        prev_lines = prev.splitlines()
        lines = screen.splitlines()
        if len(prev_lines) != len(lines):
            return False
        for index, (old, new) in enumerate(zip(prev_lines, lines)):
            if old == new:
                continue
            if index != row:
                return False  # any non-composer-row change = active child
            # Composer row itself: tolerate only a cursor-cell delta with
            # identical canonical content.
            if (self._composer_row_canonical(old)
                    != self._composer_row_canonical(new)):
                return False
        return True

    def classify(self, screen: str) -> str:
        state, _content, row = _composer_state(
            screen, self.markers, self.placeholders,
            self.separator, self.empty_requires_separator,
        )
        if state == "unrecognized":
            self.reset_stability()
            return "unrecognized-composer"
        if state == "nonempty":
            self.reset_stability()
            return "nonempty-composer"
        prev = self._last_screen
        prev_row = self._last_row
        self._last_screen = screen
        self._last_row = row
        if prev is None:
            self._stable_hits = 1
            return "busy"
        if self._stable_against(prev, prev_row, screen, row):
            self._stable_hits += 1
        else:
            self._stable_hits = 1
            return "busy"
        if self._stable_hits >= self.stable_reads:
            return "admit"
        return "busy"

    def classify_active(self, screen: str) -> str:
        """Admit an owner interrupt into an active Codex turn only when the
        provider composer is positively recognized as empty.

        Normal agent triggers still use classify() and retain the full-screen
        stable-idle requirement. The exact post-type composer equality check
        remains mandatory before Enter is emitted.
        """
        state, _content, _row = _composer_state(
            screen, self.markers, self.placeholders,
            self.separator, self.empty_requires_separator,
        )
        if state == "unrecognized":
            self.reset_stability()
            return "unrecognized-composer"
        if state == "nonempty":
            self.reset_stability()
            return "nonempty-composer"
        return "admit"


class _SafeguardRetryController:
    """Pure state machine: two stable sightings, bounded retries per child PID."""

    def __init__(self, max_retries: int = 2, stable_polls: int = 2):
        self.max_retries = max(0, int(max_retries))
        self.stable_polls = max(1, int(stable_polls))
        self.pid = None
        self.retry_count = 0
        self.visible_fingerprint = None
        self.candidate_fingerprint = None
        self.candidate_hits = 0
        self.clean_hits = 0
        self.escalated_episode = False
        self.ambiguous_episode_reported = False
        self.capacity_visible_fingerprint = None
        self.capacity_candidate_fingerprint = None
        self.capacity_candidate_hits = 0
        self.capacity_clean_hits = 0

    def _observe_capacity(self, screen_text: str):
        classification = _classify_fable_capacity_screen(screen_text)
        if classification is None:
            self.capacity_clean_hits += 1
            self.capacity_candidate_fingerprint = None
            self.capacity_candidate_hits = 0
            if self.capacity_clean_hits >= 2:
                self.capacity_visible_fingerprint = None
            return None
        self.capacity_clean_hits = 0
        fingerprint = _capacity_screen_fingerprint(screen_text)
        if fingerprint == self.capacity_visible_fingerprint:
            return None
        if fingerprint != self.capacity_candidate_fingerprint:
            self.capacity_candidate_fingerprint = fingerprint
            self.capacity_candidate_hits = 1
            return None
        self.capacity_candidate_hits += 1
        if self.capacity_candidate_hits < self.stable_polls:
            return None
        # Do not commit dedupe state until the monitor confirms delivery. A
        # transient callback failure therefore retries the same visible event.
        self.capacity_candidate_hits = self.stable_polls
        return {
            "action": "capacity",
            "category": "fable_limit",
            "fingerprint": fingerprint,
        }

    def confirm_capacity_delivery(self, fingerprint: str):
        if fingerprint != self.capacity_candidate_fingerprint:
            return
        self.capacity_visible_fingerprint = fingerprint
        self.capacity_candidate_fingerprint = None
        self.capacity_candidate_hits = 0

    def observe(self, screen_text: str, pid: int | None):
        if pid != self.pid:
            self.pid = pid
            self.retry_count = 0
            self.visible_fingerprint = None
            self.candidate_fingerprint = None
            self.candidate_hits = 0
            self.clean_hits = 0
            self.escalated_episode = False
            self.ambiguous_episode_reported = False
            self.capacity_visible_fingerprint = None
            self.capacity_candidate_fingerprint = None
            self.capacity_candidate_hits = 0
            self.capacity_clean_hits = 0

        capacity_decision = self._observe_capacity(screen_text)

        classification = _classify_fable_safeguard_screen(screen_text)
        if classification is None:
            self.clean_hits += 1
            if self.clean_hits >= 2:
                self.visible_fingerprint = None
                self.candidate_fingerprint = None
                self.candidate_hits = 0
                self.escalated_episode = False
                self.ambiguous_episode_reported = False
            return capacity_decision
        self.clean_hits = 0

        fingerprint = _safeguard_screen_fingerprint(screen_text)
        if classification == "ambiguous":
            if self.ambiguous_episode_reported:
                return None
            self.ambiguous_episode_reported = True
            return {"action": "ambiguous", "fingerprint": fingerprint}

        if fingerprint == self.visible_fingerprint:
            return None
        if fingerprint != self.candidate_fingerprint:
            self.candidate_fingerprint = fingerprint
            self.candidate_hits = 1
            return None
        self.candidate_hits += 1
        if self.candidate_hits < self.stable_polls:
            return None

        self.visible_fingerprint = fingerprint
        self.candidate_fingerprint = None
        self.candidate_hits = 0
        if self.retry_count >= self.max_retries:
            if self.escalated_episode:
                return None
            self.escalated_episode = True
            return {
                "action": "escalate",
                "attempt": self.retry_count,
                "fingerprint": fingerprint,
            }
        self.retry_count += 1
        return {
            "action": "retry",
            "attempt": self.retry_count,
            "fingerprint": fingerprint,
        }

    def cancel_retry(self):
        """Return a reserved retry token when the screen changed pre-input."""
        if self.retry_count > 0:
            self.retry_count -= 1
        self.visible_fingerprint = None


def _append_safeguard_audit(path: Path, event: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")


def _make_safeguard_emitter(*, agent: str, pid_holder, queue_file: Path,
                            event_callback=None):
    audit_path = Path(queue_file).parent / f"{agent}_safeguard-retry.jsonl"

    def emit(event):
        pid = pid_holder[0] if pid_holder is not None else None
        payload = {"agent": agent, "pid": pid, **event}
        audit_ok = False
        try:
            _append_safeguard_audit(audit_path, payload)
            audit_ok = True
        except Exception:
            pass
        if event_callback:
            try:
                callback_result = event_callback(payload)
            except Exception:
                return False
            # Existing callbacks returning None remain successful; the wrapper
            # callback now returns an explicit bool for capacity delivery.
            return callback_result is not False
        return audit_ok

    return emit


def _start_safeguard_monitor(*, agent: str, pid_holder, queue_file: Path,
                             enabled: bool, max_retries: int,
                             enter_backend: str, event_callback=None,
                             event_sink=None, poll_seconds: float = 0.5,
                             stop_event=None):
    if not _is_fable_lane(agent):
        return None
    # Capacity observation remains live when automatic safeguard-menu retry is
    # disabled. That rollback mode suppresses all safeguard-menu decisions and
    # can never select a menu option.
    controller = _SafeguardRetryController(
        max_retries=max_retries if enabled else 0
    )
    emit = event_sink or _make_safeguard_emitter(
        agent=agent,
        pid_holder=pid_holder,
        queue_file=queue_file,
        event_callback=event_callback,
    )

    def loop():
        last_error = None
        last_error_at = 0.0
        while stop_event is None or not stop_event.is_set():
            wait_seconds = max(0.1, poll_seconds)
            if stop_event is None:
                time.sleep(wait_seconds)
            elif stop_event.wait(wait_seconds):
                break
            try:
                pid = pid_holder[0] if pid_holder is not None else None
                if not pid:
                    controller.observe("", None)
                    continue
                screen = _read_visible_console_text()
                decision = controller.observe(screen, int(pid))
                if not decision:
                    continue
                if not enabled and decision["action"] != "capacity":
                    # Rollback mode observes capacity only: safeguard menus are
                    # still blocked by injection admission, but never alert,
                    # escalate, or receive monitor input.
                    continue
                if decision["action"] == "retry" and enabled:
                    # Re-read immediately before input; any redraw/wording
                    # change converts the action into a harmless audit event.
                    if _classify_fable_safeguard_screen(
                        _read_visible_console_text()
                    ) != "strict":
                        controller.cancel_retry()
                        emit({**decision, "action": "cancelled-redraw"})
                        continue
                    if not _select_second_menu_option(
                        enter_backend=enter_backend,
                        expected_fingerprint=decision.get("fingerprint"),
                    ):
                        # Down may already have been delivered.  Never press
                        # Enter or retry from an unknown pointer position.
                        emit({**decision, "action": "selection-cancelled"})
                        continue
                delivered = emit(decision)
                if decision["action"] == "capacity" and delivered is not False:
                    controller.confirm_capacity_delivery(
                        decision["fingerprint"]
                    )
            except Exception as exc:
                # A Win32/input failure must not silently kill the only
                # safeguard monitor.  Alert without logging prompt text and
                # rate-limit identical failures while keeping the thread live.
                error_type = type(exc).__name__
                now = time.monotonic()
                if error_type != last_error or now - last_error_at >= 60.0:
                    emit({
                        "action": "monitor-error",
                        "error_type": error_type,
                    })
                    last_error = error_type
                    last_error_at = now

    thread = threading.Thread(
        target=loop, daemon=True, name=f"safeguard-retry-{agent}",
    )
    thread.start()
    return thread


def get_activity_checker(pid_holder, agent_name="unknown", trigger_flag=None):
    """Return a callable that detects agent activity by diffing visible characters.

    Counts how many visible characters changed since last poll. Filters out
    invisible buffer noise (ConPTY artifacts, cursor jitter, timer ticks) by
    requiring a minimum number of changed cells. Uses hysteresis: goes active
    immediately on significant change, requires sustained quiet to go idle.

    trigger_flag: shared [bool] list — set to [True] by queue watcher when a
    message is injected. Forces active state immediately (covers thinking phase).
    pid_holder: not used for screen hashing, but kept for signature compatibility.
    """
    import array as _array
    import os as _os

    last_chars = [None]  # previous poll's character bytes
    handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    MIN_CHANGED_CELLS = 10  # idle noise is 2-5 cells; real work is 50+
    IDLE_COOLDOWN = 5       # need 5 consecutive idle polls (5s) before going idle
    _consecutive_idle = [0]
    _is_active = [False]
    activity_provider = _resolve_composer_provider(agent_name)

    def check():
        # External trigger: queue watcher injected a message → force active
        triggered = False
        if trigger_flag is not None and trigger_flag[0]:
            trigger_flag[0] = False
            triggered = True
            _consecutive_idle[0] = 0
            _is_active[0] = True

        # Get buffer dimensions
        csbi = _CONSOLE_SCREEN_BUFFER_INFO()
        if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(csbi)):
            return _is_active[0]

        rect = csbi.srWindow
        width = rect.Right - rect.Left + 1
        height = rect.Bottom - rect.Top + 1
        if width <= 0 or height <= 0:
            return _is_active[0]

        # Read visible window
        buffer_size = _COORD(width, height)
        buffer_coord = _COORD(0, 0)
        read_rect = _SMALL_RECT(rect.Left, rect.Top, rect.Right, rect.Bottom)
        char_info_array = (_CHAR_INFO * (width * height))()

        ok = kernel32.ReadConsoleOutputW(
            handle, char_info_array, buffer_size, buffer_coord,
            ctypes.byref(read_rect),
        )
        if not ok:
            return _is_active[0]

        # Extract visible characters only (skip attributes)
        raw = bytes(char_info_array)
        shorts = _array.array("H")
        shorts.frombytes(raw)
        char_units = shorts[::2]
        if activity_provider:
            rows = []
            for row in range(height):
                start = row * width
                rows.append("".join(
                    chr(value) for value in char_units[start:start + width]
                ))
            normalized = _normalize_activity_screen(
                "\n".join(rows), activity_provider
            )
            char_data = normalized.replace("\n", "").encode(
                "utf-16-le", "surrogatepass"
            )
        else:
            char_data = char_units.tobytes()

        # Count how many characters actually changed
        prev = last_chars[0]
        n_changed = 0
        if prev is not None and len(prev) == len(char_data):
            if prev != char_data:  # fast path: skip counting if identical
                for i in range(0, len(prev), 2):
                    if prev[i:i+2] != char_data[i:i+2]:
                        n_changed += 1
        significant = n_changed >= MIN_CHANGED_CELLS
        last_chars[0] = char_data

        # Hysteresis: active immediately on significant change or trigger,
        # idle only after IDLE_COOLDOWN consecutive quiet polls
        if significant or triggered:
            _consecutive_idle[0] = 0
            _is_active[0] = True
        else:
            _consecutive_idle[0] += 1
            if _consecutive_idle[0] >= IDLE_COOLDOWN:
                _is_active[0] = False

        return _is_active[0]

    return check


def _vt_keepalive_thread():
    """Re-assert VT mode every 10ms in case the child clears it.

    Newer codex builds appear to call SetConsoleMode themselves around their
    frame draws, sometimes stripping ENABLE_VIRTUAL_TERMINAL_PROCESSING in the
    process. A one-shot enable at launch wins the first frame then loses; a
    slow keepalive wins most frames but leaks during redraws. We need to win
    the race, so we hammer SetConsoleMode at 10ms intervals.

    Single long-lived CONOUT$ handle (opened once) means each iteration is just
    one SetConsoleMode syscall — ~100 per second, trivial cost.
    """
    import threading as _threading
    import time as _time

    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetConsoleMode.restype = wintypes.BOOL
    kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.SetConsoleMode.restype = wintypes.BOOL

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    REQUIRED_BITS = ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT

    out_handle = kernel32.CreateFileW(
        "CONOUT$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, 0, None,
    )
    if not out_handle or out_handle == INVALID_HANDLE_VALUE:
        return  # no console — nothing to keep alive

    def _loop():
        mode = wintypes.DWORD(0)
        # Tight initial burst (1ms × ~500 iters ≈ 0.5s) to win the race against
        # the child's startup-time SetConsoleMode calls, then settle to a slower
        # steady-state rate.
        for _ in range(500):
            try:
                if kernel32.GetConsoleMode(out_handle, ctypes.byref(mode)):
                    if (mode.value & REQUIRED_BITS) != REQUIRED_BITS:
                        kernel32.SetConsoleMode(out_handle, mode.value | REQUIRED_BITS)
            except Exception:
                pass
            _time.sleep(0.001)
        while True:
            try:
                if kernel32.GetConsoleMode(out_handle, ctypes.byref(mode)):
                    if (mode.value & REQUIRED_BITS) != REQUIRED_BITS:
                        kernel32.SetConsoleMode(out_handle, mode.value | REQUIRED_BITS)
            except Exception:
                pass
            _time.sleep(0.01)

    t = _threading.Thread(target=_loop, daemon=True, name="vt-keepalive")
    t.start()


def run_agent(command, extra_args, cwd, env, queue_file, agent, no_restart, start_watcher, strip_env=None, pid_holder=None, session_name=None, inject_env=None, inject_delay: float = 0.3, enter_backend: str = "console_input", safeguard_auto_retry: bool = False, safeguard_max_retries: int = 2, safeguard_event_callback=None, injection_admission_guard: bool = False, composer_provider: str = "", composer_markers=None, composer_placeholders=None, composer_stable_reads: int = 2):
    """Run agent as a direct subprocess, inject via Win32 console."""
    # Newer codex/claude/etc TUIs require VT processing on the parent console;
    # without this, ANSI escape sequences leak as text into the terminal.
    # One-shot at startup (with diagnostic print) then a keepalive thread.
    enable_vt_mode()
    _vt_keepalive_thread()

    if inject_env:
        env = {**env, **inject_env}
    # Queue-triggered Enter must be guarded for every Fable session, even when
    # automatic option selection is disabled as a rollback measure.
    safeguard_guard_enabled = _is_fable_lane(agent)
    safeguard_monitor_enabled = bool(
        safeguard_auto_retry and safeguard_guard_enabled
    )
    # Injection alerts are emitted for every provider (audit file + chat
    # callback) — the admission gate must cover Codex too, not only Fable.
    injection_emit = _make_safeguard_emitter(
        agent=agent,
        pid_holder=pid_holder,
        queue_file=Path(queue_file),
        event_callback=safeguard_event_callback,
    )
    safeguard_emit = injection_emit if safeguard_guard_enabled else None
    _start_safeguard_monitor(
        agent=agent,
        pid_holder=pid_holder,
        queue_file=Path(queue_file),
        enabled=safeguard_monitor_enabled,
        max_retries=safeguard_max_retries,
        enter_backend=enter_backend,
        event_callback=safeguard_event_callback,
        event_sink=safeguard_emit,
    )
    if injection_admission_guard:
        # Fail-closed queue-injection admission gate (per-agent config
        # opt-in): single attempt per watcher poll, watcher owns retries and
        # durable-queue consumption.
        provider = composer_provider or _resolve_composer_provider(agent, command)
        guard = _ComposerAdmissionGuard(
            provider,
            markers=composer_markers,
            placeholders=composer_placeholders,
            stable_reads=composer_stable_reads,
        )
        start_watcher(_make_admitted_injector(
            delay=inject_delay,
            enter_backend=enter_backend,
            safeguard_guard=safeguard_guard_enabled,
            composer_guard=guard,
            emit=injection_emit,
        ))
    else:
        # Legacy injector (pre-existing contract): blocking deferral loop,
        # Fable safeguard-menu protections only.
        start_watcher(lambda text: inject(
            text,
            delay=inject_delay,
            enter_backend=enter_backend,
            safeguard_guard=safeguard_guard_enabled,
            guard_event_callback=safeguard_emit,
        ))

    while True:
        try:
            proc = subprocess.Popen([command] + extra_args, cwd=cwd, env=env)
            if pid_holder is not None:
                pid_holder[0] = proc.pid
            proc.wait()
            if pid_holder is not None:
                pid_holder[0] = None

            if no_restart:
                break

            print(f"\n  {agent.capitalize()} exited (code {proc.returncode}).")
            print(f"  Restarting in 3s... (Ctrl+C to quit)")
            time.sleep(3)
        except KeyboardInterrupt:
            break
