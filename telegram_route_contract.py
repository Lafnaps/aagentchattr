"""Exported wire contract + real FastAPI/TestClient fixture for the Telegram
owner bridge (L-CHATT/L-TG of ORCH-MON-TELEGRAM-R1).

The previous Telegram candidate was blocked because its transport client posted
to an *invented* ``/channels/{channel}/messages`` API the accepted server never
exposed (Sol review C1).  This module is the server-truth correction: it names
the real bounded loopback endpoints, gives their exact request/response shapes,
and provides a factory that spins up the accepted agentchattr app through a real
``starlette`` ``TestClient`` so the bridge successor codes and tests against the
same contract the server actually serves.

The two endpoints reuse the accepted store/routing/delivery machinery; they are
NOT a parallel message system.  The bridge must use ONLY these paths:

* ``POST /api/telegram/inbound``  — deliver an owner Telegram message to the
  canonical responder ``codex-sol`` (two-factor gated).  Idempotent on
  ``correlation_id``: an authenticated retry (sequential, concurrent, after a
  lost 200 or a delivery-backpressure 503, or after a restart) resolves to the
  one durable owner message, the same receipt ``cursor`` and one logical wake;
  reusing a ``correlation_id`` for a different envelope fails closed generically.
* ``GET  /api/telegram/outbound`` — poll ``codex-sol``'s replies bound for
  ``owner-telegram`` (route-bearer gated, echo-excluded).  An ORDINARY canonical
  ``codex-sol`` reply is delivered without any fabricated recipient/reply/
  metadata; paging is lossless (ascending scan, at most ``limit`` per page,
  ``cursor`` = last covered id — no skip/reorder/duplicate).

NOTE: :func:`build_contract_harness` mutates the process-wide ``app`` singleton
(there is one server per process).  Always call :meth:`RouteContractHarness.close`
(or use it as a context manager) to restore the prior globals.
"""

from __future__ import annotations

import copy
from pathlib import Path

import app
import mcp_bridge
import telegram_route
from agents import AgentTrigger
from registry import RuntimeRegistry
from router import Router
from store import MessageStore


INBOUND_PATH = "/api/telegram/inbound"
OUTBOUND_PATH = "/api/telegram/outbound"

CANONICAL_RESPONDER = telegram_route.CANONICAL_RESPONDER   # "codex-sol"
OWNER_IDENTITY = telegram_route.OWNER_IDENTITY             # "owner-telegram"
ROUTE_CHANNEL = telegram_route.ROUTE_CHANNEL               # "owner-telegram"


def example_inbound_request(
    *, text: str = "What is the current task status?",
    correlation_id: str = "tg-42",
    telegram_user_id: int | str = 100200300,
    telegram_chat_id: int | str = 100200300,
    telegram_message_id: int | str = 4242,
    recipient: str | None = None,
    channel: str | None = None,
) -> dict:
    """The exact JSON body the bridge POSTs to :data:`INBOUND_PATH`.

    ``recipient`` defaults to the canonical responder; the compatibility alias
    ``"@codex"``/``"codex"`` is also accepted and resolves to ``codex-sol``.
    ``channel`` defaults to ``owner-telegram`` (``"#owner-telegram"`` accepted).
    The bridge sends its route bearer in the ``Authorization: Bearer`` header
    (never in the body).
    """
    body: dict = {
        "text": text,
        "correlation_id": correlation_id,
        "telegram_user_id": telegram_user_id,
        "telegram_chat_id": telegram_chat_id,
        "telegram_message_id": telegram_message_id,
    }
    if recipient is not None:
        body["recipient"] = recipient
    if channel is not None:
        body["channel"] = channel
    return body


def example_inbound_response(*, correlation_id: str = "tg-42",
                             cursor: int = 0) -> dict:
    """The exact JSON shape :data:`INBOUND_PATH` returns on success (HTTP 200)."""
    return {
        "status": "queued",
        "recipient": CANONICAL_RESPONDER,
        "channel": ROUTE_CHANNEL,
        "correlation_id": correlation_id,
        "cursor": cursor,
    }


def example_outbound_response(*, messages: list[dict] | None = None,
                              cursor: int = 0) -> dict:
    """The exact JSON shape :data:`OUTBOUND_PATH` returns (HTTP 200).

    Each entry preserves the monotonic ``id`` cursor, the canonical
    ``recipient`` (``owner-telegram``), the ``correlation_id`` linking the reply
    to its inbound question, the source Telegram ``reply_to_message_id``, plus
    ``sender``/``text``/``channel``.  The bridge
    resumes from ``cursor`` via ``?since_id=<cursor>``; ``cursor`` is the id of
    the last message COVERED by this page (scanned, whether or not selected), so
    forward polling never rescans, skips or reorders a reply.
    """
    return {"messages": messages or [], "cursor": cursor}


class RouteContractHarness:
    """A live, hermetic instance of the accepted server route contract.

    Attributes:
        client: a ``starlette`` ``TestClient`` bound to a loopback source
            address (so the loopback-only middleware admits it).
        guard: the provisioned :class:`telegram_route.TelegramRouteGuard`.
        data_dir: the temp data dir holding the store, queues and route config.
    """

    def __init__(self, client, guard, data_dir: Path, restore, saved_mw):
        self.client = client
        self.guard = guard
        self.data_dir = Path(data_dir)
        self._restore = restore
        self._saved_mw = saved_mw
        self._closed = False

    def responder_queue_path(self, responder: str = CANONICAL_RESPONDER) -> Path:
        """Durable per-agent delivery queue file for a responder."""
        return self.data_dir / f"{responder}_queue.jsonl"

    def __enter__(self) -> "RouteContractHarness":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.client.close()
        except Exception:
            pass
        # Restore the prior middleware stack and every mutated global.
        app.app.user_middleware[:] = self._saved_mw
        app.app.middleware_stack = None
        self._restore()


_HARNESS_GLOBALS = (
    "store", "registry", "router", "agents", "session_engine", "session_store",
    "jobs", "schedules", "summaries", "rules", "config", "room_settings",
    "telegram_route_guard", "_event_loop",
)


def build_contract_harness(
    data_dir: str | Path,
    bearer: str,
    allowlist,
    *,
    session_token: str = "CONTRACT-SESSION-TOKEN",
    client_addr: tuple[str, int] = ("127.0.0.1", 9),
) -> RouteContractHarness:
    """Wire the accepted app for the route contract and return a live harness.

    Uses TEMP-only stores under ``data_dir``.  Provisions the two-factor guard
    with ``bearer`` and ``allowlist`` (an iterable of ``(user_id, chat_id)``
    pairs).  Installs the real security middleware and returns a loopback-bound
    ``TestClient``.  No network, no live process, no live registry.
    """
    from starlette.testclient import TestClient

    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    saved = {name: getattr(app, name) for name in _HARNESS_GLOBALS}
    saved_mcp = {
        "store": mcp_bridge.store,
        "registry": mcp_bridge.registry,
        "channel_message_writer": mcp_bridge.channel_message_writer,
        "room_settings": mcp_bridge.room_settings,
    }
    saved_mw = app.app.user_middleware[:]

    def _restore():
        for name in _HARNESS_GLOBALS:
            setattr(app, name, saved[name])
        mcp_bridge.store = saved_mcp["store"]
        mcp_bridge.registry = saved_mcp["registry"]
        mcp_bridge.channel_message_writer = saved_mcp["channel_message_writer"]
        mcp_bridge.room_settings = saved_mcp["room_settings"]

    try:
        registry = RuntimeRegistry(data_dir=str(data_dir))
        registry.seed({"codex": {"label": "Codex", "color": "#10a37f"}})
        store = MessageStore(str(data_dir / "messages.jsonl"))
        guard = telegram_route.TelegramRouteGuard(
            str(data_dir / "telegram_route.json")
        )
        guard.provision(bearer, allowlist)

        app.config = {
            "server": {"data_dir": str(data_dir), "port": 8300},
            "images": {"upload_dir": str(data_dir / "uploads")},
        }
        app.room_settings = {
            "channels": ["general"],
            "max_channels": 64,
            "max_discovered_channels": 128,
            "catalogue_revision": 0,
        }
        app.store = store
        app.registry = registry
        app.router = Router(["codex"], default_mention="none")
        app.agents = AgentTrigger(registry, str(data_dir))
        app.session_engine = None
        app.session_store = None
        app.jobs = None
        app.schedules = None
        app.summaries = None
        app.rules = None
        app.telegram_route_guard = guard
        # No server event loop in the fixture: the endpoints wake the responder
        # explicitly, so the async store-callback dispatch stays inert.
        app._event_loop = None

        mcp_bridge.store = store
        mcp_bridge.registry = registry
        mcp_bridge.channel_message_writer = app.store_channel_message
        mcp_bridge.room_settings = app.room_settings

        # Rebuild the middleware stack with a known session token so the real
        # SecurityMiddleware (loopback gate for /api/telegram/) is exercised.
        app.app.user_middleware[:] = [
            mw for mw in app.app.user_middleware
            if mw.cls.__name__ != "SecurityMiddleware"
        ]
        app.app.middleware_stack = None
        app._install_security_middleware(
            session_token, {"server": {"port": 8300}}
        )
        client = TestClient(app.app, client=client_addr)
    except Exception:
        app.app.user_middleware[:] = saved_mw
        app.app.middleware_stack = None
        _restore()
        raise

    return RouteContractHarness(client, guard, data_dir, _restore, saved_mw)
