"""Telegram owner-route: canonical ``codex-sol`` responder + two-factor wake gate.

L-CHATT items 5-6 of the owner-approved ``ORCH-MON-TELEGRAM-R1`` plan.  This
module adds ONLY the missing approved route/security contract on top of the
accepted agentchattr store, routing and delivery machinery — it is not a
parallel message system.  Messages still live in the one :class:`MessageStore`
and wakes still use the one per-agent delivery queue.

Contract enforced here:

* **Canonical durable route.**  Telegram-owner messages are delivered to the
  canonical responder ``codex-sol``.  The public compatibility alias ``@codex``
  resolves to ``codex-sol`` — never the reverse — and no status, receipt or
  runtime identity is ever renamed to the legacy ``codex`` name.
* **Two-factor privileged wake.**  The ``owner-telegram`` service identity may
  take the privileged wake path only when BOTH the Telegram user/chat pair is
  in the configured allowlist AND the request presents the route's own bearer.
  Either factor missing or wrong is rejected before any persistence or wake.
* **Secret-safety.**  The raw route bearer is never stored or logged; only a
  salted HMAC-SHA256 digest is persisted.  Bearers, message bodies, Telegram
  user/chat ids and correlation ids never enter logs, metrics, audit metadata
  or error/response diagnostics.  The request-handling code does no logging at
  all; the only console output is the owner-run provisioning CLI, whose messages
  carry the store path and pair count but never the bearer (read via a hidden
  prompt) or any message body/id/correlation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
from pathlib import Path


# --- Canonical route identities (never the legacy ``codex`` name) ------------

#: The canonical durable responder for Telegram-owner messages.
CANONICAL_RESPONDER = "codex-sol"

#: The service identity that authors inbound owner messages and is the
#: recipient of outbound replies.  Not a human/browser alias.
OWNER_IDENTITY = "owner-telegram"

#: The dedicated channel (displayed ``#owner-telegram``) that carries the
#: Telegram-owner conversation in the shared message store.
ROUTE_CHANNEL = "owner-telegram"

#: Public compatibility recipient tokens that RESOLVE to the canonical
#: responder.  The legacy ``codex`` is accepted as an inbound *address* only;
#: it is never emitted as an identity, receipt or status.
_RECIPIENT_ALIASES = {
    "codex-sol": CANONICAL_RESPONDER,
    "codex": CANONICAL_RESPONDER,
}


def canonicalize_recipient(value: object) -> str | None:
    """Resolve a recipient token to the canonical responder, or ``None``.

    ``None``/empty defaults to the canonical responder.  ``@codex`` / ``codex``
    are accepted compatibility aliases that resolve to ``codex-sol``.  The
    mapping is one-way: it can only ever yield ``codex-sol``, so a caller can
    never coerce a message onto the legacy ``codex`` identity.  Unknown tokens
    return ``None`` (an invalid recipient the caller must refuse).
    """
    if value is None:
        return CANONICAL_RESPONDER
    if not isinstance(value, str):
        return None
    token = value.strip().lstrip("@").lower()
    if not token:
        return CANONICAL_RESPONDER
    return _RECIPIENT_ALIASES.get(token)


def normalize_route_channel(value: object) -> str | None:
    """Normalize ``#owner-telegram``/``owner-telegram`` to the route channel.

    ``None``/empty defaults to the route channel.  A leading ``#`` is accepted
    and stripped.  Any other channel is invalid and returns ``None``: the route
    endpoint refuses to admit owner traffic into an unexpected channel.
    """
    if value is None:
        return ROUTE_CHANNEL
    if not isinstance(value, str):
        return None
    token = value.strip().lstrip("#").lower()
    if not token:
        return ROUTE_CHANNEL
    return ROUTE_CHANNEL if token == ROUTE_CHANNEL else None


def normalize_tg_id(value: object) -> str:
    """Normalize a Telegram numeric id to a comparison string ("" if absent)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        # bool is an int subclass; a boolean id is never a valid Telegram id.
        return ""
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    return ""


def normalize_tg_message_id(value: object) -> int | None:
    """Return a positive Telegram message id, or ``None`` when invalid."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        token = value.strip()
        if token.isascii() and token.isdigit():
            parsed = int(token)
            return parsed if parsed > 0 else None
    return None


def stable_inbound_action_id(correlation_id: str, uid: str) -> str:
    """Generation-independent idempotency key for the durable inbound wake.

    Derived only from the correlation id and the persisted message uid so a
    producer retry deduplicates regardless of whether ``codex-sol`` is
    registered yet.  It matches the ``act-<sha256>`` shape consumed by the
    delivery journal.
    """
    canonical = (
        "telegram-inbound\x00" + str(correlation_id) + "\x00" + str(uid)
    ).encode("utf-8")
    return "act-" + hashlib.sha256(canonical).hexdigest()


# --- Outbound addressing / correlation helpers -------------------------------


def is_addressed_to_owner(message: dict, resolve_reply) -> bool:
    """Whether an outbound message is EXPLICITLY addressed to ``owner-telegram``.

    True when the message carries ``recipient == owner-telegram`` metadata, or
    it ``@owner-telegram``-mentions the owner, or it replies to a message
    authored by the owner.  ``resolve_reply(msg_id)`` returns the parent
    message dict (or ``None``).  Echo-loop exclusion (dropping messages whose
    sender is the owner) is applied by the caller before this check.

    This is the *explicit-addressing* predicate only; the dedicated-channel
    outbound selection (:func:`is_route_response`) also admits an ordinary
    canonical response that carries none of these markers.
    """
    metadata = message.get("metadata") or {}
    if metadata.get("recipient") == OWNER_IDENTITY:
        return True
    text = message.get("text")
    if isinstance(text, str) and ("@" + OWNER_IDENTITY) in text.lower():
        return True
    reply_id = message.get("reply_to")
    if reply_id is not None:
        parent = resolve_reply(reply_id)
        if parent and parent.get("sender") == OWNER_IDENTITY:
            return True
    return False


def is_route_response(message: dict, resolve_reply) -> bool:
    """Whether a message in the dedicated owner channel is a reply for the owner.

    The dedicated ``#owner-telegram`` channel carries only this conversation by
    construction (the inbound endpoint refuses every other channel), so an
    ordinary canonical response needs no fabricated ``recipient``/``reply_to``/
    ``@mention`` metadata to be delivered.  The caller has already excluded the
    echo source (owner-authored messages).  Selection rule (first match wins):

    * an explicit ``metadata.recipient`` decides on its own — only an
      owner-addressed reply passes; an explicit *foreign* recipient is excluded;
    * an ``@owner-telegram`` mention is included (explicit address);
    * an explicit ``reply_to`` is included only when it answers an
      owner-authored message; a reply to any other message is excluded;
    * otherwise (no explicit addressing) an ordinary message is included only
      when it comes from the canonical responder ``codex-sol`` — so a plain
      ``codex-sol`` answer is delivered, while an unrelated sender is filtered.
    """
    metadata = message.get("metadata") or {}
    recipient = metadata.get("recipient")
    if recipient is not None:
        # Explicit addressing is authoritative: foreign recipients are excluded.
        return recipient == OWNER_IDENTITY
    text = message.get("text")
    if isinstance(text, str) and ("@" + OWNER_IDENTITY) in text.lower():
        return True
    reply_id = message.get("reply_to")
    if reply_id is not None:
        parent = resolve_reply(reply_id)
        if parent is not None:
            # An explicit reply to the owner is included; to anyone else, not.
            return parent.get("sender") == OWNER_IDENTITY
        # Reply to an unknown parent: fall through to the ordinary rule below.
    # Ordinary (unaddressed) message: the canonical responder's reply is the
    # owner's answer; any other sender is unrelated chatter and is excluded.
    return message.get("sender") == CANONICAL_RESPONDER


def preceding_owner_request(channel_messages, before_id) -> dict | None:
    """The most recent owner request in the channel preceding ``before_id``.

    ``channel_messages`` is the dedicated channel in ascending id order.  The
    returned message is the latest owner-authored inbound (``source ==
    telegram-owner``) carrying a correlation id whose ``id`` is strictly less
    than ``before_id`` — the bounded sequential MVP anchor an ordinary response
    inherits its correlation from.  ``None`` if there is no such request.
    """
    found = None
    for candidate in channel_messages:
        cid_id = candidate.get("id")
        if cid_id is None or cid_id >= before_id:
            continue
        if candidate.get("sender") != OWNER_IDENTITY:
            continue
        meta = candidate.get("metadata") or {}
        if meta.get("source") != "telegram-owner":
            continue
        corr = meta.get("correlation_id")
        if isinstance(corr, str) and corr:
            found = candidate
    return found


def resolve_correlation(message: dict, resolve_reply,
                        preceding_request: dict | None = None) -> str | None:
    """Deterministically resolve an outbound message's correlation id.

    Precedence: the message's own ``metadata.correlation_id``; then the
    correlation of the owner message it explicitly ``reply_to``-answers; then —
    for an ordinary response with no explicit correlation — the correlation of
    the appropriate ``preceding_request`` (the most recent preceding owner
    request in the dedicated channel, see :func:`preceding_owner_request`).
    ``None`` when none of these carries one.  ``preceding_request`` defaults to
    ``None`` so the explicit-only two-argument form is unchanged.
    """
    metadata = message.get("metadata") or {}
    cid = metadata.get("correlation_id")
    if isinstance(cid, str) and cid:
        return cid
    reply_id = message.get("reply_to")
    if reply_id is not None:
        parent = resolve_reply(reply_id)
        if parent:
            parent_meta = parent.get("metadata") or {}
            parent_cid = parent_meta.get("correlation_id")
            if isinstance(parent_cid, str) and parent_cid:
                return parent_cid
    if preceding_request is not None:
        req_meta = preceding_request.get("metadata") or {}
        req_cid = req_meta.get("correlation_id")
        if isinstance(req_cid, str) and req_cid:
            return req_cid
    return None


def find_persisted_inbound(channel_messages, correlation_id: str) -> dict | None:
    """Return the owner inbound already persisted for ``correlation_id``.

    Scans the dedicated channel for the owner-authored (``source ==
    telegram-owner``) message whose ``metadata.correlation_id`` equals the given
    logical-request id, so an authenticated retry resolves to the one durable
    message instead of persisting a second.  ``None`` if none exists yet.
    """
    for candidate in channel_messages:
        if candidate.get("sender") != OWNER_IDENTITY:
            continue
        meta = candidate.get("metadata") or {}
        if meta.get("source") != "telegram-owner":
            continue
        if meta.get("correlation_id") == correlation_id:
            return candidate
    return None


def inbound_envelope_matches(existing: dict, recipient: str, text: str,
                             telegram_message_id: int) -> bool:
    """Whether a retry's envelope matches the already-persisted owner message.

    The logical request is identified by its correlation id; a retry is only
    idempotent when it carries the SAME canonical ``recipient`` and body
    ``text``.  A reused correlation id with a different envelope is a conflict
    the caller must fail closed (without disclosing which field differs).
    """
    meta = existing.get("metadata") or {}
    return (
        meta.get("recipient") == recipient
        and existing.get("text") == text
        and meta.get("telegram_message_id") == telegram_message_id
    )


def resolve_telegram_reply_to(message: dict, resolve_reply,
                              preceding_request: dict | None = None) -> int | None:
    """Resolve the Telegram message id an outbound response should quote.

    An explicit reply to an owner message wins. Otherwise the ordinary
    dedicated-channel response quotes the most recent preceding owner request.
    Only the positive integer stored by authenticated Telegram ingress is
    accepted; no id is inferred or fabricated.
    """
    parent = None
    reply_id = message.get("reply_to")
    if reply_id is not None:
        candidate = resolve_reply(reply_id)
        if candidate and candidate.get("sender") == OWNER_IDENTITY:
            parent = candidate
    if parent is None:
        parent = preceding_request
    metadata = (parent or {}).get("metadata") or {}
    return normalize_tg_message_id(metadata.get("telegram_message_id"))


def outbound_entry(message: dict, correlation_id: str | None,
                   reply_to_message_id: int | None = None) -> dict:
    """Build the bounded outbound wire entry for the bridge.

    Explicitly carries the monotonic message-id cursor, the canonical
    recipient, the preserved correlation id, sender, channel and text.
    """
    return {
        "id": message.get("id"),
        "sender": message.get("sender"),
        "recipient": OWNER_IDENTITY,
        "correlation_id": correlation_id,
        "reply_to_message_id": reply_to_message_id,
        "text": message.get("text", ""),
        "channel": message.get("channel", ROUTE_CHANNEL),
    }


# --- Two-factor route guard (bearer digest + Telegram allowlist) -------------

_STORE_VERSION = 1


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Durably replace a file without exposing a truncated destination."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp",
                                    dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass


def _digest(salt_hex: str, bearer: str) -> str:
    """Salted HMAC-SHA256 of a bearer.  The raw bearer never leaves memory."""
    return hmac.new(
        bytes.fromhex(salt_hex), bearer.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _allowlist_key(user_id: object, chat_id: object) -> tuple[str, str]:
    return (normalize_tg_id(user_id), normalize_tg_id(chat_id))


class TelegramRouteGuard:
    """Persistent two-factor gate for the ``owner-telegram`` privileged wake.

    The store on disk holds only a bearer *salt+digest* (never the raw bearer)
    and the Telegram (user_id, chat_id) allowlist.  Provisioning is a local,
    owner-side setup action; no secret is baked into code.
    """

    def __init__(self, path: str | os.PathLike):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._salt: str | None = None
        self._bearer_hash: str | None = None
        self._allowlist: set[tuple[str, str]] = set()
        self._load()

    # --- persistence ---

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text("utf-8"))
        except Exception:
            # A corrupt store fails closed: the guard stays un-provisioned and
            # every request is rejected until an operator repairs it.
            return
        if not isinstance(data, dict):
            return
        salt = data.get("bearer_salt")
        digest = data.get("bearer_hash")
        allowlist = data.get("allowlist")
        if isinstance(salt, str) and isinstance(digest, str):
            self._salt = salt
            self._bearer_hash = digest
        if isinstance(allowlist, list):
            self._allowlist = {
                _allowlist_key(entry.get("user_id"), entry.get("chat_id"))
                for entry in allowlist
                if isinstance(entry, dict)
            }
            self._allowlist.discard(("", ""))

    def _snapshot(self) -> dict:
        return {
            "version": _STORE_VERSION,
            "bearer_salt": self._salt,
            "bearer_hash": self._bearer_hash,
            "allowlist": [
                {"user_id": user_id, "chat_id": chat_id}
                for (user_id, chat_id) in sorted(self._allowlist)
            ],
        }

    # --- provisioning (owner setup) ---

    def provision(self, bearer: str, allowlist) -> None:
        """Provision (or re-provision) the route bearer and Telegram allowlist.

        ``bearer`` is supplied by the owner/setup and shared with the bridge;
        only its salted digest is persisted.  ``allowlist`` is an iterable of
        ``(user_id, chat_id)`` pairs or ``{"user_id","chat_id"}`` dicts.  A
        fresh random salt is minted on every provision.  The raw bearer is not
        returned, logged or stored.
        """
        if not isinstance(bearer, str) or not bearer.strip():
            raise ValueError("route bearer must be a non-empty string")
        normalized: set[tuple[str, str]] = set()
        for entry in allowlist or ():
            if isinstance(entry, dict):
                key = _allowlist_key(entry.get("user_id"), entry.get("chat_id"))
            else:
                user_id, chat_id = entry
                key = _allowlist_key(user_id, chat_id)
            if key != ("", ""):
                normalized.add(key)
        if not normalized:
            raise ValueError("route allowlist must contain at least one pair")
        salt = secrets.token_hex(16)
        with self._lock:
            self._salt = salt
            self._bearer_hash = _digest(salt, bearer)
            self._allowlist = normalized
            _atomic_write_bytes(
                self._path,
                json.dumps(self._snapshot(), ensure_ascii=True).encode("utf-8"),
            )

    def is_provisioned(self) -> bool:
        with self._lock:
            return bool(self._salt and self._bearer_hash and self._allowlist)

    # --- verification ---

    def _bearer_ok_locked(self, bearer: object) -> bool:
        if not self._salt or not self._bearer_hash:
            return False
        if not isinstance(bearer, str) or not bearer:
            return False
        return hmac.compare_digest(_digest(self._salt, bearer), self._bearer_hash)

    def verify_bearer(self, bearer: object) -> bool:
        """Single-factor route-bearer check (used by the outbound read path)."""
        with self._lock:
            return self._bearer_ok_locked(bearer)

    def verify_inbound(self, bearer: object, user_id: object,
                       chat_id: object) -> bool:
        """Two-factor gate: the route bearer AND an allowlisted user/chat pair.

        Returns ``True`` only when BOTH factors pass.  Never discloses which
        factor failed and never logs the bearer, user or chat.
        """
        with self._lock:
            if not self._allowlist:
                return False
            bearer_ok = self._bearer_ok_locked(bearer)
            pair_ok = _allowlist_key(user_id, chat_id) in self._allowlist
            # Evaluate both factors, then AND them.  Both are constant-time /
            # membership checks over non-secret-length inputs.
            return bool(bearer_ok and pair_ok)


# --- Secret-safe provisioning entrypoint (owner setup) -----------------------
#
# Operational form of the one live setup step "owner provisions the shared
# route bearer + Telegram allowlist".  The bearer is a secret and is read ONLY
# from an interactive hidden prompt (``getpass``) — never from argv or the
# environment, so it never lands in shell history, process listings or logs.
# The Telegram (user_id, chat_id) allowlist pairs are NOT secrets and are given
# as ``--allow user_id:chat_id`` arguments.  Rotation is the same command run
# again (a fresh salt is minted on every provision).
#
#   python -m telegram_route provision --store <path> \
#       --allow <user_id>:<chat_id> [--allow <user_id>:<chat_id> ...]
#
# ``--store`` is required and has no default, so setup never writes to an
# unexpected location.  Nothing about the bearer is ever printed back.


def _parse_allow_pair(value: str) -> tuple[str, str]:
    """Parse a non-secret ``user_id:chat_id`` allowlist argument."""
    if not isinstance(value, str) or value.count(":") != 1:
        raise ValueError("--allow expects exactly one 'user_id:chat_id' pair")
    user_id, chat_id = value.split(":", 1)
    user_id = user_id.strip()
    chat_id = chat_id.strip()
    if not user_id or not chat_id:
        raise ValueError("--allow user_id and chat_id must both be non-empty")
    return (user_id, chat_id)


def _read_bearer_secret(prompt_fn) -> str:
    """Read the bearer twice from a hidden prompt and confirm it matches.

    ``prompt_fn`` is a ``getpass``-style callable that returns typed input
    without echoing it.  The raw bearer is never returned to argv/env, printed
    or logged; a mismatch fails closed without revealing either entry.
    """
    first = prompt_fn("Route bearer (input hidden): ")
    if not isinstance(first, str) or not first.strip():
        raise ValueError("route bearer must be a non-empty string")
    second = prompt_fn("Re-enter route bearer: ")
    if first != second:
        raise ValueError("bearers did not match; nothing was written")
    return first


def main(argv=None) -> int:
    """``python -m telegram_route`` provisioning entrypoint (see module notes)."""
    import argparse
    import getpass

    parser = argparse.ArgumentParser(
        prog="telegram_route",
        description="Provision the Telegram owner-route two-factor guard "
                    "(bearer read from a hidden prompt; never from argv/env).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    prov = sub.add_parser(
        "provision",
        help="Provision/rotate the route bearer digest + Telegram allowlist.",
    )
    prov.add_argument("--store", required=True,
                      help="Path to the route guard JSON store to write.")
    prov.add_argument("--allow", required=True, action="append",
                      metavar="USER_ID:CHAT_ID", type=_parse_allow_pair,
                      help="Allowlisted Telegram user_id:chat_id pair (repeat "
                           "for more; ids are not secrets).")

    args = parser.parse_args(argv)
    if args.command == "provision":
        try:
            bearer = _read_bearer_secret(getpass.getpass)
            guard = TelegramRouteGuard(args.store)
            guard.provision(bearer, args.allow)
        except (ValueError, OSError) as exc:
            # Never echo the bearer; report only the non-secret reason.
            print(f"provisioning failed: {exc}")
            return 2
        finally:
            bearer = None
        print(
            f"provisioned route guard at {args.store}: "
            f"{len(args.allow)} allowlist pair(s); bearer stored as a salted "
            f"HMAC-SHA256 digest only."
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
