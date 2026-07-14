"""Agent wrapper - runs the real interactive CLI with auto-trigger on @mentions.

Usage:
    python wrapper.py claude
    python wrapper.py codex
    python wrapper.py gemini
    python wrapper.py kimi
    python wrapper.py qwen

Cross-platform:
  - Windows: injects keystrokes via Win32 WriteConsoleInput (wrapper_windows.py)
  - Mac/Linux: injects keystrokes via tmux send-keys (wrapper_unix.py)

How it works:
  1. Starts the agent CLI in an interactive terminal.
  2. Watches the queue file in the background for @mentions from the chat room.
  3. When triggered, injects "use mcp to read #channel - you're mentioned, take appropriate action and respond".
  4. The agent picks up the prompt as if the user typed it.
"""

import json
import os
import hashlib
import hmac
import re
import stat
import shutil
import sys
import threading
import time
from pathlib import Path

from delivery_io import (
    DeliveryBackpressureError,
    append_bytes_durable,
    fsync_directory_best_effort,
    queue_consumer_lease,
    queue_file_lock,
    write_unique_evidence,
    write_backpressure_marker,
)

ROOT = Path(__file__).parent

SERVER_NAME = "agentchattr"

try:
    _MAX_DELIVERY_JOURNAL_BYTES = max(
        4096, int(os.environ.get("AGENTCHATTR_MAX_JOURNAL_BYTES", 8 << 20))
    )
except (TypeError, ValueError):
    _MAX_DELIVERY_JOURNAL_BYTES = 8 << 20


# ---------------------------------------------------------------------------
# Per-instance provider config
# ---------------------------------------------------------------------------

def _write_json_mcp_settings(config_file: Path, url: str, transport: str = "http",
                              *, token: str = "", http_key: str = "httpUrl") -> Path:
    """Write/merge a settings-style JSON file with nested mcpServers config.

    Preserves existing servers in the file — only updates the agentchattr entry.

    Gemini CLI 0.32+ expects:
      - "httpUrl" key (not "url") for streamable-http transport
      - "url" key for SSE transport
      - "trust": true to skip per-call approval prompts

    `http_key` controls which JSON key names the HTTP transport URL. Defaults
    to "httpUrl" (Gemini/Qwen). Providers like CodeBuddy that follow the
    standard MCP shape should set `mcp_http_key = "url"` in their config.
    Only affects settings_file / env injector modes (not the Claude flag
    writer or Kilo env_content writer).
    """
    config_file.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if config_file.exists():
        try:
            existing = json.loads(config_file.read_text("utf-8"))
        except Exception:
            pass
    servers = existing.get("mcpServers", {})
    # Default: Gemini-style "httpUrl" for HTTP. Override with http_key="url"
    # for providers that follow the standard MCP shape (e.g. CodeBuddy).
    if transport in ("http", "streamable-http"):
        entry: dict = {"type": "http", http_key: url, "trust": True}
    else:
        entry = {"type": transport, "url": url, "trust": True}
    if token:
        entry["headers"] = {"Authorization": f"Bearer {token}"}
    servers[SERVER_NAME] = entry
    existing["mcpServers"] = servers

    # Enable folder trust so ~/.gemini/trustedFolders.json is respected
    security = existing.get("security", {})
    folder_trust = security.get("folderTrust", {})
    folder_trust["enabled"] = True
    security["folderTrust"] = folder_trust
    existing["security"] = security

    config_file.write_text(json.dumps(existing, indent=2) + "\n", "utf-8")
    return config_file


def _read_project_mcp_servers(project_dir: Path) -> dict:
    """Read existing MCP servers from the project's .mcp.json."""
    mcp_file = project_dir / ".mcp.json"
    if mcp_file.exists():
        try:
            data = json.loads(mcp_file.read_text("utf-8"))
            servers = data.get("mcpServers", {})
            # Remove agentchattr — we'll add our own authenticated version
            servers.pop(SERVER_NAME, None)
            return servers
        except Exception:
            pass
    return {}


def _write_claude_mcp_config(
    config_file: Path,
    url: str,
    *,
    token: str = "",
    project_servers: dict | None = None,
) -> Path:
    """Write a Claude Code --mcp-config file with bearer auth.

    Includes all project MCP servers (unity-mcp etc.) so --strict-mcp-config
    can be used without losing other servers."""
    config_file.parent.mkdir(parents=True, exist_ok=True)

    # Start with other project servers (e.g. unity-mcp)
    servers = dict(project_servers or {})

    # Add agentchattr with bearer token for direct server auth
    entry: dict = {"type": "http", "url": url}
    if token:
        entry["headers"] = {"Authorization": f"Bearer {token}"}
    servers[SERVER_NAME] = entry

    payload = {"mcpServers": servers}
    config_file.write_text(json.dumps(payload, indent=2) + "\n", "utf-8")
    return config_file


# ---------------------------------------------------------------------------
# Built-in provider defaults (applied when agent config has no mcp_inject)
# ---------------------------------------------------------------------------

_BUILTIN_DEFAULTS: dict[str, dict] = {
    "claude": {
        "mcp_inject": "flag",
        "mcp_flag": "--mcp-config",
        "mcp_transport": "http",
        "mcp_merge_project": True,  # include unity-mcp etc.
    },
    "gemini": {
        "mcp_inject": "env",
        "mcp_env_var": "GEMINI_CLI_SYSTEM_SETTINGS_PATH",
        "mcp_transport": "http",  # streamable-http; SSE has blocking issues in Gemini 0.32.x
        "mcp_merge_project": True,
    },
    "codex": {
        "mcp_inject": "proxy_flag",
        "mcp_proxy_flag_template": '-c mcp_servers.{server}.url="{url}"',
        # mcp_merge_project disabled — Codex reads .mcp.json natively,
        # and duplicate detection is name-based only (e.g. unityMCP vs unity-mcp)
    },
    "kimi": {
        "mcp_inject": "flag",
        "mcp_flag": "--mcp-config-file",
        "mcp_transport": "http",
        "mcp_merge_project": True,
    },
    "kilo": {
        "mcp_inject": "env_content",
        "mcp_env_var": "KILO_CONFIG_CONTENT",
        "mcp_transport": "http",
    },
}

_VALID_INJECT_MODES = {"settings_file", "env", "flag", "proxy_flag", "env_content"}


def _provider_from_command(command: object) -> str:
    """Return a built-in provider for an exact configured executable name.

    Named agent identities (for example ``fable-work``) are independent of
    the CLI they launch.  Resolve only exact known executable basenames; do
    not guess from prefixes or arbitrary command text.
    """
    if not isinstance(command, str):
        return ""
    executable = command.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if executable.endswith(suffix):
            executable = executable[:-len(suffix)]
            break
    return executable if executable in _BUILTIN_DEFAULTS else ""


def _resolve_mcp_inject(agent: str, agent_cfg: dict) -> dict:
    """Resolve MCP injection config: explicit config > provider defaults > none."""
    if agent_cfg.get("mcp_inject"):
        return dict(agent_cfg)
    provider = agent if agent in _BUILTIN_DEFAULTS else _provider_from_command(
        agent_cfg.get("command", "")
    )
    if provider:
        merged = dict(_BUILTIN_DEFAULTS[provider])
        merged.update({k: v for k, v in agent_cfg.items() if k.startswith("mcp_")})
        return merged
    return {}


def _get_server_url(mcp_cfg: dict, transport: str) -> str:
    """Build the MCP server URL for the given transport."""
    if transport == "sse":
        port = mcp_cfg.get("sse_port", 8201)
        return f"http://127.0.0.1:{port}/sse"
    port = mcp_cfg.get("http_port", 8200)
    return f"http://127.0.0.1:{port}/mcp"


def _apply_mcp_inject(
    inject_cfg: dict,
    instance_name: str,
    data_dir: Path,
    proxy_url: str | None,
    *,
    token: str = "",
    mcp_cfg: dict | None = None,
    project_dir: Path | None = None,
) -> tuple[list[str], dict[str, str], Path | None]:
    """Apply MCP config injection based on the resolved inject config.

    Returns (extra_launch_args, inject_env, settings_path_or_None).
    settings_path is stored so re-registration can rewrite it.
    """
    mode = inject_cfg.get("mcp_inject")
    if not mode:
        return [], {}, None

    launch_args: list[str] = []
    inject_env: dict[str, str] = {}
    settings_path: Path | None = None
    config_dir = data_dir / "provider-config"
    transport = inject_cfg.get("mcp_transport", "http")
    server_url = _get_server_url(mcp_cfg or {}, transport)

    http_key = inject_cfg.get("mcp_http_key", "httpUrl")

    if mode == "settings_file":
        # Write a settings JSON file at a user-specified path (e.g. .qwen/settings.json,
        # or ~/.codebuddy/.mcp.json for user-scope configs).
        raw_path = inject_cfg.get("mcp_settings_path", "")
        if not raw_path:
            raise ValueError(f"mcp_inject = 'settings_file' requires mcp_settings_path")
        # Expand ~ to user home (e.g. ~/.codebuddy/.mcp.json), then resolve
        # relative paths against project_dir/CWD as before.
        target = Path(raw_path).expanduser()
        if not target.is_absolute():
            base = Path(project_dir) if project_dir else Path.cwd()
            target = base / target
        settings_path = _write_json_mcp_settings(target, server_url,
                                                  transport=transport, token=token,
                                                  http_key=http_key)
        # Optionally set an env var pointing to the settings file
        env_var = inject_cfg.get("mcp_env_var")
        if env_var:
            inject_env[env_var] = str(settings_path)

    elif mode == "env":
        # Write a settings file in provider-config dir, expose via env var
        env_var = inject_cfg.get("mcp_env_var")
        if not env_var:
            raise ValueError(f"mcp_inject = 'env' requires mcp_env_var")
        settings_path = _write_json_mcp_settings(
            config_dir / f"{instance_name}-settings.json",
            server_url, transport=transport, token=token, http_key=http_key,
        )
        # Merge project .mcp.json servers into the settings file
        merge_project = inject_cfg.get("mcp_merge_project", False)
        if merge_project and project_dir and settings_path:
            project_servers = _read_project_mcp_servers(project_dir)
            if project_servers:
                try:
                    data = json.loads(settings_path.read_text("utf-8"))
                    servers = data.get("mcpServers", {})
                    for name, cfg in project_servers.items():
                        if name not in servers:
                            # Normalize url key for providers that expect "httpUrl"
                            # (Gemini/Qwen). For standard-MCP providers with
                            # http_key="url", leave existing "url" entries as-is.
                            entry = dict(cfg)
                            srv_type = entry.get("type", "http")
                            if srv_type in ("http", "streamable-http") and http_key != "url":
                                if "url" in entry and http_key not in entry:
                                    entry[http_key] = entry.pop("url")
                            entry.setdefault("trust", True)
                            servers[name] = entry
                    data["mcpServers"] = servers
                    settings_path.write_text(json.dumps(data, indent=2) + "\n", "utf-8")
                except Exception:
                    pass
        inject_env[env_var] = str(settings_path)

    elif mode == "flag":
        # Write a config file, pass it as a CLI flag
        flag = inject_cfg.get("mcp_flag", "--mcp-config")
        merge_project = inject_cfg.get("mcp_merge_project", False)
        project_servers = _read_project_mcp_servers(project_dir) if (merge_project and project_dir) else {}
        settings_path = _write_claude_mcp_config(
            config_dir / f"{instance_name}-mcp.json",
            server_url, token=token, project_servers=project_servers,
        )
        launch_args = [flag, str(settings_path)]

    elif mode == "env_content":
        # Build JSON config content and set it as an env var directly (no file written).
        # Used by Kilo CLI which reads KILO_CONFIG_CONTENT at startup.
        env_var = inject_cfg.get("mcp_env_var")
        if not env_var:
            raise ValueError("mcp_inject = 'env_content' requires mcp_env_var")
        entry: dict = {"type": "remote", "url": server_url, "enabled": True}
        if token:
            entry["headers"] = {"Authorization": f"Bearer {token}"}
        payload = {"mcp": {SERVER_NAME: entry}}
        inject_env[env_var] = json.dumps(payload)

    elif mode == "proxy_flag":
        # Pass the proxy URL as CLI flags (e.g. codex -c ...)
        template = inject_cfg.get("mcp_proxy_flag_template",
                                  '-c mcp_servers.{server}.url="{url}"')
        expanded = template.format(server=SERVER_NAME, url=proxy_url or "")
        launch_args = expanded.split()

    return launch_args, inject_env, settings_path


def _ensure_gemini_folder_trusted(project_dir: Path) -> None:
    """Add project_dir as TRUST_FOLDER in ~/.gemini/trustedFolders.json.

    Gemini CLI blocks ALL MCPs (including system-settings ones) for untrusted
    folders. A more-specific TRUST_FOLDER entry overrides any parent-level
    DO_NOT_TRUST rule, so we always write the exact cwd we're launching in.
    Respects GEMINI_CLI_TRUSTED_FOLDERS_PATH env override if set.
    """
    trusted_path_env = os.environ.get("GEMINI_CLI_TRUSTED_FOLDERS_PATH", "")
    if trusted_path_env:
        trusted_file = Path(trusted_path_env)
    else:
        trusted_file = Path.home() / ".gemini" / "trustedFolders.json"

    try:
        data: dict = {}
        if trusted_file.exists():
            try:
                data = json.loads(trusted_file.read_text("utf-8"))
            except Exception:
                data = {}

        folder_key = str(project_dir)
        if data.get(folder_key) == "TRUST_FOLDER":
            return  # already trusted — nothing to do

        data[folder_key] = "TRUST_FOLDER"
        trusted_file.parent.mkdir(parents=True, exist_ok=True)
        trusted_file.write_text(json.dumps(data, indent=2) + "\n", "utf-8")
        print(f"  Trusted folder for Gemini MCPs: {folder_key}")
    except Exception as exc:
        print(f"  Warning: could not update Gemini trusted folders: {exc}")


def _build_provider_launch(
    agent: str,
    agent_cfg: dict,
    instance_name: str,
    data_dir: Path,
    proxy_url: str | None,
    extra_args: list[str],
    env: dict[str, str],
    *,
    token: str = "",
    mcp_cfg: dict | None = None,
    project_dir: Path | None = None,
) -> tuple[list[str], dict[str, str], dict[str, str], Path | None]:
    """Return provider-specific launch args/env/inject_env/settings_path.

    inject_env: env vars that must propagate INTO the agent process.  On
    Mac/Linux these are prefixed onto the tmux command via ``env VAR=val``
    because subprocess.run(env=...) only affects the tmux client binary.
    On Windows they are simply merged into the Popen env dict.
    """
    inject_cfg = _resolve_mcp_inject(agent, agent_cfg)
    mcp_args, inject_env, settings_path = _apply_mcp_inject(
        inject_cfg, instance_name, data_dir, proxy_url,
        token=token, mcp_cfg=mcp_cfg, project_dir=project_dir,
    )

    launch_args = [*mcp_args, *extra_args]
    launch_env = dict(env)

    return launch_args, launch_env, inject_env, settings_path


def _register_instance(server_port: int, base: str, label: str | None = None) -> dict:
    import urllib.request

    reg_body = json.dumps({"base": base, "label": label}).encode()
    reg_req = urllib.request.Request(
        f"http://127.0.0.1:{server_port}/api/register",
        method="POST",
        data=reg_body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(reg_req, timeout=5) as reg_resp:
        return json.loads(reg_resp.read())


def _auth_headers(token: str, *, include_json: bool = False) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if include_json:
        headers["Content-Type"] = "application/json"
    return headers


_RESTART_HANDOFF_PROFILES = {
    "fable-main": "claude-main",
    "fable-work": "claude-work",
    "fable-infra": "claude-test1",
    "fable-emu": "claude-test2",
}
_RESTART_HANDOFF_KEYS = {
    "profile", "internal_id", "identity_id", "epoch", "token", "expiry", "nonce",
}
_RESTART_HANDOFF_HEX32 = re.compile(r"\A[0-9a-f]{32}\Z")
_RESTART_HANDOFF_ENTROPY = hashlib.sha256(
    b"agentchattr-wrapper-handoff-v1"
).digest()


def _dpapi_unprotect_current_user(ciphertext: bytes) -> bytearray:
    """Decrypt a CurrentUser DPAPI blob without ever using argv or stdout."""
    if os.name != "nt" or not (32 <= len(ciphertext) <= 8192):
        raise RuntimeError("restart handoff decryption unavailable")
    import ctypes
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    def _blob(data: bytes):
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))), buf

    in_blob, in_buffer = _blob(ciphertext)
    entropy_blob, entropy_buffer = _blob(_RESTART_HANDOFF_ENTROPY)
    out_blob = _DATA_BLOB()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, ctypes.byref(entropy_blob),
        None, None, 0, ctypes.byref(out_blob),
    )
    # Keep the input buffers alive through the native call.
    _ = (in_buffer, entropy_buffer)
    if not ok or not out_blob.pbData or not (2 <= out_blob.cbData <= 4096):
        if out_blob.pbData:
            if out_blob.cbData:
                ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
            kernel32.LocalFree(out_blob.pbData)
        raise RuntimeError("restart handoff decryption failed")
    try:
        plaintext = bytearray(ctypes.string_at(out_blob.pbData, out_blob.cbData))
        ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
        return plaintext
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _read_registry_handoff_identity(
    data_dir: Path, profile: str, internal_id: str, identity_id: str,
    epoch: int, token: str,
) -> dict:
    registry_path = data_dir / "registry.json"
    try:
        stat = registry_path.stat()
        if not (2 <= stat.st_size <= 8 << 20):
            raise ValueError("registry size")
        with registry_path.open("rb") as registry_file:
            registry_bytes = registry_file.read((8 << 20) + 1)
            if len(registry_bytes) > 8 << 20 or registry_file.read(1):
                raise ValueError("registry grew")
        registry = json.loads(registry_bytes.decode("utf-8", errors="strict"))
        if not isinstance(registry, dict) or not isinstance(registry.get("instances"), dict):
            raise ValueError("registry shape")
        entry = registry["instances"].get(profile)
        if not isinstance(entry, dict):
            raise ValueError("identity missing")
        if (
            entry.get("name") != profile
            or entry.get("base") != internal_id
            or not hmac.compare_digest(str(entry.get("identity_id", "")), identity_id)
            or isinstance(entry.get("epoch"), bool)
            or entry.get("epoch") != epoch
            or not hmac.compare_digest(str(entry.get("token", "")), token)
            or entry.get("state") != "active"
        ):
            raise ValueError("identity mismatch")
        slot = entry.get("slot", 1)
        if isinstance(slot, bool) or not isinstance(slot, int) or not (1 <= slot <= 1024):
            raise ValueError("slot mismatch")
        return {"name": profile, "token": token, "slot": slot,
                "identity_id": identity_id, "epoch": epoch}
    except Exception:
        raise RuntimeError("restart handoff registry verification failed") from None


def _verify_handoff_heartbeat(server_port: int, profile: str, token: str) -> None:
    import urllib.request

    request = urllib.request.Request(
        f"http://127.0.0.1:{server_port}/api/heartbeat/{profile}",
        method="POST",
        data=b'{"active":false}',
        headers=_auth_headers(token, include_json=True),
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read())
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise ValueError("heartbeat shape")
        if payload.get("name") != profile or payload.get("pending", False) is not False:
            raise ValueError("heartbeat identity")
    except Exception:
        raise RuntimeError("restart handoff server verification failed") from None


def _adopt_restart_handoff(
    handoff_file: str, *, agent: str, data_dir: Path, server_port: int,
    now: int | None = None,
) -> dict:
    """Atomically consume a DPAPI handoff and adopt its existing identity.

    The server registration is deliberately not changed.  A sibling instance
    in the same internal family therefore cannot be renamed or displaced.
    """
    if os.name != "nt" or agent not in _RESTART_HANDOFF_PROFILES:
        raise RuntimeError("restart handoff is unavailable for this agent")
    expected_dir = (data_dir / "wrapper-handoff").resolve()
    source = Path(handoff_file)
    try:
        if not source.is_absolute() or source.parent.resolve() != expected_dir:
            raise ValueError("handoff path")
        match = re.fullmatch(r"handoff-([0-9a-f]{32})\.dpapi", source.name)
        if not match:
            raise ValueError("handoff filename")
        original_nonce = match.group(1)
        before = source.lstat()
        if not source.is_file() or source.is_symlink():
            raise ValueError("handoff type")
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if getattr(before, "st_file_attributes", 0) & reparse_flag:
            raise ValueError("handoff reparse point")
        if not (32 <= before.st_size <= 8192):
            raise ValueError("handoff size")
        claimed = source.with_suffix(".consuming")
        if claimed.exists():
            raise ValueError("handoff already claimed")
        # On Windows os.rename is atomic and refuses an existing destination.
        os.rename(source, claimed)
        fsync_directory_best_effort(expected_dir)
    except Exception:
        raise RuntimeError("restart handoff claim failed") from None

    failed = source.with_suffix(".failed")
    plaintext = bytearray()
    token = ""
    try:
        claimed_before = claimed.stat()
        if not (32 <= claimed_before.st_size <= 8192):
            raise ValueError("claimed handoff size")
        with claimed.open("rb") as claimed_file:
            ciphertext = claimed_file.read(8193)
            if len(ciphertext) > 8192 or claimed_file.read(1):
                raise ValueError("claimed handoff grew")
        claimed_after = claimed.stat()
        if (
            claimed_before.st_size != claimed_after.st_size
            or claimed_before.st_mtime_ns != claimed_after.st_mtime_ns
            or claimed_before.st_ino != claimed_after.st_ino
        ):
            raise ValueError("handoff changed while reading")
        plaintext = _dpapi_unprotect_current_user(ciphertext)
        try:
            payload = json.loads(bytes(plaintext).decode("utf-8", errors="strict"))
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0
        if not isinstance(payload, dict) or set(payload) != _RESTART_HANDOFF_KEYS:
            raise ValueError("handoff schema")
        profile = payload.get("profile")
        internal_id = payload.get("internal_id")
        identity_id = payload.get("identity_id")
        epoch = payload.get("epoch")
        token = payload.get("token")
        expiry = payload.get("expiry")
        nonce = payload.get("nonce")
        if (
            profile != _RESTART_HANDOFF_PROFILES[agent]
            or internal_id != agent
            or not isinstance(identity_id, str)
            or not _RESTART_HANDOFF_HEX32.fullmatch(identity_id)
            or isinstance(epoch, bool) or not isinstance(epoch, int) or not (1 <= epoch <= 2**63 - 1)
            or not isinstance(token, str) or not _RESTART_HANDOFF_HEX32.fullmatch(token)
            or isinstance(expiry, bool) or not isinstance(expiry, int)
            or not isinstance(nonce, str) or nonce != original_nonce
        ):
            raise ValueError("handoff values")
        current_time = int(time.time()) if now is None else now
        if expiry < current_time or expiry > current_time + 900:
            raise ValueError("handoff expiry")
        registration = _read_registry_handoff_identity(
            data_dir, profile, internal_id, identity_id, epoch, token
        )
        _verify_handoff_heartbeat(server_port, profile, token)
        claimed.unlink()
        fsync_directory_best_effort(expected_dir)
        return registration
    except Exception:
        # Keep only encrypted evidence.  Never restore it to the admissible
        # .dpapi name automatically: retry is an explicit operator decision.
        try:
            if claimed.exists() and not failed.exists():
                os.rename(claimed, failed)
                fsync_directory_best_effort(expected_dir)
        except Exception:
            pass
        raise RuntimeError("restart handoff adoption failed") from None


# ---------------------------------------------------------------------------
# Queue watcher
# ---------------------------------------------------------------------------

def _notify_recovery(data_dir: Path, agent_name: str):
    """Write a flag file that the server picks up and broadcasts as a system message."""
    try:
        flag = data_dir / f"{agent_name}_recovered"
        flag.write_text(agent_name, "utf-8")
    except Exception:
        pass


_IDENTITY_HINT = (
    " (If this is a multi-instance session, reclaim your previous identity from "
    "your context window, NOT from the chat history before responding. If you "
    "didn't have one, tell the user to give you a name by clicking your status "
    "pill at the top.)"
)


def _fetch_role_status(server_port: int, agent_name: str) -> tuple[bool, str]:
    """Fetch this agent's role. Returns (ok, role) — ok=False means transport
    failure (indistinguishable data must not be treated as "no role")."""
    try:
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{server_port}/api/roles")
        with urllib.request.urlopen(req, timeout=3) as resp:
            roles = json.loads(resp.read())
        if not isinstance(roles, dict):
            return False, ""
        return True, roles.get(agent_name, "")
    except Exception:
        return False, ""


def _fetch_active_rules_status(server_port: int, token: str = "") -> tuple[bool, dict | None]:
    """Fetch active rules. Returns (ok, rules_dict). ok=False on transport
    failure or an invalid payload shape — callers must defer injection rather
    than proceed without authoritative context."""
    try:
        import urllib.request
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        req = urllib.request.Request(f"http://127.0.0.1:{server_port}/api/rules/active", headers=headers)
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("epoch"), int)
            or not isinstance(data.get("rules"), list)
        ):
            return False, None
        return True, data
    except Exception:
        return False, None


def _report_rule_sync(server_port: int, agent_name: str, epoch: int, token: str = ""):
    """Report that this agent has seen rules at the given epoch."""
    try:
        import urllib.request
        body = json.dumps({"epoch": epoch}).encode()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            f"http://127.0.0.1:{server_port}/api/rules/agent_sync/{agent_name}",
            method="POST",
            data=body,
            headers=headers,
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


def _queue_cursor_path(queue_file: Path) -> Path:
    return queue_file.with_name(queue_file.name + ".cursor")


def _sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _atomic_write_bytes(path: Path, data: bytes):
    """Crash-safe write: unique exclusive temp file + flush/fsync + replace."""
    import tempfile
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".tmp-", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
        fsync_directory_best_effort(path.parent)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _read_queue_cursor(queue_file: Path, raw: bytes) -> int:
    """Content-bound cursor: the stored offset is honored only when the
    consumed prefix hash still matches the live file and the offset sits on a
    line boundary. Any mismatch (queue replaced, rewritten, mid-line offset,
    corrupt sidecar) resets to 0 — replay is safe, silent skipping is not."""
    try:
        data = json.loads(
            _queue_cursor_path(queue_file).read_text("utf-8")
        )
        offset = int(data["offset"])
        prefix_sha = str(data["prefix_sha256"])
    except Exception:
        return 0
    if offset <= 0 or offset > len(raw):
        return 0
    if raw[offset - 1:offset] != b"\n":
        return 0
    if _sha256_hex(raw[:offset]) != prefix_sha:
        return 0
    return offset


def _write_queue_cursor(queue_file: Path, offset: int, prefix: bytes):
    """Persist the consume cursor bound to the exact consumed prefix bytes."""
    payload = json.dumps({
        "offset": int(offset),
        "prefix_sha256": _sha256_hex(prefix[:offset]),
    }).encode("utf-8")
    _atomic_write_bytes(_queue_cursor_path(queue_file), payload)


def _read_pending_triggers(queue_file: Path) -> tuple[str, str, int, bytes]:
    """Non-destructive read of unconsumed queue bytes.

    The durable queue is never truncated here; the consume cursor advances
    only after a successful admission+injection. Only complete lines are
    offered — a torn trailing line (mid-append) stays pending until its
    newline lands, so it can never be half-consumed. Decoding is STRICT
    UTF-8: undecodable pending bytes report status 'corrupt' and are never
    silently skipped or consumed past.

    Returns (status, pending_text, consume_offset, raw_snapshot) where
    status is 'ok' or 'corrupt'.
    """
    if not queue_file.exists():
        return "ok", "", 0, b""
    raw = queue_file.read_bytes()
    cursor = _read_queue_cursor(queue_file, raw)
    chunk = raw[cursor:]
    last_nl = chunk.rfind(b"\n")
    if last_nl < 0:
        return "ok", "", cursor, raw
    end = cursor + last_nl + 1
    try:
        pending = chunk[:last_nl + 1].decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "corrupt", "", end, raw
    return "ok", pending, end, raw


def _quarantine_pending_window(queue_file: Path, raw: bytes, start: int,
                               end: int) -> bool:
    """Move an unparseable pending window aside instead of skipping it.

    The window bytes are persisted (fsync) to a timestamped .quarantine file
    BEFORE the cursor is advanced past them, so nothing is silently lost —
    the quarantined records stay recoverable for manual replay."""
    try:
        window = raw[start:end]
        if window:
            write_unique_evidence(queue_file, window)
        _write_queue_cursor(queue_file, end, raw)
        return True
    except Exception:
        return False


def _preserve_stale_queue(queue_file: Path):
    """Crash-safe startup admission for an append-only active queue.

    Earlier code rewrote the queue to its unconsumed suffix.  A producer that
    appended between the snapshot and ``os.replace`` was silently lost, and a
    crash after replace but before cursor reset could skip an identical
    pending prefix.  Startup now deliberately performs *no active-file
    replacement*: the content-bound cursor remains valid and consumed bytes
    are retained as the audit log.  Producer creation and this validation use
    the same cross-process lock.
    """
    try:
        with queue_file_lock(queue_file):
            if not queue_file.exists():
                append_bytes_durable(queue_file, b"")
            raw = queue_file.read_bytes()
            cursor_path = _queue_cursor_path(queue_file)
            if not cursor_path.exists():
                _write_queue_cursor(queue_file, 0, raw)
            else:
                # Force validation while holding the producer lock.  Invalid
                # sidecars reset fail-safe to zero on every subsequent read;
                # persist that repair so startup state is unambiguous.
                cursor = _read_queue_cursor(queue_file, raw)
                if cursor == 0 and raw:
                    _write_queue_cursor(queue_file, 0, raw)
    except Exception:
        pass


def _parse_trigger_records(pending_text: str, start_offset: int = 0) -> tuple[list[dict], int, list[int]]:
    """Parse records and retain each record's absolute queue byte offset.

    The offset is part of synthesized legacy event identity.  Unlike a
    batch-local duplicate ordinal it is stable across restart-before-cursor,
    while identical records appended later receive distinct identities.
    """
    triggers = []
    offsets = []
    malformed = 0
    offset = int(start_offset)
    for physical_line in pending_text.splitlines(keepends=True):
        encoded_len = len(physical_line.encode("utf-8"))
        line = physical_line.strip()
        if not line:
            offset += encoded_len
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            offset += encoded_len
            continue
        triggers.append(data if isinstance(data, dict) else {})
        offsets.append(offset)
        offset += encoded_len
    return triggers, malformed, offsets


def _parse_trigger_lines(pending_text: str) -> tuple[list[dict], int]:
    """Compatibility view for callers that do not need record offsets."""
    triggers, malformed, _offsets = _parse_trigger_records(pending_text)
    return triggers, malformed


_TERMINAL_DELIVERY_STATES = frozenset({
    "accepted", "dead-letter",
})
_BLOCKED_DELIVERY_STATES = frozenset({
    # Input may have reached the child.  Automatic replay risks duplicate
    # side effects, while advancing would falsely claim semantic acceptance.
    "attempting", "injected-uncertain", "injection-timeout",
    "journal-corrupt-blocked",
    # Old wrappers used these names for None/ambiguous injector outcomes.
    # Never reinterpret them as semantic acceptance during upgrade.
    "accepted-legacy", "accepted-uncertain",
})
_KNOWN_DELIVERY_STATES = (
    _TERMINAL_DELIVERY_STATES
    | _BLOCKED_DELIVERY_STATES
    | frozenset({"retry", "watcher-error"})
)
_DELIVERY_RECORD_REQUIRED_FIELDS = frozenset({
    "journal_version", "at_ns", "state", "event_ids",
})
_DELIVERY_RECORD_OPTIONAL_FIELDS = frozenset({
    "action_ids", "inject_result", "error", "cursor_committed",
})
_DELIVERY_RECORD_FIELDS = (
    _DELIVERY_RECORD_REQUIRED_FIELDS | _DELIVERY_RECORD_OPTIONAL_FIELDS
)
_DELIVERY_STATE_FIELDS = {
    "attempting": (frozenset({"action_ids"}), frozenset()),
    "accepted": (
        frozenset({"action_ids", "inject_result", "cursor_committed"}),
        frozenset({"inject_result"}),
    ),
    "dead-letter": (
        frozenset({"action_ids", "inject_result", "cursor_committed"}),
        frozenset({"inject_result"}),
    ),
    "retry": (
        frozenset({"action_ids", "inject_result"}),
        frozenset({"inject_result"}),
    ),
    "injected-uncertain": (
        frozenset({"action_ids", "inject_result"}), frozenset(),
    ),
    "injection-timeout": (
        frozenset({"action_ids", "inject_result"}),
        frozenset({"inject_result"}),
    ),
    "journal-corrupt-blocked": (
        frozenset({"action_ids", "error"}), frozenset({"error"}),
    ),
    # Migration-only blockers carry identity but make no injector claim.
    "accepted-legacy": (frozenset({"action_ids"}), frozenset()),
    "accepted-uncertain": (frozenset({"action_ids"}), frozenset()),
    "watcher-error": (frozenset({"error"}), frozenset({"error"})),
}


def _delivery_journal_path(queue_file: Path) -> Path:
    """Append-only delivery state, separate from the producer queue."""
    return queue_file.with_name(queue_file.name + ".delivery.jsonl")


def _delivery_block_marker_path(queue_file: Path) -> Path:
    """Persistent manual-reconciliation fence for a corrupt journal."""
    return queue_file.with_name(queue_file.name + ".delivery.blocked.json")


def _write_delivery_block_marker(queue_file: Path, error: str,
                                 evidence: str = "") -> Path:
    """Durably fence delivery before a corrupt live journal is removed."""
    marker = _delivery_block_marker_path(queue_file)
    payload = {
        "version": 1,
        "state": "journal-corrupt-blocked",
        "queue": str(queue_file.resolve()),
        "at_ns": time.time_ns(),
        "error": str(error)[:500],
        "action": "manual journal reconciliation required",
    }
    if evidence:
        payload["evidence"] = str(evidence)
    _atomic_write_bytes(marker, json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8"))
    return marker


def _delivery_is_blocked(queue_file: Path) -> bool:
    """Marker existence alone is authoritative, even if its JSON is torn."""
    return _delivery_block_marker_path(queue_file).exists()


def _valid_delivery_id(value) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and all(
            "a" <= ch <= "z"
            or "A" <= ch <= "Z"
            or "0" <= ch <= "9"
            or ch in "-_.:"
            for ch in value
        )
    )


def _validate_delivery_record(record, line_number: int = 0) -> dict:
    """Validate the complete v1 journal schema without forward guessing."""
    where = f" line {line_number}" if line_number else ""
    if not isinstance(record, dict):
        raise ValueError(f"invalid delivery journal record{where}")
    fields = set(record)
    missing = _DELIVERY_RECORD_REQUIRED_FIELDS - fields
    unknown = fields - _DELIVERY_RECORD_FIELDS
    if missing:
        raise ValueError(
            f"missing delivery journal fields{where}: {sorted(missing)}"
        )
    if unknown:
        raise ValueError(
            f"unknown delivery journal fields{where}: {sorted(unknown)}"
        )
    version = record["journal_version"]
    if type(version) is not int or version != 1:
        raise ValueError(f"invalid delivery journal version{where}: {version!r}")
    at_ns = record["at_ns"]
    if type(at_ns) is not int or at_ns < 0:
        raise ValueError(f"invalid delivery journal at_ns{where}: {at_ns!r}")
    state = record["state"]
    if not isinstance(state, str) or state not in _KNOWN_DELIVERY_STATES:
        raise ValueError(f"invalid delivery journal state{where}: {state!r}")
    allowed_extra, required_extra = _DELIVERY_STATE_FIELDS[state]
    extra = fields - _DELIVERY_RECORD_REQUIRED_FIELDS
    forbidden = extra - allowed_extra
    missing_state = required_extra - fields
    if forbidden:
        raise ValueError(
            f"forbidden fields for delivery state {state!r}{where}: "
            f"{sorted(forbidden)}"
        )
    if missing_state:
        raise ValueError(
            f"missing fields for delivery state {state!r}{where}: "
            f"{sorted(missing_state)}"
        )
    event_ids = record["event_ids"]
    if not isinstance(event_ids, list) or not all(
        _valid_delivery_id(event_id) for event_id in event_ids
    ):
        raise ValueError(f"invalid delivery journal event_ids{where}")
    if len(set(event_ids)) != len(event_ids):
        raise ValueError(f"duplicate delivery journal event_ids{where}")
    if state == "watcher-error" and event_ids:
        raise ValueError(f"watcher-error must have empty event_ids{where}")
    if state != "watcher-error" and not event_ids:
        raise ValueError(
            f"empty delivery journal event_ids forbidden for {state!r}{where}"
        )
    if "action_ids" in record:
        action_ids = record["action_ids"]
        if not isinstance(action_ids, list) or not action_ids or not all(
            _valid_delivery_id(action_id) for action_id in action_ids
        ):
            raise ValueError(f"invalid delivery journal action_ids{where}")
        if len(set(action_ids)) != len(action_ids):
            raise ValueError(f"duplicate delivery journal action_ids{where}")
        if len(action_ids) > len(event_ids):
            raise ValueError(
                f"delivery journal action_ids exceed event_ids{where}"
            )
    if "cursor_committed" in record:
        if type(record["cursor_committed"]) is not bool or not record[
            "cursor_committed"
        ]:
            raise ValueError(f"invalid delivery journal cursor_committed{where}")
    for field in ("error", "inject_result"):
        if field in record and (
            not isinstance(record[field], str) or not record[field]
        ):
            raise ValueError(f"invalid delivery journal {field}{where}")
    if state == "accepted" and record["inject_result"] not in {
        "injected", "True",
    }:
        raise ValueError(f"accepted has invalid inject_result{where}")
    if state == "dead-letter" and record["inject_result"] != "dead-letter":
        raise ValueError(f"dead-letter has invalid inject_result{where}")
    if state == "injected-uncertain" and record.get(
        "inject_result"
    ) not in {None, "False", "injected-uncertain"}:
        raise ValueError(f"injected-uncertain has invalid result{where}")
    if state == "injection-timeout" and record[
        "inject_result"
    ] != "injection-timeout":
        raise ValueError(f"injection-timeout has invalid result{where}")
    if state == "retry" and record["inject_result"] in {
        "injected", "True", "dead-letter", "injection-timeout",
        "injected-uncertain", "False",
    }:
        raise ValueError(f"retry has terminal/uncertain result{where}")
    return record


def _strict_json_object(pairs):
    """Reject duplicate JSON members instead of silently taking the last."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key!r}")
        result[key] = value
    return result


def _prepare_delivery_events(queue_file: Path, triggers: list[dict],
                             record_offsets: list[int] | None = None) -> list[dict]:
    """Return copied trigger records with stable event IDs.

    New producers supply UUID-backed IDs. Old queue records remain supported:
    their IDs are derived from canonical content plus the duplicate ordinal,
    so a crash/restart can still recognize an already admitted legacy event.
    """
    prepared: list[dict] = []
    occurrences: dict[str, int] = {}
    absolute_queue = os.path.normcase(str(queue_file.resolve()))
    for index, trigger in enumerate(triggers):
        event = dict(trigger)
        event_id = event.get("event_id")
        if not _valid_delivery_id(event_id):
            canonical = json.dumps(
                trigger, ensure_ascii=True, sort_keys=True,
                separators=(",", ":"),
            )
            if record_offsets is not None and index < len(record_offsets):
                stable_position = f"offset:{int(record_offsets[index])}"
            else:
                ordinal = occurrences.get(canonical, 0)
                occurrences[canonical] = ordinal + 1
                stable_position = f"compat-ordinal:{ordinal}"
            digest = _sha256_hex(
                (absolute_queue + "\0" + stable_position + "\0" + canonical)
                .encode("utf-8")
            )
            event_id = "legacy-" + digest[:32]
        event["event_id"] = event_id
        prepared.append(event)
    return prepared


def _append_delivery_transition(queue_file: Path, state: str,
                                events: list[dict], *, result=None,
                                error: str = "",
                                cursor_committed: bool = False):
    """Durably append a delivery transition before returning to the watcher.

    This is an injector-result/DLQ journal, not a semantic CLI ACK.  New
    `accepted` records mean only that the local injector positively completed
    text+Enter; `dead-letter` is explicit/manual; retryable or uncertain
    states keep the queue cursor unchanged.  The append is flushed before the
    cursor can advance, allowing restart-time deduplication.
    """
    if not isinstance(state, str) or state not in _KNOWN_DELIVERY_STATES:
        raise ValueError(f"unknown delivery journal state: {state!r}")
    record = {
        "journal_version": 1,
        "at_ns": time.time_ns(),
        "state": state,
        "event_ids": [event["event_id"] for event in events],
    }
    if cursor_committed:
        record["cursor_committed"] = True
    action_ids = [
        event.get("action_id") for event in events
        if _valid_delivery_id(event.get("action_id"))
    ]
    if action_ids:
        record["action_ids"] = action_ids
    if result is not None:
        record["inject_result"] = str(result)
    if error:
        record["error"] = str(error)[:500]
    _validate_delivery_record(record)
    path = _delivery_journal_path(queue_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(
        record, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ) + "\n").encode("utf-8")
    with queue_file_lock(queue_file):
        current_size = path.stat().st_size if path.exists() else 0
        if current_size + len(encoded) > _MAX_DELIVERY_JOURNAL_BYTES:
            marker = write_backpressure_marker(
                queue_file, "delivery-journal", current_size,
                _MAX_DELIVERY_JOURNAL_BYTES,
            )
            raise DeliveryBackpressureError(
                f"delivery journal {path.name} reached "
                f"{current_size}/{_MAX_DELIVERY_JOURNAL_BYTES} bytes; "
                f"injection blocked; reconcile {marker.name}"
            )
        append_bytes_durable(path, encoded)


def _read_delivery_indexes(queue_file: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    """Read latest transitions by event and idempotent action ID.

    A single producer/maintenance lock prevents observing a journal while a
    future bounded compactor is replacing it.  An incomplete final line is
    corruption too: an ignored attempt/acceptance tail could otherwise allow
    a duplicate injection after a crash.
    """
    path = _delivery_journal_path(queue_file)
    with queue_file_lock(queue_file):
        raw = path.read_bytes() if path.exists() else b""
    if not raw:
        return {}, {}
    if not raw.endswith(b"\n"):
        raise ValueError("torn delivery journal tail (missing newline)")
    states: dict[str, dict] = {}
    actions: dict[str, dict] = {}
    for number, raw_line in enumerate(raw.splitlines(), 1):
        if not raw_line.strip():
            raise ValueError(f"empty delivery journal line {number}")
        try:
            record = json.loads(
                raw_line.decode("utf-8", "strict"),
                object_pairs_hook=_strict_json_object,
            )
        except Exception as exc:
            raise ValueError(
                f"corrupt delivery journal line {number}: {type(exc).__name__}"
            ) from exc
        record = _validate_delivery_record(record, number)
        for event_id in record["event_ids"]:
            states[event_id] = record
        raw_actions = record.get("action_ids", [])
        for action_id in raw_actions:
            actions[action_id] = record
    return states, actions


def _read_delivery_states(queue_file: Path) -> dict[str, dict]:
    """Compatibility view: latest complete transition per event ID."""
    return _read_delivery_indexes(queue_file)[0]


def _remove_corrupt_journal(path: Path) -> None:
    """Fault-injection seam: remove only after marker and evidence are durable."""
    path.unlink()


def _quarantine_delivery_journal(queue_file: Path,
                                 error: str = "") -> Path | None:
    """Preserve a corrupt journal under a never-reused evidence path.

    A durable sidecar fence is written first and is checked before every
    injection. Evidence is then copied+fsynced before the live corrupt path is
    removed. Thus every crash/OSError window leaves either the original
    corrupt journal or the authoritative fence (normally both/evidence), and
    exclusive temp creation prevents same-tick evidence overwrite.
    """
    path = _delivery_journal_path(queue_file)
    with queue_file_lock(queue_file):
        _write_delivery_block_marker(queue_file, error)
        if not path.exists():
            return None
        raw = path.read_bytes()
        target = write_unique_evidence(path, raw)
        _write_delivery_block_marker(queue_file, error, target.name)
        _remove_corrupt_journal(path)
        fsync_directory_best_effort(path.parent)
    return target


def _delivery_envelope(events: list[dict]) -> str:
    payload = {
        "v": 1,
        "event_ids": [event["event_id"] for event in events],
    }
    action_ids = [
        event.get("action_id") for event in events
        if _valid_delivery_id(event.get("action_id"))
    ]
    if action_ids:
        payload["action_ids"] = action_ids
    return "DELIVERY_ENVELOPE=" + json.dumps(
        payload, ensure_ascii=True, separators=(",", ":")
    )


def _coalesce_trigger_prompt(triggers: list[dict]) -> str:
    """Coalesce pending triggers into ONE prompt that represents EVERY
    consumed record: all distinct channels, all distinct jobs, and every
    custom prompt (in arrival order) — nothing that is consumed may be left
    unrepresented. Single-destination batches keep the legacy phrasing."""
    channels: list[str] = []
    jobs: list = []
    customs: list[str] = []
    for data in triggers:
        raw_prompt = data.get("prompt", "")
        if isinstance(raw_prompt, str) and raw_prompt.strip():
            # A custom prompt is a complete instruction authored for its
            # trigger; it represents its own record.
            customs.append(raw_prompt.strip())
            continue
        if data.get("job_id"):
            if data["job_id"] not in jobs:
                jobs.append(data["job_id"])
            if "channel" not in data:
                continue
        channel = data.get("channel", "general") or "general"
        if "channel" in data or not data.get("job_id"):
            if channel not in channels:
                channels.append(channel)
    targets = [f"#{c}" for c in channels] + [f"job_id={j}" for j in jobs]
    read_part = ""
    if len(targets) == 1 and jobs:
        read_part = (
            f"use mcp to read job_id={jobs[0]} - you're mentioned in a job "
            f"thread, take appropriate action and respond"
        )
    elif len(targets) == 1:
        read_part = (
            f"use mcp to read #{channels[0]} - you're mentioned, "
            f"take appropriate action and respond"
        )
    elif targets:
        read_part = (
            f"use mcp to read {', '.join(targets)} - you're mentioned, "
            f"take appropriate action and respond"
        )
    parts = list(customs)
    if read_part:
        parts.append(read_part)
    return "\n\n".join(parts) if parts else (
        "use mcp to read #general - you're mentioned, "
        "take appropriate action and respond"
    )


# Only a positive worker-side injector acknowledgement consumes a batch.
# This is not an end-to-end CLI semantic ACK; it proves only that the injector
# positively completed text+Enter.  Ambiguous/legacy results remain durable.
_CONSUME_RESULTS = (True, "injected", "dead-letter")


def _terminal_delivery_state(result):
    if result is True or result == "injected":
        return "accepted"
    if result == "dead-letter":
        return "dead-letter"
    return None


def _nonterminal_delivery_state(result) -> str:
    if result in (None, False, "injected-uncertain"):
        return "injected-uncertain"
    if result == "injection-timeout":
        return "injection-timeout"
    return "retry"


def _call_inject_bounded(inject_fn, prompt: str, timeout_seconds: float):
    """Run a possibly blocking injector without wedging the queue watcher.

    Python cannot safely kill a thread.  On timeout we therefore leave the
    event in a durable *blocked/uncertain* state and never auto-retry it: the
    timed-out call may still submit later, so replay would risk a duplicate.
    """
    finished = threading.Event()
    outcome: dict[str, object] = {}

    def invoke():
        try:
            outcome["result"] = inject_fn(prompt)
        except BaseException as exc:  # re-raised in the watcher thread
            outcome["error"] = exc
        finally:
            finished.set()

    thread = threading.Thread(target=invoke, daemon=True, name="queue-inject")
    thread.start()
    if not finished.wait(max(0.01, float(timeout_seconds))):
        return "injection-timeout"
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("result")


class _WatcherDefer(Exception):
    """Internal: defer this watcher iteration without consuming anything."""


def _capture_identity(get_identity_fn, get_token_fn):
    """Capture (name, queue, token) as one consistent generation: identity is
    re-read until it is unchanged across the token fetch."""
    for _ in range(3):
        name, queue = get_identity_fn()
        token = get_token_fn() if get_token_fn else ""
        name2, queue2 = get_identity_fn()
        if (name, queue) == (name2, queue2):
            return name, queue, token
    return name2, queue2, (get_token_fn() if get_token_fn else "")


_MAX_INLINE_RULES_CHARS = 640


def _rules_prompt_context(rules_data: dict) -> str:
    """Return bounded rules context suitable for an interactive composer.

    Full active rules remain authoritative. Small sets are carried inline;
    larger sets use the authenticated MCP endpoint so the prompt stays short
    enough for the admission guard to verify before pressing Enter.
    """
    rules = rules_data.get("rules", [])
    if not rules:
        return ""
    rules_text = "; ".join(str(rule) for rule in rules)
    if len(rules_text) <= _MAX_INLINE_RULES_CHARS:
        return "RULES:\n" + rules_text
    epoch = rules_data.get("epoch", "unknown")
    return (
        f"RULES: {len(rules)} active rules at epoch {epoch}. Before acting, "
        "use MCP chat_rules(action='list') and follow the complete returned "
        "rule set."
    )


def _queue_watcher(get_identity_fn, inject_fn, *, is_multi_instance: bool = False, trigger_flag=None,
                   server_port: int = 8300, agent_name: str = "", get_token_fn=None,
                   refresh_interval: int = 10, poll_seconds: float = 1.0, stop_event=None,
                   fetch_role_fn=None, fetch_rules_fn=None, report_sync_fn=None,
                   inject_timeout_seconds: float = 30.0):
    """Poll queue file and inject an MCP read task when triggered.

    Fail-closed durability contract: the queue file is read non-destructively
    and consumed (cursor advance, bound to the consumed-prefix hash) only
    after the injector reports a terminal result. Triggers arriving during a
    deferral coalesce into the next attempt's batch; every consumed record is
    represented in the injected prompt. Unavailable/invalid rules or role
    service defers injection (no context-less tasks). Undecodable/malformed
    pending records are quarantined with an alert — never silently skipped.
    A crash mid-deferral leaves queue bytes and cursor on disk, recoverable.
    """
    fetch_role = fetch_role_fn or _fetch_role_status
    fetch_rules = fetch_rules_fn or _fetch_active_rules_status
    report_sync = report_sync_fn or _report_rule_sync
    first_mention = True
    last_rules_epoch = 0  # 0 = unknown/cold start — will inject on first trigger
    trigger_count = 0
    fetch_streak_noted = False
    last_queue = None
    last_error_signature = None
    last_error_reported_at = 0.0
    while stop_event is None or not stop_event.is_set():
        consumer_lease = None
        consumer_lease_acquired = False
        try:
            name0, queue0, token0 = _capture_identity(get_identity_fn, get_token_fn)
            last_queue = queue0
            consumer_lease = queue_consumer_lease(queue0, timeout=0.0)
            try:
                consumer_lease.__enter__()
                consumer_lease_acquired = True
            except TimeoutError:
                # Another watcher owns this queue's complete delivery
                # transaction.  Producers use a different short-held lock,
                # so they remain free to append while injection is running.
                raise _WatcherDefer()
            with queue_file_lock(queue0):
                status, pending, snapshot_end, raw = _read_pending_triggers(queue0)
            pending_start = _read_queue_cursor(queue0, raw)
            triggers, malformed, record_offsets = (
                ([], 0, []) if status != "ok"
                else _parse_trigger_records(pending, pending_start)
            )
            if triggers or status == "corrupt" or malformed:
                # Signal activity BEFORE injecting — covers the thinking phase
                if trigger_flag is not None:
                    trigger_flag[0] = True
                time.sleep(0.5)
                # Re-snapshot to coalesce triggers that arrived meanwhile —
                # the durable queue stays untouched until injection succeeds.
                with queue_file_lock(queue0):
                    status, pending, snapshot_end, raw = _read_pending_triggers(queue0)
                pending_start = _read_queue_cursor(queue0, raw)
                triggers, malformed, record_offsets = (
                    ([], 0, []) if status != "ok"
                    else _parse_trigger_records(pending, pending_start)
                )

            if status == "corrupt" or malformed:
                # Never skip-and-consume past bad records: quarantine the
                # whole pending window (fsync) and alert on the console. The
                # quarantined bytes stay recoverable for manual replay.
                start = _read_queue_cursor(queue0, raw)
                if _quarantine_pending_window(queue0, raw, start, snapshot_end):
                    print(
                        f"  [wrapper] {name0}: unparseable queue records "
                        f"quarantined ({queue0.name}, {snapshot_end - start} "
                        f"bytes); manual replay required.", flush=True,
                    )
            elif triggers:
                all_events = _prepare_delivery_events(
                    queue0, triggers, record_offsets
                )
                # A corruption fence is permanent until explicit manual
                # reconciliation. Marker existence alone blocks, even if a
                # crash tore the marker JSON or the replacement journal.
                if _delivery_is_blocked(queue0):
                    raise _WatcherDefer()
                try:
                    delivery_states, action_states = _read_delivery_indexes(queue0)
                except ValueError as exc:
                    quarantined = _quarantine_delivery_journal(
                        queue0, str(exc)
                    )
                    _append_delivery_transition(
                        queue0, "journal-corrupt-blocked", all_events,
                        error=(
                            f"{exc}; quarantined="
                            f"{quarantined.name if quarantined else 'unavailable'}"
                        ),
                    )
                    print(
                        f"  [wrapper] {name0}: corrupt delivery journal "
                        f"quarantined as "
                        f"{quarantined.name if quarantined else 'unavailable'}; "
                        f"pending delivery is BLOCKED for manual "
                        f"reconciliation ({exc}).",
                        flush=True,
                    )
                    raise _WatcherDefer()

                # Deduplicate both physical event retries and logical action
                # retries.  A batch containing an uncertain prior attempt is
                # blocked in place: advancing would falsely ACK it, while
                # replay could duplicate a side effect.
                prior_records: dict[str, dict] = {}
                events: list[dict] = []
                batch_actions: dict[str, dict] = {}
                blocked = []
                duplicate_of_batch: set[str] = set()
                for event in all_events:
                    prior = delivery_states.get(event["event_id"])
                    action_id = event.get("action_id")
                    if prior is None and _valid_delivery_id(action_id):
                        prior = action_states.get(action_id)
                    if prior is not None and prior.get("state") in _TERMINAL_DELIVERY_STATES:
                        prior_records[event["event_id"]] = prior
                        continue
                    if prior is not None and prior.get("state") in _BLOCKED_DELIVERY_STATES:
                        prior_records[event["event_id"]] = prior
                        blocked.append(event)
                        continue
                    if _valid_delivery_id(action_id) and action_id in batch_actions:
                        duplicate_of_batch.add(event["event_id"])
                        continue
                    if _valid_delivery_id(action_id):
                        batch_actions[action_id] = event
                    events.append(event)

                if blocked:
                    raise _WatcherDefer()
                if not events:
                    # Every record is already terminal by event/action ID.
                    # Complete the cursor transaction without re-injection.
                    _write_queue_cursor(queue0, snapshot_end, raw)
                    for event in all_events:
                        prior = prior_records[event["event_id"]]
                        _append_delivery_transition(
                            queue0, prior["state"], [event],
                            result=prior.get("inject_result"),
                            cursor_committed=True,
                        )
                    continue

                prompt = _coalesce_trigger_prompt(events)
                prompt += "\n\n" + _delivery_envelope(events)

                # H4: authoritative context is required before injecting —
                # transport failures defer (retry next poll), they are not
                # the same as "no role" / "no rules".
                role_ok, role = fetch_role(server_port, name0)
                if role_ok and not role and name0 != agent_name:
                    role_ok, role = fetch_role(server_port, agent_name)
                rules_ok, rules_data = fetch_rules(server_port, token0)
                if not role_ok or not rules_ok:
                    if not fetch_streak_noted:
                        print(
                            f"  [wrapper] {name0}: mention deferred — "
                            f"role/rules service unavailable; retrying.",
                            flush=True,
                        )
                        fetch_streak_noted = True
                    raise _WatcherDefer()
                fetch_streak_noted = False
                if role:
                    prompt += f"\n\nROLE: {role}"

                # Smart rules injection: first trigger, epoch change, or periodic refresh
                rules_epoch_to_commit = None
                # Use server-side refresh_interval (live from settings UI)
                ri = rules_data.get("refresh_interval", refresh_interval)
                need_inject = (
                    last_rules_epoch == 0
                    or rules_data["epoch"] != last_rules_epoch
                    or (ri > 0 and (trigger_count + 1) % ri == 0)
                )
                if need_inject:
                    rules_context = _rules_prompt_context(rules_data)
                    if rules_context:
                        prompt += "\n\n" + rules_context
                    rules_epoch_to_commit = rules_data["epoch"]

                identity_hint_added = False
                if first_mention and is_multi_instance:
                    prompt += _IDENTITY_HINT
                    identity_hint_added = True

                # H5: identity must still be the captured generation right
                # before input; a rename/re-register mid-iteration abandons
                # the attempt (the new generation re-reads its own queue).
                if get_identity_fn() != (name0, queue0):
                    raise _WatcherDefer()

                # Flatten to single line — multi-line text triggers paste
                # detection in CLIs (Claude Code shows "[Pasted text +N]")
                # which can break injection of long session prompts
                if _delivery_is_blocked(queue0):
                    raise _WatcherDefer()
                _append_delivery_transition(queue0, "attempting", events)
                # Recheck after the durable attempt transition as well.  A
                # corruption fence may be published by recovery/maintenance
                # between context fetch and input; it always wins admission.
                if _delivery_is_blocked(queue0):
                    raise _WatcherDefer()
                result = _call_inject_bounded(
                    inject_fn, prompt.replace("\n", " "),
                    inject_timeout_seconds,
                )
                terminal_state = _terminal_delivery_state(result)
                if terminal_state is not None:
                    # Persist acceptance/dead-letter BEFORE the cursor. If
                    # the process dies between these writes, the next watcher
                    # advances without re-injecting the acknowledged events.
                    _append_delivery_transition(
                        queue0, terminal_state, events, result=result,
                    )
                    # Consume exactly the snapshot that built this batch
                    # (cursor bound to queue0 + prefix hash); later appends
                    # stay pending for the next batch.
                    _write_queue_cursor(queue0, snapshot_end, raw)
                    delivered_ids = {event["event_id"] for event in events}
                    for event in all_events:
                        if (
                            event["event_id"] in delivered_ids
                            or event["event_id"] in duplicate_of_batch
                        ):
                            committed_state = terminal_state
                            committed_result = result
                        else:
                            prior = prior_records[event["event_id"]]
                            committed_state = prior["state"]
                            committed_result = prior.get("inject_result")
                        _append_delivery_transition(
                            queue0, committed_state, [event],
                            result=committed_result,
                            cursor_committed=True,
                        )
                    if terminal_state == "dead-letter":
                        print(
                            f"  [wrapper] {name0}: terminal injection failure "
                            f"moved {len(events)} event(s) to delivery DLQ "
                            f"({_delivery_journal_path(queue0).name}).",
                            flush=True,
                        )
                    trigger_count += 1
                    if rules_epoch_to_commit is not None:
                        last_rules_epoch = rules_epoch_to_commit
                        report_sync(server_port, name0, rules_epoch_to_commit, token0)
                    if identity_hint_added:
                        first_mention = False
                else:
                    # Retry/uncertain state is durable and never advances the
                    # cursor.  Uncertain/timeout states are also recognized at
                    # the next poll as blocked, preventing duplicate typing.
                    nonterminal_state = _nonterminal_delivery_state(result)
                    _append_delivery_transition(
                        queue0, nonterminal_state, events,
                        result=result,
                    )
                    if nonterminal_state in _BLOCKED_DELIVERY_STATES:
                        print(
                            f"  [wrapper] {name0}: injection outcome "
                            f"{nonterminal_state}; {len(events)} event(s) "
                            f"remain unacknowledged and blocked for manual "
                            f"reconciliation.",
                            flush=True,
                        )
        except _WatcherDefer:
            pass
        except Exception as exc:
            # The old watcher swallowed every failure. Make a persistent
            # failure visible while keeping the self-recovering poll loop.
            now = time.monotonic()
            signature = f"{type(exc).__name__}: {exc}"
            if (
                signature != last_error_signature
                or now - last_error_reported_at >= 60.0
            ):
                print(
                    f"  [wrapper] queue watcher error (recovering): "
                    f"{signature}", flush=True,
                )
                if last_queue is not None:
                    try:
                        _append_delivery_transition(
                            last_queue, "watcher-error", [], error=signature,
                        )
                    except Exception:
                        pass
                last_error_signature = signature
                last_error_reported_at = now
        finally:
            if consumer_lease_acquired:
                consumer_lease.__exit__(None, None, None)

        if stop_event is not None:
            if stop_event.wait(poll_seconds):
                break
        else:
            time.sleep(poll_seconds)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    import urllib.error
    import urllib.request

    from config_loader import apply_cli_overrides, load_config

    # Apply AGENTCHATTR_* overrides (from CLI flags or env) BEFORE loading
    # config so the wrapper connects to the same data_dir/ports as a server
    # launched with matching flags.
    apply_cli_overrides()
    config = load_config(ROOT)

    agent_names = list(config.get("agents", {}).keys())

    parser = argparse.ArgumentParser(description="Agent wrapper with chat auto-trigger")
    parser.add_argument("agent", choices=agent_names, help=f"Agent to wrap ({', '.join(agent_names)})")
    parser.add_argument(
        "--handoff-file", default="", help=argparse.SUPPRESS,
    )
    parser.add_argument("--no-restart", action="store_true", help="Do not restart on exit")
    parser.add_argument("--label", type=str, default=None, help="Custom display label")
    # Per-project isolation flags (must match the server's flags so wrappers
    # launched separately connect to the right instance). Values are consumed
    # by apply_cli_overrides() above; listing here so --help shows them.
    parser.add_argument("--data-dir",      default=None, help="Override server.data_dir (path)")
    parser.add_argument("--port",          default=None, help="Override server.port (int)")
    parser.add_argument("--mcp-http-port", default=None, help="Override mcp.http_port (int)")
    parser.add_argument("--mcp-sse-port",  default=None, help="Override mcp.sse_port (int)")
    parser.add_argument("--upload-dir",    default=None, help="Override images.upload_dir (path)")
    args, extra = parser.parse_known_args()

    agent = args.agent
    agent_cfg = config.get("agents", {}).get(agent, {})
    cwd = agent_cfg.get("cwd", ".")
    command = agent_cfg.get("command", agent)
    data_dir = ROOT / config.get("server", {}).get("data_dir", "./data")
    data_dir.mkdir(parents=True, exist_ok=True)
    server_port = config.get("server", {}).get("port", 8300)
    mcp_cfg = config.get("mcp", {})

    try:
        if args.handoff_file:
            if args.label is not None:
                raise RuntimeError("restart handoff cannot override the identity label")
            registration = _adopt_restart_handoff(
                args.handoff_file, agent=agent, data_dir=data_dir,
                server_port=server_port,
            )
        else:
            registration = _register_instance(server_port, agent, args.label)
    except Exception as exc:
        print(f"  Registration failed ({exc}).")
        print("  Wrapper cannot continue without a registered identity.")
        sys.exit(1)

    assigned_name = registration["name"]
    assigned_token = registration["token"]
    print(f"  Registered as: {assigned_name} (slot {registration.get('slot', '?')})")

    proxy = None
    proxy_url = None

    # Resolve MCP injection mode to determine if a proxy is needed.
    # Direct-connect modes (settings_file, env, flag) don't need a proxy.
    # proxy_flag mode needs a proxy. No mcp_inject = proxy fallback.
    inject_cfg = _resolve_mcp_inject(agent, agent_cfg)
    inject_mode = inject_cfg.get("mcp_inject", "")
    if inject_mode and inject_mode not in _VALID_INJECT_MODES:
        print(f"  Error: unknown mcp_inject mode '{inject_mode}' for agent '{agent}'.")
        print(f"  Valid modes: {', '.join(sorted(_VALID_INJECT_MODES))}")
        sys.exit(1)
    needs_proxy = inject_mode in ("proxy_flag", "") or not inject_mode

    if needs_proxy:
        from mcp_proxy import McpIdentityProxy

        transport = inject_cfg.get("mcp_transport", "http")
        if transport == "sse":
            upstream_base = f"http://127.0.0.1:{mcp_cfg.get('sse_port', 8201)}"
            proxy_path = "/sse"
        else:
            upstream_base = f"http://127.0.0.1:{mcp_cfg.get('http_port', 8200)}"
            proxy_path = "/mcp"

        proxy = McpIdentityProxy(
            upstream_base=upstream_base,
            upstream_path=proxy_path,
            agent_name=assigned_name,
            instance_token=assigned_token,
        )
        if proxy.start() is False:
            print("  Failed to start MCP proxy.")
            sys.exit(1)
        proxy_url = f"{proxy.url}{proxy_path}"

    _identity_lock = threading.Lock()
    _identity = {
        "name": assigned_name,
        "queue": data_dir / f"{assigned_name}_queue.jsonl",
        "token": assigned_token,
    }

    def get_identity():
        with _identity_lock:
            return _identity["name"], _identity["queue"]

    def get_token():
        with _identity_lock:
            return _identity["token"]

    # Rewrite MCP config when token/name changes (e.g. after 409 re-register).
    # Most CLIs won't re-read mid-session, but the file is correct for next restart.
    def _rewrite_mcp_config(instance_name: str, new_token: str):
        if not inject_mode or needs_proxy:
            return  # proxy-based agents don't have config files to rewrite
        try:
            _apply_mcp_inject(
                inject_cfg, instance_name, data_dir, proxy_url,
                token=new_token, mcp_cfg=mcp_cfg,
                project_dir=(ROOT / cwd).resolve(),
            )
        except Exception:
            pass

    def set_runtime_identity(new_name: str | None = None, new_token: str | None = None):
        with _identity_lock:
            old_name = _identity["name"]
            old_token = _identity["token"]
            changed = False
            if new_name and new_name != old_name:
                _identity["name"] = new_name
                _identity["queue"] = data_dir / f"{new_name}_queue.jsonl"
                changed = True
            if new_token and new_token != old_token:
                _identity["token"] = new_token
                changed = True
            current_name = _identity["name"]
            current_token = _identity["token"]

        if changed and proxy is not None:
            proxy.agent_name = current_name
            proxy.token = current_token
        if changed:
            if new_name and new_name != old_name:
                print(f"  Identity updated: {old_name} -> {new_name}")
            if new_token and new_token != old_token:
                print(f"  Session refreshed for @{current_name}")
            _rewrite_mcp_config(current_name, current_token)

        return changed

    queue_file = _identity["queue"]
    _preserve_stale_queue(queue_file)

    strip_vars = {"CLAUDECODE"} | set(agent_cfg.get("strip_env", []))
    env = {k: v for k, v in os.environ.items() if k not in strip_vars}

    resolved = shutil.which(command)
    if not resolved:
        print(f"  Error: '{command}' not found on PATH.")
        print("  Install it first, then try again.")
        sys.exit(1)
    command = resolved

    project_dir = (ROOT / cwd).resolve()

    # Gemini: ensure the project directory is trusted so MCPs are allowed.
    # Gemini blocks ALL MCPs for untrusted folders — even system-settings ones.
    if agent == "gemini" or inject_cfg.get("mcp_inject") == "env":
        _ensure_gemini_folder_trusted(project_dir)

    launch_args, env, inject_env, mcp_settings_path = _build_provider_launch(
        agent=agent,
        agent_cfg=agent_cfg,
        instance_name=assigned_name,
        data_dir=data_dir,
        proxy_url=proxy_url,
        extra_args=extra,
        env=env,
        token=assigned_token,
        mcp_cfg=mcp_cfg,
        project_dir=project_dir,
    )

    print(f"  === {assigned_name.capitalize()} Chat Wrapper ===")
    if not needs_proxy:
        print(f"  MCP: direct connect ({inject_mode}) with bearer auth")
        if mcp_settings_path:
            print(f"  Config: {mcp_settings_path}")
    elif proxy_url:
        print(f"  Local MCP proxy: {proxy_url}")
    print(f"  @{assigned_name} mentions auto-inject MCP reads")
    print(f"  Starting {command} in {cwd}...\n")

    def _heartbeat():
        while True:
            current_name, _ = get_identity()
            current_token = get_token()
            url = f"http://127.0.0.1:{server_port}/api/heartbeat/{current_name}"
            try:
                req = urllib.request.Request(
                    url,
                    method="POST",
                    data=b"",
                    headers=_auth_headers(current_token),
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp_data = json.loads(resp.read())
                server_name = resp_data.get("name", current_name)
                if server_name != current_name:
                    set_runtime_identity(server_name)
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    try:
                        replacement = _register_instance(server_port, agent, args.label)
                        set_runtime_identity(replacement["name"], replacement["token"])
                        _notify_recovery(data_dir, replacement["name"])
                    except Exception:
                        pass
                time.sleep(5)
                continue
            except Exception:
                time.sleep(5)
                continue

            time.sleep(5)

    threading.Thread(target=_heartbeat, daemon=True).start()

    _watcher_inject_fn = None
    _watcher_thread = None
    _is_multi_instance = registration.get("slot", 1) > 1
    _trigger_flag = [False]  # shared: queue watcher sets True, activity checker reads
    _refresh_interval = 10  # default; overridden per-trigger by server settings

    def start_watcher(inject_fn):
        nonlocal _watcher_inject_fn, _watcher_thread
        _watcher_inject_fn = inject_fn
        _watcher_thread = threading.Thread(
            target=_queue_watcher,
            args=(get_identity, inject_fn),
            kwargs={"is_multi_instance": _is_multi_instance, "trigger_flag": _trigger_flag,
                    "server_port": server_port, "agent_name": assigned_name,
                    "get_token_fn": get_token, "refresh_interval": _refresh_interval},
            daemon=True,
        )
        _watcher_thread.start()

    def _watcher_monitor():
        nonlocal _watcher_thread
        while True:
            time.sleep(5)
            if _watcher_thread and not _watcher_thread.is_alive() and _watcher_inject_fn:
                current_name, _ = get_identity()
                print(
                    f"  [wrapper] {current_name}: queue watcher stopped; "
                    f"starting a replacement.", flush=True,
                )
                _watcher_thread = threading.Thread(
                    target=_queue_watcher,
                    args=(get_identity, _watcher_inject_fn),
                    kwargs={"is_multi_instance": _is_multi_instance, "trigger_flag": _trigger_flag,
                            "server_port": server_port, "agent_name": assigned_name,
                            "get_token_fn": get_token, "refresh_interval": _refresh_interval},
                    daemon=True,
                )
                _watcher_thread.start()
                _notify_recovery(data_dir, current_name)

    threading.Thread(target=_watcher_monitor, daemon=True).start()

    _activity_checker = None

    def _set_activity_checker(checker):
        nonlocal _activity_checker
        _activity_checker = checker

    def _activity_monitor():
        last_active = None
        last_report_time = 0
        REPORT_INTERVAL = 3  # re-send state every 3s while active (keeps server lease fresh)
        while True:
            time.sleep(1)
            if not _activity_checker:
                continue
            try:
                active = _activity_checker()
                now = time.time()
                # Send on state change, periodically while active (refresh lease),
                # or periodically while idle (keep presence alive)
                IDLE_REPORT_INTERVAL = 8  # keep-alive while idle
                should_send = (
                    active != last_active
                    or (active and now - last_report_time >= REPORT_INTERVAL)
                    or (not active and now - last_report_time >= IDLE_REPORT_INTERVAL)
                )
                if should_send:
                    current_name, _ = get_identity()
                    current_token = get_token()
                    url = f"http://127.0.0.1:{server_port}/api/heartbeat/{current_name}"
                    body = json.dumps({"active": active}).encode()
                    req = urllib.request.Request(
                        url,
                        method="POST",
                        data=body,
                        headers=_auth_headers(current_token, include_json=True),
                    )
                    resp = urllib.request.urlopen(req, timeout=5)
                    resp_code = resp.getcode()
                    last_active = active
                    last_report_time = now
            except Exception:
                pass

    threading.Thread(target=_activity_monitor, daemon=True).start()

    _agent_pid = [None]

    if sys.platform == "win32":
        from wrapper_windows import get_activity_checker, run_agent

        _set_activity_checker(get_activity_checker(_agent_pid, agent_name=assigned_name, trigger_flag=_trigger_flag))
    else:
        from wrapper_unix import get_activity_checker, run_agent

        unix_session_name = f"agentchattr-{assigned_name}"
        _set_activity_checker(get_activity_checker(unix_session_name, trigger_flag=_trigger_flag))

    run_kwargs = dict(
        command=command,
        extra_args=launch_args,
        cwd=cwd,
        env=env,
        queue_file=queue_file,
        agent=agent,
        no_restart=args.no_restart,
        start_watcher=start_watcher,
        strip_env=list(strip_vars),
        pid_holder=_agent_pid,
        inject_env=inject_env,
        inject_delay=agent_cfg.get("inject_delay", 0.3),
    )
    # Windows-only injection tuning (no-op on other platforms).
    if sys.platform == "win32":
        run_kwargs["enter_backend"] = agent_cfg.get("enter_backend", "console_input")
        run_kwargs["safeguard_auto_retry"] = agent_cfg.get(
            "safeguard_auto_retry", False
        )
        run_kwargs["safeguard_max_retries"] = agent_cfg.get(
            "safeguard_max_retries", 2
        )
        # Fail-closed queue-injection admission gate (per-agent opt-in via
        # config.toml; the code default stays off to preserve the pre-existing
        # legacy injector contract).
        run_kwargs["injection_admission_guard"] = agent_cfg.get(
            "injection_admission_guard", False
        )
        run_kwargs["composer_provider"] = agent_cfg.get("composer_provider", "")
        run_kwargs["composer_markers"] = agent_cfg.get("composer_markers", None)
        run_kwargs["composer_placeholders"] = agent_cfg.get(
            "composer_placeholders", None
        )
        run_kwargs["composer_stable_reads"] = agent_cfg.get(
            "composer_stable_reads", 2
        )

        def _report_safeguard_event(event: dict):
            action = event.get("action", "unknown")
            attempt = event.get("attempt", 0)
            fingerprint = event.get("fingerprint", "unknown")
            current_name, _ = get_identity()
            current_token = get_token()
            if action == "retry":
                text = (
                    f"@codex [wrapper] agent={current_name}: exact Fable safeguard "
                    f"menu detected; selected option 2 automatically "
                    f"(attempt {attempt}/"
                    f"{run_kwargs['safeguard_max_retries']}, "
                    f"screen={fingerprint}). Never selected Opus."
                )
            elif action == "escalate":
                text = (
                    f"@user @codex [wrapper] agent={current_name}: automatic "
                    f"Fable retry stopped after {attempt} attempts "
                    f"(screen={fingerprint}); manual prompt review required. "
                    f"No model switch was attempted."
                )
            elif action == "ambiguous":
                text = (
                    f"@user @codex [wrapper] agent={current_name}: safeguard-like "
                    f"menu wording did not match the approved exact template "
                    f"(screen={fingerprint}); no input was sent."
                )
            elif action == "selection-cancelled":
                text = (
                    f"@user @codex [wrapper] agent={current_name}: Fable retry "
                    f"was cancelled because option 2 could not be verified "
                    f"as selected (screen={fingerprint}); Enter was not sent "
                    f"and manual review is required."
                )
            elif action == "monitor-error":
                error_type = event.get("error_type", "unknown")
                text = (
                    f"@user @codex [wrapper] agent={current_name}: safeguard "
                    f"monitor recovered from {error_type}; no model switch "
                    f"was attempted. Manual screen review is required."
                )
            elif action == "injection-deferred":
                classification = event.get("classification", "unknown")
                text = (
                    f"@user @codex [wrapper] agent={current_name}: queued "
                    f"mention input is deferred while the console is "
                    f"{classification} (screen={fingerprint}); no keys were "
                    f"sent."
                )
            elif action == "injection-enter-cancelled":
                text = (
                    f"@user @codex [wrapper] agent={current_name}: a safeguard "
                    f"menu appeared after queued text was typed "
                    f"(screen={fingerprint}); Enter was suppressed. Manual "
                    f"composer recovery is required."
                )
            elif action == "injection-enter-uncertain":
                text = (
                    f"@user @codex [wrapper] agent={current_name}: queued "
                    f"input Enter delivery was only partially confirmed; the "
                    f"task was consumed and will NOT be retried to avoid a "
                    f"duplicate submission. Please verify the session "
                    f"received exactly one task."
                )
            elif action == "injection-error":
                error_type = event.get("error_type", "unknown")
                text = (
                    f"@user @codex [wrapper] agent={current_name}: queued "
                    f"input failed with {error_type}; Enter was not confirmed "
                    f"and manual composer review is required."
                )
            else:
                return
            body = json.dumps({"text": text, "channel": "general"}).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{server_port}/api/send",
                method="POST",
                data=body,
                headers=_auth_headers(current_token, include_json=True),
            )
            with urllib.request.urlopen(req, timeout=5):
                pass

        run_kwargs["safeguard_event_callback"] = _report_safeguard_event
    if sys.platform != "win32":
        run_kwargs["session_name"] = unix_session_name

    try:
        run_agent(**run_kwargs)
    finally:
        try:
            current_name, _ = get_identity()
            current_token = get_token()
            dereg_req = urllib.request.Request(
                f"http://127.0.0.1:{server_port}/api/deregister/{current_name}",
                method="POST",
                data=b"",
                headers=_auth_headers(current_token),
            )
            urllib.request.urlopen(dereg_req, timeout=5)
            print(f"  Deregistered {current_name}")
        except Exception:
            pass

        if proxy is not None:
            proxy.stop()

    print("  Wrapper stopped.")


if __name__ == "__main__":
    main()
