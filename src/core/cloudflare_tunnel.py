"""
Cloudflare named-tunnel management for NetShare Server (Feature 3).

Unlike core.tunnel.PublicTunnel (an ephemeral SSH tunnel to localhost.run --
a brand new random URL every run, zero setup), a Cloudflare "named tunnel" is
a persistent object tied to the host's own Cloudflare account and domain.
Setting one up is a multi-step, mostly one-time process:

    1. `cloudflared tunnel login`                        -> browser auth,
       writes ~/.cloudflared/cert.pem
    2. `cloudflared tunnel create <name>`                -> creates the
       tunnel, writes ~/.cloudflared/<tunnel-id>.json (credentials)
    3. `cloudflared tunnel route dns <name> <hostname>`  -> CNAME record
       pointing the chosen subdomain at the tunnel
    4. write a config.yml (ingress: hostname -> local NetShare port)
    5. `cloudflared tunnel run --config config.yml <name>`  (long-running)

Steps 1-3 are exposed as separate functions rather than one opaque
"setup everything" call, so the GUI (Part 4) can walk the host through each
step individually and show exactly where it failed (not installed, not
logged in, DNS record already taken by something else, etc).

CloudflareTunnel (the long-running process wrapper) follows the same
callback contract as core.tunnel.PublicTunnel -- on_url / on_error / on_stop
/ on_reconnecting -- so both tunnel types can share the same GUI wiring in
ServerLifecycleMixin later.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import src.state as state
from src.core.tunnel import PublicTunnel

CLOUDFLARED_DOWNLOAD_URL = "https://developers.cloudflare.com/cloudflared/downloads/"

DEFAULT_TUNNEL_NAME = "netshare-server"

_CLOUDFLARED_DIR = Path.home() / ".cloudflared"     # cloudflared's own files (cert, credentials)
_APP_TUNNEL_DIR = state._CONFIG_DIR / "cloudflare_tunnel"  # our generated config.yml


# Installation / auth state

def is_installed() -> bool:
    return shutil.which("cloudflared") is not None


def is_logged_in() -> bool:
    """cert.pem only exists once `cloudflared tunnel login` has succeeded."""
    return (_CLOUDFLARED_DIR / "cert.pem").exists()


def login(timeout: int = 180) -> dict:
    """
    Run `cloudflared tunnel login`, which opens the host's browser to
    authorize against their Cloudflare account/domain and blocks until that
    flow completes (or times out). Call this from a background thread --
    it must never run on the Tk main thread.
    """
    if not is_installed():
        return {"ok": False, "error": "cloudflared_not_installed"}
    try:
        proc = subprocess.run(
            ["cloudflared", "tunnel", "login"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    if proc.returncode != 0 or not is_logged_in():
        return {"ok": False, "error": (proc.stderr or "").strip() or "login_failed"}
    return {"ok": True}


# Tunnel / DNS setup

def list_tunnels() -> list[dict]:
    """Named tunnels already registered under the logged-in account."""
    try:
        proc = subprocess.run(
            ["cloudflared", "tunnel", "list", "--output", "json"],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0:
            return []
        return json.loads(proc.stdout or "[]")
    except Exception:
        return []


_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def create_tunnel(name: str = DEFAULT_TUNNEL_NAME) -> dict:
    """Create (or reuse, if it already exists) a named tunnel.

    Returns {"ok": True, "tunnel_id": ...} or {"ok": False, "error": ...}.
    """
    if not is_logged_in():
        return {"ok": False, "error": "not_logged_in"}
    for existing in list_tunnels():
        if existing.get("name") == name:
            return {"ok": True, "tunnel_id": existing.get("id")}
    try:
        proc = subprocess.run(
            ["cloudflared", "tunnel", "create", name],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or "").strip() or "create_failed"}
    match = _UUID_RE.search(proc.stdout)
    if match:
        return {"ok": True, "tunnel_id": match.group(0)}
    for existing in list_tunnels():
        if existing.get("name") == name:
            return {"ok": True, "tunnel_id": existing.get("id")}
    return {"ok": False, "error": "tunnel_id_not_found"}


def route_dns(hostname: str, name: str = DEFAULT_TUNNEL_NAME) -> dict:
    """Point *hostname* (e.g. partage.mondomaine.com) at the named tunnel."""
    try:
        proc = subprocess.run(
            ["cloudflared", "tunnel", "route", "dns", "--overwrite-dns", name, hostname],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or "").strip() or "route_failed"}
    return {"ok": True}


def _credentials_path(tunnel_id: str) -> Path:
    return _CLOUDFLARED_DIR / f"{tunnel_id}.json"


def write_config(tunnel_id: str, hostname: str, local_port: int) -> Path:
    """
    Write the config.yml consumed by `cloudflared tunnel run --config`.
    Hand-written rather than via PyYAML -- the structure is fixed and small
    enough that adding a dependency for it isn't worth it.
    """
    _APP_TUNNEL_DIR.mkdir(parents=True, exist_ok=True)
    creds = _credentials_path(tunnel_id)
    config_path = _APP_TUNNEL_DIR / "config.yml"
    content = (
        f"tunnel: {tunnel_id}\n"
        f"credentials-file: {creds.as_posix()}\n"
        "ingress:\n"
        f"  - hostname: {hostname}\n"
        f"    service: http://127.0.0.1:{local_port}\n"
        "  - service: http_status:404\n"
    )
    config_path.write_text(content, encoding="utf-8")
    return config_path


def retarget_config(config_path: Path, local_port: int) -> None:
    """Point an existing named tunnel at the dedicated public listener."""
    content = config_path.read_text(encoding="utf-8")
    updated = re.sub(
        r"service:\s*http://127\.0\.0\.1:\d+",
        f"service: http://127.0.0.1:{int(local_port)}",
        content,
        count=1,
    )
    if updated == content and f"127.0.0.1:{int(local_port)}" not in content:
        raise ValueError("Cloudflare ingress service was not found")
    config_path.write_text(updated, encoding="utf-8")


def setup_status(hostname: str, name: str = DEFAULT_TUNNEL_NAME) -> dict:
    """Snapshot used by the GUI to know which setup steps remain."""
    tunnel_id = None
    for existing in list_tunnels() if is_logged_in() else []:
        if existing.get("name") == name:
            tunnel_id = existing.get("id")
            break
    return {
        "installed": is_installed(),
        "logged_in": is_logged_in(),
        "tunnel_created": tunnel_id is not None,
        "tunnel_id": tunnel_id,
        "config_written": (_APP_TUNNEL_DIR / "config.yml").exists(),
    }


# Long-running tunnel process

class CloudflareTunnel(PublicTunnel):
    """
    Wraps `cloudflared tunnel run`. Same callback contract as
    core.tunnel.PublicTunnel: on_url / on_error / on_stop / on_reconnecting.

    Unlike PublicTunnel, the public URL is known up front (the configured
    hostname) instead of being parsed from process output -- on_url fires
    once cloudflared logs a registered connection.
    """

    _RETRY_DELAYS = [3, 6, 12, 30]
    _READY_PATTERN = re.compile(r"[Rr]egistered tunnel connection|Connection .*registered")

    def __init__(self, config_path: Path, hostname: str):
        super().__init__(port=0)
        self._config_path = config_path
        self._hostname = hostname
        self._url_fired = False

    def start(self, *args, **kwargs):
        self._url_fired = False
        super().start(*args, **kwargs)

    def _log_prefix(self) -> str:
        return "CF-TUNNEL"

    def _find_executable(self) -> str | None:
        return shutil.which("cloudflared")

    def _missing_executable_message(self) -> str:
        return "cloudflared not installed"

    def _run_once(self, _cloudflared_bin: str) -> bool:
        if not self._config_path.exists():
            msg = "tunnel config missing - run setup first"
            state._emit(f"CF-TUNNEL {msg}", "error")
            if self._on_error:
                self._on_error(msg)
            return False
        state._emit(f"CF-TUNNEL starting -> {self._hostname}", "dim")
        try:
            proc = subprocess.Popen(
                [_cloudflared_bin, "tunnel", "--config", str(self._config_path), "run"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            state._emit(f"CF-TUNNEL failed to start: {e}", "error")
            if self._on_error:
                self._on_error(str(e))
            return False

        self._process = proc
        connected = False

        try:
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                state._emit(f"CF-TUNNEL {line}", "dim")
                if not self._url_fired and self._READY_PATTERN.search(line):
                    connected = True
                    self._url_fired = True
                    public_url = f"https://{self._hostname}"
                    state._emit(f"CF-TUNNEL public URL -> {public_url}", "ok")
                    if self._on_url:
                        self._on_url(public_url)
        except Exception as e:
            if self._active:
                state._emit(f"CF-TUNNEL read error: {e}", "error")
        finally:
            rc = proc.wait() if proc.poll() is None else proc.returncode
            if self._active:
                state._emit(f"CF-TUNNEL process exited (rc={rc})", "dim")
            self._process = None

        return connected
