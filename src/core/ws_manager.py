"""
WebSocket client registry and server thread for NetShare Server.

WebSocketManager owns the connected client set, broadcasts file-change events,
and coordinates shutdown from the Tkinter thread into the asyncio event loop.
"""

import asyncio
import hmac
import json
import threading
from urllib.parse import parse_qs, unquote, urlparse

import src.state as state
from src.constants import VERSION
from src.deps import HAS_WEBSOCKETS

if HAS_WEBSOCKETS:
    import websockets
    import websockets.server


class WebSocketManager:

    def __init__(self):
        # A socket is targetable only after its pairing bearer was verified.
        self._clients: dict       = {}
        self._loop                = None
        self._lock                = threading.Lock()
        self._stop_event: asyncio.Event | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop       = loop
        self._stop_event = asyncio.Event()

    def add_client(self, ws, device_id: str | None = None):
        with self._lock:
            self._clients[ws] = device_id
        state._emit(f"WS  +  client connected  ({len(self._clients)} total)")

    def remove_client(self, ws):
        with self._lock:
            self._clients.pop(ws, None)
        state._emit(f"WS  −  client disconnected  ({len(self._clients)} remaining)")

    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    # Broadcast

    async def _broadcast(self, message: str):
        with self._lock:
            targets = set(self._clients)
        if not targets:
            return
        dead = set()
        for ws in targets:
            try:
                await ws.send(message)
            except Exception:
                dead.add(ws)
        if dead:
            with self._lock:
                for ws in dead:
                    self._clients.pop(ws, None)

    def broadcast_threadsafe(self, message: str):
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._broadcast(message), self._loop)

    async def _send_to_devices(self, device_ids: set[str], message: str):
        with self._lock:
            targets = {
                ws for ws, device_id in self._clients.items()
                if device_id in device_ids
            }
        dead = set()
        for ws in targets:
            try:
                await ws.send(message)
            except Exception:
                dead.add(ws)
        if dead:
            with self._lock:
                for ws in dead:
                    self._clients.pop(ws, None)

    def send_to_devices_threadsafe(self, device_ids, payload: dict):
        """Send only to sockets bound to a verified paired device."""
        clean_ids = {
            str(device_id).strip() for device_id in device_ids
            if str(device_id).strip()
        }
        if clean_ids and self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._send_to_devices(
                    clean_ids, json.dumps(payload, ensure_ascii=False)
                ),
                self._loop,
            )

    def notify_file_change(self, path: str):
        self.broadcast_threadsafe(json.dumps({"type": "file_change", "path": path}))

    def notify_address_changed(
        self,
        host: str,
        http_port: int,
        ws_port: int,
        old_ips=(),
    ):
        """Tell connected clients where to reconnect, then disconnect them."""
        if self._loop and self._loop.is_running():
            return asyncio.run_coroutine_threadsafe(
                self._address_changed_sequence(
                    host, http_port, ws_port, tuple(old_ips)
                ),
                self._loop,
            )
        return None

    async def _address_changed_sequence(
        self,
        host: str,
        http_port: int,
        ws_port: int,
        old_ips=(),
    ):
        payload = json.dumps({
            "type": "server_address_changed",
            "reason": "local_ip_changed",
            "message": "The server network address has changed.",
            "old_ips": list(old_ips),
            "host": host,
            "http_port": http_port,
            "ws_port": ws_port,
            "http_url": f"http://{host}:{http_port}",
            "ws_url": f"ws://{host}:{ws_port}",
        })
        with self._lock:
            targets = set(self._clients)
        for ws in targets:
            try:
                await ws.send(payload)
            except Exception:
                pass
        # Give clients time to process the new address before closing the socket.
        await asyncio.sleep(0.2)
        for ws in targets:
            try:
                await ws.close(1012, "Server address changed")
            except Exception:
                pass

    def notify_server_stopping(self):
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._shutdown_sequence(), self._loop
            ).result(timeout=3)

    async def _shutdown_sequence(self):
        await self._broadcast(json.dumps({"type": "server_stopping"}))
        await asyncio.sleep(0.15)
        if self._stop_event:
            self._stop_event.set()


# Per-connection handler

async def _ws_handler(websocket):
    manager: WebSocketManager | None = state._ws_manager
    if manager is None:
        await websocket.close(1001, "Manager not initialized")
        return
    authorized, device_id = _ws_identity(websocket)
    if not authorized:
        await websocket.close(1008, "Unauthorized")
        return
    manager.add_client(websocket, device_id)
    await websocket.send(json.dumps({
        "type":    "welcome",
        "name":    state.SERVER_NAME,
        "version": VERSION,
        "root":    state.ROOT_DIR.name or str(state.ROOT_DIR),
    }))
    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
                if msg.get("type") == "ping":
                    await websocket.send(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except Exception:
        pass
    finally:
        manager.remove_client(websocket)


def _request_header(websocket, name: str) -> str:
    try:
        return str(websocket.request_headers.get(name, "") or "")
    except Exception:
        pass
    try:
        return str(websocket.request.headers.get(name, "") or "")
    except Exception:
        return ""


def _ws_identity(websocket) -> tuple[bool, str | None]:
    """Authorize a socket and return its verified device identity, if any.

    Anonymous read-only sockets remain available before pairing. A stale or
    invalid device credential is downgraded to anonymous and can never become
    targetable; the local password remains mandatory when configured.
    """
    if state.LOCAL_PASSWORD:
        password = unquote(_request_header(websocket, "X-Password"))
        if not hmac.compare_digest(password, state.LOCAL_PASSWORD):
            return False, None

    device_id = _request_header(websocket, "X-Device-ID").strip()
    authorization = _request_header(websocket, "Authorization").strip()
    if not authorization:
        # The Player always sends its local device ID, including before it has
        # been paired. Keep that socket anonymous/read-only: the unverified ID
        # is deliberately not stored in the targetable client registry.
        return True, None
    if not device_id or not authorization.lower().startswith("bearer "):
        return True, None
    credential = authorization[7:].strip()
    if not state.verify_device_credential(device_id, credential):
        return True, None
    return True, device_id


def _ws_authorized(websocket) -> bool:
    """Backward-compatible boolean wrapper used by existing callers/tests."""
    return _ws_identity(websocket)[0]


# Server thread entry point

def _run_ws_server(host: str, port: int, manager: WebSocketManager):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    manager.set_loop(loop)

    async def _serve():
        async with websockets.serve(_ws_handler, host, port, reuse_address=True):
            state._emit(f"WS   :{port}   running")
            await manager._stop_event.wait()

    try:
        loop.run_until_complete(_serve())
    except Exception as e:
        state._emit(f"WS   stopped  {e}")
    finally:
        loop.close()
