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
        self._clients: set        = set()
        self._loop                = None
        self._lock                = threading.Lock()
        self._stop_event: asyncio.Event | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop       = loop
        self._stop_event = asyncio.Event()

    def add_client(self, ws):
        with self._lock:
            self._clients.add(ws)
        state._emit(f"WS  +  client connected  ({len(self._clients)} total)")

    def remove_client(self, ws):
        with self._lock:
            self._clients.discard(ws)
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
                self._clients -= dead

    def broadcast_threadsafe(self, message: str):
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._broadcast(message), self._loop)

    def notify_file_change(self, path: str):
        self.broadcast_threadsafe(json.dumps({"type": "file_change", "path": path}))

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
    if not _ws_authorized(websocket):
        await websocket.close(1008, "Unauthorized")
        return
    manager.add_client(websocket)
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


def _ws_authorized(websocket) -> bool:
    if not state.LOCAL_PASSWORD:
        return True
    password = ""
    try:
        password = websocket.request_headers.get("X-Password", "")
    except Exception:
        pass
    if not password:
        try:
            password = websocket.request.headers.get("X-Password", "")
        except Exception:
            pass
    if not password:
        try:
            path = getattr(websocket, "path", "") or getattr(getattr(websocket, "request", None), "path", "")
            params = parse_qs(urlparse(path).query)
            password = params.get("password", [""])[0]
        except Exception:
            password = ""
    password = unquote(password)
    return hmac.compare_digest(password, state.LOCAL_PASSWORD)


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
