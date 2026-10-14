"""Shared HTTP/WebSocket/index/cluster lifecycle extracted from Tkinter.

The code here intentionally mirrors the former backend portion of
``ServerLifecycleMixin._start_server`` / ``_stop_server``.  It does not own any
GUI widgets, dialogs, translations, or frontend state.  The Tkinter fallback
and the Application Service layer both delegate to the same controller.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from http.server import ThreadingHTTPServer
import socket
import sys
import traceback
import threading
import time
from typing import Any

import src.state as state
from src.deps import HAS_WEBSOCKETS
from src.core.file_index import _file_index, _start_watchers, _stop_watcher
from src.core.server_discovery import ServerDiscoveryAdvertiser, ServerDiscoveryUnavailable
from src.core.ws_manager import WebSocketManager, _run_ws_server
from src.routes.handler import NetShareHandler
from src.utils.network import get_local_ips

PUBLIC_HTTP_PORT_OFFSET = 2




class DiagnosticThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that mirrors uncaught request exceptions to Activity.

    ``socketserver`` normally prints request-thread tracebacks to stderr.  The
    packaged NetShare executable intentionally has no console, so those failures
    would otherwise disappear from exported diagnostics.
    """

    # Python 3.13's TCPServer default listen backlog is small enough that a
    # short burst of parallel localhost/LAN connections can be reset on macOS
    # before serve_forever accepts them. NetShare already uses a threaded
    # handler, so keep a bounded but practical accept queue for burst traffic.
    request_queue_size = 128

    def handle_error(self, request, client_address) -> None:  # noqa: ARG002
        try:
            exc_type, exc, tb = sys.exc_info()
            if exc_type is not None:
                rendered = "".join(traceback.format_exception(exc_type, exc, tb)).strip()
                client = client_address[0] if client_address else "<unknown>"
                state._emit(
                    f"HTTP UNHANDLED client={client} exception={exc_type.__name__}: {exc}\n"
                    f"{rendered[:12000]}",
                    "error",
                )
        except Exception:
            pass
        # Keep stdlib semantics for non-packaged/debug environments.
        try:
            super().handle_error(request, client_address)
        except Exception:
            pass


class ServerRuntimeStartError(RuntimeError):
    """Raised when the shared HTTP listeners cannot be created safely."""


class ServerRuntimeController:
    """Authoritative process-local lifecycle for NetShare's serving runtime."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._server: DiagnosticThreadingHTTPServer | None = None
        self._public_server: DiagnosticThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._public_thread: threading.Thread | None = None
        self._ws_thread: threading.Thread | None = None
        self._server_discovery: ServerDiscoveryAdvertiser | None = None
        self._server_discovery_stop = threading.Event()
        self._server_discovery_thread: threading.Thread | None = None
        self._running = False
        self._started_at: float | None = None
        self._port: int | None = None
        self._effective_upload = False
        self._effective_edit = False
        self._restart_options: dict[str, Any] | None = None

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._running)

    def started_at(self) -> float | None:
        with self._lock:
            return self._started_at

    def uptime_seconds(self) -> float | None:
        with self._lock:
            if not self._running or self._started_at is None:
                return None
            return max(0.0, time.time() - self._started_at)

    def port(self) -> int | None:
        with self._lock:
            return self._port

    @staticmethod
    def _player_discovery_should_advertise() -> bool:
        """Expose only the cluster entry point to Player discovery.

        A Slave (manual or AUTO-elected) is intentionally absent from the
        normal ``_netshare._tcp`` scan while it is serving through its Master.
        When the established Slave enters its existing direct-HTTP fallback,
        it becomes discoverable again.  AUTO promotion to Master therefore
        also becomes visible, while a superseded Master that demotes to Slave
        disappears without restarting the HTTP server.
        """
        if state.effective_cluster_role() != "slave":
            return True
        manager = getattr(state, "_cluster_runtime", None)
        runtime = getattr(manager, "runtime", None)
        fallback_check = getattr(runtime, "direct_http_enabled", None)
        return bool(callable(fallback_check) and fallback_check())

    def _run_player_discovery_gate(
        self,
        discovery: ServerDiscoveryAdvertiser,
        *,
        discovery_args: dict[str, Any],
        on_error: Callable[[Exception], None] | None,
        stop_event: threading.Event,
    ) -> None:
        """Keep Player mDNS aligned with live cluster role/fallback state."""
        last_reported_error = ""
        while not stop_event.wait(0.75):
            try:
                desired = self._player_discovery_should_advertise()
            except Exception as error:
                # Discovery visibility is a background convenience.  A transient
                # cluster/fallback failure must not kill this worker thread.  For
                # a Slave, failing closed (hidden) is safer than advertising a
                # possibly non-connectable duplicate cluster entry point.
                desired = False if state.effective_cluster_role() == "slave" else True
                message = f"discovery gate: {type(error).__name__}: {error}"
                if message != last_reported_error:
                    last_reported_error = message
                    if on_error is not None:
                        try:
                            on_error(error)
                        except Exception:
                            pass
            if desired == discovery.active:
                continue
            try:
                if desired:
                    discovery.start(**discovery_args)
                    state._emit("DISCOVERY Player advertisement enabled", "info")
                else:
                    discovery.stop()
                    state._emit("DISCOVERY Player advertisement hidden for cluster Slave", "info")
                last_reported_error = ""
            except ServerDiscoveryUnavailable as error:
                if on_error is not None:
                    try:
                        on_error(error)
                    except Exception:
                        pass
                return
            except (OSError, ValueError, RuntimeError) as error:
                # A rapid role flip can legitimately hit the advertiser's
                # restart rate-limit.  Retry on the next bounded poll without
                # flooding Activity; report other distinct failures once.
                message = str(error)
                if "rate limited" not in message.lower() and message != last_reported_error:
                    last_reported_error = message
                    if on_error is not None:
                        try:
                            on_error(error)
                        except Exception:
                            pass

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            running = bool(self._running)
            started_at = self._started_at
            port = self._port
            effective_upload = self._effective_upload
            effective_edit = self._effective_edit
        return {
            "running": running,
            "started_at": started_at,
            "uptime_seconds": self.uptime_seconds(),
            "port": port,
            "websocket_port": (port + 1) if running and port is not None and HAS_WEBSOCKETS else None,
            "public_port": (port + PUBLIC_HTTP_PORT_OFFSET) if running and port is not None else None,
            "effective_upload": effective_upload,
            "effective_edit": effective_edit,
            "addresses": list(get_local_ips()) if running else [],
        }

    def start(
        self,
        *,
        shared_roots: Iterable[str],
        port: int,
        server_name: str,
        local_password: str,
        allow_upload: bool,
        allow_edit: bool,
        community_password: str,
        admin_password: str,
        community_browse_root: bool,
        community_download: bool,
        community_upload: bool,
        public_upload_mode: str,
        max_uploads_per_hour: int,
        max_upload_size_mb: int,
        allowed_upload_extensions: Iterable[str],
        remote_flags: Mapping[str, bool | None],
        stop_dispatch: Callable[[], None] | None = None,
        on_discovery_error: Callable[[Exception], None] | None = None,
        on_cluster_error: Callable[[Exception], None] | None = None,
        on_cluster_ready: Callable[[str], None] | None = None,
        on_cluster_node_change: Callable[[str, str, bool], None] | None = None,
        on_cluster_fallback_change: Callable[[bool, dict], None] | None = None,
    ) -> dict[str, Any]:
        """Start the same backend runtime formerly owned by Tkinter.

        UI-only validation/prompting happens before this method.  All arguments
        are already resolved values; this method performs the former runtime
        mutations and process orchestration without any GUI dependency.
        """
        with self._lock:
            if self._running:
                return self.snapshot()

        restart_options = {
            "shared_roots": tuple(shared_roots),
            "port": port,
            "server_name": server_name,
            "local_password": local_password,
            "allow_upload": allow_upload,
            "allow_edit": allow_edit,
            "community_password": community_password,
            "admin_password": admin_password,
            "community_browse_root": community_browse_root,
            "community_download": community_download,
            "community_upload": community_upload,
            "public_upload_mode": public_upload_mode,
            "max_uploads_per_hour": max_uploads_per_hour,
            "max_upload_size_mb": max_upload_size_mb,
            "allowed_upload_extensions": tuple(allowed_upload_extensions),
            "remote_flags": dict(remote_flags),
            "stop_dispatch": stop_dispatch,
            "on_discovery_error": on_discovery_error,
            "on_cluster_error": on_cluster_error,
            "on_cluster_ready": on_cluster_ready,
            "on_cluster_node_change": on_cluster_node_change,
            "on_cluster_fallback_change": on_cluster_fallback_change,
        }
        shared_roots = restart_options["shared_roots"]
        allowed_upload_extensions = restart_options["allowed_upload_extensions"]

        # Non-GUI starts must honor the same crash-recovery journal as the
        # PyWebView shell.  Do this before binding listeners so a partially
        # reset process can never accept ordinary traffic.
        try:
            from src.core.local_data_reset import recover_interrupted_reset
            recover_interrupted_reset()
        except Exception as error:
            raise ServerRuntimeStartError(
                f"interrupted local data reset recovery failed: {type(error).__name__}"
            ) from error

        roots = [str(value) for value in shared_roots if str(value).strip()]
        if not roots:
            raise ValueError("at least one shared root is required")
        port = int(port)
        if not 1 <= port <= 65532:
            raise ValueError("port must be between 1 and 65532")

        # These assignments are intentionally the same mutations previously
        # performed directly by ServerLifecycleMixin before listener creation.
        configured_roots = state.set_shared_roots(roots)
        state.SERVER_NAME = str(server_name or socket.gethostname())
        state.LOCAL_PASSWORD = str(local_password or "").strip()
        state.COMMUNITY_PASSWORD = str(community_password or "").strip()
        state.ADMIN_PASSWORD = str(admin_password or "").strip()
        state.COMMUNITY_BROWSE_ROOT = bool(community_browse_root)
        state.COMMUNITY_DOWNLOAD = bool(community_download)
        state.COMMUNITY_UPLOAD = bool(community_upload)
        state.PUBLIC_UPLOAD_MODE = str(public_upload_mode)
        state.MAX_UPLOADS_PER_HOUR = max(1, int(max_uploads_per_hour))
        state.MAX_UPLOAD_SIZE_MB = max(1, int(max_upload_size_mb))
        state.ALLOWED_UPLOAD_EXTENSIONS = {
            str(value).lower().strip() for value in allowed_upload_extensions if str(value).strip()
        }
        state.save_public_config()

        flags = dict(remote_flags)
        effective_upload = bool(allow_upload)
        effective_edit = bool(allow_edit)
        if flags.get("upload") is False:
            effective_upload = False
        if flags.get("document_edit") is False:
            effective_edit = False
        state.FEATURE_FLAGS.update(
            {
                "upload": effective_upload,
                "document_edit": effective_edit,
                # PyWebView does not synchronously fetch Remote Config before a
                # manual server start.  Treat an unknown value (None/missing) as
                # locally available because choosing MASTER/SLAVE is already an
                # explicit operator opt-in.  A real remote False still takes
                # precedence and disables the cluster exactly as required.
                "cluster": flags.get("cluster") is not False,
                "write_pairing": True,
            }
        )

        _file_index.resume()
        _file_index.clear()
        from src.core.inbox_migration import migrate_legacy_inbox

        migrate_legacy_inbox(
            state.INBOX_DIR,
            (
                state.ROOT_DIR / "incoming",
                state.ROOT_DIR / state.UPLOAD_DIRNAME,
            ),
            log=state._emit,
        )

        tls_context = None
        server: DiagnosticThreadingHTTPServer | None = None
        public_server: DiagnosticThreadingHTTPServer | None = None
        try:
            from src.core.server_tls import (
                ServerTlsIdentityStore,
                server_ssl_context,
                set_transport_tls_active,
                tls_enabled,
            )

            if tls_enabled(state._CONFIG_DIR):
                tls_identity = ServerTlsIdentityStore(state._CONFIG_DIR).ensure_identity(state.SERVER_ID)
                tls_context = server_ssl_context(tls_identity)
            server = DiagnosticThreadingHTTPServer(("0.0.0.0", port), NetShareHandler)
            server.is_public_listener = False
            if tls_context is not None:
                server.socket = tls_context.wrap_socket(server.socket, server_side=True)
            public_server = DiagnosticThreadingHTTPServer(
                ("127.0.0.1", port + PUBLIC_HTTP_PORT_OFFSET), NetShareHandler
            )
            public_server.is_public_listener = True
            server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
            set_transport_tls_active(tls_context is not None)
        except (OSError, RuntimeError, ValueError) as error:
            try:
                from src.core.server_tls import set_transport_tls_active

                set_transport_tls_active(False)
            except Exception:
                pass
            if public_server is not None:
                public_server.server_close()
            if server is not None:
                server.server_close()
            raise ServerRuntimeStartError(str(error)) from error

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        public_thread = threading.Thread(
            target=public_server.serve_forever,
            daemon=True,
            name="netshare-public-http",
        )
        thread.start()
        public_thread.start()

        _file_index.build_all(state.SHARED_ROOTS)
        _start_watchers(state.SHARED_ROOTS)
        _file_index.start_periodic_flush_all(state.SHARED_ROOTS)
        self._start_cluster_runtime(
            port,
            on_error=on_cluster_error,
            on_ready=on_cluster_ready,
            on_node_change=on_cluster_node_change,
            on_fallback_change=on_cluster_fallback_change,
        )

        discovery: ServerDiscoveryAdvertiser | None = ServerDiscoveryAdvertiser()
        discovery_args = {
            "addresses": get_local_ips(),
            "port": port,
            "password_protected": bool(state.LOCAL_PASSWORD),
            "tls_enabled": tls_context is not None,
            "capabilities": tuple(
                key for key, enabled in state.FEATURE_FLAGS.items() if enabled
            ),
        }
        try:
            if self._player_discovery_should_advertise():
                discovery.start(**discovery_args)
            else:
                state._emit(
                    "DISCOVERY Player advertisement hidden for cluster Slave", "info"
                )
        except (ServerDiscoveryUnavailable, OSError, ValueError, RuntimeError) as error:
            discovery = None
            if on_discovery_error is not None:
                try:
                    on_discovery_error(error)
                except Exception:
                    pass

        discovery_stop = threading.Event()
        discovery_thread: threading.Thread | None = None
        if discovery is not None:
            discovery_thread = threading.Thread(
                target=self._run_player_discovery_gate,
                kwargs={
                    "discovery": discovery,
                    "discovery_args": discovery_args,
                    "on_error": on_discovery_error,
                    "stop_event": discovery_stop,
                },
                daemon=True,
                name="netshare-player-discovery-gate",
            )
            discovery_thread.start()

        ws_thread: threading.Thread | None = None
        if HAS_WEBSOCKETS:
            state._ws_manager = WebSocketManager()
            ws_thread = threading.Thread(
                target=_run_ws_server,
                args=("0.0.0.0", port + 1, state._ws_manager, tls_context),
                daemon=True,
            )
            ws_thread.start()
        else:
            state._ws_manager = None

        with self._lock:
            self._server = server
            self._public_server = public_server
            self._thread = thread
            self._public_thread = public_thread
            self._ws_thread = ws_thread
            self._server_discovery = discovery
            self._server_discovery_stop = discovery_stop
            self._server_discovery_thread = discovery_thread
            self._running = True
            self._started_at = time.time()
            self._port = port
            self._effective_upload = effective_upload
            self._effective_edit = effective_edit
            self._restart_options = restart_options

        # Acquire Keep Alive only once the server is genuinely running.  This
        # is best-effort: an unsupported OS inhibitor must not prevent serving.
        try:
            from src.runtime.permissions_runtime import permissions_runtime_controller
            permissions_runtime_controller.set_server_running(True)
        except Exception as exc:
            state._emit(f"SLEEP  Keep Alive activation failed: {type(exc).__name__}", "warning")

        from src.core.server_control import server_control

        server_control.set_stop_callback(stop_dispatch or self.stop)

        primary_root = configured_roots[0].path
        state.record_folder_share(str(primary_root))
        if len(state.SHARED_ROOTS) == 2:
            state.record_folder_share(str(state.SHARED_ROOTS[1].path))
            state.record_folder_pair([shared.path for shared in state.SHARED_ROOTS])

        return self.snapshot()


    def restart(self) -> dict[str, Any]:
        """Restart the live server with the exact last successful start options."""
        with self._lock:
            if not self._running:
                return self.snapshot()
            options = dict(self._restart_options or {})
        if not options:
            raise ServerRuntimeStartError("server restart options are unavailable")
        self.stop()
        return self.start(**options)

    def replace_shared_roots(self, paths: Iterable[str], *, persist: bool = True):
        """Apply the existing live shared-root reindex workflow without a second consumer."""
        clean = [str(value) for value in paths if str(value).strip()]
        if not clean:
            raise ValueError("at least one shared root is required")
        with self._lock:
            running = bool(self._running)
        if not running:
            return state.set_shared_roots(clean, persist=persist)

        old_roots = state.SHARED_ROOTS
        _file_index.flush_all_if_dirty(old_roots)
        roots = state.set_shared_roots(clean, persist=persist)
        _file_index.clear()
        _file_index.build_all(roots)
        _start_watchers(roots)
        _file_index.start_periodic_flush_all(roots)
        if state._ws_manager:
            state._ws_manager.notify_file_change("/")
        return roots

    def stop(self, *, before_stop: Callable[[], None] | None = None) -> dict[str, Any]:
        """Stop the shared runtime using the former Tkinter shutdown order."""
        from src.core.server_control import server_control
        from src.core.server_tls import set_transport_tls_active

        with self._lock:
            was_running = bool(self._running)
        if not was_running:
            return self.snapshot()

        server_control.set_stop_callback(None)
        set_transport_tls_active(False)

        # Release the wake lock at the start of shutdown so an incomplete
        # listener teardown can never keep the host awake indefinitely.
        try:
            from src.runtime.permissions_runtime import permissions_runtime_controller
            permissions_runtime_controller.set_server_running(False)
        except Exception:
            pass

        # Public tunnels are only valid while the local/public HTTP listeners
        # are alive. Stop them first so an external URL can never outlive the
        # local server runtime.
        try:
            from src.runtime.tunnel_runtime import tunnel_runtime_controller
            tunnel_runtime_controller.stop_all()
        except Exception:
            pass

        if before_stop is not None:
            before_stop()

        if state._ws_manager:
            state._ws_manager.notify_server_stopping()
            state._ws_manager = None

        # Stop the adaptive Player advertisement before tearing down cluster
        # state.  Otherwise effective_role briefly becomes standalone and a
        # hidden Slave could re-advertise during shutdown.
        with self._lock:
            server_discovery = self._server_discovery
            discovery_stop = self._server_discovery_stop
            discovery_thread = self._server_discovery_thread
            self._server_discovery = None
            self._server_discovery_thread = None
        discovery_stop.set()
        if discovery_thread is not None and discovery_thread.is_alive():
            discovery_thread.join(timeout=1.5)

        self._stop_cluster_runtime()
        if server_discovery is not None:
            server_discovery.stop()

        _file_index.pause()
        _file_index.flush_all_if_dirty(state.SHARED_ROOTS)
        _file_index.clear()
        _stop_watcher()

        with self._lock:
            server = self._server
            public_server = self._public_server
            self._server = None
            self._public_server = None
            self._thread = None
            self._public_thread = None
            self._ws_thread = None
        if server is not None:
            threading.Thread(target=server.shutdown, daemon=True).start()
        if public_server is not None:
            threading.Thread(target=public_server.shutdown, daemon=True).start()

        state.LOCAL_PASSWORD = ""
        state.TUNNEL_PASSWORD = ""
        state.TUNNEL_ACTIVE = False
        state.clear_write_auth()
        state.FEATURE_FLAGS.update(
            {
                "upload": False,
                "document_edit": False,
                "write_pairing": False,
            }
        )

        with self._lock:
            self._running = False
            self._started_at = None
            self._port = None
            self._effective_upload = False
            self._effective_edit = False
        return self.snapshot()

    def _start_cluster_runtime(
        self,
        port: int,
        *,
        on_error: Callable[[Exception], None] | None,
        on_ready: Callable[[str], None] | None,
        on_node_change: Callable[[str, str, bool], None] | None,
        on_fallback_change: Callable[[bool, dict], None] | None,
    ) -> None:
        if (
            state.FEATURE_FLAGS.get("cluster") is not True
            or state.CLUSTER_ROLE == "standalone"
            or state._cluster_runtime is not None
        ):
            return
        from src.core.cluster.runtime import ClusterRuntimeManager

        manager = ClusterRuntimeManager()

        def publish_cluster_runtime(controller, relay, _effective_role) -> None:
            # AUTO promotion/demotion swaps the live runtime without restarting
            # the HTTP server.  Keep the route-facing references synchronized so
            # /list, streaming, ART and MEDIA_ANALYSIS immediately use the new
            # Master's registry/relay (or the demoted Slave's fail-closed state).
            state._cluster_controller = controller
            state._cluster_relay = relay

        try:
            manager.start(
                feature_enabled=True,
                role=state.CLUSTER_ROLE,
                config_dir=state._CONFIG_DIR,
                roots=state.SHARED_ROOTS,
                node_id=state.SERVER_ID.replace("-", ""),
                node_name=state.SERVER_NAME,
                addresses=list(get_local_ips()),
                base_port=port,
                node_created_at=state.CLUSTER_NODE_CREATED_AT,
                on_node_change=on_node_change,
                on_fallback_change=on_fallback_change,
                on_runtime_change=publish_cluster_runtime,
                log=state._emit,
            )
        except Exception as error:
            manager.stop()
            if on_error is not None:
                try:
                    on_error(error)
                except Exception:
                    pass
            return
        state._cluster_runtime = manager
        state._cluster_controller = manager.controller
        state._cluster_relay = manager.relay
        if on_ready is not None:
            try:
                on_ready(manager.effective_role)
            except Exception:
                pass

    def stop_cluster_runtime(self) -> None:
        self._stop_cluster_runtime()

    @staticmethod
    def _stop_cluster_runtime() -> None:
        manager, state._cluster_runtime = state._cluster_runtime, None
        state._cluster_controller = None
        state._cluster_relay = None
        if manager is not None:
            manager.stop()


server_runtime_controller = ServerRuntimeController()
