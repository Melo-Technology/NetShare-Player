"""
HTTP request handler for NetShare Server.

NetShareHandler is a BaseHTTPRequestHandler subclass that serves all
API routes used by the Flutter mobile client. This file is intentionally
kept thin: it owns the do_GET / do_POST / do_PUT / do_OPTIONS dispatch
tables, and assembles the handler from focused mixins so route logic for
each area lives in its own file under routes/.

    GET /ping           server info + auth mode
    GET /list           directory listing
    GET /search         file-index search
    GET /file           full / ranged file download
    GET /thumbnail      image thumbnail (Pillow) or video frame (ffmpeg)
    GET /art            MP3 cover-art extraction
    GET /waveform       cached audio peak extraction (ffmpeg)
    GET /document       read text document (UTF-8)
    GET /setup-totp     local pairing QR + secret
    GET /cloud/accounts connected cloud provider accounts (Drive/Dropbox/Mega)
    GET /cloud/list     browse a cloud account's folder (?provider=&account=&folder=)
    GET /cloud/file     stream/download a cloud file (?provider=&account=&id=), Range-aware
    POST /register-device trust a local device with TOTP
    POST /upload        file upload with optional overwrite
    POST /redeem         redeem a premium-folder unlock code
    PUT /document       write text document (UTF-8)

Adding a new route:
  1. Pick (or create) the matching routes/<category>.py mixin.
  2. Add the `_route_xxx` method there.
  3. Wire the endpoint into do_GET / do_POST / do_PUT below.
"""

from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from .base import NetShareHandlerBase
from .auth import AuthMixin
from .tunnel import _uses_public_access_policy
from .routes.ping import PingRoutesMixin
from .routes.v2 import V2RoutesMixin
from .routes.browse import BrowseRoutesMixin
from .routes.files import FileRoutesMixin
from .routes.streaming import StreamingRoutesMixin
from .routes.documents import DocumentRoutesMixin
from .routes.uploads import UploadRoutesMixin
from .routes.transfers import TransferRoutesMixin
from .routes.share_tickets import ShareTicketRoutesMixin
from .routes.p2p_invitations import P2PInvitationRoutesMixin
from .routes.p2p_relay import P2PRelayRoutesMixin
from .routes.diagnostics import DiagnosticRoutesMixin
from .routes.collections import CollectionRoutesMixin
from .routes.offline import OfflineRoutesMixin
from .routes.collaboration import CollaborationRoutesMixin
from .routes.sync_rooms import SyncRoomRoutesMixin
from .routes.cloud import CloudRoutesMixin
from .routes.session_groups import SessionGroupRoutesMixin
from .routes.premium import PremiumRoutesMixin
from .routes.cluster import ClusterRoutesMixin
from .routes.inbox import InboxRoutesMixin
from .routes.duplicates import DuplicateRoutesMixin
from .routes.user_metadata import UserMetadataRoutesMixin
from .routes.folder_visibility import FolderVisibilityRoutesMixin
from .routes.control import ControlRoutesMixin
from .routes.guests import GuestRoutesMixin
from .routes.web_sessions import WebSessionRoutesMixin
from .routes.web_downloads import WebDownloadRoutesMixin

import src.state as state
from src.core.cluster.identity import joined_slave_files_exist


class NetShareHandler(
    NetShareHandlerBase,
    AuthMixin,
    PingRoutesMixin,
    V2RoutesMixin,
    BrowseRoutesMixin,
    FileRoutesMixin,
    StreamingRoutesMixin,
    DocumentRoutesMixin,
    UploadRoutesMixin,
    TransferRoutesMixin,
    ShareTicketRoutesMixin,
    P2PInvitationRoutesMixin,
    P2PRelayRoutesMixin,
    DiagnosticRoutesMixin,
    CollectionRoutesMixin,
    OfflineRoutesMixin,
    CollaborationRoutesMixin,
    SyncRoomRoutesMixin,
    CloudRoutesMixin,
    SessionGroupRoutesMixin,
    PremiumRoutesMixin,
    ClusterRoutesMixin,
    InboxRoutesMixin,
    DuplicateRoutesMixin,
    UserMetadataRoutesMixin,
    FolderVisibilityRoutesMixin,
    ControlRoutesMixin,
    GuestRoutesMixin,
    WebSessionRoutesMixin,
    WebDownloadRoutesMixin,
    BaseHTTPRequestHandler,
):

    def _is_linked_cluster_slave(self) -> bool:
        if state.effective_cluster_role() != "slave":
            return False
        manager = getattr(state, "_cluster_runtime", None)
        runtime = getattr(manager, "runtime", None)
        store = getattr(runtime, "store", None)
        if store is not None:
            return store.exists("slave")
        return joined_slave_files_exist(state._CONFIG_DIR)

    def _reject_linked_slave_http(self, endpoint: str) -> bool:
        if not self._is_linked_cluster_slave() or endpoint == "/ping":
            return False
        manager = getattr(state, "_cluster_runtime", None)
        runtime = getattr(manager, "runtime", None)
        fallback_check = getattr(runtime, "direct_http_enabled", None)
        if callable(fallback_check) and fallback_check():
            # The ordinary route guards remain in force during fallback:
            # LAN password, trusted device, premium, hidden files and safe path.
            return False
        self.send_error_json("Linked cluster Slave: connect through its Master", 403)
        return True

    # OPTIONS (CORS pre-flight)

    def do_OPTIONS(self):
        if not self._security_preflight():
            return
        if self.headers.get("Origin") and not self._is_allowed_cors_origin():
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(200)
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-Password, X-Web-Password, X-Device-ID, X-Device-Credential, X-Room-Ticket, X-Tunnel, X-File-Path-B64, X-Filename, X-Upload-Token, Authorization, Content-Type, Range, If-Range, If-None-Match, Ngrok-Skip-Browser-Warning, X-P2P-Invitation-Token, X-P2P-Relay-Token")
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    # GET router

    def do_HEAD(self):
        if not self._security_preflight():
            return
        parsed = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)
        if self._reject_linked_slave_http(endpoint):
            return
        if self._reject_spoofed_tunnel_header():
            return
        if self._reject_misplaced_web_password(endpoint):
            return
        if endpoint != "/api/v2/cluster/file":
            return self.send_error_json("Unknown endpoint", 404)
        if self._reject_invalid_guest_session():
            return
        if not self._has_guest_session() and not self._check_password():
            return self.send_error_json("Unauthorized", 401)
        if self._reject_guest_endpoint(endpoint):
            return
        return self._route_cluster_file(params, method="HEAD")

    def do_GET(self):
        if not self._security_preflight():
            return
        parsed   = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params   = parse_qs(parsed.query)
        if self._reject_linked_slave_http(endpoint):
            return

        if self._reject_spoofed_tunnel_header():
            return
        if self._reject_misplaced_web_password(endpoint):
            return
        if _uses_public_access_policy(self) and not state.general_request_allowed(self._rate_key("traffic")):
            return self.send_error_json("Too many requests", 429)

        if endpoint == "/api/v2/capabilities":
            self._route_v2_capabilities()
            return

        if endpoint == "/api/v2/web/session":
            return self._route_web_session_get()

        download_parts = endpoint.strip("/").split("/")
        if download_parts[:4] == ["api", "v2", "web", "download"] and len(download_parts) == 5:
            return self._route_web_download(download_parts[4])
        if download_parts[:4] == ["api", "v2", "web", "media"] and len(download_parts) == 5:
            return self._route_web_media(download_parts[4])
        if (download_parts[:4] == ["api", "v2", "web", "media"]
                and len(download_parts) == 7 and download_parts[5] == "subtitle"):
            return self._route_web_media_subtitle(download_parts[4], download_parts[6])

        share_parts = endpoint.strip("/").split("/")
        if len(share_parts) in (2, 3) and share_parts[0] == "s":
            if len(share_parts) == 2:
                return self._route_shared_page(share_parts[1])
            if share_parts[2] == "file":
                return self._route_shared_file(share_parts[1], params)

        if endpoint == "/api/v2/p2p/invitations/resolve":
            return self._route_p2p_invitation_get()

        if endpoint == "/api/v2/p2p/relay/status":
            return self._route_p2p_relay_receiver_status()
        relay_public = endpoint.strip("/").split("/")
        if (relay_public[:4] == ["api", "v2", "p2p", "relay"] and len(relay_public) == 9
                and relay_public[5] == "files" and relay_public[7] == "chunks"):
            return self._route_p2p_relay_chunk_get(relay_public[4], relay_public[6], relay_public[8])

        if endpoint == "/ping":
            self._route_ping(params)
            return

        if endpoint == "/setup-totp":
            self._route_setup_totp()
            return

        web_read = self._authorize_web_read(endpoint)
        if web_read is not True:
            if web_read is False:
                return
            if self._reject_invalid_guest_session():
                return
            if not self._has_guest_session() and not self._check_password():
                self.send_error_json("Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized", 429 if getattr(self, "_auth_rate_limited", False) else 401)
                return
            if self._reject_guest_endpoint(endpoint):
                return

        transfer_parts = endpoint.strip("/").split("/")
        if transfer_parts[:3] == ["api", "v2", "transfers"] and len(transfer_parts) == 4:
            if not self._has_upload_access():
                return self.send_error_json("Trusted device or upload key required", 403)
            return self._route_transfer_get(transfer_parts[3])

        relay_parts = endpoint.strip("/").split("/")
        if relay_parts[:4] == ["api", "v2", "p2p", "relay"] and len(relay_parts) == 5:
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_p2p_relay_sender_status(relay_parts[4])

        invitation_parts = endpoint.strip("/").split("/")
        if (invitation_parts[:4] == ["api", "v2", "p2p", "invitations"]
                and len(invitation_parts) == 6 and invitation_parts[5] == "status"):
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_p2p_invitation_sender_status(invitation_parts[4])

        if endpoint == "/api/v2/diagnostics/ping":
            return self._route_diagnostic_ping()
        if endpoint == "/api/v2/web/sessions":
            if not self._has_full_write_access():
                return self.send_error_json("Admin access required", 403)
            return self._route_web_sessions_list()
        if endpoint == "/api/v2/folders":
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_folder_tree(params)
        if endpoint == "/api/v2/diagnostics/throughput":
            return self._route_diagnostic_throughput(params)
        if endpoint == "/api/v2/cluster/nodes":
            return self._route_cluster_nodes()
        if endpoint == "/api/v2/cluster/events":
            return self._route_cluster_events()
        if endpoint == "/api/v2/inbox":
            return self._route_inbox()
        if endpoint == "/api/v2/library/duplicates":
            return self._route_duplicates()
        if endpoint == "/api/v2/user-metadata":
            return self._route_user_metadata_list()
        if endpoint == "/api/v2/cluster/file":
            return self._route_cluster_file(params)
        if endpoint == "/api/v2/cluster/list":
            return self._route_cluster_list(params)
        if endpoint == "/api/v2/resume/history":
            return self._route_resume_history(params)
        room_parts = endpoint.strip("/").split("/")
        if room_parts[:3] == ["api", "v2", "rooms"] and len(room_parts) == 4:
            return self._route_room_get(room_parts[3])
        sync_parts = endpoint.strip("/").split("/")
        if sync_parts[:3] == ["api", "v2", "sync-rooms"] and len(sync_parts) == 4:
            return self._route_sync_get(sync_parts[3])

        collection_parts = endpoint.strip("/").split("/")
        if collection_parts[:3] == ["api", "v2", "collections"]:
            if len(collection_parts) == 3:
                return self._route_collections_list()
            if len(collection_parts) == 5 and collection_parts[4] == "items":
                return self._route_collection_items(collection_parts[3], params)
            return self.send_error_json("Unknown endpoint", 404)

        if endpoint == "/list":
            if web_read is True and not self._enforce_web_rate("list", self._web_session_lookup(touch=False).session.id, 120, 60):
                return
            self._route_list(params)
        elif endpoint == "/search":
            if web_read is True and not self._enforce_web_rate("search", self._web_session_lookup(touch=False).session.id, 60, 60):
                return
            self._route_search(params)
        elif endpoint == "/media-analysis":
            self._route_media_analysis(params)
        elif endpoint == "/session-groups/state":
            self._route_session_group_state(params)
        elif endpoint == "/session-groups/members":
            self._route_session_group_members(params)
        elif endpoint == "/file":
            self._route_file(params)
        elif endpoint == "/manifest":
            self._route_manifest(params)
        elif endpoint == "/segment":
            self._route_segment(params)
        elif endpoint == "/audio-manifest":
            self._route_audio_manifest(params)
        elif endpoint == "/audio-segment":
            self._route_audio_segment(params)
        elif endpoint == "/thumbnail":
            self._route_thumbnail(params)
        elif endpoint == "/art":
            self._route_art(params)
        elif endpoint == "/waveform":
            self._route_waveform(params)
        elif endpoint == "/lyrics":
            if web_read is True and not self._enforce_web_rate("lyrics", self._web_session_lookup(touch=False).session.id, 20, 60):
                return
            self._route_lyrics(params)
        elif endpoint == "/document":
            # GET is a read operation like /file: ordinary authentication is
            # sufficient. PUT keeps its write guards in do_PUT and the route.
            self._route_document_get(params)
        elif endpoint == "/upload-request":
            if not self._has_upload_access():
                self.send_error_json("Trusted device or upload key required", 403)
                return
            self._route_upload_request_status(params)
        elif endpoint == "/cloud/accounts":
            self._route_cloud_accounts()
        elif endpoint == "/cloud/list":
            self._route_cloud_list(params)
        elif endpoint == "/cloud/file":
            self._route_cloud_file(params)
        else:
            self.send_error_json("Unknown endpoint", 404)

    # POST / PUT routers

    def do_POST(self):
        if not self._security_preflight():
            return
        parsed   = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params   = parse_qs(parsed.query)
        if self._reject_linked_slave_http(endpoint):
            return

        if self._reject_spoofed_tunnel_header():
            return
        if self._reject_misplaced_web_password(endpoint):
            return
        if _uses_public_access_policy(self) and not state.general_request_allowed(self._rate_key("traffic")):
            return self.send_error_json("Too many requests", 429)

        if endpoint == "/register-device":
            self._route_register_device()
            return

        if endpoint == "/api/v2/web/session":
            return self._route_web_session_create()

        if endpoint == "/api/v2/web/session/refresh":
            return self._route_web_session_refresh()

        if endpoint == "/api/v2/web/download-tickets":
            return self._route_web_download_ticket_create()

        if endpoint == "/api/v2/web/media-grants":
            return self._route_web_media_grant_create()

        if self._reject_web_mutation():
            return

        if endpoint == "/session-groups/link":
            self._route_session_group_link()
            return

        if endpoint == "/session-groups/invite":
            self._route_session_group_invite()
            return

        if endpoint == "/api/v2/guest/session":
            return self._route_guest_session_create()

        if self._reject_invalid_guest_session():
            return
        if endpoint == "/api/v2/p2p/invitations/consume":
            return self._route_p2p_invitation_consume()
        if endpoint == "/api/v2/p2p/relay/accept":
            return self._route_p2p_relay_accept()
        if endpoint == "/api/v2/p2p/relay/complete":
            return self._route_p2p_relay_download_complete()

        if not self._has_guest_session() and not self._check_password():
            self.send_error_json("Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized", 429 if getattr(self, "_auth_rate_limited", False) else 401)
            return
        if self._reject_guest_endpoint(endpoint):
            return
        transfer_parts = endpoint.strip("/").split("/")
        if transfer_parts[:3] == ["api", "v2", "transfers"]:
            if not self._has_upload_access():
                return self.send_error_json("Trusted device or upload key required", 403)
            if len(transfer_parts) == 3:
                return self._route_transfer_create()
            if len(transfer_parts) == 5 and transfer_parts[4] == "commit":
                return self._route_transfer_commit(transfer_parts[3])
            return self.send_error_json("Unknown endpoint", 404)

        relay_parts = endpoint.strip("/").split("/")
        if relay_parts[:4] == ["api", "v2", "p2p", "relay"]:
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            if len(relay_parts) == 6 and relay_parts[5] == "configure":
                return self._route_p2p_relay_configure(relay_parts[4])
            if len(relay_parts) == 6 and relay_parts[5] == "commit":
                return self._route_p2p_relay_commit(relay_parts[4])

        if endpoint == "/api/v2/p2p/invitations":
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_p2p_invitation_create()
        if endpoint == "/api/v2/share-tickets":
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_share_ticket_create()
        if endpoint == "/api/v2/web/sessions/revoke-all":
            if not self._has_full_write_access():
                return self.send_error_json("Admin access required", 403)
            return self._route_web_sessions_revoke_all()
        if endpoint == "/api/v2/inbox/import":
            return self._route_inbox_import()
        if endpoint == "/api/v2/library/duplicates/scan":
            return self._route_duplicate_scan()
        if endpoint == "/api/v2/user-metadata":
            return self._route_user_metadata_upsert()
        if endpoint == "/api/v2/folders/hide":
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_folder_hide()
        if endpoint == "/api/v2/collections":
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_collection_create()
        if endpoint == "/api/v2/resume/state":
            return self._route_resume_update()
        if endpoint == "/api/v2/resume/handoff":
            return self._route_handoff_request()
        if endpoint == "/api/v2/resume/respond":
            return self._route_handoff_respond()
        if endpoint == "/api/v2/offline-manifest":
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_offline_manifest()
        if endpoint == "/api/v2/control/indexing/pause":
            return self._route_control_pause_indexing()
        if endpoint == "/api/v2/control/indexing/resume":
            return self._route_control_resume_indexing()
        if endpoint == "/api/v2/control/sharing/stop":
            return self._route_control_stop_sharing()
        room_parts = endpoint.strip("/").split("/")
        if endpoint == "/api/v2/rooms":
            return self._route_room_create()
        if endpoint == "/api/v2/rooms/join":
            return self._route_room_join()
        if room_parts[:3] == ["api", "v2", "rooms"] and len(room_parts) == 5:
            if room_parts[4] == "queue":
                return self._route_queue_add(room_parts[3])
            if room_parts[4] == "votes":
                return self._route_vote(room_parts[3])
            if room_parts[4] == "members":
                return self._route_room_action(room_parts[3])
        sync_parts = endpoint.strip("/").split("/")
        if endpoint == "/api/v2/sync-rooms":
            return self._route_sync_create()
        if endpoint == "/api/v2/sync-rooms/join":
            return self._route_sync_join()
        if sync_parts[:3] == ["api", "v2", "sync-rooms"] and len(sync_parts) == 5:
            if sync_parts[4] == "status":
                return self._route_sync_report(sync_parts[3])
            if sync_parts[4] == "command":
                return self._route_sync_command(sync_parts[3])
            if sync_parts[4] == "close":
                return self._route_sync_close(sync_parts[3])

        if endpoint == "/redeem":
            self._route_redeem()
        elif endpoint == "/session-groups/ping":
            self._route_session_group_ping()
        elif endpoint == "/session-groups/leave":
            self._route_session_group_leave()
        elif endpoint == "/session-groups/remove":
            self._route_session_group_remove()
        elif endpoint == "/device/migrate":
            self._route_device_migrate()
        elif endpoint == "/upload":
            if not self._has_upload_access():
                self.send_error_json("Trusted device or upload key required", 403)
                return
            self._route_upload(params)
        elif endpoint == "/upload-request":
            if not self._has_upload_access():
                self.send_error_json("Trusted device or upload key required", 403)
                return
            self._route_upload_request_create()
        else:
            self.send_error_json("Unknown endpoint", 404)

    def do_PUT(self):
        if not self._security_preflight():
            return
        parsed   = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params   = parse_qs(parsed.query)
        if self._reject_linked_slave_http(endpoint):
            return

        if self._reject_spoofed_tunnel_header():
            return
        if self._reject_misplaced_web_password(endpoint):
            return
        if _uses_public_access_policy(self) and not state.general_request_allowed(self._rate_key("traffic")):
            return self.send_error_json("Too many requests", 429)

        if self._reject_web_mutation():
            return

        if self._reject_invalid_guest_session():
            return
        if not self._has_guest_session() and not self._check_password():
            self.send_error_json("Too many auth attempts" if getattr(self, "_auth_rate_limited", False) else "Unauthorized", 429 if getattr(self, "_auth_rate_limited", False) else 401)
            return
        if self._reject_guest_endpoint(endpoint):
            return
        relay_parts = endpoint.strip("/").split("/")
        if (relay_parts[:4] == ["api", "v2", "p2p", "relay"] and len(relay_parts) == 9
                and relay_parts[5] == "files" and relay_parts[7] == "chunks"):
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_p2p_relay_chunk_put(relay_parts[4], relay_parts[6], relay_parts[8])

        transfer_parts = endpoint.strip("/").split("/")
        if transfer_parts[:3] == ["api", "v2", "transfers"]:
            if not self._has_upload_access():
                return self.send_error_json("Trusted device or upload key required", 403)
            if len(transfer_parts) == 8 and transfer_parts[4] == "items" and transfer_parts[6] == "chunks":
                return self._route_transfer_chunk(transfer_parts[3], transfer_parts[5], transfer_parts[7])
            return self.send_error_json("Unknown endpoint", 404)

        if not self._has_full_write_access():
            self.send_error_json("Trusted device or admin key required", 403)
            return

        if endpoint == "/document":
            self._route_document_put(params)
        elif transfer_parts[:3] == ["api", "v2", "collections"] and len(transfer_parts) == 4:
            self._route_collection_update(transfer_parts[3])
        else:
            self.send_error_json("Unknown endpoint", 404)

    def do_DELETE(self):
        if not self._security_preflight():
            return
        parsed = urlparse(self.path)
        endpoint = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)
        if self._reject_linked_slave_http(endpoint):
            return
        if self._reject_spoofed_tunnel_header():
            return
        if self._reject_misplaced_web_password(endpoint):
            return
        if endpoint == "/api/v2/web/session":
            return self._route_web_session_delete()
        if self._reject_web_mutation():
            return
        if self._reject_invalid_guest_session():
            return
        if not self._has_guest_session() and not self._check_password():
            return self.send_error_json("Unauthorized", 401)
        if self._reject_guest_endpoint(endpoint):
            return
        parts = endpoint.strip("/").split("/")
        if parts[:4] == ["api", "v2", "web", "sessions"] and len(parts) == 5:
            if not self._has_full_write_access():
                return self.send_error_json("Admin access required", 403)
            return self._route_web_session_admin_delete(parts[4])
        if endpoint == "/api/v2/inbox/history":
            return self._route_inbox_history_purge()
        if endpoint == "/api/v2/user-metadata":
            return self._route_user_metadata_delete(params)
        if endpoint == "/api/v2/folders/hide":
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_folder_show(params)
        if parts[:3] == ["api", "v2", "transfers"] and len(parts) == 4:
            if not self._has_upload_access():
                return self.send_error_json("Trusted device or upload key required", 403)
            return self._route_transfer_delete(parts[3])
        if parts[:4] == ["api", "v2", "p2p", "relay"] and len(parts) == 5:
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_p2p_relay_revoke(parts[4])
        if parts[:4] == ["api", "v2", "p2p", "invitations"] and len(parts) == 5:
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_p2p_invitation_revoke(parts[4])
        if parts[:3] == ["api", "v2", "share-tickets"] and len(parts) == 4:
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_share_ticket_revoke(parts[3])
        if parts[:3] == ["api", "v2", "collections"] and len(parts) == 4:
            if not self._has_full_write_access():
                return self.send_error_json("Trusted device or admin key required", 403)
            return self._route_collection_delete(parts[3])
        if parts[:3] == ["api", "v2", "cluster"] and len(parts) == 5 and parts[3] == "nodes":
            return self._route_cluster_node_delete(parts[4])
        self.send_error_json("Unknown endpoint", 404)
