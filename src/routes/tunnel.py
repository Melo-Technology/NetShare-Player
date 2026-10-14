"""
Tunnel / LAN request detection helpers.

These are plain module-level functions (not handler methods) because they
only need a handler instance to read its headers/address - they don't hold
any state of their own. Kept separate from auth.py because they're about
*where a request came from*, not *who is allowed to do what*.
"""

import ipaddress
import re

import src.state as state

_CF_RAY_RE = re.compile(r"^[0-9a-fA-F]{16,32}-[A-Z]{3}$")


def _is_trusted_external_proxy(handler) -> bool:
    """Return whether the TCP peer belongs to an explicitly trusted proxy."""
    try:
        peer = ipaddress.ip_address(handler.client_address[0])
    except ValueError:
        return False
    for value in state.EXTERNAL_TUNNEL_TRUSTED_PROXIES:
        try:
            if peer in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_external_tunnel_request(handler) -> bool:
    """Recognise an explicitly configured, locally proxied Cloudflare request."""
    header_name = state.EXTERNAL_TUNNEL_TRUSTED_HEADER.strip()
    if header_name.lower() != "cf-ray":
        return False
    ray_id = handler.headers.get(header_name, "").strip()
    if not _CF_RAY_RE.fullmatch(ray_id):
        return False

    return _is_trusted_external_proxy(handler)


def _trusted_forwarded_client_ip(handler) -> str | None:
    """Return Cloudflare's client IP only for an authenticated proxy hop."""
    if not _is_external_tunnel_request(handler):
        return None
    value = handler.headers.get("CF-Connecting-IP", "").strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_unspecified:
        return None
    return str(address)


def _is_tunnel_request(handler) -> bool:
    """
    Return True when the request is forwarded through a public tunnel.

    The dedicated public listener is authoritative for built-in tunnels.
    OS-managed cloudflared tunnels are recognised only through the explicit,
    proxy-address-bound opt-in above.
    """
    return bool(
        getattr(handler.server, "is_public_listener", False)
        or _is_external_tunnel_request(handler)
    )


def _is_lan_request(handler) -> bool:
    """Return whether the TCP peer is in an RFC1918 private LAN range.

    Loopback is deliberately excluded: a locally relayed public tunnel has
    the same peer address as a process running on this machine and therefore
    cannot be trusted as LAN traffic.
    """
    try:
        ip = ipaddress.ip_address(handler.client_address[0])
        if ip.version != 4 or ip.is_loopback:
            return False
        return any(
            ip in network
            for network in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
        )
    except ValueError:
        return False


def _uses_public_access_policy(handler) -> bool:
    """Return whether public credentials and authorization rules apply."""
    return _is_tunnel_request(handler) or not _is_lan_request(handler)
