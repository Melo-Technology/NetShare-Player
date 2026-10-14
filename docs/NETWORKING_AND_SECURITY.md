# Networking and security

## Listener layout

For the main port `N` (8080 by default):

| Address | Purpose | Exposure |
|---|---|---|
| `0.0.0.0:N` | LAN API and files | Local network |
| `0.0.0.0:N+1` | WebSocket or WSS | Local network |
| `127.0.0.1:N+2` | Public tunnel backend | Loopback only |

Cluster bootstrap and secure node traffic use additional derived ports. They are separate from ordinary Player routes.

## Discovery

NetShare uses two DNS-SD services:

- `_netshare._tcp.local.` for NetShare Player discovery;
- `_netshare-node._tcp.local.` for server-to-server cluster discovery.

Cluster advertisements do not establish trust. Standalone servers and active masters are normally visible to Player clients; workers are hidden unless a controlled fallback mode requires direct visibility.

## Trust domains

Player transport and cluster transport are separate trust domains. Player TLS uses a stable server identity and a trust-on-first-use model. Cluster traffic uses a local certificate authority, node identities, and mutual TLS 1.3. Trust in one domain does not grant access to the other.

The cluster enrollment ceremony combines ephemeral key agreement with a short authentication string that users compare on both computers. The resulting enrollment data is authenticated and encrypted before a node joins the permanent mTLS channel.

## Web and proxy boundaries

Browser origins are compared strictly. Authenticated web sessions are read-only and federated through the cluster master. A forwarded client address is trusted only when both the proxy and its header are explicitly configured.

The public tunnel listener is isolated from LAN listeners. Client-controlled headers cannot convert a LAN request into a trusted tunnel request.

## Cross-network relay

For peer-to-peer cross-network transfers, the Server acts as an invitation registry and ciphertext relay. End-to-end encryption keys and plaintext remain with the participating clients. Relay storage is bounded and includes integrity checks and cleanup.
