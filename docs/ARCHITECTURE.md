# Architecture

NetShare Server turns a computer into a media library accessible from NetShare Player and the web interface. The Server remains authoritative for files, permissions, sessions, and exposed capabilities.

## Layers

The main dependency direction is:

```text
frontend -> desktop_shell -> desktop_api -> application -> runtime/core/state
clients -> routes -> core/state
```

`routes` is independent of the desktop UI. The frontend requests snapshots and actions through the desktop API and does not duplicate Python business rules.

## Source tree

```text
main.py
frontend/
  design-system/   Shared tokens and controls
  shell/           Navigation, bridge, dialogs, and notifications
  views/           Application screens
src/
  application/     UI-neutral services, DTOs, and adapters
  desktop_api/     JSON-safe frontend contract
  desktop_shell/   PyWebView and native integration
  ui_event_bus/    Backend-to-frontend events
  runtime/         Server, tunnel, pairing, flags, and lifecycle controllers
  core/            Business logic and persistence
  core/cluster/    Discovery, pairing, mTLS, tickets, and failover
  core/cloud/      Cloud provider integrations
  routes/          HTTP and WebSocket endpoints
  utils/           Network and platform helpers
  state.py         Shared settings and persistence
  constants.py     Version, ports, and limits
  deps.py          Optional dependency detection
```

## Storage

NetShare uses local files, atomic JSON stores, operating-system secure storage, and SQLite. The file index can be restored from a cache, but filesystem metadata remains authoritative. Live filesystem events are coalesced and bounded; overflow requests an explicit rescan instead of allowing unbounded memory growth.

Derived thumbnails and analysis data are rebuildable caches. Visibility and permission rules are applied before catalog data is exposed to clients.

## Cluster

Cluster services have a dedicated trust and protocol layer under `src/core/cluster`. Discovery advertisements are untrusted hints. Enrollment uses a short authentication string, and permanent node traffic uses TLS 1.3 with mutual authentication. A normal cluster presents one Player-facing entry point through its active master.
