# Configuration

Persistent settings are managed by `src.state`. They include server identity, approved devices, shared roots, visibility, guest profiles, cluster role, appearance, language, performance preset, FFmpeg path, and advanced preferences.

## Cluster role

Supported values are `standalone`, `auto`, `master`, and `slave`. In `auto` mode, the effective cryptographic role can change without rewriting the user's preference.

## Feature flags

Remote feature flags use three states:

- `true`: the capability is allowed;
- `false`: the capability is explicitly disabled;
- unknown: no remote value is available in the current process.

Effective flags are resolved by the backend when the server starts. The frontend displays that state but does not decide whether a capability is active.

## Appearance and advanced settings

Themes are `system`, `dark`, or `light`. Text sizes are `small`, `normal`, or `large`. Language changes are persisted and rebuild the active view.

The advanced-settings preference controls whether advanced sections are shown. Hiding them does not disable already configured runtime features.

## Player TLS

Player-facing TLS can be enabled with `NETSHARE_TLS_ENABLED` or the local `server_player_tls.json` setting. Accepted environment values are `1`, `true`, `yes`, and `on`. Configuration is read at startup.

When TLS is enabled successfully, the LAN HTTP and WebSocket listeners use HTTPS and WSS. Startup fails visibly if the identity or listeners cannot be initialized; the server does not silently downgrade an explicit TLS configuration.
