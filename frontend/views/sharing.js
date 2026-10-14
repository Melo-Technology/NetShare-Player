import { callDesktopApi } from "../shell/js/bridge.js";
import { t } from "../shell/js/i18n.js";
import { choiceDialog, qrDialog } from "../shell/js/dialogs.js";
import { showToast } from "../shell/js/toast-manager.js";

const UPLOAD_GROUPS = {
  images: [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic"],
  video: [".mp4", ".mov", ".mkv", ".avi", ".webm"],
  audio: [".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg"],
  documents: [".txt", ".md", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"],
  archives: [".zip", ".rar", ".7z", ".tar", ".gz"],
};

function el(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function button(label, className = "") {
  const node = el("button", `ns-button ${className}`.trim(), label);
  node.type = "button";
  return node;
}

function card(title, description = "") {
  const root = document.createElement("ns-card");
  const section = el("div", "ns-card__section");
  section.appendChild(el("h2", "ns-card__title", title));
  if (description) section.appendChild(el("p", "ns-card__description", description));
  root.appendChild(section);
  return { root, section };
}


function iconButton(kind, label) {
  const node = el("button", "ns-icon-button ns-sharing__url-action");
  node.type = "button";
  node.setAttribute("aria-label", label);
  node.title = label;
  node.innerHTML = kind === "qr"
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM19 14v7M14 19h4"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="9" y="9" width="12" height="12"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
  return node;
}

function statusBadge(tone, text) {
  const badge = document.createElement("ns-status-badge");
  badge.setAttribute("tone", tone);
  badge.textContent = text;
  return badge;
}

function switchControl(checked, label, description, onChange) {
  const row = el("div", "ns-toggle-row");
  const copy = el("div", "ns-toggle-row__copy");
  copy.appendChild(el("div", "ns-toggle-row__title", label));
  if (description) copy.appendChild(el("div", "ns-toggle-row__description", description));
  const control = el("button", "ns-switch");
  control.type = "button";
  control.setAttribute("role", "switch");
  control.setAttribute("aria-checked", checked ? "true" : "false");
  control.setAttribute("aria-label", label);
  control.addEventListener("click", async () => {
    const next = control.getAttribute("aria-checked") !== "true";
    control.disabled = true;
    try {
      const accepted = await onChange(next);
      if (accepted !== false) control.setAttribute("aria-checked", next ? "true" : "false");
    } finally { control.disabled = false; }
  });
  row.append(copy, control);
  return row;
}

async function copyText(value) {
  if (!value) return false;
  try {
    await navigator.clipboard.writeText(String(value));
    return true;
  } catch (_) {
    try {
      const input = document.createElement("textarea");
      input.value = String(value);
      input.style.position = "fixed";
      input.style.opacity = "0";
      document.body.appendChild(input);
      input.select();
      const ok = document.execCommand("copy");
      input.remove();
      return Boolean(ok);
    } catch (_) { return false; }
  }
}

export function mountSharing({ host, headerTitle }) {
  let disposed = false;
  let sharing = null;
  let sessions = [];
  let sessionsUnavailable = false;
  let tunnel = { ssh: { active: false, url: "" }, cloudflare: { active: false, url: "", hostname: "" }, any_active: false };
  let server = { server_running: false, shared_roots: [] };
  let connectingTimer = null;
  let sessionRefreshTimer = null;
  let vaultLocked = false;
  const plaintext = { community: "", admin: "", web: "" };

  headerTitle.textContent = t("public_sharing");
  host.replaceChildren();

  const loading = document.createElement("ns-loading-state");
  host.appendChild(loading);

  function stopConnectingTimer() {
    if (connectingTimer) globalThis.clearTimeout(connectingTimer);
    connectingTimer = null;
  }

  function stopSessionRefreshTimer() {
    if (sessionRefreshTimer) globalThis.clearInterval(sessionRefreshTimer);
    sessionRefreshTimer = null;
  }

  function sessionSignature(items) {
    return (Array.isArray(items) ? items : [])
      .map((item) => `${item?.id || ""}|${item?.last_seen_at || ""}|${item?.idle_expires_at || ""}`)
      .join("\n");
  }

  function startSessionRefreshTimer() {
    stopSessionRefreshTimer();
    sessionRefreshTimer = globalThis.setInterval(async () => {
      if (disposed) return;
      try {
        const response = await callDesktopApi("list_web_sessions");
        if (!response?.ok) { sessionsUnavailable = true; return; }
        sessionsUnavailable = false;
        const next = Array.isArray(response.data) ? response.data : [];
        if (sessionSignature(next) !== sessionSignature(sessions)) {
          sessions = next;
          render();
        }
      } catch (_) {}
    }, 5000);
  }

  function scheduleTunnelRefresh() {
    stopConnectingTimer();
    if (disposed || !tunnel?.ssh?.active || tunnel?.ssh?.url) return;
    connectingTimer = globalThis.setTimeout(async () => {
      try {
        const response = await callDesktopApi("get_tunnel_status");
        if (response?.ok) {
          tunnel = response.data;
          if (!disposed) render();
        }
      } finally { scheduleTunnelRefresh(); }
    }, 1500);
  }

  function responseErrorCode(response) {
    return String(response?.error?.code || "");
  }

  async function fetchState() {
    const vaultResponse = await callDesktopApi("get_data_vault_settings");
    if (!vaultResponse?.ok) throw new Error(responseErrorCode(vaultResponse) || "vault status failed");
    vaultLocked = Boolean(vaultResponse.data?.configured && !vaultResponse.data?.unlocked);
    if (vaultLocked) {
      renderVaultLocked();
      stopConnectingTimer();
      stopSessionRefreshTimer();
      return;
    }

    // Load the core Public Sharing configuration first. Auxiliary state must
    // never keep the complete screen stuck on its loading placeholder.
    const sharingResponse = await callDesktopApi("get_sharing_snapshot");
    if (!sharingResponse?.ok) {
      if (responseErrorCode(sharingResponse) === "vault_locked") {
        vaultLocked = true;
        renderVaultLocked();
        return;
      }
      throw new Error(responseErrorCode(sharingResponse) || "sharing snapshot failed");
    }
    sharing = sharingResponse.data || {};
    if (!disposed) render();

    const [sessionsResult, tunnelResult, serverResult] = await Promise.allSettled([
      callDesktopApi("list_web_sessions"),
      callDesktopApi("get_tunnel_status"),
      callDesktopApi("get_server_snapshot"),
    ]);

    const sessionsResponse = sessionsResult.status === "fulfilled" ? sessionsResult.value : null;
    sessionsUnavailable = !sessionsResponse?.ok;
    if (responseErrorCode(sessionsResponse) === "vault_locked") {
      vaultLocked = true;
      renderVaultLocked();
      return;
    }
    sessions = sessionsResponse?.ok && Array.isArray(sessionsResponse.data) ? sessionsResponse.data : [];

    const tunnelResponse = tunnelResult.status === "fulfilled" ? tunnelResult.value : null;
    if (tunnelResponse?.ok && tunnelResponse.data) tunnel = tunnelResponse.data;

    const serverResponse = serverResult.status === "fulfilled" ? serverResult.value : null;
    if (serverResponse?.ok && serverResponse.data) server = serverResponse.data;

    if (!disposed) {
      render();
      scheduleTunnelRefresh();
      startSessionRefreshTimer();
    }
  }

  function openVaultSettings() {
    globalThis.dispatchEvent(new CustomEvent("netshare:navigate", { detail: { route: "settings", section: "data_vault" } }));
  }

  function renderVaultLocked() {
    if (disposed) return;
    host.replaceChildren();
    const state = document.createElement("ns-error-state");
    state.setAttribute("title", t("vault_locked"));
    state.setAttribute("message", t("vault_locked_section_message"));
    const unlock = button(t("vault_unlock"), "ns-button--primary");
    unlock.dataset.stateAction = "true";
    unlock.addEventListener("click", openVaultSettings);
    state.appendChild(unlock);
    host.appendChild(state);
  }

  function renderError() {
    if (disposed) return;
    host.replaceChildren();
    const state = document.createElement("ns-error-state");
    state.setAttribute("title", t("public_sharing"));
    state.setAttribute("message", t("server_start_failed"));
    const retry = button(t("retry"), "ns-button--primary");
    retry.dataset.stateAction = "true";
    retry.addEventListener("click", () => load());
    state.appendChild(retry);
    host.appendChild(state);
  }

  async function load() {
    try { await fetchState(); }
    catch (_) { renderError(); }
  }

  async function savePublicConfig(patch = {}) {
    const next = { ...sharing, ...patch };
    const response = await callDesktopApi("update_public_sharing", {
      community_browse_root: Boolean(next.community_browse_root),
      community_download: Boolean(next.community_download),
      community_upload: Boolean(next.community_upload),
      public_upload_mode: String(next.public_upload_mode),
      max_uploads_per_hour: Number(next.max_uploads_per_hour),
      max_upload_size_mb: Number(next.max_upload_size_mb),
      allowed_upload_extensions: Array.from(next.allowed_upload_extensions || []),
    });
    if (!response?.ok) {
      showToast("error", "folder_update_failed");
      return false;
    }
    sharing = response.data;
    showToast("success", "folder_updated_toast");
    render();
    return true;
  }


  async function openUrlQr(value, title) {
    const clean = String(value || "").trim();
    if (!clean) return;
    const response = await callDesktopApi("get_qr_code", { value: clean });
    if (!response?.ok || !response.data?.available || !response.data?.data_url) {
      showToast("error", "server_start_failed");
      return;
    }
    await qrDialog({
      title,
      value: response.data.value || clean,
      dataUrl: response.data.data_url,
      closeLabel: t("close"),
    });
  }

  function urlField(value, { title, placeholder = "", enabled = true } = {}) {
    const row = el("div", "ns-sharing__url ns-sharing__url--with-actions");
    const input = el("input", "ns-input ns-sharing__url-input");
    input.readOnly = true;
    input.value = value || "";
    input.placeholder = placeholder;
    const actions = el("div", "ns-sharing__url-actions");
    const qr = iconButton("qr", t("qr_short"));
    const copy = iconButton("copy", t("copy"));
    qr.disabled = copy.disabled = !enabled || !value;
    qr.addEventListener("click", async () => {
      qr.disabled = true;
      try { await openUrlQr(value, title); }
      finally { if (qr.isConnected) qr.disabled = !enabled || !value; }
    });
    copy.addEventListener("click", async () => {
      copy.disabled = true;
      try {
        if (await copyText(value)) showToast("success", "copy");
        else showToast("error", "server_start_failed");
      } finally { if (copy.isConnected) copy.disabled = !enabled || !value; }
    });
    actions.append(qr, copy);
    row.append(input, actions);
    return row;
  }

  function renderPublicLink() {
    const { root, section } = card("", "");
    const active = Boolean(tunnel?.ssh?.active);
    const publicUrl = String(tunnel?.ssh?.url || "");
    const head = el("div", "ns-sharing__card-head");
    const copy = el("div", "ns-sharing__card-head-copy");
    copy.append(el("h2", "ns-card__title", t("public_link")), el("p", "ns-card__description", t("public_link_description")));
    const status = active
      ? statusBadge(publicUrl ? "success" : "warning", publicUrl ? t("online") : t("connecting"))
      : statusBadge("neutral", t("offline"));
    head.append(copy, status);
    section.appendChild(head);

    const wrapper = el("div", "ns-sharing__public-link");
    wrapper.appendChild(urlField(publicUrl, {
      title: t("public_link"),
      placeholder: active ? t("connecting") : t("offline"),
      enabled: active,
    }));

    const action = button(active ? t("stop_sharing") : t("share_publicly"), active ? "ns-button--danger ns-button--block" : "ns-button--primary ns-button--block");
    action.disabled = !active && !server?.server_running;
    action.addEventListener("click", async () => {
      action.disabled = true;
      try {
        if (active) {
          const response = await callDesktopApi("stop_tunnel");
          if (!response?.ok) throw new Error(response?.error?.code || "stop tunnel failed");
          tunnel = response.data;
          showToast("success", "tunnel_stopped", { service: "TUNNEL" });
          render();
          return;
        }
        const folder = server?.shared_roots?.[0]?.path || "";
        const choice = await choiceDialog({
          title: t("security_title"),
          message: t("security_message", { folder }),
          actions: [
            { label: t("cancel"), value: "cancel" },
            { label: t("start_sharing"), value: "start", kind: "danger" },
          ],
        });
        if (choice !== "start") return;
        const response = await callDesktopApi("start_tunnel", { rotate_keys: true });
        if (!response?.ok) throw new Error(response?.error?.code || "start tunnel failed");
        tunnel = response.data.tunnel;
        plaintext.community = response.data.community_key || "";
        plaintext.admin = response.data.admin_key || "";
        sharing.community_key_configured = Boolean(plaintext.community) || sharing.community_key_configured;
        sharing.admin_key_configured = Boolean(plaintext.admin) || sharing.admin_key_configured;
        render();
        scheduleTunnelRefresh();
      } catch (error) {
        const code = String(error?.message || "");
        showToast("error", code === "sharing.server_not_running" ? "start_server_first" : "server_start_failed");
      } finally { if (action.isConnected) action.disabled = false; }
    });
    wrapper.appendChild(action);
    if (!server?.server_running && !active) wrapper.appendChild(el("div", "ns-subtle", t("start_server_first")));
    section.appendChild(wrapper);
    return root;
  }

  function keyField(kind, label, configured) {
    const field = el("div", "ns-field");
    field.appendChild(el("div", "ns-field__label", label));
    const row = el("div", "ns-secret-row");
    const input = el("input", "ns-input");
    input.readOnly = true;
    input.type = "password";
    input.value = plaintext[kind] || "";
    input.placeholder = configured ? "••••••••" : t("none");
    const visibility = button(t("show"), "ns-button--compact");
    visibility.disabled = !plaintext[kind];
    visibility.addEventListener("click", () => {
      const visible = input.type === "text";
      input.type = visible ? "password" : "text";
      visibility.textContent = visible ? t("show") : t("hide");
    });
    const generate = button(t("generate"), "ns-button--compact");
    generate.addEventListener("click", async () => {
      const response = await callDesktopApi("generate_access_key", { kind });
      if (!response?.ok) return showToast("error", "server_start_failed");
      plaintext[kind] = response.data[`${kind}_key`] || "";
      if (kind === "community") sharing.community_key_configured = true;
      else sharing.admin_key_configured = true;
      render();
    });
    row.append(input, visibility, generate);
    field.appendChild(row);
    const actions = el("div", "ns-sharing__key-actions");
    const copy = button(t("copy"), "ns-button--compact");
    copy.disabled = !plaintext[kind];
    copy.addEventListener("click", async () => {
      if (await copyText(plaintext[kind])) showToast("success", "copy");
    });
    actions.appendChild(copy);
    field.appendChild(actions);
    return field;
  }

  function renderAccessKeys() {
    const { root, section } = card(t("access_keys"), t("access_keys_description"));
    const stack = el("div", "ns-form-stack");
    stack.append(
      keyField("community", t("community_key"), sharing?.community_key_configured),
      keyField("admin", t("admin_key"), sharing?.admin_key_configured),
    );
    section.appendChild(stack);
    return root;
  }

  function renderGuestPermissions() {
    const { root, section } = card(t("guest_permissions"));
    const uploadRemote = sharing?.remote_flags?.upload;
    section.append(
      switchControl(Boolean(sharing?.community_browse_root), t("root_browser"), "", (value) => savePublicConfig({ community_browse_root: value })),
      switchControl(Boolean(sharing?.community_download), t("download"), "", (value) => savePublicConfig({ community_download: value })),
      switchControl(Boolean(sharing?.community_upload), t("upload"), "", (value) => savePublicConfig({ community_upload: value })),
    );

    const fields = el("div", "ns-form-stack");
    const mode = el("div", "ns-field");
    mode.appendChild(el("label", "ns-field__label", t("receive_mode")));
    const select = el("select", "ns-select");
    for (const [label, value] of [[t("direct_accept"), "direct"], [t("ask_first"), "request"]]) {
      const option = el("option", "", label); option.value = value; select.appendChild(option);
    }
    select.value = sharing?.public_upload_mode || "request";
    select.addEventListener("change", () => savePublicConfig({ public_upload_mode: select.value }));
    mode.appendChild(select);
    fields.appendChild(mode);

    if (uploadRemote === false) {
      fields.appendChild(el("div", "ns-settings-note", t("upload_disabled_remotely")));
    } else {
      const limits = el("div", "ns-sharing__limits");
      for (const [key, label, min, max] of [
        ["max_uploads_per_hour", t("uploads_per_hour"), 1, 100],
        ["max_upload_size_mb", t("max_size_mb"), 1, 500],
      ]) {
        const field = el("label", "ns-field");
        field.appendChild(el("span", "ns-field__label", label));
        const input = el("input", "ns-input");
        input.type = "number"; input.min = String(min); input.max = String(max); input.value = String(sharing?.[key] ?? min);
        input.addEventListener("change", () => savePublicConfig({ [key]: Math.max(min, Math.min(max, Number(input.value) || min)) }));
        field.appendChild(input); limits.appendChild(field);
      }
      fields.appendChild(limits);

      const types = el("div", "ns-field");
      types.appendChild(el("div", "ns-field__label", t("allowed_types")));
      const grid = el("div", "ns-checkbox-grid");
      const current = new Set(sharing?.allowed_upload_extensions || []);
      const known = new Set(Object.values(UPLOAD_GROUPS).flat());
      const extras = Array.from(current).filter((value) => !known.has(value));
      for (const [name, extensions] of Object.entries(UPLOAD_GROUPS)) {
        const label = el("label", "ns-checkbox");
        const input = document.createElement("input"); input.type = "checkbox";
        input.checked = extensions.some((value) => current.has(value));
        input.addEventListener("change", () => {
          const selected = new Set(extras);
          for (const [groupName, groupExtensions] of Object.entries(UPLOAD_GROUPS)) {
            const groupInput = grid.querySelector(`[data-group="${groupName}"]`);
            if (groupInput?.checked) groupExtensions.forEach((value) => selected.add(value));
          }
          savePublicConfig({ allowed_upload_extensions: Array.from(selected).sort() });
        });
        input.dataset.group = name;
        label.append(input, el("span", "", name.toUpperCase()));
        grid.appendChild(label);
      }
      types.appendChild(grid); fields.appendChild(types);
    }
    section.appendChild(fields);
    return root;
  }

  function renderWebAccess() {
    const { root, section } = card("", "");
    const enabled = Boolean(sharing?.web_access_enabled);
    const webUrl = String(tunnel?.ssh?.url || "");
    const tunnelActive = Boolean(tunnel?.ssh?.active);
    const head = el("div", "ns-sharing__card-head");
    const copy = el("div", "ns-sharing__card-head-copy");
    copy.append(el("h2", "ns-card__title", t("web_read_only_access")), el("p", "ns-card__description", t("web_read_only_description")));
    const status = enabled
      ? statusBadge(tunnelActive && webUrl ? "success" : "warning", tunnelActive && webUrl ? t("online") : t("connecting"))
      : statusBadge("neutral", t("offline"));
    head.append(copy, status);
    section.appendChild(head);
    section.appendChild(switchControl(enabled, t("web_read_only_access"), "", async (value) => {
      if (value) {
        const response = await callDesktopApi("generate_web_access_password");
        if (!response?.ok) { showToast("error", "web_password_invalid"); return false; }
        plaintext.web = response.data.password || "";
        sharing = response.data.sharing;
        sessions = [];
        showToast("success", "password_saved_title");
        render();
        return true;
      }
      const response = await callDesktopApi("set_web_access", { password: "", enabled: false });
      if (!response?.ok) return false;
      await callDesktopApi("revoke_all_web_sessions");
      plaintext.web = ""; sharing = response.data; sessions = [];
      render();
      return true;
    }));

    section.appendChild(urlField(webUrl, {
      title: t("web_read_only_access"),
      placeholder: tunnelActive ? t("connecting") : t("offline"),
      enabled: enabled && tunnelActive,
    }));

    const field = el("div", "ns-field");
    field.appendChild(el("div", "ns-field__label", t("web_read_only_access")));
    const row = el("div", "ns-secret-row");
    const input = el("input", "ns-input");
    input.type = "password";
    input.value = plaintext.web;
    input.placeholder = sharing?.web_password_configured ? "••••••••" : t("none");
    input.autocomplete = "new-password";
    const visibility = button(t("show"), "ns-button--compact");
    visibility.disabled = !plaintext.web;
    visibility.addEventListener("click", () => {
      const visible=input.type === "text"; input.type=visible ? "password" : "text"; visibility.textContent=visible ? t("show") : t("hide");
    });
    const copyAccess = button(t("copy"), "ns-button--compact");
    copyAccess.disabled = !plaintext.web;
    copyAccess.addEventListener("click", async()=>{ if(await copyText(plaintext.web)) showToast("success","copy"); });
    const save = button(t("save"), "ns-button--compact");
    save.addEventListener("click", async () => {
      if (!input.value) return;
      const response = await callDesktopApi("set_web_access", { password: input.value, enabled: true });
      if (!response?.ok) return showToast("error", "web_password_invalid");
      await callDesktopApi("revoke_all_web_sessions");
      plaintext.web = input.value; sharing = response.data; sessions = [];
      showToast("success", "password_saved_title"); render();
    });
    const generate = button(t("generate"), "ns-button--compact");
    generate.addEventListener("click", async () => {
      const response = await callDesktopApi("generate_web_access_password");
      if (!response?.ok) return showToast("error", "web_password_invalid");
      plaintext.web = response.data.password || ""; sharing = response.data.sharing; sessions = [];
      render();
    });
    row.append(input, visibility, copyAccess, save, generate); field.appendChild(row);
    section.appendChild(field);

    const sessionHeader = el("div", "ns-inline-status");
    sessionHeader.appendChild(el("div", "ns-card__title", t("web_active_sessions", { count: sessions.length })));
    const revokeAll = button(t("revoke_all_web_sessions"), "ns-button--compact ns-button--danger");
    revokeAll.disabled = sessions.length === 0;
    revokeAll.addEventListener("click", async () => {
      const response = await callDesktopApi("revoke_all_web_sessions");
      if (response?.ok) { sessions = []; render(); }
    });
    sessionHeader.appendChild(revokeAll); section.appendChild(sessionHeader);

    if (sessionsUnavailable) section.appendChild(el("div", "ns-subtle", t("unavailable")));
    else if (!sessions.length) section.appendChild(el("div", "ns-subtle", t("none")));
    for (const session of sessions) {
      const rowNode = el("div", "ns-sharing__session");
      const copy = el("div");
      copy.append(el("div", "ns-sharing__session-name", `${session.browser_family} / ${session.os_family}`), el("div", "ns-sharing__session-meta", session.id));
      const revoke = button(t("revoke"), "ns-button--compact ns-button--danger");
      revoke.addEventListener("click", async () => {
        const response = await callDesktopApi("revoke_web_session", { session_id: session.id });
        if (response?.ok) { sessions = sessions.filter((item) => item.id !== session.id); render(); }
      });
      rowNode.append(copy, revoke); section.appendChild(rowNode);
    }
    return root;
  }

  function render() {
    if (disposed || !sharing) return;
    host.replaceChildren();
    const heading = el("div", "ns-section-heading");
    const titleWrap = el("div");
    titleWrap.append(el("div", "ns-section-heading__eyebrow", `02 / ${t("public_sharing")}`), el("h1", "ns-section-heading__title", t("public_sharing")), el("p", "ns-section-heading__description", t("public_sharing_description")));
    heading.appendChild(titleWrap); host.appendChild(heading);
    const view = el("div", "ns-sharing");
    const left = el("div", "ns-sharing__column");
    const right = el("div", "ns-sharing__column");
    left.append(renderPublicLink(), renderAccessKeys());
    right.append(renderGuestPermissions(), renderWebAccess());
    view.append(left, right); host.appendChild(view);
  }

  const refresh = () => { if (!disposed) fetchState().catch(() => {}); };
  globalThis.addEventListener("netshare:sharing.changed", refresh);
  globalThis.addEventListener("netshare:server.status.changed", refresh);
  load();

  return () => {
    disposed = true;
    stopConnectingTimer();
    stopSessionRefreshTimer();
    globalThis.removeEventListener("netshare:sharing.changed", refresh);
    globalThis.removeEventListener("netshare:server.status.changed", refresh);
  };
}
