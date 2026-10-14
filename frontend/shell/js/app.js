import "../../design-system/js/index.js";
import {
  BACKEND_EVENT,
  installBackendEventReceiver,
  pingBridge,
  probeEventBridge,
  notifyFrontendReady,
  callDesktopApi,
} from "./bridge.js";
import { setUiLanguage, getUiLanguage, languages, t } from "./i18n.js";
import { installToastEventHandler, showToast, showActionToast, showDecisionToast } from "./toast-manager.js";
import { choiceDialog, passwordDialog } from "./dialogs.js";
import { mountOverview } from "../../views/overview.js";
import { mountSharing } from "../../views/sharing.js";
import { mountDevices } from "../../views/devices.js";
import { mountActivity } from "../../views/activity.js";
import { mountSettings } from "../../views/settings.js";

installBackendEventReceiver();
installToastEventHandler();

let disposeCurrent = () => {};
let currentRoute = "overview";
let currentTheme = "dark";
let chromeRefreshTimer = null;
let clusterDiscoveryTimer = null;
let shellServerRunning = false;
const clusterDiscoverySeen = new Map();
const incomingTransferToastSeen = new Map();
const pendingTransferLabels = new Map();
const header = document.createElement("span");

function applyTheme(theme) {
  const value = String(theme || "system").toLowerCase();
  currentTheme = value;
  const dark = value === "dark" || (value === "system" && globalThis.matchMedia?.("(prefers-color-scheme: dark)")?.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  const toggle = document.getElementById("theme-switch");
  if (toggle) {
    toggle.dataset.currentTheme = dark ? "dark" : "light";
    const targetLabel = dark ? t("light") : t("dark");
    toggle.title = targetLabel;
    toggle.setAttribute("aria-label", targetLabel);
  }
}

function applyTextSize(size) {
  const value = ["small", "normal", "large"].includes(String(size)) ? String(size) : "normal";
  document.documentElement.dataset.textSize = value;
}

function routeKey(route) {
  return ({overview:"overview", sharing:"public_sharing", devices:"devices", activity:"activity", settings:"settings"})[route] || route;
}

function updateNavigationLabels() {
  for (const node of document.querySelectorAll("[data-route-label]")) {
    node.textContent = t(routeKey(node.dataset.routeLabel));
  }
  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.dataset.i18n);
  }
  for (const node of document.querySelectorAll("[data-i18n-aria-label]")) {
    node.setAttribute("aria-label", t(node.dataset.i18nAriaLabel));
  }
  for (const node of document.querySelectorAll("[data-i18n-title]")) {
    node.title = t(node.dataset.i18nTitle);
  }
  const languageTitle = document.getElementById("language-title");
  if (languageTitle) languageTitle.textContent = t("language");
}

function openSidebar() {
  document.getElementById("sidebar")?.classList.add("open");
  document.getElementById("scrim")?.classList.add("open");
}
function closeSidebar() {
  document.getElementById("sidebar")?.classList.remove("open");
  document.getElementById("scrim")?.classList.remove("open");
}

function navigate(route) {
  currentRoute = route;
  try { disposeCurrent(); } catch (_) {}
  disposeCurrent = () => {};
  for (const node of document.querySelectorAll("[data-route]")) {
    node.classList.toggle("active", node.dataset.route === route);
    if (node.dataset.route === route) node.setAttribute("aria-current", "page");
    else node.removeAttribute("aria-current");
  }
  const host = document.getElementById("shell-content");
  if (!host) return;
  document.getElementById("content")?.scrollTo({top:0});
  closeSidebar();
  if (route === "overview") disposeCurrent = mountOverview({ host, headerTitle: header });
  else if (route === "sharing") disposeCurrent = mountSharing({ host, headerTitle: header });
  else if (route === "devices") disposeCurrent = mountDevices({ host, headerTitle: header });
  else if (route === "activity") disposeCurrent = mountActivity({ host, headerTitle: header });
  else if (route === "settings") disposeCurrent = mountSettings({ host, headerTitle: header });
}

function installNavigation() {
  for (const node of document.querySelectorAll("[data-route]")) {
    node.addEventListener("click", () => navigate(node.dataset.route));
  }
  document.getElementById("mobile-menu-button")?.addEventListener("click", openSidebar);
  document.getElementById("scrim")?.addEventListener("click", closeSidebar);
}

globalThis.addEventListener("netshare:navigate", (event) => {
  const route=String(event?.detail?.route||"");
  const section=String(event?.detail?.section||"");
  if(!route)return;
  if(route==="settings"&&section)globalThis.__netshareSettingsInitialSection=section;
  navigate(route);
  if(route==="settings"&&section){
    globalThis.setTimeout(()=>globalThis.dispatchEvent(new CustomEvent("netshare:settings.open-section",{detail:{section}})),0);
  }
});

function openLanguageModal() {
  document.getElementById("modal-language")?.classList.add("open");
  document.getElementById("modal-language")?.setAttribute("aria-hidden", "false");
}
function closeLanguageModal() {
  document.getElementById("modal-language")?.classList.remove("open");
  document.getElementById("modal-language")?.setAttribute("aria-hidden", "true");
}

function renderLanguageOptions() {
  const host = document.getElementById("language-grid");
  if (!host) return;
  host.replaceChildren();
  const selected = getUiLanguage();
  for (const [code, label] of Object.entries(languages())) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `btn ${code === selected ? "btn-fill" : "btn-ghost"} language-option`;
    button.textContent = label;
    button.addEventListener("click", async () => {
      const response = await callDesktopApi("update_language", { language: code });
      if (!response?.ok) { showToast("error", "service_unavailable_safe", {service:t("language"),support_code:response?.error?.code || "LANG"}); return; }
      setUiLanguage(code);
      updateNavigationLabels();
      renderLanguageOptions();
      closeLanguageModal();
      navigate(currentRoute);
    });
    host.appendChild(button);
  }
}

async function startServerFromChrome(params = {}) {
  const response = await callDesktopApi("start_server", params);
  if (response?.ok) {
    showToast("success", "server_started_toast");
    await refreshShellChrome();
    return true;
  }
  const code = response?.error?.code;
  if (code === "server.password_reminder_due") {
    const days = response?.error?.details?.days ?? 7;
    const choice = await choiceDialog({
      title: t("password_reminder_title"),
      message: t("password_reminder_message", { days }),
      actions: [
        { label: t("cancel"), value: "cancel" },
        { label: t("start_anyway"), value: "start", kind: "primary" },
        { label: t("change_password"), value: "change" },
      ],
    });
    if (choice === "change") {
      const password = await passwordDialog({
        title: t("password_reminder_title"), message: "", label: t("new_password"),
        saveLabel: t("save"), cancelLabel: t("cancel"),
      });
      if (password === null) return false;
      const saved = await callDesktopApi("update_local_password", { password, reminder_days: days });
      if (!saved?.ok) throw new Error(saved?.error?.code || "server.password_update_failed");
      return startServerFromChrome({ ...params, acknowledge_password_reminder: true, allow_no_password: !password });
    }
    if (choice === "start") return startServerFromChrome({ ...params, acknowledge_password_reminder: true });
    return false;
  }
  if (code === "server.vault_locked" || code === "server.vault_state_unavailable") {
    globalThis.dispatchEvent(new CustomEvent("netshare:navigate", { detail: { route: "settings", section: "data_vault" } }));
    return false;
  }
  if (code === "server.no_password_confirmation_required") {
    const choice = await choiceDialog({
      title: t("no_password_warning_title"), message: t("no_password_warning_message"),
      actions: [
        { label: t("cancel"), value: "cancel" },
        { label: t("start_anyway"), value: "start", kind: "primary" },
      ],
    });
    if (choice === "start") return startServerFromChrome({ ...params, allow_no_password: true });
    return false;
  }
  throw new Error(code || "server_start_failed");
}

async function toggleServerFromChrome() {
  const button = document.getElementById("server-power-button");
  if (!button || button.disabled) return;
  button.disabled = true;
  button.classList.add("is-busy");
  try {
    const snapshot = await callDesktopApi("get_server_snapshot");
    if (!snapshot?.ok) throw new Error(snapshot?.error?.code || "server_snapshot_failed");
    shellServerRunning = Boolean(snapshot.data?.server_running);
    if (shellServerRunning) {
      const response = await callDesktopApi("stop_server");
      if (!response?.ok) throw new Error(response?.error?.code || "server_stop_failed");
      showToast("success", "server_stopped_toast");
      shellServerRunning = false;
      await refreshShellChrome();
    } else {
      await startServerFromChrome({});
    }
  } catch (error) {
    showToast("error", shellServerRunning ? "server_stop_failed" : "server_start_failed");
  } finally {
    button.disabled = false;
    button.classList.remove("is-busy");
    await refreshShellChrome();
  }
}

function installChromeActions() {
  document.getElementById("server-power-button")?.addEventListener("click", () => { void toggleServerFromChrome(); });
  document.getElementById("language-button")?.addEventListener("click", () => { renderLanguageOptions(); openLanguageModal(); });
  document.querySelector("[data-close-language]")?.addEventListener("click", closeLanguageModal);
  document.getElementById("modal-language")?.addEventListener("click", (event) => {
    if (event.target?.id === "modal-language") closeLanguageModal();
  });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") { closeLanguageModal(); closeSidebar(); } });
  document.getElementById("theme-switch")?.addEventListener("click", async () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    const response = await callDesktopApi("update_appearance", { theme: next });
    if (response?.ok) applyTheme(response.data?.theme || next);
  });
}

async function refreshShellChrome() {
  try {
    const [serverResponse, metricsResponse, devicesResponse, aboutResponse] = await Promise.all([
      callDesktopApi("get_server_snapshot"), callDesktopApi("get_metrics_snapshot"),
      callDesktopApi("list_trusted_devices"), callDesktopApi("get_about_settings"),
    ]);
    if (serverResponse?.ok) {
      const server = serverResponse.data || {};
      const status = document.getElementById("server-status-chip");
      const label = document.getElementById("server-status-label");
      const sub = document.getElementById("server-status-sub");
      shellServerRunning = Boolean(server.server_running);
      status?.classList.toggle("live", shellServerRunning);
      const power = document.getElementById("server-power-button");
      if (power) {
        power.classList.toggle("is-running", shellServerRunning);
        const powerLabel = shellServerRunning ? t("stop_server") : t("start_server");
        power.title = powerLabel;
        power.setAttribute("aria-label", powerLabel);
      }
      if (label) label.textContent = shellServerRunning ? t("server_running_label") : t("server_offline_label");
      if (sub) sub.textContent = t("sharing_folder_count", { count: server.shared_roots?.length || 0 });
      const machine = document.getElementById("machine-name");
      if (machine) machine.textContent = String(server.server_name || "NETSHARE SERVER").toUpperCase();
    }
    if (devicesResponse?.ok) {
      const badge = document.getElementById("device-count-badge");
      const count = Array.isArray(devicesResponse.data) ? devicesResponse.data.length : 0;
      if (badge) { badge.textContent = String(count); badge.hidden = count <= 0; }
    }
    if (aboutResponse?.ok) {
      const meta = document.getElementById("version-company");
      if (meta) meta.textContent = `v${aboutResponse.data.version} · ${aboutResponse.data.company}`;
    }
    void metricsResponse;
  } catch (_) {}
}

function scheduleChromeRefresh() {
  if (chromeRefreshTimer) globalThis.clearTimeout(chromeRefreshTimer);
  chromeRefreshTimer = globalThis.setTimeout(async () => { await refreshShellChrome(); scheduleChromeRefresh(); }, 7000);
}

function openActivityFromToast() {
  if (currentRoute !== "activity") navigate("activity");
}

async function resolveIncomingTransfer(requestId, accepted) {
  try {
    const response = await callDesktopApi("resolve_upload", { request_id: requestId, accepted: Boolean(accepted) });
    if (!response?.ok) {
      showToast("error", "request_expired");
      return;
    }
    showToast(accepted ? "success" : "warning", accepted ? "accepted" : "declined");
  } catch (_) {
    showToast("error", "request_expired");
  }
}

function handleIncomingTransferActivity(activity) {
  try {
    const now = Date.now();
    for (const [key, seenAt] of incomingTransferToastSeen) if (now - seenAt > 10 * 60 * 1000) incomingTransferToastSeen.delete(key);
    for (const [key, seenAt] of pendingTransferLabels) if (now - seenAt > 2 * 60 * 1000) pendingTransferLabels.delete(key);

    if (activity?.stream === "write" && activity?.action === "upload-request" && activity?.request_id) {
      const requestId = String(activity.request_id);
      const toastKey = `approval:${requestId}`;
      if (incomingTransferToastSeen.has(toastKey)) return;
      incomingTransferToastSeen.set(toastKey, now);
      const labelKey = `${String(activity.path||"")}${String(activity.client||"")}`;
      pendingTransferLabels.set(labelKey, now);
      showDecisionToast(
        "info",
        "incoming_transfer_request_message",
        { filename: activity.path || "—", client: activity.client || "—" },
        [
          { labelKey: "decline", kind: "danger", onAction: () => resolveIncomingTransfer(requestId, false) },
          { labelKey: "accept", kind: "primary", onAction: () => resolveIncomingTransfer(requestId, true) },
        ],
        "incoming_transfer_request_title",
        openActivityFromToast,
      );
      return;
    }

    if (activity?.stream === "transfer" && activity?.id && String(activity.status||"") === "receiving") {
      const transferId = String(activity.id);
      const toastKey = `transfer:${transferId}`;
      if (incomingTransferToastSeen.has(toastKey)) return;
      incomingTransferToastSeen.set(toastKey, now);
      const labelKey = `${String(activity.filename||"")}${String(activity.client||"")}`;
      if (pendingTransferLabels.has(labelKey)) return;
      showActionToast(
        "info",
        "incoming_transfer_started_message",
        { filename: activity.filename || "—", client: activity.client || "—" },
        "open_activity",
        openActivityFromToast,
        "incoming_transfer_started_title",
        openActivityFromToast,
      );
    }
  } catch (_) {}
}

globalThis.addEventListener("netshare:activity.appended", (event) => {
  handleIncomingTransferActivity(event?.detail?.payload?.activity);
});

function openClusterSettings() {
  globalThis.__netshareSettingsInitialSection = "co_servers";
  if (currentRoute !== "settings") navigate("settings");
  globalThis.setTimeout(() => {
    globalThis.dispatchEvent(new CustomEvent("netshare:settings.open-section", { detail: { section: "co_servers" } }));
  }, 0);
}

async function clusterToastAction(snapshot, node) {
  const localRole = String(snapshot?.effective_role || snapshot?.role || "standalone");
  try {
    if (localRole === "master" && node?.role === "slave" && node?.pairing_open && Number(snapshot?.available_slots ?? 0) > 0) {
      const response = await callDesktopApi("start_cluster_pairing", { node_id: node.node_id, window_id: node.window_id });
      if (!response?.ok) showToast("error", "service_unavailable_safe", {service:t("co_servers"),support_code:response?.error?.code || "CLUSTER_LINK"});
    } else if (localRole === "slave" && node?.role === "master" && !snapshot?.slave_paired && !snapshot?.pairing_active) {
      const response = await callDesktopApi("start_cluster_pairing");
      if (!response?.ok) showToast("error", "service_unavailable_safe", {service:t("co_servers"),support_code:response?.error?.code || "CLUSTER_PAIR"});
    }
  } catch (error) {
    showToast("error", "service_unavailable_safe", {service:t("co_servers"),support_code:String(error?.message || "CLUSTER_LINK").slice(0,72)});
  }
  openClusterSettings();
}

async function refreshClusterDiscovery() {
  try {
    const response = await callDesktopApi("get_cluster_settings");
    if (response?.ok) {
      const snapshot = response.data || {};
      const localRole = String(snapshot.effective_role || snapshot.role || "standalone");
      const linked = new Set((snapshot.nodes || []).map((node) => String(node.node_id || "")));
      const activeKeys = new Set();
      if (snapshot.running && localRole !== "standalone") {
        for (const node of snapshot.nearby_nodes || []) {
          if (!node?.node_id || linked.has(String(node.node_id)) || (localRole === "slave" && snapshot.slave_paired)) continue;
          const key = `${node.node_id}:${node.role}:${node.pairing_open ? "open" : "seen"}`;
          activeKeys.add(key);
          if (clusterDiscoverySeen.has(key)) continue;
          clusterDiscoverySeen.set(key, Date.now());
          const request = localRole === "master" && node.role === "slave" && node.pairing_open;
          showActionToast(
            request ? "success" : "info",
            request ? "cluster_pairing_request" : "cluster_nearby_found",
            { name: node.name || node.node_id, role: String(node.role || "").toUpperCase() },
            "cluster_link",
            () => clusterToastAction(snapshot, node),
            "cluster_nearby_found_title",
          );
        }
      }
      const now = Date.now();
      for (const [key, seenAt] of clusterDiscoverySeen) {
        if (!activeKeys.has(key) && now - seenAt > 15000) clusterDiscoverySeen.delete(key);
      }
    }
  } catch (_) {}
}

function scheduleClusterDiscovery() {
  if (clusterDiscoveryTimer) globalThis.clearTimeout(clusterDiscoveryTimer);
  clusterDiscoveryTimer = globalThis.setTimeout(async () => {
    await refreshClusterDiscovery();
    scheduleClusterDiscovery();
  }, 1800);
}

function renderShellError(error) {
  try {
    const app = document.getElementById("app-shell");
    if (app) app.setAttribute("aria-hidden", "false");
    notifyFrontendReady().catch(() => {});
  } catch (_) {}
  try {
    const host = document.getElementById("shell-content");
    if (!host) return;
    host.replaceChildren();
    const state = document.createElement("ns-error-state");
    state.setAttribute("title", t("netshare_title"));
    state.setAttribute("message", t("service_unavailable_safe", {service:t("shell_ui_service"),support_code:"SHELL"}));
    host.appendChild(state);
  } catch (_) {}
  try { console.error("[NetShare Shell]", error); } catch (_) {}
}

async function gateLockedDataVaultAtStartup(){
  const response=await callDesktopApi("get_data_vault_settings");
  if(!response?.ok)return false;
  const status=response.data||{};
  if(status.configured&&!status.unlocked){
    globalThis.__netshareSettingsInitialSection="data_vault";
    navigate("settings");
    return true;
  }
  return false;
}

async function maybeOfferDataVault(){
  const response=await callDesktopApi("get_data_vault_intro");
  if(!response?.ok||!response.data?.should_offer)return;
  await callDesktopApi("mark_data_vault_intro_offered");
  const update=response.data.context==="update";
  const choice=await choiceDialog({
    title:t(update?"vault_intro_update_title":"vault_intro_first_title"),
    message:t(update?"vault_intro_update_message":"vault_intro_first_message"),
    actions:[
      {label:t("vault_intro_defer"),value:"defer"},
      {label:t("vault_intro_configure_now"),value:"configure",kind:"primary"},
    ],
  });
  if(choice==="configure"){
    globalThis.__netshareSettingsInitialSection="data_vault";
    navigate("settings");
    return;
  }
  if(choice==="defer")await callDesktopApi("defer_data_vault_intro");
}

async function initializeShellBridge() {
  // The native frameless splash is a separate local WebView. The main document
  // loads hidden and signals Python only after its real UI is fully initialized.
  const result = await pingBridge();
  if (!result?.ok) throw new Error(result?.error?.code || "bridge failed");
  const settingsResponse = await callDesktopApi("get_settings_snapshot");
  if (settingsResponse?.ok) {
    setUiLanguage(settingsResponse.data.language);
    applyTheme(settingsResponse.data.theme);
    applyTextSize(settingsResponse.data.text_size);
  }
  updateNavigationLabels();
  installNavigation();
  installChromeActions();
  renderLanguageOptions();
  await refreshShellChrome();
  const vaultNeedsUnlock=await gateLockedDataVaultAtStartup();
  if(!vaultNeedsUnlock)navigate("overview");
  scheduleChromeRefresh();
  scheduleClusterDiscovery();
  await probeEventBridge(result?.meta?.correlation_id || null);
  document.getElementById("app-shell")?.setAttribute("aria-hidden", "false");
  await notifyFrontendReady(result?.meta?.correlation_id || null);
  await maybeOfferDataVault();
}

globalThis.addEventListener(BACKEND_EVENT, (event) => {
  try {
    const name = event?.detail?.name;
    if (["server.status.changed","server.addresses.changed","devices.changed","settings.changed","sharing.changed"].includes(name)) refreshShellChrome();
    if (name === "settings.changed") {
      callDesktopApi("get_settings_snapshot").then((response) => {
        if (!response?.ok) return;
        setUiLanguage(response.data.language);
        applyTheme(response.data.theme);
        applyTextSize(response.data.text_size);
        updateNavigationLabels();
        renderLanguageOptions();
      }).catch(() => {});
    }
  } catch (_) {}
});
function reportRuntimeUiError(error, fallbackCode="UI-RUNTIME") {
  try {
    const raw=String(error?.message||error||fallbackCode);
    const supportCode=raw.slice(0,72)||fallbackCode;
    console.error("[NetShare Shell runtime]", error);
    showToast("error","service_unavailable_safe",{service:t("shell_ui_service"),support_code:supportCode});
  } catch (_) {}
}

// Runtime action errors are recoverable and must never replace the whole app
// with the fatal SHELL state. The fatal state is reserved for initialization
// failures where the bridge or the main document cannot be brought up at all.
globalThis.addEventListener("error", (event) => reportRuntimeUiError(event?.error || new Error("Shell JavaScript error"),"UI-ERROR"));
globalThis.addEventListener("unhandledrejection", (event) => {
  try { event?.preventDefault?.(); } catch (_) {}
  reportRuntimeUiError(event?.reason || new Error("Unhandled shell promise rejection"),"UI-PROMISE");
});

initializeShellBridge().catch(renderShellError);
