import { t } from "./i18n.js";

function region() {
  let host = document.getElementById("toast-region");
  if (!host) {
    host = document.createElement("div");
    host.id = "toast-region";
    host.setAttribute("aria-live", "polite");
    host.setAttribute("aria-relevant", "additions");
    document.body.appendChild(host);
  }
  Object.assign(host.style, {
    position: "fixed", right: "18px", bottom: "18px", zIndex: "2147483000",
    display: "flex", flexDirection: "column", alignItems: "stretch", gap: "8px",
    width: "380px", maxWidth: "calc(100vw - 36px)", pointerEvents: "none",
  });
  return host;
}

function toneRail(level) {
  if (level === "success") return "var(--green, #39FF88)";
  if (level === "warning") return "var(--amber, #FFB74C)";
  if (level === "error" || level === "danger") return "var(--red, #FF5C56)";
  return "var(--blue, #4C8DFF)";
}

function actionButton(actionLabel, onAction, kind = "primary") {
  const action = document.createElement("button");
  action.type = "button";
  action.textContent = String(actionLabel);
  action.setAttribute("data-toast-action", "true");
  const danger = kind === "danger";
  Object.assign(action.style, {
    flex: "0 0 auto", display: "inline-flex", alignItems: "center", justifyContent: "center",
    minHeight: "44px", padding: "9px 12px",
    border: `1px solid ${danger ? "var(--red, #FF5C56)" : "var(--border-strong, rgba(255,255,255,.26))"}`,
    borderRadius: "var(--r-s, 3px)",
    background: danger ? "transparent" : "var(--fill, #FFFFFF)",
    color: danger ? "var(--red, #FF5C56)" : "var(--fill-text, #000000)",
    fontFamily: "var(--font, ui-monospace, Menlo, Monaco, Consolas, monospace)",
    fontSize: "10px", fontWeight: "700", letterSpacing: ".06em", lineHeight: "1",
    whiteSpace: "nowrap", cursor: "pointer", WebkitAppearance: "none", appearance: "none",
    opacity: "1", visibility: "visible",
  });
  action.addEventListener("click", async (event) => {
    event.stopPropagation();
    action.disabled = true; action.style.opacity = ".55"; action.style.cursor = "wait";
    try { if (typeof onAction === "function") await onAction(); }
    catch (_) {}
  });
  return action;
}

function makeToast({ level = "info", title = "", message = "", actionLabel = "", onAction = null, actions = [], onOpen = null }) {
  const toast = document.createElement("div");
  toast.setAttribute("role", level === "error" || level === "danger" ? "alert" : "status");
  toast.setAttribute("data-component", "ShellToast");
  toast.setAttribute("data-tone", String(level || "info"));
  Object.assign(toast.style, {
    position: "relative", display: "flex", alignItems: "center", gap: "10px", width: "100%",
    minHeight: "54px", padding: "12px 12px 12px 16px", boxSizing: "border-box", overflow: "hidden",
    background: "var(--surface, #101010)", color: "var(--text, #FFFFFF)",
    border: "1px solid var(--border-strong, rgba(255,255,255,.26))", borderRadius: "var(--r-m, 4px)",
    boxShadow: "0 12px 36px rgba(0,0,0,.32)",
    fontFamily: "var(--font, ui-monospace, Menlo, Monaco, Consolas, monospace)",
    pointerEvents: "auto", WebkitFontSmoothing: "antialiased", opacity: "1", visibility: "visible",
    cursor: typeof onOpen === "function" ? "pointer" : "default",
  });
  if (typeof onOpen === "function") {
    toast.tabIndex = 0;
    const open = async (event) => {
      if (event?.target?.closest?.("button")) return;
      try { await onOpen(); } catch (_) {}
    };
    toast.addEventListener("click", open);
    toast.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(event); }
    });
  }

  const rail = document.createElement("div");
  rail.setAttribute("aria-hidden", "true");
  Object.assign(rail.style, { position: "absolute", left: "0", top: "0", bottom: "0", width: "3px", background: toneRail(level), pointerEvents: "none" });

  const content = document.createElement("div");
  Object.assign(content.style, { display: "block", flex: "1 1 auto", minWidth: "0", color: "var(--text, #FFFFFF)", overflow: "visible", opacity: "1", visibility: "visible" });
  const titleNode = document.createElement("div");
  titleNode.textContent = String(title || "NETSHARE");
  Object.assign(titleNode.style, { display: "block", margin: "0", padding: "0", color: "var(--text, #FFFFFF)", fontSize: "11px", fontWeight: "700", lineHeight: "1.35", letterSpacing: ".02em", whiteSpace: "normal", overflowWrap: "anywhere", opacity: "1", visibility: "visible" });
  content.appendChild(titleNode);
  if (message) {
    const messageNode = document.createElement("div");
    messageNode.textContent = String(message);
    Object.assign(messageNode.style, { display: "block", marginTop: "3px", color: "var(--text-2, rgba(255,255,255,.58))", fontSize: "10.5px", fontWeight: "400", lineHeight: "1.45", whiteSpace: "normal", overflowWrap: "anywhere", opacity: "1", visibility: "visible" });
    content.appendChild(messageNode);
  }
  toast.append(rail, content);

  const normalizedActions = Array.isArray(actions) ? actions.filter(item => item?.label) : [];
  if (actionLabel) normalizedActions.push({label: actionLabel, onAction, kind: "primary"});
  if (normalizedActions.length) {
    const actionHost = document.createElement("div");
    Object.assign(actionHost.style, { display: "flex", flex: "0 0 auto", gap: "6px", alignItems: "center", flexWrap: "wrap", justifyContent: "flex-end" });
    for (const item of normalizedActions.slice(0, 3)) {
      const node = actionButton(item.label, async () => {
        try { if (typeof item.onAction === "function") await item.onAction(); }
        finally { try { toast.remove(); } catch (_) {} }
      }, item.kind || "primary");
      actionHost.appendChild(node);
    }
    toast.appendChild(actionHost);
  }

  const close = document.createElement("button");
  close.type = "button"; close.textContent = "×"; close.setAttribute("aria-label", t("cancel"));
  Object.assign(close.style, { flex: "0 0 44px", width: "44px", height: "44px", padding: "0", border: "0", background: "transparent", color: "var(--text-2, rgba(255,255,255,.58))", fontFamily: "Arial, sans-serif", fontSize: "18px", fontWeight: "400", lineHeight: "44px", textAlign: "center", cursor: "pointer", WebkitAppearance: "none", appearance: "none", opacity: "1", visibility: "visible" });
  close.addEventListener("click", (event) => { event.stopPropagation(); toast.remove(); }, { once: true });
  toast.appendChild(close);
  return toast;
}

function appendWithExpiry(toast, timeoutMs) {
  const host = region(); if (!host) return false; host.appendChild(toast);
  try { void toast.offsetHeight; } catch (_) {}
  globalThis.setTimeout(() => { try { toast.remove(); } catch (_) {} }, timeoutMs);
  return true;
}

export function showToast(level, messageKey, params = {}, titleKey = null) {
  try { return appendWithExpiry(makeToast({level,title:titleKey?t(titleKey):t(messageKey,params),message:titleKey?t(messageKey,params):""}),5500); }
  catch (_) { return false; }
}

export function showActionToast(level, messageKey, params = {}, actionLabelKey = null, onAction = null, titleKey = null, onOpen = null) {
  try {
    const toast = makeToast({level,title:titleKey?t(titleKey):t(messageKey,params),message:titleKey?t(messageKey,params):"",actionLabel:actionLabelKey?t(actionLabelKey):"",onAction,onOpen});
    return appendWithExpiry(toast, 30000);
  } catch (_) { return false; }
}

export function showDecisionToast(level, messageKey, params = {}, actions = [], titleKey = null, onOpen = null) {
  try {
    const mapped = actions.map(item => ({...item, label:item?.labelKey ? t(item.labelKey) : String(item?.label||"")}));
    return appendWithExpiry(makeToast({level,title:titleKey?t(titleKey):t(messageKey,params),message:titleKey?t(messageKey,params):"",actions:mapped,onOpen}),60000);
  } catch (_) { return false; }
}

export function installToastEventHandler() {
  globalThis.addEventListener("netshare:toast.requested", (event) => {
    try { const payload=event?.detail?.payload||{}; if(payload.message_key==="shell.bridge.probe")return; showToast(payload.level||"info",payload.message_key||"netshare_title",payload.params||{}); } catch (_) {}
  });
}
