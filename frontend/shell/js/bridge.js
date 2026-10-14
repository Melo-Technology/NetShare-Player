const READY_EVENT = "pywebviewready";
const BACKEND_EVENT = "netshare:backend-event";

function dispatchSafely(name, detail) {
  try {
    globalThis.dispatchEvent(new CustomEvent(name, { detail }));
    return true;
  } catch (_) {
    return false;
  }
}

function normalizeBackendEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) return null;
  if (typeof event.name !== "string" || !event.name) return null;
  if (typeof event.correlation_id !== "string") return null;
  return event;
}

export function installBackendEventReceiver() {
  const receiver = Object.freeze({
    receiveBackendEvent(event) {
      try {
        const normalized = normalizeBackendEvent(event);
        if (!normalized) return false;
        dispatchSafely(BACKEND_EVENT, normalized);
        dispatchSafely(`netshare:${normalized.name}`, normalized);
        return true;
      } catch (_) {
        return false;
      }
    },
  });
  globalThis.NetShareShell = receiver;
  return receiver;
}

export function waitForPyWebView(timeoutMs = 10000) {
  if (globalThis.pywebview?.api) return Promise.resolve(globalThis.pywebview.api);

  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = globalThis.setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("PyWebView bridge was not ready before timeout"));
    }, timeoutMs);

    globalThis.addEventListener(
      READY_EVENT,
      () => {
        if (settled) return;
        settled = true;
        globalThis.clearTimeout(timeout);
        if (globalThis.pywebview?.api) resolve(globalThis.pywebview.api);
        else reject(new Error("PyWebView API is unavailable"));
      },
      { once: true },
    );
  });
}

export async function pingBridge() {
  const api = await waitForPyWebView();
  return api.ping();
}

export async function notifyFrontendReady(correlationId = null) {
  const api = await waitForPyWebView();
  return api.frontend_ready(correlationId);
}

export async function probeEventBridge(correlationId) {
  const api = await waitForPyWebView();
  return api.probe_event(correlationId || null);
}

export async function callDesktopApi(method, params = {}, correlationId = null) {
  const api = await waitForPyWebView();
  return api.call_api(method, params, correlationId);
}

export async function chooseSaveFile(suggestedName = "netshare-logs.txt", correlationId = null) {
  const api = await waitForPyWebView();
  return api.choose_save_file(suggestedName, correlationId);
}

export async function chooseFolder(correlationId = null) {
  const api = await waitForPyWebView();
  return api.choose_folder(correlationId);
}

export async function chooseFile(correlationId = null) {
  const api = await waitForPyWebView();
  return api.choose_file(correlationId);
}

export async function openExternalUrl(url, correlationId = null) {
  const api = await waitForPyWebView();
  return api.open_external_url(url, correlationId);
}

export { BACKEND_EVENT };
