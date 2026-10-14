const NOISY_STRUCTURED_EVENTS = new Set([
  "service.initialized",
  "service.called",
  "service.completed",
  "desktop_api.called",
  "desktop_api.completed",
  "event.published",
  "event.delivered",
  "metrics.collected",
  "toast.published",
  "shell.bridge.initialized",
  "shell.bridge.called",
  "shell.bridge.completed",
  "shell.event.forwarded",
]);
const IMPORTANT_STRUCTURED_EVENTS = new Set([
  "settings.updated",
  "settings.validation_failed",
  "desktop_api.error",
  "service.failed",
  "event.delivery_failed",
  "event.queue_full",
  "event.dropped",
  "migration.fallback_used",
]);


function normalizedKind(value, status = "") {
  const raw = String(value || "info").toLowerCase();
  const state = String(status || "").toLowerCase();
  if (["error", "critical", "danger"].includes(raw) || ["error", "failed", "failure"].includes(state)) return "error";
  if (["warning", "warn"].includes(raw)) return "warning";
  if (["success", "ok"].includes(raw) || state === "success") return "success";
  return "info";
}

function structuredMessage(payload) {
  const component = String(payload.component || "APP");
  const event = String(payload.event || "event");
  const operation = String(payload.operation || "").trim();
  const status = String(payload.status || "").trim();
  const code = String(payload.error_code || payload.reason || "").trim();
  const settings = Array.isArray(payload.settings) ? payload.settings.filter(Boolean).join(", ") : "";

  if (event === "settings.updated") {
    return [component, operation || event, settings].filter(Boolean).join(" · ");
  }
  if (event === "settings.validation_failed") {
    return [component, operation || event, code || "validation"].filter(Boolean).join(" · ");
  }
  if (event === "desktop_api.error" || event === "service.failed") {
    return [component, operation || event, code || status || "failed"].filter(Boolean).join(" · ");
  }
  if (["event.delivery_failed", "event.queue_full", "event.dropped"].includes(event)) {
    return [component, event, payload.event_name || code].filter(Boolean).join(" · ");
  }
  return [component, operation || event, code || status].filter(Boolean).join(" · ");
}

export function normalizeLogEntry(entry) {
  const raw = String(entry?.message || "").trim();
  if (!raw) return null;
  const fallbackKind = normalizedKind(entry?.kind);

  if (!raw.startsWith("APP ")) {
    return {
      ...entry,
      message: raw,
      kind: fallbackKind,
      important: true,
      structured: false,
    };
  }

  let payload;
  try { payload = JSON.parse(raw.slice(4)); }
  catch (_) {
    return { ...entry, message: raw, kind: fallbackKind, important: true, structured: false };
  }

  const level = String(payload.level || entry?.kind || "info").toLowerCase();
  const status = String(payload.status || "").toLowerCase();
  const kind = normalizedKind(level, status);
  const event = String(payload.event || "");
  const important = kind === "error" || kind === "warning" || IMPORTANT_STRUCTURED_EVENTS.has(event) || event.endsWith(".failed") || event.endsWith(".error") || event.endsWith(".dropped");
  if (!important) return null;

  return {
    ...entry,
    message: structuredMessage(payload),
    kind,
    important: true,
    structured: true,
    event,
    component: String(payload.component || ""),
    operation: String(payload.operation || ""),
    correlation_id: String(payload.correlation_id || ""),
  };
}

export function importantLogs(entries, limit = null) {
  const normalized = (Array.isArray(entries) ? entries : []).map(normalizeLogEntry).filter(Boolean);
  return Number.isFinite(limit) && limit >= 0 ? normalized.slice(-limit) : normalized;
}

export function normalizeWriteActivity(entry) {
  if (!entry) return null;
  const action = String(entry.action || "write").toUpperCase();
  const path = String(entry.path || "").trim();
  const client = String(entry.client || "").trim();
  return {
    ...entry,
    message: [action, path || "—", client].filter(Boolean).join(" · "),
    kind: action.includes("ERROR") || action.includes("REJECT") ? "error" : "success",
    important: true,
    structured: false,
  };
}

function activityEntryKey(entry, stream) {
  const item = entry || {};
  return [
    stream,
    Number(item.time || 0),
    String(item.kind || ""),
    String(item.message || ""),
    String(item.action || ""),
    String(item.path || ""),
    String(item.request_id || ""),
  ].join("\u001f");
}

function mergeActivityEntries(previous, incoming, stream, capacity) {
  const merged = new Map();
  for (const item of [...(Array.isArray(previous) ? previous : []), ...(Array.isArray(incoming) ? incoming : [])]) {
    if (!item) continue;
    merged.set(activityEntryKey(item, stream), item);
  }
  return [...merged.values()]
    .sort((a, b) => Number(a?.time || 0) - Number(b?.time || 0))
    .slice(-capacity);
}

export function mergeActivitySnapshot(previous, incoming) {
  if (!incoming) return previous || null;
  if (!previous) return incoming;
  const capacity = Math.max(1, Number(incoming.capacity || previous.capacity || 1000));
  return {
    ...previous,
    ...incoming,
    logs: mergeActivityEntries(previous.logs, incoming.logs, "log", capacity),
    write_activity: mergeActivityEntries(previous.write_activity, incoming.write_activity, "write", capacity),
    transfers: mergeTransfers(previous.transfers, incoming.transfers, capacity),
  };
}

function mergeTransfers(previous, incoming, capacity) {
  const merged = new Map();
  for (const item of [...(Array.isArray(previous) ? previous : []), ...(Array.isArray(incoming) ? incoming : [])]) {
    if (!item?.id) continue;
    const key = String(item.id);
    merged.set(key, { ...(merged.get(key) || {}), ...item });
  }
  return [...merged.values()]
    .sort((a, b) => Number(a?.time || 0) - Number(b?.time || 0))
    .slice(-capacity);
}
