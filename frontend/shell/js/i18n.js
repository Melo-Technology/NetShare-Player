import { I18N_CATALOG } from "../../i18n/catalog.js";

let current = "en";

function normalizeLanguage(value) {
  const raw = String(value || "").toLowerCase().replace("_", "-");
  if (!raw || raw === "system") {
    const browser = String(globalThis.navigator?.language || "en").toLowerCase();
    const short = browser.split("-")[0];
    return I18N_CATALOG.translations[short] ? short : "en";
  }
  const short = raw.split("-")[0];
  return I18N_CATALOG.translations[raw] ? raw : (I18N_CATALOG.translations[short] ? short : "en");
}

export function setUiLanguage(value) {
  current = normalizeLanguage(value);
  try { document.documentElement.lang = current; } catch (_) {}
  return current;
}

export function getUiLanguage() { return current; }

export function languages() { return { ...I18N_CATALOG.languages }; }

export function t(key, params = {}) {
  const catalog = I18N_CATALOG.translations[current] || I18N_CATALOG.translations.en || {};
  const fallback = I18N_CATALOG.translations.en || {};
  let value = catalog[key] ?? fallback[key] ?? String(key);
  for (const [name, replacement] of Object.entries(params || {})) {
    value = value.replaceAll(`{${name}}`, String(replacement));
  }
  return value;
}
