/**
 * Dependency-free diagnostics for visual components.
 *
 * This module intentionally has no backend event dependency. Components only emit a local
 * DOM CustomEvent so the future shell may observe failures without coupling the visual layer
 * to backend infrastructure.
 */
export function reportDesignSystemError(component, operation, error) {
  const detail = Object.freeze({
    component: String(component || "unknown"),
    operation: String(operation || "render"),
    errorName: error instanceof Error ? error.name : "Error",
  });

  try {
    globalThis.dispatchEvent?.(new CustomEvent("netshare:design-system-error", { detail }));
  } catch (_) {
    // Diagnostics must never become the source of a component crash.
  }

  try {
    globalThis.console?.error?.("[NetShare Design System]", detail, error);
  } catch (_) {
    // Crash containment wins over diagnostics.
  }
}

export function safeComponentRender(element, component, renderer) {
  try {
    renderer();
    element.removeAttribute("data-ns-component-error");
    return true;
  } catch (error) {
    try {
      element.setAttribute("data-ns-component-error", "true");
    } catch (_) {
      // Nothing else to do if even the host element is unavailable.
    }
    reportDesignSystemError(component, "render", error);
    return false;
  }
}
