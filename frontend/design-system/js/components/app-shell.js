import { safeComponentRender } from "../core/diagnostics.js";

export class NSAppShell extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "AppShell", () => {
      this.classList.add("ns-app-shell");
      this.setAttribute("data-component", "AppShell");
    });
  }
}

export function defineAppShell() {
  if (!customElements.get("ns-app-shell")) customElements.define("ns-app-shell", NSAppShell);
}
