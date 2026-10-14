import { safeComponentRender } from "../core/diagnostics.js";

export class NSSidebar extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "Sidebar", () => {
      this.classList.add("ns-sidebar");
      this.setAttribute("data-component", "Sidebar");
    });
  }
}

export function defineSidebar() {
  if (!customElements.get("ns-sidebar")) customElements.define("ns-sidebar", NSSidebar);
}
