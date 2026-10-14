import { safeComponentRender } from "../core/diagnostics.js";

export class NSHeader extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "Header", () => {
      this.classList.add("ns-header");
      this.setAttribute("data-component", "Header");
    });
  }
}

export function defineHeader() {
  if (!customElements.get("ns-header")) customElements.define("ns-header", NSHeader);
}
