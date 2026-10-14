import { safeComponentRender } from "../core/diagnostics.js";

export class NSCard extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "Card", () => {
      this.classList.add("ns-card");
      this.setAttribute("data-component", "Card");
    });
  }
}

export function defineCard() {
  if (!customElements.get("ns-card")) customElements.define("ns-card", NSCard);
}
