import { safeComponentRender } from "../core/diagnostics.js";

const TONES = new Set(["neutral", "success", "info", "warning", "danger"]);

export class NSStatusBadge extends HTMLElement {
  static get observedAttributes() { return ["tone"]; }

  connectedCallback() { this.render(); }
  attributeChangedCallback() { if (this.isConnected) this.render(); }

  render() {
    safeComponentRender(this, "StatusBadge", () => {
      this.classList.add("ns-status-badge");
      this.setAttribute("data-component", "StatusBadge");
      const tone = this.getAttribute("tone") || "neutral";
      this.dataset.tone = TONES.has(tone) ? tone : "neutral";
    });
  }
}

export function defineStatusBadge() {
  if (!customElements.get("ns-status-badge")) customElements.define("ns-status-badge", NSStatusBadge);
}
