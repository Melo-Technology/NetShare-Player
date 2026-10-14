import { safeComponentRender } from "../core/diagnostics.js";
import { element } from "../core/dom.js";

const TONES = new Set(["info", "success", "warning", "danger"]);

export class NSToast extends HTMLElement {
  static get observedAttributes() { return ["tone", "title", "message", "dismiss-label", "action-label"]; }

  connectedCallback() { this.render(); }
  attributeChangedCallback() { if (this.isConnected) this.render(); }

  render() {
    safeComponentRender(this, "Toast", () => {
      this.classList.add("ns-toast");
      this.setAttribute("data-component", "Toast");
      this.setAttribute("role", this.getAttribute("tone") === "danger" ? "alert" : "status");
      const tone = this.getAttribute("tone") || "info";
      this.dataset.tone = TONES.has(tone) ? tone : "info";
      this.replaceChildren();

      const rail = element("div", "ns-toast__rail");
      rail.setAttribute("aria-hidden", "true");
      const content = element("div", "ns-toast__content");
      content.append(element("div", "ns-toast__title", this.getAttribute("title") || ""));
      const message = this.getAttribute("message");
      if (message) content.append(element("div", "ns-toast__message", message));

      const actionLabel = this.getAttribute("action-label");
      let action = null;
      if (actionLabel) {
        action = element("button", "ns-toast__action", actionLabel);
        action.type = "button";
        action.addEventListener("click", () => {
          this.dispatchEvent(new CustomEvent("ns-toast-action", { bubbles: true }));
        });
      }

      const close = element("button", "ns-toast__close", "×");
      close.type = "button";
      close.setAttribute("aria-label", this.getAttribute("dismiss-label") || "Dismiss");
      close.addEventListener("click", () => this.remove(), { once: true });
      this.append(rail, content);
      if (action) this.appendChild(action);
      this.appendChild(close);
    });
  }
}

export class NSToastRegion extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "ToastRegion", () => {
      this.classList.add("ns-toast-region");
      this.setAttribute("data-component", "ToastRegion");
      this.setAttribute("aria-live", "polite");
      this.setAttribute("aria-relevant", "additions");
    });
  }
}

export function defineToast() {
  if (!customElements.get("ns-toast")) customElements.define("ns-toast", NSToast);
  if (!customElements.get("ns-toast-region")) customElements.define("ns-toast-region", NSToastRegion);
}
