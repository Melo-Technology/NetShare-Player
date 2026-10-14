import { safeComponentRender } from "../core/diagnostics.js";
import { element, ensureElementId } from "../core/dom.js";

export class NSDialog extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "Dialog", () => {
      if (this._overlay) return;
      this.setAttribute("data-component", "Dialog");

      const preserved = Array.from(this.childNodes);
      const overlay = element("div", "ns-dialog-overlay");
      overlay.hidden = true;
      const panel = element("div", "ns-dialog-panel");
      panel.setAttribute("role", "dialog");
      panel.setAttribute("aria-modal", "true");
      panel.tabIndex = -1;
      panel.append(...preserved);
      overlay.append(panel);
      this.replaceChildren(overlay);

      const labelledBy = this.getAttribute("aria-labelledby");
      if (labelledBy) panel.setAttribute("aria-labelledby", labelledBy);
      const describedBy = this.getAttribute("aria-describedby");
      if (describedBy) panel.setAttribute("aria-describedby", describedBy);

      this._overlay = overlay;
      this._panel = panel;
      this._onKeyDown = (event) => {
        if (event.key === "Escape" && this.hasAttribute("open")) this.close("escape");
      };
      document.addEventListener("keydown", this._onKeyDown);
    });
  }

  disconnectedCallback() {
    if (this._onKeyDown) document.removeEventListener("keydown", this._onKeyDown);
  }

  showModal() {
    safeComponentRender(this, "Dialog", () => {
      if (!this._overlay || !this._panel) throw new Error("Dialog is not connected");
      if (this.hasAttribute("open")) return;
      this._previousFocus = document.activeElement;
      this._overlay.hidden = false;
      this.setAttribute("open", "");
      const target = this._panel.querySelector("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
      (target || this._panel).focus({ preventScroll: true });
    });
  }

  close(returnValue = "") {
    safeComponentRender(this, "Dialog", () => {
      if (!this._overlay) throw new Error("Dialog is not connected");
      if (!this.hasAttribute("open")) return;
      this.returnValue = String(returnValue);
      this.removeAttribute("open");
      this._overlay.hidden = true;
      if (this._previousFocus?.focus) this._previousFocus.focus({ preventScroll: true });
      this.dispatchEvent(new CustomEvent("close", { detail: { returnValue: this.returnValue } }));
    });
  }
}

export function dialogTitle(value) {
  const title = element("h2", "ns-dialog__title", value);
  ensureElementId(title, "ns-dialog-title");
  return title;
}

export function defineDialog() {
  if (!customElements.get("ns-dialog")) customElements.define("ns-dialog", NSDialog);
}
