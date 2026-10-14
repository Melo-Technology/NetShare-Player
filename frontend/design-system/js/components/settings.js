import { safeComponentRender } from "../core/diagnostics.js";

export class NSSettingsCategory extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "SettingsCategory", () => {
      this.classList.add("ns-settings-category");
      this.setAttribute("data-component", "SettingsCategory");
    });
  }
}

export class NSSettingsSection extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "SettingsSection", () => {
      this.classList.add("ns-settings-section");
      this.setAttribute("data-component", "SettingsSection");
    });
  }
}

export function defineSettingsComponents() {
  if (!customElements.get("ns-settings-category")) customElements.define("ns-settings-category", NSSettingsCategory);
  if (!customElements.get("ns-settings-section")) customElements.define("ns-settings-section", NSSettingsSection);
}
