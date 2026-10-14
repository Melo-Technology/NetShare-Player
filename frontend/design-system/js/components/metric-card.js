import { safeComponentRender } from "../core/diagnostics.js";
import { element, setText } from "../core/dom.js";

export class NSMetricCard extends HTMLElement {
  static get observedAttributes() { return ["label", "value", "unit", "hint"]; }

  connectedCallback() { this.render(); }
  attributeChangedCallback() { if (this.isConnected) this.render(); }

  render() {
    safeComponentRender(this, "MetricCard", () => {
      this.classList.add("ns-card", "ns-metric-card");
      this.setAttribute("data-component", "MetricCard");
      this.replaceChildren();

      const label = element("div", "ns-metric-card__label");
      setText(label, this.getAttribute("label"));

      const value = element("div", "ns-metric-card__value");
      const valueText = element("span", "ns-metric-card__number");
      setText(valueText, this.getAttribute("value"), "—");
      value.append(valueText);

      const unitValue = this.getAttribute("unit");
      if (unitValue) value.append(element("span", "ns-metric-card__unit", unitValue));

      this.append(label, value);
      const hintValue = this.getAttribute("hint");
      if (hintValue) this.append(element("div", "ns-metric-card__hint", hintValue));
    });
  }
}

export function defineMetricCard() {
  if (!customElements.get("ns-metric-card")) customElements.define("ns-metric-card", NSMetricCard);
}
