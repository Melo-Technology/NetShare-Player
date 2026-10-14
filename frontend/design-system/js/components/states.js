import { safeComponentRender } from "../core/diagnostics.js";
import { element } from "../core/dom.js";

class NSStateBase extends HTMLElement {
  build(componentName, marker) {
    safeComponentRender(this, componentName, () => {
      this.classList.add("ns-state");
      this.setAttribute("data-component", componentName);
      const title = this.getAttribute("title") || "";
      const message = this.getAttribute("message") || "";
      const preservedActions = Array.from(this.querySelectorAll("[data-state-action]"));
      this.replaceChildren();

      const content = element("div", "ns-state__content");
      const mark = element("div", "ns-state__mark", marker);
      mark.setAttribute("aria-hidden", "true");
      content.append(mark, element("h3", "ns-state__title", title));
      if (message) content.append(element("p", "ns-state__message", message));
      if (preservedActions.length) {
        const actions = element("div", "ns-state__actions");
        actions.append(...preservedActions);
        content.append(actions);
      }
      this.append(content);
    });
  }
}

export class NSLoadingState extends HTMLElement {
  connectedCallback() {
    safeComponentRender(this, "LoadingState", () => {
      this.classList.add("ns-state", "ns-loading-state");
      this.setAttribute("data-component", "LoadingState");
      this.setAttribute("aria-busy", "true");
      this.replaceChildren(element("div", "ns-loading-state__bar"));
    });
  }
}

export class NSEmptyState extends NSStateBase {
  connectedCallback() { this.classList.add("ns-empty-state"); this.build("EmptyState", "· · ·"); }
}

export class NSErrorState extends NSStateBase {
  connectedCallback() { this.classList.add("ns-error-state"); this.build("ErrorState", "!"); }
}

export function defineStates() {
  if (!customElements.get("ns-loading-state")) customElements.define("ns-loading-state", NSLoadingState);
  if (!customElements.get("ns-empty-state")) customElements.define("ns-empty-state", NSEmptyState);
  if (!customElements.get("ns-error-state")) customElements.define("ns-error-state", NSErrorState);
}
