function element(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

export function choiceDialog({ title, message, actions }) {
  return new Promise((resolve) => {
    const host = document.getElementById("dialog-host") || document.body;
    const dialog = document.createElement("ns-dialog");
    const header = element("div", "ns-dialog__header");
    const heading = element("h2", "ns-dialog__title", title);
    header.appendChild(heading);
    const body = element("div", "ns-dialog__body", message);
    const footer = element("div", "ns-dialog__footer");
    for (const action of actions) {
      const button = element("button", `ns-button ${action.kind === "danger" ? "ns-button--danger" : action.kind === "primary" ? "ns-button--primary" : ""}`, action.label);
      button.type = "button";
      button.addEventListener("click", () => dialog.close(action.value), { once: true });
      footer.appendChild(button);
    }
    dialog.append(header, body, footer);
    dialog.addEventListener("close", (event) => {
      const value = event?.detail?.returnValue ?? "cancel";
      try { dialog.remove(); } catch (_) {}
      resolve(value);
    }, { once: true });
    host.appendChild(dialog);
    dialog.showModal();
  });
}

export function passwordDialog({ title, message, label, saveLabel, cancelLabel }) {
  return new Promise((resolve) => {
    const host = document.getElementById("dialog-host") || document.body;
    const dialog = document.createElement("ns-dialog");
    const header = element("div", "ns-dialog__header");
    header.appendChild(element("h2", "ns-dialog__title", title));
    const body = element("div", "ns-dialog__body");
    if (message) body.appendChild(element("div", "ns-muted", message));
    const field = element("label", "ns-form-field");
    field.appendChild(element("span", "ns-form-field__label", label));
    const input = element("input", "ns-input");
    input.type = "password";
    input.autocomplete = "new-password";
    field.appendChild(input);
    body.appendChild(field);
    const footer = element("div", "ns-dialog__footer");
    const cancel = element("button", "ns-button", cancelLabel);
    cancel.type = "button";
    cancel.addEventListener("click", () => dialog.close("cancel"), { once: true });
    const save = element("button", "ns-button ns-button--primary", saveLabel);
    save.type = "button";
    save.addEventListener("click", () => {
      dialog._passwordValue = input.value;
      dialog.close("save");
    }, { once: true });
    footer.append(cancel, save);
    dialog.append(header, body, footer);
    dialog.addEventListener("close", (event) => {
      const accepted = event?.detail?.returnValue === "save";
      const value = accepted ? String(dialog._passwordValue || "") : null;
      try { dialog.remove(); } catch (_) {}
      resolve(value);
    }, { once: true });
    host.appendChild(dialog);
    dialog.showModal();
    globalThis.setTimeout(() => input.focus(), 0);
  });
}

export function qrDialog({ title, value, dataUrl, closeLabel = "" }) {
  return new Promise((resolve) => {
    const host = document.getElementById("dialog-host") || document.body;
    const dialog = document.createElement("ns-dialog");
    const header = element("div", "ns-dialog__header");
    header.appendChild(element("h2", "ns-dialog__title", title));
    const body = element("div", "ns-dialog__body ns-dialog__body--centered");
    if (dataUrl) {
      const image = document.createElement("img");
      image.className = "ns-dialog__qr-image";
      image.src = dataUrl;
      image.alt = title;
      image.width = 220;
      image.height = 220;
      body.appendChild(image);
    }
    if (value) body.appendChild(element("div", "ns-dialog__qr-value", value));
    const footer = element("div", "ns-dialog__footer");
    const close = element("button", "ns-button", closeLabel);
    close.type = "button";
    close.addEventListener("click", () => dialog.close("close"), { once: true });
    footer.appendChild(close);
    dialog.append(header, body, footer);
    dialog.addEventListener("close", () => {
      try { dialog.remove(); } catch (_) {}
      resolve();
    }, { once: true });
    host.appendChild(dialog);
    dialog.showModal();
  });
}

export function editablePasswordDialog({
  title,
  message = "",
  currentPassword = "",
  passwordLabel,
  confirmLabel,
  showLabel,
  hideLabel,
  saveLabel,
  cancelLabel,
  tooShortMessage,
  mismatchMessage,
  saveErrorMessage,
  savedMessage,
  onSave,
}) {
  return new Promise((resolve) => {
    const host = document.getElementById("dialog-host") || document.body;
    const dialog = document.createElement("ns-dialog");
    const header = element("div", "ns-dialog__header");
    header.appendChild(element("h2", "ns-dialog__title", title));
    const body = element("div", "ns-dialog__body");
    if (message) body.appendChild(element("div", "ns-muted", message));

    const field = element("label", "ns-form-field");
    field.appendChild(element("span", "ns-form-field__label", passwordLabel));
    const row = element("div", "ns-password-dialog__row");
    const input = element("input", "ns-input");
    input.type = "password";
    input.autocomplete = "new-password";
    input.value = String(currentPassword || "");
    const visibility = element("button", "ns-button ns-button--compact", showLabel);
    visibility.type = "button";
    row.append(input, visibility);
    field.appendChild(row);

    const confirmField = element("label", "ns-form-field");
    confirmField.appendChild(element("span", "ns-form-field__label", confirmLabel));
    const confirm = element("input", "ns-input");
    confirm.type = "password";
    confirm.autocomplete = "new-password";
    confirm.value = String(currentPassword || "");
    confirmField.appendChild(confirm);

    const feedback = element("div", "ns-dialog__feedback");
    feedback.setAttribute("role", "status");
    feedback.setAttribute("aria-live", "polite");
    body.append(field, confirmField, feedback);

    visibility.addEventListener("click", () => {
      const reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      confirm.type = reveal ? "text" : "password";
      visibility.textContent = reveal ? hideLabel : showLabel;
      input.focus();
    });

    const footer = element("div", "ns-dialog__footer");
    const cancel = element("button", "ns-button", cancelLabel);
    cancel.type = "button";
    cancel.addEventListener("click", () => dialog.close("cancel"), { once: true });
    const save = element("button", "ns-button ns-button--primary", saveLabel);
    save.type = "button";
    save.addEventListener("click", async () => {
      const value = String(input.value || "");
      feedback.textContent = "";
      feedback.classList.remove("ns-dialog__feedback--success");
      if (value && value.length < 8) {
        feedback.textContent = tooShortMessage;
        input.focus();
        return;
      }
      if (value !== String(confirm.value || "")) {
        feedback.textContent = mismatchMessage;
        confirm.focus();
        return;
      }
      save.disabled = true;
      cancel.disabled = true;
      visibility.disabled = true;
      try {
        const outcome = await onSave(value);
        if (outcome?.ok === false) {
          feedback.textContent = String(outcome.error || saveErrorMessage || "");
          return;
        }
        feedback.classList.add("ns-dialog__feedback--success");
        feedback.textContent = String(outcome?.message || savedMessage || "");
        globalThis.setTimeout(() => dialog.close("save"), 350);
      } catch (error) {
        feedback.textContent = String(error?.message || saveErrorMessage || "");
      } finally {
        if (dialog.isConnected) {
          save.disabled = false;
          cancel.disabled = false;
          visibility.disabled = false;
        }
      }
    });
    footer.append(cancel, save);
    dialog.append(header, body, footer);
    dialog.addEventListener("close", (event) => {
      const accepted = event?.detail?.returnValue === "save";
      // Avoid keeping the plaintext secret attached to a hidden DOM tree.
      input.value = "";
      confirm.value = "";
      try { dialog.remove(); } catch (_) {}
      resolve(accepted);
    }, { once: true });
    host.appendChild(dialog);
    dialog.showModal();
    globalThis.setTimeout(() => input.focus(), 0);
  });
}
