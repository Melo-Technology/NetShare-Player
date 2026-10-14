export function text(value, fallback = "") {
  return value == null ? fallback : String(value);
}

export function setText(element, value, fallback = "") {
  element.textContent = text(value, fallback);
  return element;
}

export function element(tagName, className, textContent) {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  if (textContent !== undefined) node.textContent = text(textContent);
  return node;
}

export function ensureElementId(element, prefix = "ns") {
  if (element.id) return element.id;
  const randomPart = globalThis.crypto?.randomUUID?.() || Math.random().toString(36).slice(2);
  element.id = `${prefix}-${randomPart}`;
  return element.id;
}
