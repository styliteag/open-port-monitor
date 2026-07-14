import { describe, it, expect, vi, afterEach } from "vitest";
import { renderHook } from "@testing-library/react";

import {
  isEditableTarget,
  useKeyboardShortcuts,
} from "./useKeyboardShortcuts";

function pressKey(
  key: string,
  options: KeyboardEventInit = {},
  target: HTMLElement | Window = window,
) {
  const event = new KeyboardEvent("keydown", {
    key,
    bubbles: true,
    cancelable: true,
    ...options,
  });
  target.dispatchEvent(event);
  return event;
}

afterEach(() => {
  document.body.innerHTML = "";
});

describe("useKeyboardShortcuts", () => {
  it("fires the handler for a matching key", () => {
    const handler = vi.fn();
    renderHook(() => useKeyboardShortcuts([{ key: "j", handler }]));

    pressKey("j");
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("matches case-insensitively", () => {
    const handler = vi.fn();
    renderHook(() => useKeyboardShortcuts([{ key: "a", handler }]));

    pressKey("A");
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("ignores keys with modifiers held", () => {
    const handler = vi.fn();
    renderHook(() => useKeyboardShortcuts([{ key: "a", handler }]));

    pressKey("a", { ctrlKey: true });
    pressKey("a", { metaKey: true });
    pressKey("a", { altKey: true });
    expect(handler).not.toHaveBeenCalled();
  });

  it("ignores non-matching keys", () => {
    const handler = vi.fn();
    renderHook(() => useKeyboardShortcuts([{ key: "a", handler }]));

    pressKey("b");
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not fire while typing in an input", () => {
    const handler = vi.fn();
    renderHook(() => useKeyboardShortcuts([{ key: "a", handler }]));

    const input = document.createElement("input");
    document.body.appendChild(input);
    pressKey("a", {}, input);
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not fire inside a dialog", () => {
    const handler = vi.fn();
    renderHook(() => useKeyboardShortcuts([{ key: "a", handler }]));

    const dialog = document.createElement("div");
    dialog.setAttribute("role", "dialog");
    const button = document.createElement("button");
    dialog.appendChild(button);
    document.body.appendChild(dialog);
    pressKey("a", {}, button);
    expect(handler).not.toHaveBeenCalled();
  });

  it("does nothing when disabled", () => {
    const handler = vi.fn();
    renderHook(() => useKeyboardShortcuts([{ key: "a", handler }], false));

    pressKey("a");
    expect(handler).not.toHaveBeenCalled();
  });

  it("removes the listener on unmount", () => {
    const handler = vi.fn();
    const { unmount } = renderHook(() =>
      useKeyboardShortcuts([{ key: "a", handler }]),
    );

    unmount();
    pressKey("a");
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("isEditableTarget", () => {
  it("detects inputs, textareas, and selects", () => {
    for (const tag of ["input", "textarea", "select"]) {
      const el = document.createElement(tag);
      document.body.appendChild(el);
      expect(isEditableTarget(el)).toBe(true);
    }
  });

  it("detects elements inside menus", () => {
    const menu = document.createElement("div");
    menu.setAttribute("role", "menu");
    const item = document.createElement("span");
    menu.appendChild(item);
    document.body.appendChild(menu);
    expect(isEditableTarget(item)).toBe(true);
  });

  it("returns false for plain elements", () => {
    const div = document.createElement("div");
    document.body.appendChild(div);
    expect(isEditableTarget(div)).toBe(false);
  });
});
