import { describe, it, expect } from "vitest";

import { hasRole } from "./roles";

describe("hasRole", () => {
  it("allows equal role", () => {
    expect(hasRole("operator", "operator")).toBe(true);
  });

  it("allows higher role", () => {
    expect(hasRole("admin", "viewer")).toBe(true);
    expect(hasRole("operator", "analyst")).toBe(true);
  });

  it("rejects lower role", () => {
    expect(hasRole("viewer", "analyst")).toBe(false);
    expect(hasRole("analyst", "operator")).toBe(false);
    expect(hasRole("operator", "admin")).toBe(false);
  });

  it("rejects undefined role", () => {
    expect(hasRole(undefined, "viewer")).toBe(false);
  });
});
