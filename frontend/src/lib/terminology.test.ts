import { describe, it, expect } from "vitest";

import { ALERT_ACTIONS, ALERT_STATUS, NAV_AREAS } from "./terminology";

describe("terminology", () => {
  it("uses effect-based action labels from the glossary", () => {
    expect(ALERT_ACTIONS.allow.label).toBe("Allow");
    expect(ALERT_ACTIONS.mute.label).toBe("Mute");
    expect(ALERT_ACTIONS.revokeRule.label).toBe("Revoke rule");
  });

  it("never uses the old accept/dismiss wording in labels", () => {
    const labels = Object.values(ALERT_ACTIONS).map((a) =>
      a.label.toLowerCase(),
    );
    expect(labels).not.toContain("accept");
    expect(labels).not.toContain("dismiss");
  });

  it("states the consequence for allow and mute", () => {
    expect(ALERT_ACTIONS.allow.description).toContain("never alert again");
    expect(ALERT_ACTIONS.mute.description).toContain("next scan");
  });

  it("defines the three status labels", () => {
    expect(ALERT_STATUS.open.label).toBe("Open");
    expect(ALERT_STATUS.muted.label).toBe("Muted");
    expect(ALERT_STATUS.allowed.label).toBe("Allowed");
  });

  it("defines the three navigation areas", () => {
    expect(Object.values(NAV_AREAS)).toEqual([
      "Monitor",
      "Configuration",
      "Administration",
    ]);
  });
});
