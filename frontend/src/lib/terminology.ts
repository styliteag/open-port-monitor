/**
 * UI v3 terminology — single source of truth for user-facing alert wording.
 *
 * Mirrors docs/redesign/glossary.md. UI labels are effect-based (Allow/Mute);
 * API and DB names (accept/dismiss) are unchanged — the mapping lives in the
 * glossary and must not leak into UI copy.
 */

export interface TermEntry {
  label: string;
  description: string;
}

export const ALERT_STATUS: Record<"open" | "muted" | "allowed", TermEntry> = {
  open: {
    label: "Open",
    description: "Needs a decision.",
  },
  muted: {
    label: "Muted",
    description: "Muted until the next scan finds it again.",
  },
  allowed: {
    label: "Allowed",
    description: "Covered by an allow rule.",
  },
};

export type AlertStatusKey = keyof typeof ALERT_STATUS;

export const ALERT_ACTIONS: Record<
  "allow" | "mute" | "assign" | "reopen" | "revokeRule",
  TermEntry
> = {
  allow: {
    label: "Allow",
    description:
      "Creates a rule: this port is expected here; it will never alert again.",
  },
  mute: {
    label: "Mute",
    description: "Hides this alert; the next scan will raise it again.",
  },
  assign: {
    label: "Assign",
    description: "A colleague takes ownership.",
  },
  reopen: {
    label: "Reopen",
    description: "Back to Open. Any existing allow rule stays in effect.",
  },
  revokeRule: {
    label: "Revoke rule",
    description: "Deletes the allow rule; future scans alert again.",
  },
};

export type AlertActionKey = keyof typeof ALERT_ACTIONS;

export const NAV_AREAS: Record<
  "monitor" | "configuration" | "administration",
  string
> = {
  monitor: "Monitor",
  configuration: "Configuration",
  administration: "Administration",
};
