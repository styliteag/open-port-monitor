# ADR 0003: Alert triage becomes an inbox with effect-based action names

- Status: accepted
- Date: 2026-07-14
- Deciders: Wim Bonis

## Context

Alert triage is the single most frequent job in the UI. Today it is a filter-heavy table
(341-line filter component) with modal dialogs, and the state vocabulary confuses every
user: *dismiss* means "hide it, but the next scan raises it again", *accept* means "a
port rule is created and it never alerts again" — the crucial difference is documented
only in AGENTS.md, not in the UI. "Blocked" is not even a state, just a severity filter.

## Decision

1. **Inbox layout**: split view — alert list left, full detail right (host, port,
   history, evidence, matching rules). Keyboard shortcuts drive triage: j/k navigate,
   A allow, M mute, S assign, Enter opens the host. Zero-inbox is the working model.
2. **Effect-based action names** (UI copy only; API and DB fields keep their names):
   - **Allow** (was Accept) — "creates a rule: this port is expected here; it will never
     alert again."
   - **Mute** (was Dismiss) — "hides this alert; the next scan will raise it again."
   - Assign / Resolve / Reopen keep their meanings.
   - The "Blocked" pseudo-status is removed; it becomes a plain severity filter.
   - Every action button carries a one-line consequence subtitle.
3. **Filters shrink** to: status (Open / Muted / Allowed), severity, network, source.

## Consequences

- The UI-label ↔ API-field mapping (Allow ↔ `accept`/port rule, Mute ↔ `dismissed=true`)
  must be documented in the glossary and `docs/alert-states.md`, and frontend code uses a
  single terminology module so labels never drift per page.
- No backend changes; endpoints (`PUT /alerts/{id}/dismiss`, `bulk-accept-global`, …)
  keep their names.
- Keyboard/split-view infrastructure is built in the first phase so it gets the longest
  beta soak.
