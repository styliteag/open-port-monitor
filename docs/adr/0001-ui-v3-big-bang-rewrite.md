# ADR 0001: UI v3 is a big-bang rewrite on a dedicated branch

- Status: accepted
- Date: 2026-07-14
- Deciders: Wim Bonis

## Context

Users (internal technical team and management) describe the WebUI as cluttered and hard to
use. All four pain classes were confirmed: scattered navigation (16 items in 4 groups),
overloaded pages, unexplained domain jargon, and an 806-line network form exposing every
scan option at once. The scope decision was explicitly "rebuild everything" rather than
incremental fixes. There is no deadline pressure.

Alternatives considered: incremental page-by-page replacement on `main` (house default,
lowest risk), and a parallel new UI behind a per-user switch (double maintenance).

## Decision

Rebuild the entire frontend as **UI v3** on a long-lived branch (`ui-v3`). Nothing ships
until feature parity (minus deliberate cuts, see ADR 0007) is reached. Before release, the
rewrite is deployed to our own instance and beta-tested by the team in daily work
("rewrite, beta test here, then release"). Release is a major version (3.0.0); the old
pages are deleted at cut-over, not kept in parallel.

## Consequences

- One coherent design pass instead of a hybrid UI during transition.
- Long-lived branch risk: `ui-v3` must be rebased onto `main` regularly, and feature work
  on the old UI is frozen during the rewrite to limit drift.
- Feedback arrives late; the beta phase on our own instance is the only real-usage gate,
  so it must be long enough (2–4 weeks of daily triage work) to count.
- The page-inventory parity checklist in the master plan is the release gate.
