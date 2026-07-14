# UI v3 Master Plan — "Triage first"

Outcome of the grilling session 2026-07-14. Decisions are recorded as ADRs in
[docs/adr/](../adr/README.md); terminology in [glossary.md](glossary.md).

## Problem

Internal technicians and management describe the WebUI as cluttered and hard to use.
Confirmed pain classes: scattered navigation (16 items / 4 groups), overloaded pages,
unexplained state vocabulary (dismiss vs. accept), and an 806-line network form. The most
frequent job — alert triage — has no dedicated flow.

## North star

**The UI is a triage tool with a configuration annex — not a database browser.**
A technician logs in, sees what needs a decision, clears the inbox with the keyboard, and
leaves. Management opens one page and sees traffic lights.

## Decisions (summary)

| Topic | Decision | ADR |
|-------|----------|-----|
| Rollout | Big-bang rewrite on branch `ui-v3`, beta on own instance, release as 3.0.0 | 0001 |
| Navigation | 3 task areas (Monitor / Configuration / Administration) + Overview | 0002 |
| Triage | Inbox split view, keyboard-driven, actions renamed by effect (Allow / Mute) | 0003 |
| Network form | Wizard for create, tab pages for edit | 0004 |
| Management | Read-only Overview page, 1 new aggregate endpoint, PDF deferred | 0005 |
| Design & language | Design system and English stay; tool names (GVM/NSE/nuclei/OID) stay | 0006 |
| Cuts | Trends page dropped; charts fold into Dashboard + Overview | 0007 |

## Page inventory (parity checklist = release gate)

| Old route | New home | Phase |
|-----------|----------|-------|
| `/` (dashboard) | Monitor → **Triage Dashboard** (absorbs trend module) | 1 |
| `/alerts`, `/alerts/$id` | Monitor → **Alerts Inbox** (detail stays deep-linkable) | 1 |
| `/hosts`, `/hosts/$id` | Monitor → Hosts | 3 |
| `/scans`, `/scans/$id` | Monitor → Scans | 3 |
| `/nse/results` | folded into Scans/Host detail as **Findings** | 3 |
| `/trends` | **dropped** (ADR 0007) | — |
| `/networks`, `/networks/$id` | Configuration → Networks (wizard + tabs) | 2 |
| `/scanners`, `/scanners/$id` | Configuration → Scanners | 4 |
| `/nse/profiles`, `/nse/library`, `/nse/editor.$scriptName` | Configuration → **Scan Templates** | 4 |
| `/admin/gvm-library` | Configuration → **Scan Templates** | 4 |
| `/alert-rules` | Configuration → **Alerting** | 4 |
| `/admin/severity-rules` | Configuration → **Alerting** | 4 |
| `/admin/ssh-alert-defaults` | Configuration → **Alerting** | 4 |
| `/admin/users`, `/admin/users_.$userId`, `/admin/roles` | Administration → Users & Roles | 5 |
| `/admin/organization` | Administration → Organization | 5 |
| `/admin/hostname-lookup` | Administration → System | 5 |
| `/settings/security` | user menu → Account security | 5 |
| *(new)* `/overview` | **Executive Overview** (read-only) | 5 |

Old routes get redirects at cut-over so bookmarks survive.

Route parity alone is not the gate: behavior-level parity (filters, actions, permissions,
deep links) is tracked in [ui-v3-parity-matrix.md](ui-v3-parity-matrix.md); alert state
semantics in [alert-state-action-matrix.md](alert-state-action-matrix.md).

## Phases (all on `ui-v3`; each phase browser-verified and `just frontend-check` green)

**Phase 0 — Foundations.** New app shell + sidebar (3 areas, role-filtered), route
skeleton with placeholder pages, keyboard-shortcut infrastructure, shared split-view
(list/detail) component, terminology module (`lib/terminology.ts`) generated from the
glossary, shared empty-state/consequence-copy components.

**Phase 1 — Triage core.** Alerts Inbox (split view, j/k/A/M/S shortcuts, reduced
filters: status/severity/network/source) + Triage Dashboard (open-alert counts by
severity, scanner health, last/next scans, 30-day trend module, CTA into inbox). Built
first so it gets the longest beta soak.

**Phase 2 — Network wizard + tab editor.** Steps: Basics → Scan type → Schedule →
Alerting → Review. Backend validation rules (nuclei only with masscan/nmap, GVM
combinations) mirrored as wizard branching. Edit view reuses the same section components
as tabs.

**Phase 3 — Hosts & Scans.** Hosts list/detail, Scans list/detail, NSE results folded in
as Findings. Vulnerability panels (GVM/nuclei/NSE) keep the severity-rule entry points.

**Phase 4 — Configuration hubs.** Scan Templates (NSE profiles + script library/editor +
GVM library as tabs), Alerting (alert rules + severity rules + SSH defaults as tabs),
Scanners.

**Phase 5 — Administration + Overview.** Users & Roles, Organization, System (hostname
cache), account security in the user menu. Executive Overview page + new backend
aggregate endpoint `GET /api/overview/executive` (service + router + tests per house
rules — the only backend feature work in the plan).

**Phase 6 — Parity audit, beta, cut-over.** Walk the inventory table above in the
browser; add redirects; delete old routes/components; CHANGELOG (`**Frontend**:` +
`**Backend**:` paragraphs); deploy to our own instance; team works in it 2–4 weeks;
fix on `ui-v3`; then merge and `just release major` → 3.0.0.

## Backend impact (deliberately minimal)

- New: executive overview aggregate endpoint (Phase 5).
- New: alert list API extension — server-side `queue_state`/`policy_state` (+ allow-rule
  info) so the inbox filters Open/Muted/Allowed paginate correctly (Phase 1; decided in
  [alert-state-action-matrix.md](alert-state-action-matrix.md)). Query/schema layer only,
  no new tables or columns.
- No schema changes, no API renames — Allow/Mute are UI labels over the existing
  dismiss/accept endpoints (mapping fixed in the glossary).
- Trend endpoints stay (consumed by Dashboard/Overview modules).

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Long-lived branch drifts from `main` | Rebase `ui-v3` regularly; freeze old-UI feature work during the rewrite (ADR 0001). |
| Parity gaps discovered late | Inventory table above is the release gate; each phase ticks its rows. |
| Big-bang lands and users are lost | Beta phase is real daily work on our own instance, not a demo click-through. |
| Label/terminology drift across pages | Single terminology module; glossary is the source of truth. |
| Keyboard/split-view complexity underestimated | Built in Phases 0–1, longest soak time. |

## Explicitly deferred

- PDF export / scheduled report delivery for the Overview page (PLANNED-FEATURES.md
  story 4 covers scheduled reports).
- Configurable traffic-light thresholds on the Overview page.
- i18n / German UI.
- Command palette (can layer on top of the new navigation later).
