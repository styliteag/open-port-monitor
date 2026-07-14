# UI v3 Behavioral Parity Matrix

- Status: accepted (2026-07-14)
- Scope: UI v2 to UI v3
- Related: [UI v3 master plan](ui-v3-plan.md)

## Purpose

The route inventory in the master plan proves that every page has a destination. This
matrix goes one level deeper: it records what happens to the behavior on those pages.
It is the release gate against accidentally losing a filter, action, permission, deep
link, or operational workflow while the frontend is rebuilt.

This document does not change the big-bang delivery decision in ADR 0001. It defines
what must be checked before that cut-over is allowed.

## Decision values

| Value | Meaning |
|-------|---------|
| **Keep** | Preserve the current behavior. Layout and copy may change. |
| **Change** | Replace the behavior intentionally; the new behavior is described here. |
| **Drop** | Remove intentionally. The loss and its approval must be explicit. |
| **New** | Add behavior that does not exist in UI v2. |
| **Open** | A product or technical decision is still required. |

## Cross-cutting behavior

| UI v2 behavior | UI v3 destination | Decision | Phase | Required evidence |
|----------------|-------------------|----------|-------|-------------------|
| Login, logout, and expired-session handling | New app shell | Keep | 0 | End-to-end test |
| 2FA setup, backup codes, and account security | User menu -> Account security | Change | 5 | End-to-end test for every role |
| Dark theme and DESIGN.md tokens | All pages | Keep | 0 | Browser and visual review |
| Collapsible sidebar | New app shell | Keep | 0 | Component test |
| Quick Scan entry point | Sidebar button kept (decided 2026-07-14, Phase 0) | Keep | 0 | Browser test |
| Viewer, analyst, operator, and admin behavior | Permission-aware navigation and actions | Change | 0 | End-to-end test for every role |
| Old bookmarks and shared URLs | Redirects to new destinations | Keep | 6 | Redirect tests including path parameters |
| Loading, error, empty, and retry states | Shared state components | Change | All | Component tests and browser review |
| Destructive-action confirmation | Shared confirmation pattern | Keep | 0 | Component and end-to-end tests |

## Alerts

| UI v2 behavior | UI v3 destination | Decision | Required evidence |
|----------------|-------------------|----------|-------------------|
| Active alerts are the default view | Inbox is the default view | Change | End-to-end test |
| Alert detail has its own URL | Split view plus a directly addressable alert URL | Keep | Deep-link end-to-end test |
| Search by IP, hostname, and text | Inbox search | Keep | API and end-to-end tests |
| Severity filter | Primary filter | Keep | End-to-end test |
| Network filter | Primary filter | Keep | End-to-end test |
| Source filter | Primary filter | Keep | End-to-end test |
| Alert-type filter | Advanced filters | Keep | End-to-end test |
| Port filter | Advanced filters | Keep | End-to-end test |
| Active/dismissed filter | Server-side queue and policy filters (list API extension decided 2026-07-14, see alert behavior matrix) | Change | API contract and pagination test |
| Table sorting | Inbox list sorting | Keep | Component test |
| Pagination and page size | Inbox list pagination | Keep | End-to-end test |
| CSV and PDF export | Inbox export menu, gated by `export_data` | Keep | Permission and export tests |
| Accept globally or for a network | Allow dialog with explicit scope | Change | End-to-end tests for both scopes |
| Dismiss | Mute | Change | End-to-end test |
| Reopen | Alert detail action | Keep | End-to-end test |
| Assignment | Detail panel and `S` shortcut | Keep | End-to-end test |
| Comments and activity timeline | Detail panel | Keep | End-to-end test |
| Evidence and scan presence | Detail panel | Keep | Browser and component tests |
| Severity override and severity-rule entry points | Detail panel | Keep | End-to-end test |
| Bulk actions | Inbox selection actions | Keep | End-to-end test including partial failure |
| Permanent deletion | Restricted overflow action with confirmation | Keep/Open | Permission decision and end-to-end test |
| Keyboard navigation | `j`/`k`; action keys open dialogs or menus | New | End-to-end and accessibility tests |

The precise state derivation, action effects, scopes, and permissions are defined in
[Alert State and Action Matrix](alert-state-action-matrix.md).

## Networks

| UI v2 behavior | UI v3 destination | Decision | Required evidence |
|----------------|-------------------|----------|-------------------|
| Create a network | Guided wizard | Change | End-to-end test |
| Edit a network | Direct-access tab pages | Change | End-to-end test |
| Clone a network | Pre-filled creation wizard | Keep | End-to-end test |
| Name and CIDR | Basics | Keep | API and end-to-end tests |
| Network description | Basics; backend field does not currently exist | New/Open | Model, migration, schema, and API tests if retained |
| Port specification | Scan type -> Advanced | Keep | End-to-end test |
| Scanner, scanner type, and protocol | Scan type | Keep | End-to-end test |
| Rate and timeout settings | Scan type -> Advanced | Keep | End-to-end test |
| Scan phases and host discovery | Scan type -> Advanced | Keep | End-to-end test |
| NSE profile selection | Vulnerability scanning | Keep | End-to-end test |
| Nuclei settings | Vulnerability scanning; only for valid scanner types | Keep | Branching and payload tests |
| GVM scan config and port list | Vulnerability scanning; only for Greenbone | Keep | Branching and payload tests |
| Schedule and schedule presets | Schedule | Keep | End-to-end test |
| Alert recipients and thresholds | Alerting | Keep | End-to-end test |
| SSH probe and per-network overrides | Alerting -> Advanced | Keep | Payload round-trip test |
| Initial port rules during creation | Not in the wizard (decided 2026-07-14): rules stay managed on the network detail page after creation, unchanged from v2 | Drop | Browser test of detail-page rules editor |
| Review submitted configuration before creation | Review step | New | End-to-end test |
| Invalid scanner/phase combinations | Impossible to select and still rejected by the backend | Keep/Change | Schema and end-to-end tests |

## Trends

Dropping the route does not automatically approve dropping every capability on it. Each
existing trend must have an explicit destination or an explicit Drop decision.

| UI v2 behavior | UI v3 destination | Decision | Required evidence |
|----------------|-------------------|----------|-------------------|
| Standalone `/trends` route | No standalone route | Drop | ADR 0007 |
| 30-day alert/risk trend | Triage Dashboard | Change | Browser and data-contract tests |
| Executive risk trend | Executive Overview | Change | API and browser tests |
| Open-port trend | Destination not yet defined | Open | Product decision |
| Host trend | Destination not yet defined | Open | Product decision |
| Resolution-rate trend | Destination not yet defined | Open | Product decision |
| 7/30/90-day range selection | Module filter or explicit removal | Open | Product decision |
| Per-network trend filter | Module filter or explicit removal | Open | Product decision |

## Hosts (inventoried 2026-07-14, Phase 3)

| UI v2 behavior | UI v3 destination | Decision | Required evidence |
|----------------|-------------------|----------|-------------------|
| Hosts/global-ports view toggle, search, network + IPv4/IPv6 + staleness filters, service quick-filters, sorting, pagination | Unchanged | Keep | Browser test |
| Bulk deletion with confirmation; CSV export | Unchanged | Keep | Browser test |
| Host detail: risk score + sparkline, comment, known hostnames, rescan/custom scan, CSV/PDF export | Unchanged | Keep | Browser test |
| Host detail tabs (Ports/Alerts/Vulnerabilities/Scans/SSH/Timeline) incl. severity-rule entry points | Unchanged — already matches the v3 tab pattern | Keep | Browser test |

## Scans & Findings (inventoried 2026-07-14, Phase 3)

| UI v2 behavior | UI v3 destination | Decision | Required evidence |
|----------------|-------------------|----------|-------------------|
| Scan list (status, ports, trigger, timestamps, pagination) | + visible network filter and network column (network_id search param existed but was never rendered) | Change | Browser test |
| Scan detail: progress, cancel, hide, port table, nuclei summary, all-source vulnerabilities table, diff view, engine logs | Unchanged | Keep | Browser test |
| `/nse/results` standalone page (global severity/IP/CVE search across scans) | **Dropped**: scan detail and host detail already render all NSE/GVM/nuclei findings via `GET /api/scans/{id}/vulnerabilities` and the host vulnerabilities panel; the alert detail NSE link now targets the host's findings instead. The cross-scan CVE search has no v3 home — revisit before cut-over if the beta misses it. Route stays URL-reachable until Phase 6. | Drop | Product approval recorded here; browser test of relinked entry points |

## Configuration hubs (inventoried 2026-07-14, Phase 4)

| UI v2 behavior | UI v3 destination | Decision | Required evidence |
|----------------|-------------------|----------|-------------------|
| `/nse/profiles`, `/nse/library` (+ editor deep link), `/admin/gvm-library` | **Scan Templates** hub (`/scan-templates?tab=profiles|scripts|gvm`); page bodies extracted unchanged into feature components, old routes render the same components until cut-over | Change | Browser test of all three tabs |
| `/alert-rules`, `/admin/severity-rules`, `/admin/ssh-alert-defaults` | **Alerting** hub (`/alerting?tab=rules|severity|ssh`); same extraction pattern | Change | Browser test of all three tabs |
| `/scanners` list + detail | Unchanged | Keep | Browser test |
| Rule-type wording ("Accepted") inside AlertRulesTable | Rename to Allow terminology in the Phase 6 polish sweep | Open | Terminology sweep |

## Remaining route groups

The following groups must receive the same behavior-level inventory before their phase
starts. A route is not considered inventoried merely because it appears in the master
plan.

| Group | Minimum behaviors to inventory | Phase | Status |
|-------|--------------------------------|-------|--------|
| Dashboard | Counts, scanner health, scan activity, next scans, navigation actions | 1 | Done (Phase 1) |
| Hosts | Search/filter/sort, port data, comments, SSH data, findings, severity rules | 3 | Done (see Hosts section) |
| Scans | Trigger/cancel actions, status, logs, results, findings, exports, deep links | 3 | Done (see Scans & Findings section) |
| Scan Templates | NSE profiles, library/editor behavior, GVM library upload/refresh | 4 | Done (see Configuration hubs) |
| Alerting | Alert rules, severity rules, SSH defaults, scope and permissions | 4 | Done (see Configuration hubs) |
| Scanners | Create/edit/auth, kind, status, metadata refresh, GVM behavior | 4 | Done (Keep, unchanged) |
| Administration | Users, roles, organization, hostname cache, permission boundaries | 5 | Done: `/admin/users` hub gains a read-only Roles tab (`?tab=roles`); `/admin/system` hosts the hostname cache (page body extracted); organization unchanged; account security already lived in the user menu (header email badge → `/settings/security`) | 
| Executive Overview | Freshness, coverage, risk semantics, unknown/degraded states | 5 | Done: `GET /api/overview/executive` (any role) — red = open critical, amber = open high, green otherwise, lightweight severity incl. overrides; top 5 open risks; "handled 30d" approximates via created_at of dismissed alerts (no dismissed_at column). Trend module reuses the existing alert-trend endpoint |

## Phase and release gates

A phase is complete only when:

1. Every behavior in scope has a **Keep**, **Change**, **Drop**, or **New** decision.
2. Every **Drop** has explicit product approval and a documented consequence.
3. Every **Keep** and **Change** has the required evidence recorded.
4. Role and permission behavior has been checked for viewer, analyst, operator, and admin.
5. Browser verification, `just frontend-check`, and `just frontend-build` pass.

The UI v3 cut-over is allowed only when every surviving route group is complete and no
release-blocking **Open** row remains.
