# UI v3 Alert State and Action Matrix

- Status: accepted (2026-07-14)
- Scope: UI v3 alert inbox, detail panel, filters, and actions
- Related: [ADR 0003](../adr/0003-alert-inbox-with-effect-based-actions.md),
  [alert state documentation](../alert-states.md)

## Purpose

An alert does not have one state. Queue visibility, suppression policy, assignment, and
severity are independent. This matrix prevents UI labels such as Open, Muted, and Allowed
from hiding valid combinations or causing an action to have a broader effect than the
user intended.

## Independent state dimensions

| Dimension | Values | Persistence / derivation | Meaning |
|-----------|--------|--------------------------|---------|
| Queue | `inbox`, `out_of_inbox` | Derived from `dismissed` | Whether the alert currently needs review in the inbox |
| Policy | `none`, `allowed_network`, `allowed_global` | Derived from a matching accepted **port rule** (`port_rules` / `global_port_rules` with `rule_type='accepted'` — not the `alert_rules` table) | Whether equivalent future alerts are suppressed, and at what scope |
| Assignment | unassigned or a user | `assigned_to_user_id` | Who owns the work |
| Severity | native or overridden | Native severity plus override/rule resolution | How urgently the alert is prioritized |

### No workflow dimension

Earlier drafts carried a workflow dimension (`open`, `in_progress`, `fix_planned`,
`resolved`) backed by `resolution_status`. That column was **dropped in migration
`006_remove_resolution_status`** (2026-04-09); no `/api/alerts/{id}/status` endpoint
exists. `docs/alert-states.md` and AGENTS.md still describe it — stale, code wins.
Workflow tracking is **out of scope for UI v3**; if wanted later, it is a separate
planned feature, not part of this redesign.

## Derived UI presentation

| `dismissed` | Matching accepted rule | Primary label | Required secondary information |
|-------------|------------------------|---------------|--------------------------------|
| `false` | No | **Open** | Assignment badge when present |
| `true` | No | **Muted** | Mute reason when present |
| `true` | Yes | **Allowed** | Network or Global scope, rule, and reason |
| `false` | Yes | **Open** | **Allowed rule exists** badge with scope |

The final row is valid: reopening an alert does not revoke its underlying Allow rule. The
UI must represent this combination instead of forcing it into a single mutually exclusive
status.

## Filters

The canonical filters are independent:

- **Queue:** In inbox / Out of inbox
- **Policy:** Not allowed / Allowed for network / Allowed globally
- **Priority:** Severity
- **Context:** Network and source

The simple UI may expose Open, Muted, and Allowed as presets:

| Preset | Server-side predicate |
|--------|-----------------------|
| Open | `dismissed=false` |
| Muted | `dismissed=true AND no matching accepted rule` |
| Allowed | `matching accepted rule exists` |

These predicates must be evaluated server-side for correct totals and pagination. Row-level
client-side rule matching (the UI v2 approach for "Accepted") is not sufficient for a
list filter. **Decision 2026-07-14: the alert list API will be extended** to evaluate
queue and policy state server-side (see "Required list API contract" below); the
badge-only fallback is rejected because triage is the core job of UI v3.

## Action matrix

`Analyst+` means analyst, operator, or admin. Current Allow endpoints require operator or
admin access because they create policy rules.

| UI action | Persistent effect | Effect on future matching alerts | Permission | Shortcut behavior |
|-----------|-------------------|----------------------------------|------------|-------------------|
| **Mute** | Set `dismissed=true`; store reason/comment; create no rule | A later scan may create a new alert | Analyst+ | `M` opens the Mute dialog |
| **Allow for Network** | Create a network-scoped accepted rule and dismiss matching current alerts | Suppressed only in the affected network | Operator/Admin | `A` opens the Allow dialog with Network selected |
| **Allow Globally** | Create a global accepted rule and dismiss matching current alerts | Suppressed across all networks | Operator/Admin | Available only after explicit scope selection |
| **Reopen** | Set `dismissed=false` and clear the dismiss reason | Any existing Allow rule remains effective | Analyst+ | Detail action; never revokes a rule |
| **Assign** | Change `assigned_to_user_id` | No effect | Analyst+ | `S` opens the assignment control |
| **Revoke Rule** | Delete the accepted rule | Future matching alerts may be created again | Operator/Admin | Rule action; does not reopen old alerts |
| **Override Severity** | Set or clear an alert severity override | Changes prioritization, not queue or policy | Analyst+ | Detail action |

## Interaction and safety rules

1. Pressing `A`, `M`, or `S` opens a dialog or control; it never performs a persistent
   action immediately.
2. The Allow dialog defaults to the current network. Global scope must be selected
   explicitly.
3. Every Allow action requires a reason and shows the resulting scope before confirmation.
4. Reopen never removes an Allow rule.
5. Revoke Rule never reopens an existing dismissed alert.
6. Bulk Allow across alerts from different networks must make its scope and affected rules
   explicit before confirmation.
7. Bulk responses must surface missing alert IDs, rule-creation failures, and partial
   success instead of reporting unconditional success.
8. Action shortcuts are disabled while focus is in an input, textarea, select, editable
   element, menu, or dialog.
9. After a mutation, the selected alert, list results, counts, matching-rule data, and
   activity timeline are refreshed consistently.

## Required list API contract

To support correct filtering and display, the alert list needs equivalent server-side
concepts for:

```text
queue_state=inbox|out_of_inbox
policy_state=none|allowed_network|allowed_global
```

Names may differ in the final schema, but the response must provide enough information to
render the dimensions without additional per-row requests:

```json
{
  "queue_state": "inbox",
  "policy_state": "allowed_network",
  "allow_rule_id": 42,
  "allow_scope": "network"
}
```

This extension is decided (2026-07-14) and is, together with the executive overview
endpoint, one of the two backend work items of the redesign (see the master plan's
"Backend impact" section). It is query- and schema-layer work only — no new tables or
columns; policy state is derived by joining against the existing port-rule tables.

## Acceptance scenarios

1. **Mute:** The alert leaves the inbox, no Allow rule is created, and a later scan may
   create a new matching alert.
2. **Network Allow:** Current matching alerts are dismissed, and future matching alerts are
   suppressed only for that network.
3. **Global Allow:** Current matching alerts are dismissed, and future matching alerts are
   suppressed across all networks.
4. **Reopen with existing rule:** The UI shows Open plus an Allowed-rule badge; future scan
   behavior remains suppressed until the rule is revoked.
5. **Revoke without reopen:** Future alerts are enabled again, while old dismissed alerts
   remain outside the inbox.
6. **Role boundaries:** A viewer has no mutation controls; an analyst can mute, reopen,
   assign, and override severity; only an operator or admin can create or revoke Allow
   rules.
7. **Mixed-network bulk selection:** The UI cannot silently create a global rule or attach a
   network rule to an unrelated alert.
8. **Keyboard safety:** Typing `a`, `m`, `s`, `j`, or `k` in any editable control never
   triggers an inbox shortcut.
