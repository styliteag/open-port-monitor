---
name: feature-slice
description: Build a full-stack feature as one vertical slice — DB model, migration, schema, service, router, tests, frontend types/hook/UI, CHANGELOG — in the house order with verification gates. Use for any new feature or field that spans backend and frontend.
---

# Feature Slice

Build the feature bottom-up in the order below. Each step has a gate; do not move on until the gate passes. The result is ONE commit spanning every layer (see CLAUDE.md §2 — never split backend and frontend commits).

Skip steps that don't apply (pure-frontend feature: start at step 7; new field on existing table: skip step 1's new-file parts but keep the migration).

## Step 0 — Scope and precedent

1. State in one sentence what the feature does and which existing feature it most resembles.
2. Find the precedent with the knowledge graph (`semantic_search_nodes`) — e.g. a new per-network toggle resembles `ssh_probe_enabled`; a new admin CRUD page resembles severity-rules. Open the precedent's model, schema, service, router, hook, and component. **Copy its shapes; do not invent new ones.**
3. If the feature is in `PLANNED-FEATURES.md`, note it — step 12 updates the planning files.

## Step 1 — Model (`backend/src/app/models/`)

- One file per table, singular name (`network.py` → `Network`).
- `mapped_column()` everywhere; FK columns get explicit `index=True`.
- Enum columns: enum inherits `(str, Enum)`, column sets `values_callable=lambda x: [e.value for e in x]`.
- Datetime columns: `DateTime` (naive UTC), `server_default=func.utc_timestamp()`, `onupdate=func.utc_timestamp()` for `updated_at`.
- Relationship type hints under `if TYPE_CHECKING:` with string targets.
- **Register the model in `models/__init__.py`** — Alembic and `relationship()` strings break without it.

## Step 2 — Migration

```bash
just migrate "add <thing>"                                  # autogenerate inside opm-backend
docker exec opm-backend uv run alembic heads                # confirm the real head
```

Then hand-review the generated file in `backend/src/migrations/versions/`:
- `down_revision` must equal the `alembic heads` output (numbering is NOT linear — `16a`, `025_add_2fa_totp` exist).
- Add idempotency guards for added columns/tables (copy the `_column_exists()` / `_table_exists()` helpers from `013_add_ssh_probe_enabled.py`) — dev DBs may have columns pre-created by `create_all`.
- Write a real `downgrade()`.

**Gate:** `docker compose -f compose-dev.yml restart backend && just dev-logs-backend` — migration applies cleanly, no startup errors.

## Step 3 — Schemas (`backend/src/app/schemas/`)

- Naming: `XCreateRequest`, `XUpdateRequest`, `XResponse`, `XListResponse` (wrapper with typed list field: `networks: list[NetworkResponse]`).
- Responses: `model_config = {"from_attributes": True}`.
- Field names identical to the model — no renames between layers.
- Cross-field validation via `@model_validator(mode="after") -> "Self"`; single-field via `@field_validator` + `@classmethod` delegating to free module functions.
- **Nullable update field?** It needs the `clear_*` flag pattern — plan it now (schema field + service params + router derivation, see step 4/5).

## Step 4 — Service (`backend/src/app/services/`)

- Free `async def` functions, signature `async def x(db: AsyncSession, ...)`.
- `await db.flush()` + `await db.refresh(obj)` after writes. **Never `db.commit()`** — the router owns the transaction.
- Return `Model | None | list | dict`. **Never raise HTTPException** from a service.
- Nullable updates: `if value is not None or clear_value:` pattern.
- If a relationship will be accessed after return, add `selectinload()` to the query here.
- New domain = new file; don't bloat an existing service module.

**Test now (TDD encouraged):** service tests call the function directly with the `db_session` fixture in `backend/tests/test_<domain>.py`. Use `NetworkFactory` / `UserFactory` / `ScannerFactory` from conftest. `asyncio_mode="auto"` — no decorator needed.

## Step 5 — Router (`backend/src/app/routers/`)

Canonical shape (copy from `routers/networks.py`):

```python
@router.post("", response_model=XResponse, status_code=status.HTTP_201_CREATED)
async def create_x(request: XCreateRequest, user: OperatorUser, db: DbSession) -> XResponse:
    obj = await services.xs.create_x(db, ...)
    await db.commit()
    return XResponse.model_validate(obj)
```

- DI aliases: `CurrentUser` / `OperatorUser` / `AdminUser` / `CurrentScanner` / `DbSession` from `core/deps.py`.
- Missing resource → `raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=...)` (raw, not `core/exceptions.py`).
- Nested resources: validate parent ownership (`rule.network_id == network_id`) before acting.
- Update endpoints derive clear-flags: `clear_x="x" in request.model_fields_set`.
- New router → register in `main.py`.

**Gate:** `just backend-check` fully green (ruff + mypy strict + pytest). Router tests go through the `client` fixture with `admin_headers` / `viewer_headers`; cover happy path + 401/403 + 404.

## Step 6 — Scanner (only if the feature changes scanner behavior)

- Follow the extension patterns in CLAUDE.md §5 (ScannerProtocol / post-phase / own job path).
- Sanitize all job-derived subprocess input (`sanitize_cidr` / `sanitize_port_spec`).
- Post-phases are best-effort — must never fail the scan.
- **Gate:** `cd scanner && uv run mypy src/ && uv run ruff check src/ && uv run --extra dev pytest`, then `docker compose -f compose-dev.yml restart scanner` (no hot-reload!) and check `just dev-logs-scanner`.

## Step 7 — Frontend types (`frontend/src/lib/types.ts`)

Mirror the Pydantic response 1:1 — same field names, same optionality. Do NOT touch `api-client.ts` / `api-types.ts` (dormant scaffolding).

## Step 8 — Frontend hook (`frontend/src/features/<x>/hooks/useX.ts`)

```ts
export function useX(id: number) {
  return useQuery({
    queryKey: ["xs", id],
    queryFn: () => fetchApi<XResponse>(`/api/xs/${id}`),
    enabled: id > 0,
  })
}
```

- Query keys `["resource", id, "sub"]`; list keys end with the filter object; query strings via a `buildXParams` URLSearchParams helper.
- Mutations bundled in `useXMutations()`; every `onSuccess` invalidates the root key: `qc.invalidateQueries({ queryKey: ["xs"] })`. Cross-resource effects invalidate those keys too.
- Hook test co-located (`useX.test.tsx`): fresh QueryClient wrapper (`retry: false, gcTime: 0`), `useAuthStore.setState({ token })`, `vi.stubGlobal("fetch", mockFetch)`.

## Step 9 — Frontend UI

- Components in `features/<x>/components/`; the route file in `src/routes/` stays thin (hook + `LoadingState`/`ErrorState` + components).
- Route filename grammar: `_authenticated` prefix for app pages, `$param` for dynamics, trailing `_` (`users_.$userId.tsx`) to un-nest from a list route without `<Outlet/>`. Never edit `routeTree.gen.ts`.
- Forms: react-hook-form + `zodResolver`, `import * as z from "zod/v4"`, schema in a sibling `*Schema.ts`. Nullable numbers: the `z.preprocess` house idiom.
- Styling: semantic tokens + `cn()`; `font-emphasis`/`font-strong`, never `font-bold`; badges copy `SeverityBadge`/`StatusBadge`; new primitives follow the `cva` pattern in `components/ui/button.tsx`.
- `import type` for type-only imports; named exports only.

**Gate:** `just frontend-check` fully green.

## Step 10 — Browser verification (mandatory for any UI change)

Dev stack up (`just dev-up`), then verify at http://localhost:5173 (login `admin@example.com` / `admin`):
- The new page/control renders without console errors.
- The happy path works end-to-end against the real backend.
- Loading and error states appear when expected.
- Screenshot if the change is visual.

The feature is NOT done until this passes.

## Step 11 — CHANGELOG.md

Add entries under `## [Unreleased]` in the correct category (`Added`/`Changed`/`Fixed`), one per layer, prefixed `**Backend**:` / `**Frontend**:` / `**Scanner**:`. House style is a full descriptive paragraph naming endpoints, columns, and the migration number — read the existing block and match its density. Example shape:

> - **Backend**: per-network foo threshold. New column `foo_threshold` on `networks` (migration `026_add_foo_threshold`), exposed via `PUT /api/networks/{id}` with a `clear_foo_threshold`-style semantics. Alerts below the threshold are stored but not emitted.

## Step 12 — Planning files + commit

- If the feature was planned: move its story from `PLANNED-FEATURES.md` to `COMPLETED-FEATURES.md` with an `**Implemented:**` paragraph; tick the box in `TODO.md`.
- One commit, conventional format, detailed body (why + scoping + how verified). Run `/ship` if available, otherwise follow CLAUDE.md §7 "Commit" checklist.
