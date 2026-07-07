---
name: ship
description: Pre-commit ritual — run the right checks for the touched stacks, write the CHANGELOG entry in house style, compose the commit message, commit. Optionally cut a release. Use whenever work is ready to commit ("ship it", "commit this").
---

# Ship

Turn the working tree into a correct house-style commit. Local checks are the ONLY quality gate in this repo (CI runs nothing on push), so nothing gets committed before the checks pass.

## Step 1 — Inventory the change

```bash
git status --short && git diff --stat
```

Classify every changed path into stacks: `backend/`, `frontend/`, `scanner/`, docs/config. Decide the commit type (`feat` / `fix` / `refactor` / `docs` / `test` / `chore` / `perf` / `ci` / `security`).

Sanity checks before anything else:
- Unrelated changes mixed in? Separate them (multiple commits, still vertical slices per feature).
- Secrets in the diff (keys, tokens, passwords)? STOP, report, remove before proceeding.
- `routeTree.gen.ts` changed? That's fine ONLY if routes changed too — regeneration is expected, hand-edits are not.
- New migration present? Confirm `down_revision` matches `docker exec opm-backend uv run alembic heads`.

## Step 2 — Run the gates (only for touched stacks)

```bash
# backend touched:
cd backend && uv run ruff check src tests && uv run --extra dev mypy src/ && uv run --extra dev pytest -q

# frontend touched:
cd frontend && npm run lint && npm run typecheck && npm run test

# scanner touched:
cd scanner && uv run ruff check src tests && uv run mypy src/ && uv run --extra dev pytest -q
```

- Fixable ruff issues: `uv run ruff check --fix`, then show what changed.
- Any failure: fix it, re-run. After 2 genuinely different fix attempts on the same failure, stop and report (CLAUDE.md §8.6).
- Scanner code changed and needs runtime verification? Remember it does not hot-reload: `docker compose -f compose-dev.yml restart scanner`.
- UI changed? Browser verification at :5173 must already have happened (feature-slice step 10). If it hasn't, do it now.

## Step 3 — CHANGELOG.md (mandatory for feat/fix/refactor/perf/security)

Read the current `## [Unreleased]` block first, then add entries that match its density and shape:

- Correct Keep-a-Changelog category: `Added` / `Changed` / `Fixed` / `Security` (plus `Known issues` when honest).
- One bullet per layer, prefixed `**Backend**:` / `**Frontend**:` / `**Scanner**:` / `**Admin**:` / `**Dependencies**:`.
- House style = full descriptive paragraph: name the endpoints, columns, table names, migration numbers, defaults, and user-visible behavior. Trade-offs and accepted limitations go in too.

Real examples from this repo's CHANGELOG (match this level of detail):

> - **Backend**: `/api/auth/me` now exposes `totp_enabled` and `backup_codes_remaining`. 2FA verify step is rate-limited to 5 attempts / 60s per user (stricter than the per-IP login limit).

> - **Frontend**: the admin user edit route is now regeneration-stable. `users.$userId.tsx` was renamed to `users_.$userId.tsx` so the TanStack route generator un-nests it from the `users` list route (which has no `<Outlet/>`); previously the checked-in `routeTree.gen.ts` was a stale flat tree that worked but would break `/admin/users/$userId` on any regeneration. URL is unchanged.

Pure `chore:`/`docs:` commits may skip the CHANGELOG unless they change behavior.

## Step 4 — Compose the commit message

Format: `<type>: <imperative description>` — no trailing period, no scope parens, no co-authored-by, no emoji.

Body (for anything non-trivial) answers three questions:
1. **Why** — the motivation or the failure mechanism (for fixes: the exact broken behavior, e.g. the error string or the race).
2. **What was deliberately NOT done** — scoping decisions, accepted limitations.
3. **How it was verified** — which checks ran, what was browser-tested.

Fix commits name the mechanism, not the symptom: "Token expiry check used `<` instead of `<=`" beats "fix login bug".

## Step 5 — Commit

```bash
git add <the files that belong to this slice> && git commit -m "..." 
```

- Stage explicitly — no blind `git add -A` when the tree contains unrelated work.
- Vertical slice: the feature's model + migration + schemas + service + router + frontend + tests + CHANGELOG all in this one commit.
- Do not push unless asked; the user pushes or releases.

## Step 6 — Release (only when explicitly requested)

`just release patch|minor|major` — preconditions:
- Working tree completely clean (release.sh aborts otherwise).
- `[Unreleased]` curated: entries in the right categories, wording tightened, nothing left that describes abandoned work.
- It is interactive (y/N prompt, needs a TTY) — tell the user to run `! just release patch` themselves if you cannot answer prompts.
- After the push, the tag `X.Y.Z` triggers the CI build (3 images × Docker Hub + GHCR, multi-arch). Only frontend typecheck gates it — everything else was your job in step 2.

## Report

End with: stacks checked and their pass/fail, the CHANGELOG entries added, the commit hash + subject, and anything deliberately left uncommitted.
