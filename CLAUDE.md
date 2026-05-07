# CLAUDE.md

STYLiTE Orbit Monitor — distributed network port scanning + monitoring (FastAPI, React 19, MariaDB 11, Docker).

Full conventions, architecture, patterns: @AGENTS.md

## Commands

Use `just` (see `justfile` in root). Common recipes:

```bash
just dev-up          # start dev stack (compose-dev.yml)
just dev-down
just dev-logs

just backend-check   # mypy + ruff + pytest
just frontend-check  # typecheck + lint + test
just check           # both stacks

just migrate "desc"  # alembic autogenerate migration
just gvm-up          # start GVM stack (optional)

just release patch   # bump version, tag, push
```

**Do NOT use `npx tsc`** — fails. Use `npm run typecheck` or `just frontend-typecheck`.

## Commit Format

`<type>: <description>` — types: feat, fix, refactor, docs, test, chore, perf, ci

**Every commit MUST update `CHANGELOG.md`** under `## [Unreleased]` (Keep a Changelog categories).

## Gotchas

- Frontend routing: TanStack Router in `src/routes/`, NOT `src/pages/`
- Feature modules in `src/features/` (admin, alerts, auth, dashboard, hosts, networks, nse, scanners, scans)
- Use `TYPE_CHECKING` for circular imports in SQLAlchemy relationship type hints
- Alembic migrations auto-apply on startup
- Scanner uses `uv` with hatchling build system; GVM scanner variant uses `Dockerfile.gvm` and `compose-gvm.yml`
- Subdirectory CLAUDE.md files in `backend/`, `frontend/`, `scanner/` load automatically

## Rules

- [Design System](/.claude/rules/design-system.md) — Linear-inspired tokens (fonts, colors, surfaces)
- [Workflow](/.claude/rules/workflow.md) — Plan mode, verification, self-improvement loop

## Verification

After making changes, run all applicable checks:
```bash
cd backend && uv run --extra dev mypy src/ && uv run ruff check src/ && uv run --extra dev pytest
cd frontend && npm run typecheck && npm run lint && npm run test
```

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.
