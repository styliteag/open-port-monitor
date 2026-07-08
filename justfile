# https://github.com/casey/just
set shell := ["bash", "-cu"]

default:
    @just --list

# --- Backend ---------------------------------------------------------------

backend-install:
    cd backend && uv sync --all-extras

backend-test:
    cd backend && uv run --extra dev pytest -q

backend-lint:
    cd backend && uv run ruff check src tests

backend-fmt:
    cd backend && uv run ruff format src tests

backend-typecheck:
    cd backend && uv run --extra dev mypy src/

backend-check: backend-lint backend-typecheck backend-test

# Run an alembic migration (usage: just migrate "description")
migrate msg="auto":
    docker exec opm-backend uv run alembic revision --autogenerate -m "{{msg}}"

# --- Frontend --------------------------------------------------------------

frontend-install:
    cd frontend && npm install

frontend-dev:
    cd frontend && npm run dev

frontend-build:
    cd frontend && npm run build

frontend-lint:
    cd frontend && npm run lint

frontend-typecheck:
    cd frontend && npm run typecheck

frontend-test:
    cd frontend && npm run test

frontend-check: frontend-lint frontend-typecheck frontend-test

# --- Scanner ---------------------------------------------------------------

scanner-install:
    cd scanner && uv sync --all-extras

# --- Full check (all stacks) -----------------------------------------------

check: backend-check frontend-check

# --- Stack (production: single combined image) -----------------------------

up:
    docker compose up -d --build

down:
    docker compose down

logs:
    docker compose logs -f --tail=200

# --- Stack (development: hot-reload, bind-mounted sources) -----------------

dev:
    docker compose -f compose-dev.yml up --build

dev-up:
    docker compose -f compose-dev.yml up -d --build

dev-down:
    docker compose -f compose-dev.yml down

dev-logs:
    docker compose -f compose-dev.yml logs -f --tail=200

dev-logs-backend:
    docker compose -f compose-dev.yml logs -f --tail=200 backend

dev-logs-frontend:
    docker compose -f compose-dev.yml logs -f --tail=200 frontend

dev-logs-scanner:
    docker compose -f compose-dev.yml logs -f --tail=200 scanner

# --- GVM scanner (optional, runs alongside main dev stack) -----------------

gvm-up:
    docker compose -f compose-gvm.yml up -d

gvm-down:
    docker compose -f compose-gvm.yml down

gvm-logs:
    docker compose -f compose-gvm.yml logs -f --tail=200

# --- Release ----------------------------------------------------------------

# Bump version, update CHANGELOG.md, tag, push. CI builds + publishes images.
# Usage: just release patch|minor|major
release type="patch":
    ./release.sh {{type}}
