# ADR 0007: Drop the standalone Trends page

- Status: accepted
- Date: 2026-07-14
- Deciders: Wim Bonis

## Context

Big-bang parity (ADR 0001) means every surviving page must be rebuilt. Each page was
challenged for its right to exist. Candidates for removal were the NSE browser editor,
the hostname-cache admin page, and the Trends page. Only Trends was cut; the NSE editor
and hostname-cache page stay.

## Decision

The standalone `/trends` route is **not rebuilt**. Its charts move to where they are
actually consumed:

- the triage Dashboard gets a compact 30-day trend module,
- the executive Overview page (ADR 0005) gets the risk trend.

Backend trend endpoints stay untouched; only the frontend route disappears.

## Consequences

- One page less to rebuild and maintain; one navigation entry less.
- Anyone who used deep Trends views loses them; if that turns out to matter during beta,
  the decision is revisited before cut-over.
