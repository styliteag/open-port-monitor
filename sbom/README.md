# SBOM — Software Bill of Materials

Machine-readable [CycloneDX](https://cyclonedx.org/) JSON inventories of OPM's
dependencies, one per build surface.

| File | Surface | Components | Source |
|---|---|---|---|
| `backend.cdx.json` | Backend Python env | 62 | `cyclonedx-py environment backend/.venv` |
| `scanner.cdx.json` | Scanner Python env (incl. `gvm` extra) | 36 | `cyclonedx-py environment scanner/.venv` |
| `frontend.cdx.json` | Frontend npm (prod) | 306 | `npm sbom --sbom-format cyclonedx --omit dev` |
| `scanner-image.cdx.json` | Scanner Docker image OS layer + bundled tools (Debian debs incl. masscan/nmap + nuclei) | 150 | `dpkg-query` in the built image |

License obligations and the copyleft analysis live in
[`../THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md).

## Regenerate

```bash
# Python (needs the venvs synced: cd backend && uv sync --extra dev; cd scanner && uv sync --extra dev --extra gvm)
uvx --from cyclonedx-bom cyclonedx-py environment backend/.venv  --of JSON -o sbom/backend.cdx.json
uvx --from cyclonedx-bom cyclonedx-py environment scanner/.venv  --of JSON -o sbom/scanner.cdx.json

# Frontend
cd frontend && npm sbom --sbom-format cyclonedx --omit dev > ../sbom/frontend.cdx.json

# Scanner image OS layer (after `just dev-up`/build)
docker run --rm styliteag/opm-scanner:latest \
  dpkg-query -W -f='${Package}\t${Version}\t${Homepage}\n'
# → fold into scanner-image.cdx.json (deb purls) + add the COPY'd nuclei binary
```

> Component counts are point-in-time (recorded after the dependency remediation
> of 2026-06-28). Re-run after dependency changes.

## Notes

- `scanner-image.cdx.json` covers the **standard** scanner image. The
  `opm-scanner-gvm` image differs: it drops masscan/nmap/nuclei and adds
  `python-gvm` (GPL-3.0) + `paramiko` (already in `scanner.cdx.json`).
- For a full container SBOM including file-level detail, use
  [`syft`](https://github.com/anchore/syft): `syft styliteag/opm-scanner:latest
  -o cyclonedx-json`.
