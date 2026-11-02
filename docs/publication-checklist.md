# GitHub release checklist — AEGIS SOC

> This release contains **documentation and selected screenshot assets only**. It **does not replace** the working SOC application, Windows collectors or Kali systemd services.

## A. What this bundle contains

- [LAB] `README.md` — English portfolio front page.
- [LAB] `README.tr.md` — Turkish equivalent.
- [LAB] `docs/architecture.md`, `docs/opnsense-setup.md`, `docs/active-directory-setup.md`, `docs/blocklists.md`, `docs/detections.md`, `docs/data-flow.md`.
- [LAB] `docs/screenshots/` — curated user-supplied screenshots and index.
- [LAB] `docs/publication-checklist.md` — release checks.
- [LAB] `scripts/Publish-AegisDocs.ps1` — local copy, backup, stage, commit and optional push for exactly this documentation bundle.

## B. Check `.gitignore` before pushing

[KOD] The attached application source snapshot stores SQLite data below `data/` by default and accepts secrets via environment variables. This means a public repository must avoid committing working databases, local environment files, logs and private backups. [LAB] Inspect the existing `.gitignore` rather than overwriting it with an unreviewed template.

Recommended patterns **to merge into the repository's existing `.gitignore` only if absent**:

```gitignore
# Local secrets / environment
.env
.env.*
!.env.example
*.key
*.pem
*.pfx
*.p12

# Python / IDE / local env
.venv/
venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.vscode/
.idea/

# Runtime / operational evidence / local backups
*.sqlite
*.sqlite3
*.sqlite3-wal
*.sqlite3-shm
*.db
*.log
logs/
backups/
data/
output/
*.bak
*.bak_*

# Optional local output
*.zip
```

[LAB] `.env.example` is allowed to be public only when its values are placeholders. **Do not use `git add -f` to override an ignored secret.** Repo-local documentation images remain unignored.

## C. Validate dependency metadata

[LAB] The dependency list supplied for review was:

```text
fastapi
uvicorn
pydantic
requests
pyyaml
psutil
python-dotenv
python-multipart
```

[LAB] This is a **review list, not a claim that every name is imported by the supplied source snapshot**. Keep the existing `requirements.txt`, check its content and ensure it matches current imports (`app/main.py`, optional identity/MITRE modules, Windows/Kali collectors and optional Ollama integration). Versions should be tested/pinned by the repository owner; no versions have been invented for this release.

```powershell
# Run from the existing repository root
Get-Content .gitignore
Get-Content requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## D. Secret and publication hygiene

```powershell
# Review what is being staged (read-only)
git status --short
git diff --cached --stat
git diff --cached --check

# Search names of potentially sensitive files; inspect results manually
Get-ChildItem -Recurse -File -Force |
  Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' -and $_.Name -match '(?i)\.env|token|secret|password|credential|\.sqlite|\.pfx|\.pem' } |
  Select-Object -First 30 FullName
```

[LAB] Do not commit actual IP blacklists with unidentified provenance, raw event logs, private SIDs, screenshots with tokens, or machine-specific desktop paths. `192.168.x.x` and `10.x.x.x` values in documentation are **lab addresses**; `198.51.100.77` is a reserved test address.

## E. Verify the diagrams and links

- [LAB] GitHub Mermaid should render all **seven required concepts**: topology, log pipeline, AD structure, IP blacklist, DNS blacklist, detection flow and identity/privilege model.
- [LAB] Confirm README image links load on GitHub. The guide uses relative paths, so it works regardless of repository owner or branch.
- [LAB] Review every screenshot at full size for private information before pushing.
- [LAB] All eight requested primary Markdown files are present; additional guides are supporting material.
- [LAB] Check `LICENSE` and use the exact license already in the repository. If none exists, obtain the owner's selection; do not invent MIT/Apache terms.

## F. What is verified, and what needs export for exact rebuilding?

| Status | Item |
|---|---|
| [KOD] Verified in supplied Python snapshots | FastAPI ingest, SQLite WAL and SHA-256, network thresholds, Sysmon 11-rule engine, selected AD/identity APIs and parsing. |
| [LAB] Reported/observed | OPNsense segmentation, DC01/WIN01/Kali addresses, active Sysmon alerts, PF test block and screenshot evidence. |
| [LAB] Known limitation | Unbound collector does not forward definitive block decision; SOC confirmed DNS block counter is therefore unavailable. |
| [LAB] Deliberate validation boundary | Sysmon ID 8/10/25 were not live-triggered with invasive LSASS/tampering behavior. |
| TODO | OPNsense release and WAN assignment; exact DHCP pool, Unbound feeds, ordered PF UUIDs, Suricata mode/categories, GPO export, Sysmon source and latest branch/requirements/license. |

## Eksik Bilgiler / Information needed for exact reproduction

1. [LAB] **OPNsense:** Version, current WAN/em0/em1 mapping, authoritative interface mask for em5, backup/redacted interface export.
2. [LAB] **Services:** KEA DHCP ranges/reservations and exact Windows/Unbound DNS forwarding configuration.
3. [LAB] **Firewall:** Complete ordered PF rule table, aliases and UUID allow-register (redacted).
4. [LAB] **IP/DNS feeds:** Exact origin/source URLs, usage permissions and refresh schedule (do not assume any feed name).
5. [LAB] **Suricata:** IDS/IPS mode, observed interface, installed/enabled rules and update schedule.
6. [LAB] **Windows AD:** Redacted GPO inventory, audit subcategories, account/group privilege-purpose table.
7. [LAB] **Sysmon:** Provenance and current XML revision per host; actual collector source and delivery schedule.
8. [LAB] **Repository:** Current requirements, default branch, verified LICENSE, screenshots cleared for release.

[LAB] These are reproducibility/evidence TODOs, **not claims that the live laboratory failed**. The project can be presented as a completed learning/portfolio implementation with honest boundaries.
