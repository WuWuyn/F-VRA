# PyShare

PyShare is a Python vulnerability reachability analysis product focused on
mapping CVEs to vulnerable Python functions and checking whether application
usage can reach them.

The repository is a monorepo with hard runtime boundaries:

- `pyshare-client` / `pyshare`: client-side project scanning, callgraph
  generation, dependency report handling, and reachability checks.
- `pyshare-server`: server-side CVE-to-vulnerable-function localization,
  metadata/patch fetching, LLM-assisted ranking, and file-backed DB ingestion.
- `pyshare_core`: shared Pydantic contracts, identifiers, repository protocols,
  and common configuration used across both sides.

Client-safe code must not import `pyshare_server`; shared core code must not
import either client or server packages. This is enforced by unit tests.

The project intentionally excludes baseline SCA. Its production scope is:

1. CVE-to-vulnerable-function localization.
2. Vulnerable-function knowledge storage.
3. Package call graphs and `S_i` / `S_o` summaries.
4. Project entry points and external API usage.
5. Compositional vulnerability reachability.

## Modules

| Module | Responsibility | Documentation |
| --- | --- | --- |
| `pyshare_server.localization` | CVE metadata, patches, AST extraction, candidate retrieval and ranking | [Localization](docs/localization.md) |
| `pyshare_client.package_analysis` | Library call graph, public APIs, `S_i` and `S_o` | [Package analysis](docs/package-analysis.md) |
| `pyshare_client.project_analysis` | Entrypoints, reachable project graph and Usage Index | [Project analysis](docs/project-analysis.md) |
| `pyshare_client.reachability` | Compose Usage Index and package summaries into paths | [Reachability](docs/reachability.md) |
| `pyshare_core` | Vulnerable-function records, package summaries, artefacts, and repository contracts | [Knowledge base](docs/knowledge-base.md) |

## Quick Start

```powershell
pip install -e ".[dev]"
pytest
```

## HTTP API

The HTTP layer lives in `pyshare_api` and is intentionally separate from the
existing Typer CLI entrypoints. Run it locally with:

```powershell
pip install -e ".[api]"
$env:PYTHONPATH="src"
uvicorn pyshare_api.main:app --reload --host 127.0.0.1 --port 8000
```

The API is mounted under `/api` so the production frontend can serve the UI and
proxy backend calls from the same domain:

```text
GET  /api/health
GET  /api/dashboard/summary
GET  /api/projects
GET  /api/projects/{project_id}
GET  /api/vulnerabilities
GET  /api/packages
GET  /api/scans
POST /api/scans
POST /api/reachability/check
POST /api/localization/cve
```

## Commands

| Command | Surface | Purpose |
| --- | --- | --- |
| `pyshare` | Client | Scan projects, build call graph reports, and run reachability checks. |
| `pyshare-client` | Client | Equivalent client entrypoint for environments that prefer explicit names. |
| `pyshare-server` | Server | Localize CVEs to vulnerable functions and ingest server-side artefacts. |

Run server-side CVE-to-VF localization:

```powershell
pyshare-server localize CVE-2023-32681 `
  --auto-resolve-patch `
  --top-k 20 `
  --output .\report.json
```

PyShare resolves CVE metadata, infers a GitHub repository from CVE references,
clones it into the repository cache, and runs the VFarche-style CVE-to-VF
pipeline.

Set `OPENROUTER_RERANK_MODEL` to use a rerank model that is separate from
`OPENROUTER_MODEL`, for example
`nvidia/llama-nemotron-rerank-vl-1b-v2:free`.

See the [documentation index](docs/index.md) or the
[localization guide](docs/localization.md)
for environment variables, diagnostics, patch-present and patch-absent modes.

Run client-side project scanning with an explicit vulnerable-function target:

```powershell
pyshare scan `
  --cve CVE-2024-0000 `
  --project .\myapp `
  --vf vulnerable_package.module.function `
  --explain
```

Run transitive reachability with package summary reports:

```powershell
pyshare reachability check `
  --project .\myapp `
  --vf vulnerable_package.module.function `
  --package-report vulnerable_package=.\vulnerable-package-callgraph.json `
  --explain `
  --format json
```

## Source Layout

```text
src/pyshare_core/
src/pyshare_client/
src/pyshare_server/
```

For source-tree smoke checks without installation:

```powershell
$env:PYTHONPATH="src"
python -c "from pyshare_client.cli import app; from pyshare_server.cli import app as server_app"
```
