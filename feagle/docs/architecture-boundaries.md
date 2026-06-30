# Architecture Boundaries

PyShare is a monorepo with three physical import packages in one wheel:

- `pyshare_core`: shared contracts, identifiers, repository protocols, config,
  and common errors.
- `pyshare_client`: client-side project/package analysis, reachability, cache,
  and CLI.
- `pyshare_server`: server-side CVE-to-VF localization, ingestion, file DB, and
  CLI.

The console command `pyshare` points directly to `pyshare_client.cli`.

## Runtime Surfaces

### Client

Entrypoints:

- `pyshare`
- `pyshare-client`

Allowed responsibilities:

- scan a local project
- build static project/package callgraph reports
- read package summaries and vulnerable-function records
- evaluate direct and transitive reachability
- emit table, JSON, or future SARIF reports

Client-safe code lives in `pyshare_client` and must not import
`pyshare_server`.

`pyshare_client.callgraph` owns the shared Jarvis-grade type graph core used by
both package and project analysis. Package analysis runs it exhaustively over a
source root; project analysis runs it application-centered from entry points.

### Server

Entrypoint:

- `pyshare-server`

Allowed responsibilities:

- resolve CVE metadata from OSV/NVD
- discover and parse patches
- clone or update upstream repositories
- run CVE-to-vulnerable-function localization
- call LLM, embedding, or reranking providers
- write vulnerable-function records and package summaries to the file DB

Server code lives in `pyshare_server`. It may import shared contracts from
`pyshare_core`, but must not import `pyshare_client`.

### Shared Contracts

Shared code owns stable data contracts only:

- `pyshare_core.models`
- `pyshare_core.errors`
- `pyshare_core.repositories`
- `pyshare_core.kb`

The shared layer is the handoff point between CVE-to-VF localization and
client-side reachability. Localization produces vulnerable-function records;
reachability consumes those records through explicit inputs, API responses, or
repository adapters.

## Packaging

Install the client surface:

```powershell
pip install -e ".[client]"
```

Install the server surface:

```powershell
pip install -e ".[server]"
```

Install everything for development:

```powershell
pip install -e ".[dev]"
```

## Boundary Tests

`tests/unit/test_architecture_boundaries.py` statically checks imports so
package boundaries cannot drift.
