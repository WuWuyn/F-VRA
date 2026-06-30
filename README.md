# F-VRA Deploy

Production-oriented Docker stack for the F-VRA web app, API, worker, and Postgres database.

## Run

```powershell
docker compose up --build
```

Open:

```text
http://localhost:8080
```

Services:

- `postgres`: Postgres 16 metadata store.
- `api`: FastAPI service on `http://localhost:8000`.
- `worker`: Polls queued scan jobs and writes graph/reachability artifacts.
- `web`: React/Nginx frontend on `http://localhost:8080`.

## Storage

Postgres stores projects, advisories, package versions, scan jobs, findings, paths, and artifact metadata.
Full graph-like payloads are stored as JSON artifacts in the `fvra-artifacts` Docker volume, with Postgres rows holding the content hash, size, node/edge counts, and URI.

## First Workflow

1. Add a project from the Projects page with a Git URL and branch.
2. Seed advisory data into Postgres through repository scripts/tests or future ingestion endpoints.
3. Open the project and run a scan.
4. The worker clones the repo, resolves dependencies, queries advisory data, builds/reuses artifacts, runs reachability, and persists findings.
