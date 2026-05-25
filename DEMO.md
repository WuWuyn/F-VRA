# PyShare — Demo Quick Start

5-minute walkthrough of the **vf → Fp** pipeline (the graph layer in
this branch). Runs end-to-end against three bundled sample projects
and prints a verdict per project.

---

## What you'll see at the end

```
Sample              Expected      Actual         Pass
------              --------      ------         ----
affected_yaml       AFFECTED      AFFECTED       True
safe_yaml           NOT_AFFECTED  NOT_AFFECTED   True
affected_requests   AFFECTED      AFFECTED       True

3 / 3 samples produced the expected verdict.
```

---

## Prerequisites (one-time setup)

| Tool | Why | How |
|------|-----|-----|
| Python 3.11+ | runtime | https://www.python.org/downloads/ |
| Docker Desktop | hosts Neo4j 5 | https://www.docker.com/products/docker-desktop |
| JARVIS (cloned) | call-graph builder | `git clone https://github.com/pythonJaRvis/pythonJaRvis.github.io.git` |

> Skip Docker if you only want to read the schema / inspect code. The
> CLI degrades to `UNKNOWN` with a clear "Neo4j unreachable" message
> instead of crashing.

---

## Setup (4 commands)

### 1. Install pyshare

```powershell
git clone https://github.com/WuWuyn/pyshare
cd pyshare
git checkout feat/graph-layer
pip install -e .
```

### 2. Start Neo4j

```powershell
docker run -d --name pyshare-neo4j `
    -p 7474:7474 -p 7687:7687 `
    -e NEO4J_AUTH=neo4j/pyshare-dev-pwd `
    neo4j:5-community
```

First pull is ~600 MB / ~2 minutes. Subsequent restarts:
```powershell
docker start pyshare-neo4j
```

### 3. Configure `.env`

Copy the template and fill in the JARVIS path:

```powershell
Copy-Item .env.example .env
# edit .env -- only JARVIS_CLI_PATH usually needs your local path
```

`.env` minimum contents:
```
NEO4J_PASSWORD=pyshare-dev-pwd
JARVIS_CLI_PATH=C:/abs/path/to/pythonJaRvis.github.io/Jarvis/tool/Jarvis/jarvis_cli.py
```

The config loader searches `.env` at CWD, the package dir, parent
dirs, and `~/.pyshare/.env`, so it works from any folder.

### 4. Run the demo

```powershell
./scripts/run_demo.ps1
```

The script will:
1. Check prerequisites (Python, Docker, pyshare CLI, Neo4j container)
2. Seed `~/.pyshare/cve/` with sample CVE entries
3. Provision a `.venv` in each sample project + `pip install` its deps
4. Run `pyshare scan` for each sample
5. Print a pass/fail report

First run takes ~30-60 s (mostly venv creation + JARVIS cold start).
Subsequent runs hit the JARVIS cache and finish in ~5 s.

---

## What the samples demonstrate

| Sample | What it does | vf | Expected |
|--------|--------------|----|----------|
| [affected_yaml](sample_projects/affected_yaml/README.md) | calls `yaml.load(f)` directly | `yaml.load` (CVE-2020-14343) | **AFFECTED** |
| [safe_yaml](sample_projects/safe_yaml/README.md) | only uses `yaml.safe_load` | `yaml.load` (CVE-2020-14343) | **NOT_AFFECTED** |
| [affected_requests](sample_projects/affected_requests/README.md) | calls `Session.request(...)` directly | `requests.sessions.Session.request` (CVE-2024-35195) | **AFFECTED** |

Each sample is ~30 LOC, deliberately minimal so reviewers can trace the
verdict by eye.

---

## Trying it manually (one project at a time)

If `run_demo.ps1` already worked, you can also drive the CLI yourself:

```powershell
pyshare scan `
    --cve CVE-2020-14343 `
    --project sample_projects/affected_yaml `
    --explain
```

Add `--vf "yaml.load"` to bypass the CVE cache (useful when
`pyshare localize` hasn't been wired yet by the Phase 0 owner).

### Portfolio scan (all three at once)

```powershell
pyshare scan --cve CVE-2020-14343 `
    --portfolio examples/portfolio-demo.yaml `
    --vf "yaml.load"
```

Where `examples/portfolio-demo.yaml` lists the three sample paths.

### Inspect the graph in Neo4j Browser

Open http://localhost:7474 (user `neo4j` / password `pyshare-dev-pwd`)
and try:

```cypher
MATCH path = (e:EntryPoint)-[:CALLS*1..5]->(v:Function)
WHERE v.qname = 'yaml.load'
RETURN path
```

You'll see one path for `affected_yaml` and no nodes at all for
`safe_yaml`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Neo.ClientError.Security.Unauthorized -- missing key 'credentials'` | Settings couldn't find `.env` | Check `python -c "from pyshare.core.config import settings; print(settings.env_file_used)"`. Should print a path. If `None`, place `.env` at the repo root. |
| `JARVIS_CLI_PATH is not set` | `.env` missing the var | Add `JARVIS_CLI_PATH=...` to `.env` |
| `JARVIS failed (exit 1)` on a sample | JARVIS hit a project it can't analyse | Pipeline falls back to AST-only mode and still emits a verdict; the note appears in `call_chain[0]`. No action needed for the demo. |
| `Verdict: UNKNOWN` with `No vf found` | CVE cache missing the entry | `run_demo.ps1` seeds the cache automatically; if you ran the CLI manually before that, just rerun the script or copy `sample_projects/cve_cache/*.json` into `~/.pyshare/cve/` |

For deeper architectural docs, see [docs/GRAPH_LAYER.md](docs/GRAPH_LAYER.md).

---

## Stopping Neo4j when you're done

```powershell
docker stop pyshare-neo4j         # graphs persist
# or:
docker rm -f pyshare-neo4j        # delete container + data
```
