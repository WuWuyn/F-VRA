# Graph Layer — Setup & Usage

This document covers the end-to-end **vf → Fp** pipeline that this
branch adds (PyShare Phase 3 + Phase 4): given a vulnerable function
qname and a Python project, decide whether the project has a call path
from any entry point to that function.

If you only want to *run* `pyshare scan`, jump to
[Quick Start](#quick-start). Architecture and internals live further
down.

---

## Table of Contents

- [What this layer does](#what-this-layer-does)
- [Quick Start](#quick-start)
- [Setup (one-time)](#setup-one-time)
- [Daily commands](#daily-commands)
- [Architecture](#architecture)
- [File map](#file-map)
- [Tests](#tests)
- [Empirical results (scale verification)](#empirical-results-scale-verification)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)

---

## What this layer does

```
[project + .venv]
       │
       │   1. discover entry .py modules (server.py, app/, manage.py, ...)
       │   2. invoke JARVIS subprocess (with --decy --precision)
       ▼
[jarvis.json]  ─ flat dict {caller_qname: [callee_qname, ...]}
       │
       │   3. parse + classify nodes (app/tpl/stdlib/builtin/...)
       │   4. detect entry points
       │   5. prune noise (builtins, unreachable-from-app)
       ▼
[CallGraph]    ─ typed Python object
       │
       │   6. batch UNWIND into Neo4j
       ▼
[Neo4j G_P]    ─ (:Function), (:EntryPoint:Function), [:CALLS]
       │
       │   7. reachability query: EXISTS path entry → vf
       │   8. (optional) shortest-path explanation
       ▼
[ScanResult]   ─ AFFECTED / NOT_AFFECTED / UNKNOWN
```

Scope of this branch: steps 1–8. Out of scope (other modules): CVE → vf
localization (Phase 0), per-library indexing (Phase 1+2).

---

## Quick Start

After [setup](#setup-one-time), one command:

```bash
pyshare scan \
    --cve CVE-2024-X \
    --project /path/to/project \
    --vf "aiohttp.web_ws.WebSocketResponse.prepare" \
    --explain
```

Output (table):
```
┌──────── ⚠  AFFECTED ────────┐
│ vf: aiohttp.web_ws.WebSocketResponse.prepare
│ Affected entries (1):
│   • server.ws_handler
│ Query time: 521 ms
└──────────────────────────────┘
Call chain
└── server.ws_handler
    └── aiohttp.web_ws.WebSocketResponse.prepare
```

For batch audits:
```bash
pyshare scan --cve CVE-2024-X --portfolio portfolio.yaml
```

For CI gates (exit 1 if any project affected):
```bash
pyshare scan --cve X --project . --vf "..." --fail-on-affected
```

---

## Setup (one-time)

### 1. Python environment

```bash
git checkout feat/graph-layer
pip install -e ".[dev]"
cp .env.example .env
```

### 2. Neo4j (Docker)

```bash
docker run -d --name pyshare-neo4j \
    -p 7474:7474 -p 7687:7687 \
    -e NEO4J_AUTH=neo4j/pyshare-dev-pwd \
    neo4j:5-community
```

Verify:
```bash
docker ps | grep pyshare-neo4j      # status should be 'Up ... (healthy)'
```

Stop / start later:
```bash
docker stop pyshare-neo4j
docker start pyshare-neo4j           # data persists between restarts
```

UI: http://localhost:7474 — login `neo4j` / `pyshare-dev-pwd`.

### 3. JARVIS

Clone (or have ready):
```bash
git clone https://github.com/pythonJaRvis/pythonJaRvis.github.io.git
```

### 4. `.env`

Edit `.env` with absolute paths:

```
ANTHROPIC_API_KEY=
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=pyshare-dev-pwd
JARVIS_CLI_PATH=/abs/path/to/pythonJaRvis.github.io/Jarvis/tool/Jarvis/jarvis_cli.py
```

### 5. Verify

```bash
pytest tests/                                    # 90 tests, ~2s
pytest tests/unit/                               # no Neo4j needed
pytest tests/integration/                        # needs running Neo4j
```

### 6. Each target project needs a venv

JARVIS reads TPL imports from the project's virtualenv. Before scanning
project `X`:

```bash
cd /path/to/X
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# or: .venv/bin/pip install -r requirements.txt                # Unix
```

PyShare auto-detects `<project>/.venv` or `<project>/venv`.

---

## Daily commands

### Single project

```bash
pyshare scan --cve CVE-X --project ./myapp                 # CVE cache lookup
pyshare scan --cve CVE-X --project ./myapp --vf "qname"    # dev override
pyshare scan --cve CVE-X --project ./myapp --explain       # + call chain
pyshare scan --cve CVE-X --project ./myapp --format json   # CI-friendly
```

### Portfolio

Create `portfolio.yaml`:
```yaml
projects:
  - path: /repos/service-a
  - path: /repos/service-b
  - path: /repos/legacy-tool
```

Then:
```bash
pyshare scan --cve CVE-X --portfolio portfolio.yaml
```

### Override auto-detection

If the project layout confuses auto-detect (e.g. `src/` layout, monorepo):
```bash
pyshare scan --cve X --project . --app-pkg mypackage,utils
```

If you've already run JARVIS and don't want re-run:
```bash
pyshare scan --cve X --project . --no-jarvis
# (requires <project>/jarvis.json or .pyshare/jarvis.json to exist)
```

### Inspect Neo4j directly

```bash
# Count nodes per project
docker exec pyshare-neo4j cypher-shell -u neo4j -p pyshare-dev-pwd \
  "MATCH (f:Function) RETURN f.project_id, f.kind, count(f) ORDER BY 1, 2;"

# Find entries reaching a given qname
docker exec pyshare-neo4j cypher-shell -u neo4j -p pyshare-dev-pwd \
  "MATCH (e:EntryPoint)-[:CALLS*1..30]->(v:Function {qname:'aiohttp.X'}) RETURN e.qname;"
```

Or via the Neo4j Browser at http://localhost:7474.

---

## Architecture

### Module responsibilities

| Module | Role |
|--------|------|
| `pipeline/project_scanner/jarvis_runner.py` | subprocess wrapper, venv detection, cache |
| `pipeline/project_scanner/jarvis_parser.py` | JSON → typed CallGraph; classify, prune |
| `pipeline/reachability_query/__init__.py` | end-to-end orchestration; the `query()` API |
| `graph/_driver.py` | Neo4j driver singleton |
| `graph/_schema.py` | constraints + indexes (idempotent) |
| `graph/project_graph.py` | write / delete / exists / node_count (batch UNWIND) |
| `graph/reachability.py` | `is_reachable`, `get_affected_entries`, `find_affected_in_portfolio` |
| `graph/path_explainer.py` | shortest-path Cypher for `--explain` |
| `cli/scan.py` | Typer command + per-result rendering |

### Neo4j schema

```cypher
// Primary label
(:Function {
    project_id:  STRING,
    commit_sha:  STRING,
    qname:       STRING,
    kind:        STRING,    // app | tpl | stdlib | builtin | type_method | unresolved
    is_entry:    BOOLEAN
})

// Dual label — auto-set when is_entry = true
(:EntryPoint:Function {...})

// Edge
(:Function)-[:CALLS {source: STRING}]->(:Function)

// Constraints + indexes (auto-created on first init_schema() call)
CONSTRAINT (project_id, commit_sha, qname) IS UNIQUE
INDEX qname
INDEX (project_id, commit_sha)
INDEX kind
```

**Identity**: `(project_id, commit_sha, qname)` is unique. Multiple
projects coexist; multiple commits of the same project coexist; the
same TPL qname (e.g. `aiohttp.X`) appears once per (project, commit)
because each project has its own slice of TPL functions reached.

**Why dual `:EntryPoint` label** instead of a property filter:
- Cypher reachability queries always start from entries → high query
  frequency → label match is O(1) on bitmap; property filter scans.
- Cypher reads cleaner: `MATCH (e:EntryPoint {project_id: $p})` vs
  `MATCH (e:Function {project_id: $p, is_entry: true})`.

### Classification rules (jarvis_parser.classify)

| Pattern | FuncKind | Example |
|---------|----------|---------|
| `<builtin>.X` | BUILTIN | `<builtin>.print` |
| `<TYPE>.X` (angle prefix) | TYPE_METHOD | `<map>.items`, `<str>.split` |
| No dot at all | UNRESOLVED | `append`, `extend`, `pop` |
| Root in `app_packages` | APP | `server.main` (for `app_packages={"server"}`) |
| Root in `sys.stdlib_module_names` | STDLIB | `os.path.join`, `asyncio.tasks.sleep` |
| Otherwise | TPL | `aiohttp.web.run_app`, `requests.Session.request` |

### App-package detection (priority order)

1. **Explicit override** — `--app-pkg pkg1,pkg2` on CLI.
2. **Filesystem walk** — top-level `.py` files (excluding `setup`,
   `conftest`, `manage`, underscore-prefixed) + folders with
   `__init__.py`. Skips `.venv`, `venv`, `tests`, `docs`, `scripts`,
   `build`, `dist`, `__pycache__`.
3. **JSON auto-detect** — JARVIS module-level keys filtered against
   `sys.stdlib_module_names`. Final fallback only.

### Entry-point heuristic

A function is marked `is_entry = true` if all of:
- kind = APP
- qname has exactly 2 segments (`pkg.func`, not `pkg.Class.method`)
- segment 2 starts with a lowercase letter (Python convention for
  functions; class names start with uppercase)

This catches `server.main`, `server.ws_handler`, `server.health` while
ignoring `server.Player.send`, `server.Game.fire`, etc.

### Pruning

`prune()` does two passes:
1. **Drop noise kinds**: BUILTIN, TYPE_METHOD, UNRESOLVED (none of these
   are CVE targets — built-ins don't have CVEs; bare names are
   unresolved over-approximations).
2. **Reachability filter**: BFS forward from APP nodes; keep only nodes
   reachable from app code.

For operation-deploy: 1228 raw → 151 kept (-87%).
For bpytop: 782 raw → 261 kept (-67%).

### Verdict semantics

| Verdict | Meaning |
|---------|---------|
| `AFFECTED` | Some `:EntryPoint` reaches the vf qname within max_depth (default 30 hops). |
| `NOT_AFFECTED` | No entry reaches vf. Vf may or may not be in the graph at all. |
| `UNKNOWN` | vf could not be resolved (no CVE cache entry, no `--vf`), JARVIS failed, Neo4j unreachable, or some other infrastructure error. The reason is surfaced in `ScanResult.call_chain[0]`. |

---

## File map

```
src/
├── cli/
│   ├── scan.py                              # CLI command (Typer)
│   └── _display.py                          # Rich rendering
├── core/
│   └── config.py                            # +JARVIS_CLI_PATH setting
├── pipeline/
│   ├── project_scanner/
│   │   ├── __init__.py                      # public re-exports
│   │   ├── jarvis_parser.py                 # JSON → CallGraph
│   │   └── jarvis_runner.py                 # subprocess wrapper
│   └── reachability_query/
│       └── __init__.py                      # query() orchestration
└── graph/
    ├── __init__.py                          # public re-exports
    ├── _driver.py                           # Neo4j driver singleton
    ├── _schema.py                           # constraints + indexes
    ├── project_graph.py                     # write/delete/exists
    ├── reachability.py                      # is_reachable + portfolio
    └── path_explainer.py                    # shortestPath

tests/
├── unit/                                    # 67 tests, no I/O
│   ├── test_jarvis_parser.py                # 33 tests
│   └── test_jarvis_runner.py                # 12 tests
├── integration/                             # 23 tests, needs Neo4j
│   ├── conftest.py
│   ├── test_project_graph.py                # 8 tests
│   └── test_reachability.py                 # 15 tests (incl 4 portfolio)
└── e2e/                                     # CLI runner

examples/
├── portfolio.yaml                           # 2-project example
└── portfolio-scale.yaml                     # scale-test fixture

scripts/
├── demo_e2e.py                              # canonical 5-vf demo
└── demo_load_graph.py                       # parser + Neo4j writer demo
```

---

## Tests

```bash
pytest                                       # all 90 tests
pytest tests/unit/                           # 67 tests, no Neo4j
pytest tests/integration/                    # 23 tests, needs Neo4j
pytest tests/integration/ -k portfolio       # just bulk-query tests
pytest --cov=src/pyshare --cov-report=term-missing
```

Integration tests **auto-skip** if Neo4j is unreachable, so the suite
still passes on machines without Docker.

---

## Empirical results (scale verification)

Verified on three real projects:

### Single-project (operation-deploy, aiohttp websocket server)

5 vf candidates, all verdicts correct:

| vf | Verdict | Chain |
|----|---------|-------|
| `aiohttp.web_ws.WebSocketResponse.prepare` | AFFECTED | 2 hops |
| `aiohttp.web_ws.WebSocketResponse.send_str` | AFFECTED | 3 hops |
| `aiohttp.web.run_app` | AFFECTED | 2 hops |
| `base64.b64decode` (deep transitive) | AFFECTED | 5 hops |
| `requests.sessions.Session.request` | NOT_AFFECTED | — |

### Single-project (bpytop, JARVIS paper benchmark, 5687 LOC)

| Metric | Value |
|--------|------:|
| JARVIS cold run | ~4s |
| Raw nodes | 782 |
| After prune | 261 |
| Cached query | ~526 ms |

Sample verdicts on bpytop:
- `subprocess.check_output` → AFFECTED via 3 entries (correct — bpytop
  uses it directly)
- `subprocess.run` → AFFECTED via internal chain
  `check_output → run` (correct — JARVIS traced subprocess internals)
- `re.compile` → NOT_AFFECTED (JARVIS doesn't trace `re.sub` internals
  on this version — limitation)
- `requests.*`, `aiohttp.*` → NOT_AFFECTED (correct — not imported)

### Portfolio (bpytop + operation-deploy, vf = `subprocess.check_output`)

```
⚠ AFFECTED      bpytop              3 entries     526 ms
✓ NOT_AFFECTED  operation-deploy    0             95 ms
Total: 2 projects | 1 AFFECTED | 1 NOT_AFFECTED
```

→ Portfolio aggregation correctly distinguishes affected vs unaffected.

---

## Known limitations

These are **JARVIS limitations** that propagate into our verdicts; not
bugs in this layer.

1. **C extension dependencies are not traced.** E.g. `psutil` is a
   hybrid (Python wrapper + C core). JARVIS only follows pure-Python
   imports, so `psutil.Process.X` qnames will not appear in the graph
   and queries against them return NOT_AFFECTED even when the project
   *does* import psutil. Workaround: if you need C-ext analysis, use
   a stricter tool or document the gap.

2. **Internal callees of TPL functions are sometimes missed.** Example:
   bpytop calls `re.sub(...)`. JARVIS records the edge
   `bpytop.X → re.sub` but doesn't necessarily expand the chain
   `re.sub → re.compile` if `re.sub`'s internal flow doesn't statically
   resolve. So `re.compile` may show NOT_AFFECTED.

3. **JARVIS occasionally crashes on certain projects** (we saw
   `AttributeError: 'NoneType' object has no attribute
   'analyze_localfunction'` on TextRank4ZH). Our pipeline catches this
   and returns UNKNOWN with the JARVIS stderr in `call_chain[0]` — no
   silent false negative.

4. **Framework callback registration via decorators isn't fully
   captured** in all cases. Works for aiohttp's `app.router.add_get`
   (JARVIS does pick up `ws_handler` as an entry). Other frameworks
   may need explicit `--app-pkg` and/or entry-module hints.

5. **JARVIS bug `--entry_point` flag is ignored.** Reading
   `jarvis_cli.py`, the flag is declared but `args.entry_point` is
   never passed into `CallGraphGenerator`. We mark entry points
   downstream (parser + Neo4j) instead.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `verdict: UNKNOWN, reason: Neo4j unreachable` | Container stopped | `docker start pyshare-neo4j` |
| `verdict: UNKNOWN, reason: Unauthorized` | Password mismatch | Check `.env` matches container `NEO4J_AUTH` |
| `verdict: UNKNOWN, reason: No vf found` | No `--vf` given and no CVE cache entry | Either `--vf "qname"` directly, or wait for Phase 0 |
| `verdict: UNKNOWN, reason: JARVIS_CLI_PATH not set` | `.env` missing path | Edit `.env` (`JARVIS_CLI_PATH=...`) |
| `verdict: UNKNOWN, reason: JARVIS failed` | JARVIS crashed on this project | Check `call_chain[0]` for JARVIS stderr; may need to pass specific entry modules |
| `verdict: NOT_AFFECTED` but you expected AFFECTED | qname mismatch (different namespace than JARVIS uses), or hits a known JARVIS limitation | Inspect Neo4j directly: `MATCH (f:Function) WHERE f.qname CONTAINS '<keyword>' RETURN f.qname` to see what's in the graph |
| Cold run is slow (~5s on big projects) | First-time JARVIS subprocess | Subsequent runs use cached `<project>/.pyshare/jarvis.json` (~0.5 ms cache hit). Pass `--force-jarvis` to invalidate (not yet exposed — delete the file manually) |
| Tests fail with `OpenBLAS error` on Windows | numpy thread allocation | Run with `OPENBLAS_NUM_THREADS=1` |

---

## Open work / handover to next person

- **PyCG parser fallback** — useful when JARVIS crashes (see TextRank4ZH case).
- **SARIF output format** — for GitHub Code Scanning integration.
- **Incremental update per git commit** — paper's optimization claim; current implementation re-indexes from scratch on each commit change.
- **`pyshare index` command** for Phase 1+2 per-library indexing.
- **Coordinate with Phase 0 owner** on CVE-cache JSON schema. Current assumption: `{"vf": "qname.string"}` at `~/.pyshare/cve/<CVE>.json`.
