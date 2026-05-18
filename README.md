# PyShare

> **Status: In Development**

An end-to-end Vulnerability Reachability Analysis (VRA) framework for the Python/PyPI ecosystem. PyShare determines whether a known CVE in a third-party library actually reaches your application code — eliminating the false positives produced by metadata-only SCA tools.

```
CVE-2024-35195 affects requests==2.31.0

  pip-audit:  ⚠ VULNERABLE  (version match only)
  PyShare:    ✓ NOT AFFECTED (fetch_data() never calls Session.request)
```

---

## How it works

PyShare separates expensive analysis from fast queries into two modes:

**Offline** — run once per library version, results reused forever:
```
PyPI source → [callgraph_builder] Call Graph → [pcsg_indexer] PCSG Index (Si / So)
                                                         stored at ~/.pyshare/index/
```

**Online** — fast query when a new CVE is disclosed:
```
CVE-ID → [cve_localization] locate vf → [project_scanner] scan → [reachability_query] verdict
                                                                          ↑
                                                               reuses Si from index
```

### Storage layers

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Library KG | Neo4j | Raw call graph, path explanation |
| Project KG | Neo4j | Incremental project graph per commit |
| PCSG Index | CSR `.npz` | Precomputed Si/So, O(1) lookup |

---

## Installation

Requirements: Python 3.11+, Neo4j 5.x *(optional, needed for `--explain`)*

```bash
git clone https://github.com/DHATeam/pyshare
cd pyshare
pip install -e ".[dev]"
cp .env.example .env   # set ANTHROPIC_API_KEY, NEO4J_URI
```

---

## Quick start

**Step 1 — Index a library (offline, once per version)**
```bash
pyshare index requests==2.31.0
```

**Step 2 — Localize a CVE (once per CVE)**
```bash
pyshare localize CVE-2024-35195
```

**Step 3 — Scan your project**
```bash
pyshare scan --cve CVE-2024-35195 --project ./myapp
```

Sample output:
```
╔══════════════════════════════╗
║  ⚠  AFFECTED                 ║
╚══════════════════════════════╝

Entry point : myapp/api/client.py::fetch_data
Hit set     : Session.request  ← vf reachable
Query time  : 0.34s  (index lookup, no LLM invoked)
```

---

## CLI reference

```
pyshare index    <pkg==version>  [--force] [--no-llm] [--neo4j]
pyshare localize <CVE-ID>        [--top-k N] [--no-cache]
pyshare scan     --cve <ID>      [--project PATH] [--portfolio FILE]
                                 [--explain] [--format table|json|sarif]
                                 [--output FILE] [--fail-on-affected]
pyshare status   [pkg==version]
pyshare eval     [--benchmark DIR] [--baseline sca|pycg|jarvis|all]
                 [--output DIR] [--format csv|latex]
```

---

## Project structure

```
pyshare/
├── cli/                  # Typer commands (presentation layer only)
│   ├── main.py           # Root app, registers all sub-apps
│   ├── index.py
│   ├── localize.py
│   ├── scan.py
│   ├── status.py
│   ├── eval.py
│   └── _display.py       # Rich output helpers
│
├── core/                 # Shared models & config
│   ├── models.py         # CVERecord, FunctionNode, ScanResult
│   ├── config.py         # Settings via pydantic-settings
│   └── exceptions.py
│
├── pipeline/             # Business logic (no CLI imports)
│   ├── cve_localization/ # CVE → vulnerable function
│   ├── callgraph_builder/# Build library call graph GL
│   ├── pcsg_indexer/     # Transitive closure → Si / So index
│   ├── project_scanner/  # Scan project: UI(P,L) + GP
│   └── reachability_query/ # Reachability query engine
│
├── graph/                # Neo4j layer
│   ├── library_graph.py
│   ├── project_graph.py  # Incremental updates per git commit
│   └── path_explainer.py # --explain call chains
│
├── storage/              # File persistence (.npz, JSON cache)
├── llm/                  # LLM client, prompt templates, cache
├── benchmark/            # PyBM-Python dataset
├── evaluation/           # Metrics, baselines, reporter
└── tests/
```

**Key rule:** `pipeline/` never imports from `cli/`. Business logic takes plain Python objects and returns plain Python objects — testable without any CLI machinery.

---

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Table | *(default)* | Terminal, human-readable |
| JSON | `--format json` | Scripting, CI pipelines |
| SARIF | `--format sarif` | GitHub Code Scanning, GitLab SAST |
