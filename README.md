# PyShare

PyShare is a Python vulnerability reachability analysis product focused on
mapping CVEs to vulnerable Python functions and checking whether application
usage can reach them.

The project intentionally excludes baseline SCA. Its production scope is:

1. CVE-to-vulnerable-function localization.
2. Vulnerable-function knowledge storage.
3. Package call graphs and `S_i` / `S_o` summaries.
4. Project entry points and external API usage.
5. Compositional vulnerability reachability.

## Modules

| Module | Responsibility | Documentation |
| --- | --- | --- |
| Localization | CVE metadata, patches, AST extraction, candidate retrieval and ranking | [Localization](docs/localization.md) |
| Package analysis | Library call graph, public APIs, `S_i` and `S_o` | [Package analysis](docs/package-analysis.md) |
| Project analysis | Entrypoints, reachable project graph and Usage Index | [Project analysis](docs/project-analysis.md) |
| Reachability | Compose Usage Index and package summaries into paths | [Reachability](docs/reachability.md) |
| Knowledge base | Vulnerable-function records and repository contract | [Knowledge base](docs/knowledge-base.md) |

Other directories such as `reporting`, `storage`, `integrations`, and
`evaluation` are reserved product boundaries. Their module documentation should
be added when they expose runnable behavior.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest
```

Run CVE-to-VF localization:

```powershell
pyshare localize CVE-2023-32681 `
  --auto-resolve-patch `
  --top-k 20 `
  --output .\report.json
```

When `--repository` is omitted or points to a path that does not exist, PyShare
tries to infer a GitHub repository from CVE metadata and clones it into the
repository cache automatically.

LLM and embedding calls use an OpenAI-compatible provider configured through
`LOCAL_LLM_*` and `LOCAL_EMBEDDING_*` environment variables. The local `.env`
can point both chat and embedding traffic at the same `/v1` endpoint.

See the [documentation index](docs/index.md) or the
[localization guide](docs/localization.md)
for environment variables, diagnostics, patch-present and patch-absent modes.

`pyshare scan` is already present as a CLI boundary, but the current scan
service still returns `UNKNOWN` until the project analyzer, KB, and persisted
package-summary loader are wired together. Use the experiment script above for
the runnable transitive reachability check today.

## Repository Layout

```text
pyshare/
|-- README.md
|-- configs/
|-- src/
|-- data/
|   |-- raw/
|   |-- interim/
|   |-- annotations/
|   `-- processed/
|-- artifacts/
|-- experiments/
|-- results/
|   |-- tables/
|   |-- figures/
|   |-- metrics/
|   `-- logs/
|-- tools/
`-- docs/
```

## Source Layout

```text
src/pyshare/
|-- analysis/
|   |-- callgraph/
|   |-- dependencies/
|   |-- package/
|   `-- project/
|-- cli/
|-- core/
|   `-- kb/
|-- cve_vf/
|-- localization/
|   |-- code/
|   |-- providers/
|   |-- ranking/
|   |-- retrieval/
|   `-- sources/
|-- reachability/
|-- reporting/
|-- storage/
|-- integrations/
`-- evaluation/
```

`pyshare` is the single import root. Analysis, localization, reachability,
storage, and CVE/VF helpers live under that package instead of separate
top-level namespaces. API services, workers, web UI, Docker application shells,
and server database adapters are intentionally left out.

For a source-tree import check without installation:

```powershell
$env:PYTHONPATH="src"
python -c "import pyshare; from pyshare.cli.main import app"
```

For a focused reachability regression:

```powershell
pytest tests/unit/test_reachability.py
```

## Jarvis Local Project Scan

Local project scans are controlled by `configs/local_projects.json`. Keep real
project checkouts under `data/raw/projects/` and list them in that manifest;
experiment scripts should not clone arbitrary repositories.

The current manifest contains only:

```text
alerta -> https://github.com/alerta/alerta.git
```

Prepare the local checkout:

```powershell
git clone --depth 1 https://github.com/alerta/alerta.git .\data\raw\projects\alerta
git -C .\data\raw\projects\alerta rev-parse HEAD
```

Jarvis is expected at `tool/Jarvis/jarvis_cli.py` under
`PYSHARE_JARVIS_ROOT`. For the cached pythonJaRvis artifact used locally:

```powershell
$env:PYSHARE_JARVIS_ROOT=".tools/pythonJaRvis/Jarvis"
```

Run Jarvis through Docker's Python 3.8 image:

```powershell
.\.venv\Scripts\python.exe .\experiments\run_jarvis_local_project.py `
  --project-id alerta `
  --runner docker `
  --timeout 300
```

Expected result on the pinned Alerta commit:

```text
PASS jarvis alerta
report: results\metrics\jarvis_alerta_project_graph.json
nodes: 403
edges: 994
usage_index: 36
```

If Docker Desktop is installed but stopped, start it first and confirm:

```powershell
docker info --format "{{.ServerVersion}}"
```

## Legacy SCA Import

Legacy metadata and scanner tooling from
`FPT-University-Lab/feagle@old-sca-tools` is preserved under:

- `tools/`: original SCA runner scripts and helper Dockerfile.
- `data/raw/sca/legacy_inventory/`: imported raw SCA outputs, checkpoints, and summaries.
- `data/raw/metadata/cloned-projects-metadata.json`: imported project inventory.
- `src/pyshare/cve_vf/legacy/`: old advisory/annotation import helpers that still
  depend on the former server database package.
