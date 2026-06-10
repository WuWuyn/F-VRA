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
| Benchmarks | Evaluation fixtures and benchmark layout | [Benchmarks](benchmarks/README.md) |

Other directories such as `reporting`, `storage`, `integrations`, and
`evaluation` are reserved product boundaries. Their module documentation should
be added when they expose runnable behavior.

## Quick Start

```powershell
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

Set `OPENROUTER_RERANK_MODEL` to use a rerank model that is separate from
`OPENROUTER_MODEL`, for example
`nvidia/llama-nemotron-rerank-vl-1b-v2:free`.

See the [documentation index](docs/index.md) or the
[localization guide](docs/localization.md)
for environment variables, diagnostics, patch-present and patch-absent modes.

## Source Layout

```text
src/pyshare/
|-- cli/
|-- core/
|-- kb/
|-- localization/
|-- package_analysis/
|-- project_analysis/
|-- reachability/
|-- reporting/
|-- storage/
|-- integrations/
`-- evaluation/
```

For source-tree smoke checks without installation:

```powershell
$env:PYTHONPATH="src"
python -c "import pyshare; from pyshare.cli.main import app"
```
