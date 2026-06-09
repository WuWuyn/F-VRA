# PyShare

PyShare is a Python vulnerability reachability analysis product focused on
mapping CVEs to vulnerable Python functions and checking whether application
usage can reach them.

This repository intentionally does not implement a baseline SCA scanner. The
production focus is:

1. CVE-to-vulnerable-function localization for Python repositories.
2. Vulnerable-function knowledge base.
3. Package analysis: public APIs, call graph, and S_i / S_o summaries.
4. Project analysis: entry points, imports, usage index, and context.
5. Reachability verdicts and evidence-rich reports.

## Source Layout

```text
src/pyshare/
├── cli/                 # Typer command layer and terminal output
├── core/                # Shared models, config, and errors
├── kb/                  # CVE-to-vulnerable-function repository contracts
├── localization/        # Python VFloc implementation: AST parse + BM25 + optional LLM
├── package_analysis/    # Library call graph and S_i / S_o summary building
├── project_analysis/    # Project entry points, usage index, and project graph
├── reachability/        # Reachability query engine and service boundary
├── reporting/           # Report rendering models and formats
├── storage/             # Cache and persistence helpers
└── integrations/        # External system adapters
```

Legacy Java/replication packages and the Snyk reference CLI tree were removed
from the production workspace. The Python VFloc implementation formerly under
`tests/vfloc-py` has been migrated into `src/pyshare/localization`.

## CLI

```bash
pyshare index requests==2.31.0
pyshare localize CVE-2023-32681
pyshare scan --project ./myapp --cve CVE-2023-32681
pyshare eval --benchmark benchmarks/
pyshare status
```

`localize` currently needs repository/CVE context when called through the Python
service API. The CLI command is kept stable while the KB workflow is wired in.

## Development

```bash
pip install -e ".[dev]"
pytest
```

For source-tree smoke checks without installing:

```bash
PYTHONPATH=src python -c "import pyshare; from pyshare.cli.main import app"
```
