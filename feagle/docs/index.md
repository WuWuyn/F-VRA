# PyShare Documentation

PyShare maps disclosed vulnerabilities to vulnerable Python functions and
checks whether application usage can reach them.

## Module Documentation

| Module | Responsibility |
| --- | --- |
| [Architecture boundaries](architecture-boundaries.md) | Monorepo package boundaries, client/server runtime rules, and dependency ownership |
| [Localization](localization.md) | Resolve CVE metadata and patches, extract functions, retrieve candidates, and rank vulnerable functions |
| [Package analysis](package-analysis.md) | Build library call graphs, public API indexes, and `S_i` / `S_o` summaries |
| [Project analysis](project-analysis.md) | Discover entry points, build the reachable project graph, and produce the Usage Index |
| [Reachability](reachability.md) | Compose project usage and package summaries into vulnerability paths |
| [Knowledge base](knowledge-base.md) | Define vulnerable-function records and persistence contracts |

## Development

```powershell
pip install -e ".[dev]"
pytest
```

## Command Overview

```powershell
pyshare scan --cve CVE-2024-0000 --project .\myapp --vf package.module.function
pyshare callgraph project .\myapp --sample 20
pyshare callgraph package .\package-src --sample 20
pyshare reachability check --project .\myapp --vf package.module.function --package-report package=.\package-callgraph.json
pyshare-server localize CVE-2024-35195 --top-k 20 --output .\cve-to-vf.json
pyshare-server summaries ingest --package-report .\package-callgraph.json --package package
```
