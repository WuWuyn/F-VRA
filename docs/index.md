# PyShare Documentation

PyShare maps disclosed vulnerabilities to vulnerable Python functions and
checks whether application usage can reach them.

## Module Documentation

| Module | Responsibility |
| --- | --- |
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

Benchmark data conventions remain documented next to the data in
[`benchmarks/README.md`](../benchmarks/README.md).
