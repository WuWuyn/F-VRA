# Package Analysis

This module statically analyzes Python library source with the shared
`pyshare_client.callgraph` engine. Package mode is exhaustive: every discovered
function and method is analyzed so the resulting library graph is complete for
that source root. It identifies public APIs and derives:

- `S_i`: internal functions reachable from each public API.
- `S_o`: external symbols reachable from each public API.

The shared pipeline is:

```text
Source files
  -> AST + symbol/scope table
  -> import resolver
  -> type graph / points-to / binding analysis
  -> call target resolution
  -> internal graph + external boundary graph
```

It parses source with `ast`, builds lexical symbol tables with Python's
`symtable`, and does not import or execute the target package.

## Python API

High-level source indexing:

```python
from pyshare_client.package_analysis import index_source

result = index_source(
    "./requests",
    package="requests",
    version="2.30.0",
)

print(result.functions)
print(result.api_count)
```

Inspect the graph and summaries:

```python
from pyshare_client.package_analysis.callgraph import LibraryAnalyzer
from pyshare_client.package_analysis.summary import build_library_summary

analyzer = LibraryAnalyzer()
graph = analyzer.build_library_graph("./requests")
summary = build_library_summary(graph, analyzer.index.public_api)

print(summary.inner_summary)
print(summary.outer_summary)
```

`CallGraph` keeps one unified graph, and exposes `internal_edges` plus
`external_edges` views when callers need to separate first-party calls from
third-party/stdlib boundary calls.

## CLI

Build an exhaustive package/library call graph for a source root:

```powershell
pyshare callgraph package .\requests --sample 20
```

Resolve dependencies from Python manifests/lockfiles, then build package call
graph reports for packages with source available in the active environment:

```powershell
pyshare deps resolve . --output .\pyshare-dependencies.json

pyshare deps build-callgraphs `
  --dependency-report .\pyshare-dependencies.json `
  --output-dir .\package-callgraphs `
  --limit 20
```

`pyshare deps resolve` reads supported Python inputs such as `pyproject.toml`,
`poetry.lock`, `uv.lock`, `Pipfile.lock`, and `requirements*.txt`. Lockfiles
produce resolved versions; plain manifests may only produce version
constraints.

## Test

```powershell
pytest tests/unit/test_analysis.py -k package
```

Expected checks include internal call edges, external call edges, `S_i`, and
`S_o`.
