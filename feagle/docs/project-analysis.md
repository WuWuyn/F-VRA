# Project Analysis

This module analyzes the application side of reachability with the same
`pyshare_client.callgraph` engine used by package analysis.

Project mode differs only in orchestration: it discovers entry points, walks only
project code reachable from those entry points, and produces a Usage Index
containing external APIs called by reachable code.

```text
Source files
  -> AST + symbol/scope table
  -> import resolver
  -> type graph / points-to / binding analysis
  -> call target resolution
  -> reachable internal graph + external Usage Index
```

Recognized entry-point signals include:

- calls under `if __name__ == "__main__"`
- CLI decorators such as `@app.command`
- web route decorators such as `@app.get` and `@router.post`
- pytest-style test functions in the standalone scanner

The analyzer uses static `ast` parsing, lexical symbol tables, and never executes
project code. It stops at third-party/stdlib boundary nodes; downstream
reachability composes those Usage Index entries with package summaries.

## Python API

Discover entry points:

```python
from pyshare_client.project_analysis import scan_project

entrypoints = scan_project("./myapp")
for entrypoint in entrypoints:
    print(entrypoint.qualified_name, entrypoint.entry_type)
```

Build the reachable project graph and Usage Index:

```python
from pyshare_client.project_analysis import build_project_graph

graph, usage_index = build_project_graph("./myapp")

for edge in graph.edges:
    print(edge.caller.qualified_name, "->", edge.callee.qualified_name)

for external in usage_index:
    print(external.identity_string)
```

Only external calls reached from detected entry points should appear in the
Usage Index. Calls in dead or unreachable helpers should not appear.

## CLI

Build a reachable project graph and Usage Index:

```powershell
pyshare callgraph project .\myapp --sample 20
```

The report includes `edges_detail`, `unresolved_calls`, `candidate_edges`,
`parameter_type_facts`, `entry_points`, and the external Usage Index used by
reachability checks.

## Test

```powershell
pytest tests/unit/test_analysis.py -k project
```

The fixture verifies entry-point discovery, reachable internal edges, external
API usage, and exclusion of an unused external call.
