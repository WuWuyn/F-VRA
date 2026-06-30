# Reachability

This module composes:

- the project Usage Index
- package `S_i` and `S_o` summaries
- known vulnerable-function names

It performs path-aware breadth-first search and returns concrete paths that
reach a vulnerable function.

Transitive traversal follows `S_o` package boundaries until a vulnerable
function is found, no package summary is available, or the configured depth is
reached. Cycle detection is local to each path, so distinct callers that
converge on the same package API remain distinct witness paths.

`QueryReport.unresolved_targets` records package APIs that could not be expanded
because a summary/API key was missing or the depth limit was reached.
Reachability reports classify unresolved targets as target-related or unrelated:
only target-related uncertainty can produce `potentially_reachable`.

## Python API

```python
from pyshare_core.models import ExternalNode, LibrarySummary
from pyshare_client.reachability.engine import ReachabilityQueryEngine

usage_index = [
    ExternalNode(
        file_path="<external:sample>",
        function_name="sample.public_api",
        qualified_name="sample.public_api",
        target_module="sample",
        target_name="public_api",
    )
]

summaries = {
    "sample": LibrarySummary(
        inner_summary={
            "sample.public_api": {"sample.Client.fetch"},
        },
        outer_summary={
            "sample.public_api": {"requests.get"},
        },
    )
}

report = ReachabilityQueryEngine(
    usage_index,
    summaries,
    vulnerabilities={"requests.get"},
    max_depth=25,
    max_paths=100,
).check_reachability()

print(report.is_vulnerable)
for path in report.paths:
    print(" -> ".join(path.tpl_chain))
```

The engine checks direct vulnerable calls before summary expansion, then
follows `S_o` across package boundaries. Vulnerabilities can match either
internal `S_i` functions or external `S_o` targets. Exact qualified names are
preferred, with component-aligned suffix matching for localization/call-graph
qualification differences.

## Scan Service

Run direct reachability from a project to a known vulnerable function:

```powershell
pyshare scan `
  --cve CVE-2024-0000 `
  --project .\myapp `
  --vf vulnerable_package.module.function `
  --explain
```

The Python service accepts a map of `LibrarySummary` objects through its
`summaries` argument to enable transitive package-to-package traversal. The
`reachability check` command is the report-driven CLI path for supplying package
summaries explicitly.

## CLI

Run project-to-package transitive reachability directly from source plus
package call graph reports:

```powershell
pyshare reachability check `
  --project .\myapp `
  --vf vulnerable.package.function `
  --package-report alpha=.\alpha-callgraph-package.json `
  --package-report beta=.\beta-callgraph-package.json `
  --package-report vulnerable=.\vulnerable-callgraph-package.json `
  --explain `
  --format json
```

`--package-report` uses `ROOT=PATH`. `ROOT` is the import root used to route
outer-summary hops, for example `requests`, `yaml`, or `werkzeug`. Vulnerable
functions can be passed repeatedly with `--vf` or loaded from a JSON/JSONL file
with `--vf-file`.

Package call graph reports can include static root re-export metadata in
`public_api_aliases`, for example `{"flash": "helpers.flash"}`. When the report
is loaded as `flask=...`, the reachability service expands that alias to
`flask.flash` and reuses the summary for `helpers.flash`. This is generic for
normal `__init__.py` re-exports such as `from .helpers import flash`; dynamic
exports (`__getattr__`, runtime monkey-patching, highly dynamic `*` exports)
remain conservative limitations.

Find concrete paths from a project call graph JSON to one or more targets:

```powershell
pyshare reachability paths `
  --project-report artifacts/fe-agents-callgraph-project.json `
  --target argparse.ArgumentParser `
  --sample 10
```

Write the path report:

```powershell
pyshare reachability paths `
  --project-report artifacts/fe-agents-callgraph-project.json `
  --target argparse.ArgumentParser `
  --output artifacts/fe-agents-reachable-paths.json
```

You can also provide package graph reports to compose supply-chain paths through
package summaries:

```powershell
pyshare reachability paths `
  --project-report artifacts/app-callgraph-project.json `
  --package-report artifacts/pkg-callgraph-package.json `
  --target vulnerable.package.function
```

Resolve direct + transitive dependencies from Python manifests/lockfiles:

```powershell
pyshare deps resolve . --output artifacts/fe-agents-dependencies.json
```

Build package call graph reports for the resolved dependency tree:

```powershell
pyshare deps build-callgraphs `
  --dependency-report artifacts/fe-agents-dependencies.json `
  --output-dir artifacts/fe-agents-package-callgraphs `
  --limit 20
```

The dependency hot path is intentionally split into an SCA-style inventory step
and a package-summary build step.

`pyshare scan` is the CVE-oriented client command. `pyshare reachability check`
is the explicit report-driven command for structural reachability experiments
and CI validation.

## Test

```powershell
pytest tests/unit/test_reachability.py
```

Tests cover direct vulnerable usage, multi-package transitive expansion,
converging paths, cycles, path limits, and suffix-matched internal sinks.
