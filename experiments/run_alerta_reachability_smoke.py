from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from pyshare_analysis.callgraph.jarvis_backend import (  # noqa: E402
    JarvisOptions,
    build_jarvis_project_graph,
)
from pyshare_analysis.dependencies.resolver import resolve_dependency_graph  # noqa: E402
from pyshare_core.models import LibrarySummary  # noqa: E402
from pyshare_reachability.engine import ReachabilityQueryEngine  # noqa: E402
from pyshare_reachability.service import _graph_artifact, _with_project_callers  # noqa: E402


def _resolve(path_value: str | Path) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else REPO_ROOT / path


def _json_default(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _project_from_manifest(path: Path, project_id: str) -> dict[str, Any]:
    manifest = _load_json(path)
    for project in manifest.get("projects", []):
        if project.get("id") == project_id:
            return project
    raise RuntimeError(f"project is not listed in local manifest: {project_id}")


def _default_jarvis_root() -> Path | None:
    env_value = os.getenv("PYSHARE_JARVIS_ROOT")
    if env_value:
        return _resolve(env_value)
    bundled = REPO_ROOT / ".tools" / "pythonJaRvis" / "Jarvis"
    return bundled if (bundled / "tool" / "Jarvis" / "jarvis_cli.py").exists() else None


def _node_name(node: Any) -> str:
    return getattr(node, "qualified_name", "") or getattr(node, "function_name", "")


def _graph_snapshot(graph: Any, usage_index: list[Any]) -> dict[str, Any]:
    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "internal_edges": len(graph.internal_edges),
        "external_edges": len(graph.external_edges),
        "entry_points": graph.metadata.get("entry_points", []),
        "usage_index": [
            {
                "identity": node.identity_string,
                "target_module": node.target_module,
                "target_name": node.target_name,
            }
            for node in usage_index
        ],
        "edges_detail": [
            {
                "caller": _node_name(edge.caller),
                "callee": _node_name(edge.callee),
                "callee_type": "external" if edge.callee.is_external else "internal",
                "resolver": getattr(edge, "resolver", ""),
                "edge_type": getattr(edge, "edge_type", ""),
                "confidence": getattr(edge, "confidence", 0.0),
            }
            for edge in graph.edges
        ],
    }


def _report_dict(report: Any, graph: Any) -> dict[str, Any]:
    report.paths = _with_project_callers(report.paths, graph)
    return {
        "is_vulnerable": report.is_vulnerable,
        "hit_set": sorted({path.vulnerable_target for path in report.paths}),
        "paths": [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in report.paths
        ],
        "unresolved_targets": report.unresolved_targets,
        "unresolved_frontier": report.unresolved_frontier,
        "used_summaries": report.used_summaries,
    }


def _choose_demo_vf(usage_index: list[Any], requested: str = "") -> str:
    identities = sorted(node.identity_string for node in usage_index if node.identity_string)
    if requested:
        if requested not in identities:
            raise RuntimeError(f"requested VF is not in Usage Index: {requested}")
        return requested
    for preferred in ("requests.get", "flask.jsonify", "flask.Response", "click.echo"):
        if preferred in identities:
            return preferred
    if not identities:
        raise RuntimeError("Usage Index is empty; cannot choose a demo VF")
    return identities[0]


def run(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    project = _project_from_manifest(_resolve(args.local_projects), args.project_id)
    project_root = _resolve(project["path"])
    if not project_root.exists():
        raise RuntimeError(f"project path does not exist: {project_root}")

    jarvis_root = _resolve(args.jarvis_root) if args.jarvis_root else _default_jarvis_root()
    if jarvis_root is None:
        raise RuntimeError("Jarvis root not found; set PYSHARE_JARVIS_ROOT or pass --jarvis-root")

    output_dir = _resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    graph, usage_index = build_jarvis_project_graph(
        project_root,
        JarvisOptions(
            jarvis_root=jarvis_root,
            runner=args.runner,
            scope=args.scope,
            mode=args.mode,
            timeout_s=args.timeout,
        ),
    )
    _write_json(output_dir / "project_graph_artifact.json", _graph_artifact(project_root, graph, usage_index))
    _write_json(output_dir / "project_graph_snapshot.json", _graph_snapshot(graph, usage_index))

    dependency_graph = resolve_dependency_graph(project_root)
    _write_json(output_dir / "dependency_graph.json", dependency_graph)

    direct_vf = _choose_demo_vf(usage_index, args.direct_vf)
    direct_report = ReachabilityQueryEngine(usage_index, {}, {direct_vf}).check_reachability()
    direct_payload = {
        "mode": "direct_demo",
        "assumption": f"Treat real Usage Index symbol {direct_vf!r} as the vulnerable function.",
        "vulnerable_target": direct_vf,
        **_report_dict(direct_report, graph),
    }
    _write_json(output_dir / "reachability_direct_demo.json", direct_payload)

    root, _, api_tail = direct_vf.partition(".")
    transitive_vf = args.transitive_vf
    summary = LibrarySummary(
        outer_summary={direct_vf: {transitive_vf}},
        outer_paths={direct_vf: {transitive_vf: [direct_vf, transitive_vf]}},
    )
    transitive_report = ReachabilityQueryEngine(
        usage_index,
        {root: summary},
        {transitive_vf},
    ).check_reachability()
    transitive_payload = {
        "mode": "transitive_demo",
        "assumption": (
            f"Treat package API {direct_vf!r} as reaching mocked vulnerable "
            f"function {transitive_vf!r}."
        ),
        "mock_summary": {
            "root": root,
            "api": direct_vf,
            "outer_target": transitive_vf,
        },
        "vulnerable_target": transitive_vf,
        **_report_dict(transitive_report, graph),
    }
    _write_json(output_dir / "reachability_transitive_demo.json", transitive_payload)

    summary_payload = {
        "project": project,
        "output_dir": str(output_dir),
        "elapsed_s": round(time.perf_counter() - started, 3),
        "counts": {
            "project_nodes": len(graph.nodes),
            "project_edges": len(graph.edges),
            "usage_index": len(usage_index),
            "dependencies": len(dependency_graph.dependencies),
            "direct_paths": len(direct_payload["paths"]),
            "transitive_paths": len(transitive_payload["paths"]),
        },
        "demo_targets": {
            "direct_vf": direct_vf,
            "transitive_vf": transitive_vf,
        },
        "artifacts": [
            "project_graph_artifact.json",
            "project_graph_snapshot.json",
            "dependency_graph.json",
            "reachability_direct_demo.json",
            "reachability_transitive_demo.json",
            "summary.json",
        ],
    }
    _write_json(output_dir / "summary.json", summary_payload)

    print(f"PASS alerta reachability smoke")
    print(f"run_dir: {output_dir.relative_to(REPO_ROOT)}")
    print(f"dependency_count: {len(dependency_graph.dependencies)}")
    print(f"usage_index_count: {len(usage_index)}")
    print(f"direct_vf: {direct_vf} paths={len(direct_payload['paths'])}")
    print(f"transitive_vf: {transitive_vf} paths={len(transitive_payload['paths'])}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a small Alerta reachability smoke pipeline.")
    parser.add_argument("--project-id", default="alerta")
    parser.add_argument("--local-projects", type=Path, default=REPO_ROOT / "configs" / "local_projects.json")
    parser.add_argument("--jarvis-root", type=Path, default=None)
    parser.add_argument("--runner", choices=["docker", "local"], default="docker")
    parser.add_argument("--scope", choices=["entrypoints", "whole-project", "whole_project", "all"], default="entrypoints")
    parser.add_argument("--mode", choices=["EA", "DW", "AW"], default="EA")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--direct-vf", default="")
    parser.add_argument("--transitive-vf", default="mock_vuln.demo_sink")
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "artifacts" / "pipeline_runs" / "alerta_reachability_smoke")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
