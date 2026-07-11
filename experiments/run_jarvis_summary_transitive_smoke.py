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

from pyshare.analysis.callgraph.jarvis_backend import (  # noqa: E402
    JarvisOptions,
    build_jarvis_project_graph,
)
from pyshare.core.models import LibrarySummary  # noqa: E402
from pyshare.reachability.engine import ReachabilityQueryEngine  # noqa: E402
from pyshare.reachability.service import (  # noqa: E402
    _graph_artifact,
    _with_project_callers,
    decide_reachability_verdict,
)


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
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8",
    )


def _default_jarvis_root() -> Path | None:
    env_value = os.getenv("PYSHARE_JARVIS_ROOT")
    if env_value:
        return _resolve(env_value)
    bundled = REPO_ROOT / ".tools" / "pythonJaRvis" / "Jarvis"
    return bundled if (bundled / "tool" / "Jarvis" / "jarvis_cli.py").exists() else None


def _usage_summary(graph: Any, usage_index: list[Any]) -> dict[str, Any]:
    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "internal_edges": len(graph.internal_edges),
        "external_edges": len(graph.external_edges),
        "usage_index_count": len(usage_index),
        "entry_points": graph.metadata.get("entry_points", []),
        "metadata": graph.metadata,
        "usage_index": [
            {
                "identity": node.identity_string,
                "target_module": node.target_module,
                "target_name": node.target_name,
            }
            for node in usage_index
        ],
    }


def _module_root(identity: str) -> str:
    return identity.split(".", 1)[0] if identity else ""


def _mock_summary_for_usage(usage_identity: str) -> tuple[str, LibrarySummary, str]:
    root = _module_root(usage_identity)
    if not root:
        raise ValueError(f"cannot derive package root from usage identity: {usage_identity!r}")
    api = usage_identity
    helper = f"{root}.__pyshare_mock_helper"
    vf = f"{root}.__pyshare_mock_vf"
    summary = LibrarySummary(
        inner_summary={api: {helper, vf}},
        outer_summary={api: set()},
        inner_paths={api: {helper: [api, helper], vf: [api, helper, vf]}},
        outer_paths={api: {}},
        diagnostics={
            "mock": True,
            "purpose": "transitive summary smoke test",
            "source_usage_identity": usage_identity,
        },
    )
    return root, summary, vf


def _mock_transitive_summaries_for_usage(
    usage_identity: str,
) -> tuple[dict[str, LibrarySummary], str, dict[str, str]]:
    root = _module_root(usage_identity)
    if not root:
        raise ValueError(f"cannot derive package root from usage identity: {usage_identity!r}")
    package_b = f"{root}_mock_b"
    package_c = f"{root}_mock_c"
    b_api = f"{package_b}.public_api"
    c_api = f"{package_c}.public_api"
    vf = f"{package_c}.vulnerable_function"

    summaries = {
        root: LibrarySummary(
            inner_summary={usage_identity: set()},
            outer_summary={usage_identity: {b_api}},
            inner_paths={usage_identity: {}},
            outer_paths={usage_identity: {b_api: [usage_identity, b_api]}},
            diagnostics={
                "mock": True,
                "purpose": "transitive A->B edge",
                "source_usage_identity": usage_identity,
            },
        ),
        package_b: LibrarySummary(
            inner_summary={b_api: set()},
            outer_summary={b_api: {c_api}},
            inner_paths={b_api: {}},
            outer_paths={b_api: {c_api: [b_api, c_api]}},
            diagnostics={
                "mock": True,
                "purpose": "transitive B->C edge",
            },
        ),
        package_c: LibrarySummary(
            inner_summary={c_api: {vf}},
            outer_summary={c_api: set()},
            inner_paths={c_api: {vf: [c_api, vf]}},
            outer_paths={c_api: {}},
            diagnostics={
                "mock": True,
                "purpose": "transitive C->VF edge",
            },
        ),
    }
    chain = {
        "package_a": root,
        "package_b": package_b,
        "package_c": package_c,
        "usage_identity": usage_identity,
        "b_api": b_api,
        "c_api": c_api,
        "vf": vf,
    }
    return summaries, vf, chain


def _select_usage_identity(usage_index: list[Any], preferred_root: str = "") -> str:
    identities = sorted({node.identity_string for node in usage_index if node.identity_string})
    if preferred_root:
        for identity in identities:
            if _module_root(identity).lower() == preferred_root.lower():
                return identity
    if not identities:
        raise RuntimeError("Jarvis produced an empty usage index; cannot build a summary smoke target")
    return identities[0]


def run(args: argparse.Namespace) -> int:
    project_root = _resolve(args.project_root)
    if not project_root.exists():
        raise RuntimeError(f"project root does not exist: {project_root}")

    run_dir = _resolve(args.output_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    jarvis_root = _resolve(args.jarvis_root) if args.jarvis_root else _default_jarvis_root()
    if jarvis_root is None:
        raise RuntimeError("Jarvis root not found; set PYSHARE_JARVIS_ROOT or pass --jarvis-root")

    manifest = {
        "project_root": str(project_root),
        "jarvis_root": str(jarvis_root),
        "runner": args.runner,
        "scope": args.scope,
        "mode": args.mode,
        "started_at_epoch": time.time(),
    }
    _write_json(run_dir / "manifest.json", manifest)

    graph, usage_index = build_jarvis_project_graph(
        project_root,
        JarvisOptions(
            jarvis_root=jarvis_root,
            runner=args.runner,
            scope=args.scope,
            mode=args.mode,
            timeout_s=args.timeout,
            pip_install=args.pip_install,
        ),
    )
    _write_json(run_dir / "project_graph_jarvis.json", _graph_artifact(project_root, graph, usage_index))
    _write_json(run_dir / "usage_index.json", _usage_summary(graph, usage_index))

    usage_identity = _select_usage_identity(usage_index, args.preferred_root)
    root, summary, mock_vf = _mock_summary_for_usage(usage_identity)
    direct_summaries = {root: summary}
    _write_json(run_dir / "package_summaries" / f"{root}.json", summary)
    transitive_summaries, transitive_vf, transitive_chain = _mock_transitive_summaries_for_usage(
        usage_identity
    )
    for transitive_root, transitive_summary in transitive_summaries.items():
        _write_json(
            run_dir / "transitive_package_summaries" / f"{transitive_root}.json",
            transitive_summary,
        )
    _write_json(
        run_dir / "mock_vf.json",
        {
            "package_root": root,
            "usage_identity": usage_identity,
            "mock_vf": mock_vf,
            "transitive_chain": transitive_chain,
            "note": "VFs are intentionally synthetic; transitive_chain verifies Project->A->B->C->VF composition.",
        },
    )

    query_report = ReachabilityQueryEngine(
        usage_index,
        direct_summaries,
        {mock_vf},
        max_depth=args.max_depth,
        max_paths=args.max_paths,
    ).check_reachability()
    verdict, uncertainty = decide_reachability_verdict(
        query_report,
        {mock_vf},
        direct_summaries,
        usage_index,
        graph_metadata=graph.metadata,
    )
    query_report.paths = _with_project_callers(query_report.paths, graph)

    transitive_report = ReachabilityQueryEngine(
        usage_index,
        transitive_summaries,
        {transitive_vf},
        max_depth=args.max_depth,
        max_paths=args.max_paths,
    ).check_reachability()
    transitive_verdict, transitive_uncertainty = decide_reachability_verdict(
        transitive_report,
        {transitive_vf},
        transitive_summaries,
        usage_index,
        graph_metadata=graph.metadata,
    )
    transitive_report.paths = _with_project_callers(transitive_report.paths, graph)

    partial_summaries = {
        key: value
        for key, value in transitive_summaries.items()
        if key != transitive_chain["package_b"]
    }
    partial_report = ReachabilityQueryEngine(
        usage_index,
        partial_summaries,
        {transitive_vf},
        max_depth=args.max_depth,
        max_paths=args.max_paths,
    ).check_reachability()
    partial_verdict, partial_uncertainty = decide_reachability_verdict(
        partial_report,
        {transitive_vf},
        partial_summaries,
        usage_index,
        graph_metadata=graph.metadata,
    )
    partial_report.paths = _with_project_callers(partial_report.paths, graph)

    reachability = {
        "verdict": verdict.value,
        "mock_vf": mock_vf,
        "usage_identity": usage_identity,
        "hit_set": sorted({path.vulnerable_target for path in query_report.paths}),
        "paths": [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in query_report.paths
        ],
        "unresolved_targets": query_report.unresolved_targets,
        "unresolved_frontier": query_report.unresolved_frontier,
        "used_summaries": query_report.used_summaries,
        "uncertainty": uncertainty,
    }
    _write_json(run_dir / "reachability_report.json", reachability)
    transitive_reachability = {
        "verdict": transitive_verdict.value,
        "mock_vf": transitive_vf,
        "chain": transitive_chain,
        "hit_set": sorted({path.vulnerable_target for path in transitive_report.paths}),
        "paths": [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in transitive_report.paths
        ],
        "unresolved_targets": transitive_report.unresolved_targets,
        "unresolved_frontier": transitive_report.unresolved_frontier,
        "used_summaries": transitive_report.used_summaries,
        "uncertainty": transitive_uncertainty,
    }
    _write_json(run_dir / "transitive_reachability_report.json", transitive_reachability)
    partial_reachability = {
        "verdict": partial_verdict.value,
        "mock_vf": transitive_vf,
        "omitted_summary": transitive_chain["package_b"],
        "loaded_summaries": sorted(partial_summaries),
        "paths": [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in partial_report.paths
        ],
        "unresolved_targets": partial_report.unresolved_targets,
        "unresolved_frontier": partial_report.unresolved_frontier,
        "used_summaries": partial_report.used_summaries,
        "uncertainty": partial_uncertainty,
    }
    _write_json(run_dir / "transitive_missing_middle_summary_report.json", partial_reachability)

    summary_payload = {
        "project_root": str(project_root),
        "artifacts": {
            "manifest": str(run_dir / "manifest.json"),
            "project_graph": str(run_dir / "project_graph_jarvis.json"),
            "usage_index": str(run_dir / "usage_index.json"),
            "package_summary": str(run_dir / "package_summaries" / f"{root}.json"),
            "transitive_package_summaries": str(run_dir / "transitive_package_summaries"),
            "mock_vf": str(run_dir / "mock_vf.json"),
            "reachability": str(run_dir / "reachability_report.json"),
            "transitive_reachability": str(run_dir / "transitive_reachability_report.json"),
            "transitive_missing_middle_summary": str(run_dir / "transitive_missing_middle_summary_report.json"),
        },
        "counts": {
            "project_nodes": len(graph.nodes),
            "project_edges": len(graph.edges),
            "usage_index": len(usage_index),
            "paths": len(query_report.paths),
            "transitive_paths": len(transitive_report.paths),
            "partial_transitive_paths": len(partial_report.paths),
        },
        "mock": {
            "package_root": root,
            "usage_identity": usage_identity,
            "vf": mock_vf,
            "transitive_chain": transitive_chain,
        },
        "verdict": verdict.value,
        "transitive_verdict": transitive_verdict.value,
        "missing_middle_summary_verdict": partial_verdict.value,
        "used_summaries": query_report.used_summaries,
        "transitive_used_summaries": transitive_report.used_summaries,
    }
    _write_json(run_dir / "summary.json", summary_payload)
    _write_json(
        REPO_ROOT / "results" / "metrics" / f"{args.project_id}_jarvis_summary_transitive_smoke.json",
        summary_payload,
    )

    print(f"PASS jarvis-summary-transitive {args.project_id}")
    print(f"run_dir: {run_dir.relative_to(REPO_ROOT)}")
    print(f"project: nodes={len(graph.nodes)} edges={len(graph.edges)} usage_index={len(usage_index)}")
    print(f"mock_vf: {mock_vf}")
    print(f"usage_identity: {usage_identity}")
    print(f"reachability: verdict={verdict.value} paths={len(query_report.paths)} used_summaries={query_report.used_summaries}")
    print(
        "transitive: "
        f"verdict={transitive_verdict.value} "
        f"paths={len(transitive_report.paths)} "
        f"used_summaries={transitive_report.used_summaries}"
    )
    print(
        "missing_middle_summary: "
        f"verdict={partial_verdict.value} "
        f"paths={len(partial_report.paths)} "
        f"unresolved_frontier={partial_report.unresolved_frontier}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Jarvis on one local repo and verify transitive summary composition with a mock VF."
    )
    parser.add_argument("--project-id", default="alerta__alerta")
    parser.add_argument("--project-root", type=Path, default=REPO_ROOT / "data" / "raw" / "projects" / "alerta__alerta")
    parser.add_argument("--jarvis-root", type=Path, default=None)
    parser.add_argument("--runner", choices=["docker", "local"], default="docker")
    parser.add_argument("--scope", choices=["entrypoints", "whole-project", "whole_project", "all"], default="entrypoints")
    parser.add_argument("--mode", choices=["EA", "DW", "AW"], default="EA")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--pip-install", default="")
    parser.add_argument("--preferred-root", default="")
    parser.add_argument("--max-depth", type=int, default=10)
    parser.add_argument("--max-paths", type=int, default=20)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "artifacts" / "pipeline_runs" / "alerta_jarvis_summary_transitive_smoke",
    )
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
