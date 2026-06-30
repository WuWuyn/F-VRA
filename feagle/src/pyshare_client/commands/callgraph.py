from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Literal, Optional

import typer
from rich import box
from rich.table import Table

from pyshare_client.output.display import console, make_progress
from pyshare_core.models import CallGraph, ExternalNode
from pyshare_client.package_analysis.callgraph import LibraryAnalyzer
from pyshare_client.project_analysis.project_graph import build_project_graph

app = typer.Typer(help="Build Python call graphs for projects or packages.")


def _validate_root(root: Path, label: str) -> Path:
    resolved = root.resolve()
    if not resolved.exists():
        console.print(f"[red]Error:[/red] {label} does not exist: {resolved}")
        raise typer.Exit(1)
    if not resolved.is_dir():
        console.print(f"[red]Error:[/red] {label} is not a directory: {resolved}")
        raise typer.Exit(1)
    return resolved


def _node_name(node: Any) -> str:
    return getattr(node, "qualified_name", "") or getattr(node, "function_name", "")


def _edge_dict(edge: Any) -> dict[str, Any]:
    return {
        "caller": _node_name(edge.caller),
        "callee": _node_name(edge.callee),
        "callee_type": "external" if edge.callee.is_external else "internal",
        "edge_type": getattr(edge, "edge_type", "confirmed_static"),
        "confidence": getattr(edge, "confidence", 1.0),
        "resolver": getattr(edge, "resolver", "static"),
        "reason": getattr(edge, "reason", ""),
        "call_expr": getattr(edge, "call_expr", ""),
        "line_number": getattr(edge, "line_number", 0),
    }


def _function_metadata(graph: CallGraph) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for node in sorted(graph.internal_nodes, key=lambda item: item.qualified_name or item.function_name):
        out.append(
            {
                "name": node.qualified_name or node.function_name,
                "file_path": node.file_path,
                "line_number": node.line_number,
                "module": node.module,
                "scope": node.scope,
                "signature": node.signature,
                "arity": node.arity,
                "source_snippet": node.source_snippet,
            }
        )
    return out


def _graph_report(
    *,
    mode: Literal["project", "package"],
    root: Path,
    graph: CallGraph,
    elapsed_s: float,
    usage_index: Optional[list[ExternalNode]] = None,
    public_api_aliases: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    external_targets = sorted({edge.callee.qualified_name for edge in graph.external_edges})
    edges_detail = [_edge_dict(edge) for edge in graph.edges]
    unresolved_calls = graph.metadata.get("unresolved_calls", [])
    candidate_edges = graph.metadata.get("candidate_edges", [])
    llm_kept_edges = graph.metadata.get("llm_kept_edges", [])
    llm_pruned_edges = graph.metadata.get("llm_pruned_edges", [])
    assignment_type_facts = graph.metadata.get("assignment_type_facts", [])
    return_type_facts = graph.metadata.get("return_type_facts", [])
    external_model_facts = graph.metadata.get("external_model_facts", [])
    function_summaries = graph.metadata.get("function_summaries", {})
    skipped_files = graph.metadata.get("skipped_files", [])
    unresolved_public_exports = graph.metadata.get("unresolved_public_exports", [])
    return {
        "mode": mode,
        "root": str(root),
        "elapsed_s": elapsed_s,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "internal_nodes": len(graph.internal_nodes),
        "external_nodes": len(graph.external_nodes),
        "internal_edges": len(graph.internal_edges),
        "external_edges": len(graph.external_edges),
        "usage_index": sorted(node.identity_string for node in usage_index or []),
        "public_api_aliases": public_api_aliases or {},
        "external_targets": external_targets,
        "unresolved_calls": unresolved_calls,
        "candidate_edges": candidate_edges,
        "llm_kept_edges": llm_kept_edges,
        "llm_pruned_edges": llm_pruned_edges,
        "assignment_type_facts": assignment_type_facts,
        "return_type_facts": return_type_facts,
        "external_model_facts": external_model_facts,
        "function_summaries": function_summaries,
        "unresolved_public_exports": unresolved_public_exports,
        "skipped_files": skipped_files,
        "function_metadata": _function_metadata(graph),
        "edges_detail": edges_detail,
        "final_edges_detail": list(edges_detail),
    }


def _print_summary(report: dict[str, Any], sample: int) -> None:
    title = f"{report['mode'].title()} Call Graph"
    table = Table(title=title, show_header=True, box=box.ASCII)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Root", report["root"])
    table.add_row("Elapsed (s)", f"{report['elapsed_s']:.2f}")
    table.add_row("Nodes", str(report["nodes"]))
    table.add_row("Edges", str(report["edges"]))
    table.add_row("Final edges", str(len(report.get("final_edges_detail", []))))
    table.add_row("Internal nodes", str(report["internal_nodes"]))
    table.add_row("External nodes", str(report["external_nodes"]))
    table.add_row("Internal edges", str(report["internal_edges"]))
    table.add_row("External edges", str(report["external_edges"]))
    table.add_row("Unresolved calls", str(len(report["unresolved_calls"])))
    table.add_row("Coarse candidates", str(len(report["candidate_edges"])))
    table.add_row("LLM kept/pruned", f"{len(report['llm_kept_edges'])}/{len(report['llm_pruned_edges'])}")
    table.add_row("Unresolved exports", str(len(report.get("unresolved_public_exports", []))))
    table.add_row("Skipped files", str(len(report["skipped_files"])))
    if report["mode"] == "project":
        table.add_row("Usage Index", str(len(report["usage_index"])))
    else:
        table.add_row("Unique external targets", str(len(report["external_targets"])))
    console.print(table)

    if sample > 0:
        values = report["usage_index"] if report["mode"] == "project" else report["external_targets"]
        label = "Usage Index sample" if report["mode"] == "project" else "External target sample"
        sample_table = Table(title=label, show_header=True, box=box.ASCII)
        sample_table.add_column("#", justify="right")
        sample_table.add_column("Target")
        for i, target in enumerate(values[:sample], start=1):
            sample_table.add_row(str(i), target)
        if values:
            console.print(sample_table)
        else:
            console.print(f"[dim]{label}: none[/dim]")


def _write_report(report: dict[str, Any], output: Optional[Path]) -> None:
    if output is None:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[green]Report written:[/green] {output}")


def _default_output(root: Path, mode: Literal["project", "package"]) -> Path:
    return root.parent / f"{root.name}-callgraph-{mode}.json"


@app.command(name="project")
def project_graph(
    root: Path = typer.Argument(..., help="Project root to analyze"),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON report; defaults to <root>-callgraph-project.json",
    ),
    sample: int = typer.Option(20, "--sample", min=0, help="Number of targets to display"),
) -> None:
    """Build reachable project graph and Usage Index from detected entry points."""
    resolved = _validate_root(root, "Project root")
    output_path = output or _default_output(resolved, "project")

    started = time.perf_counter()
    with make_progress() as progress:
        task = progress.add_task("Validating project root...", total=None)
        progress.update(task, description="Building reachable project graph...")
        graph, usage_index = build_project_graph(resolved)
        progress.update(task, description="Summarizing project graph...")
        report = _graph_report(
            mode="project",
            root=resolved,
            graph=graph,
            usage_index=usage_index,
            elapsed_s=time.perf_counter() - started,
        )
        progress.update(task, description="Writing JSON report...")
        _write_report(report, output_path)
        progress.update(task, description="[green]Project call graph complete[/green]")

    _print_summary(report, sample)


@app.command(name="package")
def package_graph(
    root: Path = typer.Argument(..., help="Package/source root to analyze exhaustively"),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON report; defaults to <root>-callgraph-package.json",
    ),
    sample: int = typer.Option(20, "--sample", min=0, help="Number of targets to display"),
) -> None:
    """Build exhaustive package/library call graph for a source root."""
    resolved = _validate_root(root, "Package root")
    output_path = output or _default_output(resolved, "package")

    analyzer = LibraryAnalyzer()
    started = time.perf_counter()
    with make_progress() as progress:
        task = progress.add_task("Validating package root...", total=None)
        progress.update(task, description="Building exhaustive package graph...")
        graph = analyzer.build_library_graph(resolved)
        progress.update(task, description="Summarizing package graph...")
        report = _graph_report(
            mode="package",
            root=resolved,
            graph=graph,
            elapsed_s=time.perf_counter() - started,
            public_api_aliases=analyzer.index.public_api_aliases() if analyzer.index is not None else {},
        )
        progress.update(task, description="Writing JSON report...")
        _write_report(report, output_path)
        progress.update(task, description="[green]Package call graph complete[/green]")

    _print_summary(report, sample)
