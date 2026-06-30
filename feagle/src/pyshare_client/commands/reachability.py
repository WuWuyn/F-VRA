from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Literal, Optional

import typer
from rich import box
from rich.table import Table

from pyshare_core.models import Verdict
from pyshare_client.output.display import console
from pyshare_core.models import ExternalNode, LibrarySummary
from pyshare_client.reachability.engine import ReachabilityQueryEngine
from pyshare_client.reachability.service import (
    check_transitive_reachability,
    load_package_report_summaries,
    read_vulnerable_targets,
    summary_from_callgraph_report,
)

app = typer.Typer(help="Build concrete reachable paths from call graph reports.")


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        console.print(f"[red]Error:[/red] report does not exist: {path}")
        raise typer.Exit(1)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _matches(name: str, targets: set[str]) -> Optional[str]:
    if name in targets:
        return name
    best: Optional[str] = None
    best_len = -1
    for target in targets:
        if name == target or name.endswith("." + target) or target.endswith("." + name):
            score = len(set(name.split(".")) & set(target.split(".")))
            if score > best_len:
                best = target
                best_len = score
    return best


def _edge_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("final_edges_detail") or report.get("edges_detail") or []
    return [row for row in rows if row.get("caller") and row.get("callee")]


def _infer_roots(edges: list[dict[str, Any]]) -> list[str]:
    callers = {edge["caller"] for edge in edges}
    internal_callees = {
        edge["callee"]
        for edge in edges
        if edge.get("callee_type") != "external"
    }
    roots = sorted(callers - internal_callees)
    return roots or sorted(callers)


def _find_graph_paths(
    report: dict[str, Any],
    targets: set[str],
    *,
    max_depth: int,
    max_paths: int,
) -> list[dict[str, Any]]:
    edges = _edge_rows(report)
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        adjacency.setdefault(edge["caller"], []).append(edge)

    paths: list[dict[str, Any]] = []
    for root in _infer_roots(edges):
        queue = deque([(root, [root])])
        seen = {(root,)}
        while queue and len(paths) < max_paths:
            node, path = queue.popleft()
            matched = _matches(node, targets)
            if matched is not None:
                paths.append(
                    {
                        "kind": "project_graph",
                        "target": matched,
                        "path": path,
                    }
                )
                continue
            if len(path) > max_depth:
                continue
            for edge in adjacency.get(node, []):
                nxt = edge["callee"]
                if nxt in path:
                    continue
                key = tuple(path + [nxt])
                if key in seen:
                    continue
                seen.add(key)
                queue.append((nxt, path + [nxt]))
    return paths


def _usage_index(report: dict[str, Any]) -> list[ExternalNode]:
    out: list[ExternalNode] = []
    for target in report.get("usage_index", []):
        module, _, name = target.rpartition(".")
        out.append(
            ExternalNode(
                file_path=f"<external:{module or target}>",
                function_name=target,
                qualified_name=target,
                target_module=module or target,
                target_name=name,
            )
        )
    return out


def _package_root(report: dict[str, Any]) -> str:
    for edge in _edge_rows(report):
        for key in ("caller", "callee"):
            value = edge.get(key, "")
            if value and edge.get("callee_type") != "external":
                return value.split(".", 1)[0]
    root = Path(str(report.get("root", "package"))).name
    return root.replace("-", "_")


def _summary_from_report(report: dict[str, Any]) -> LibrarySummary:
    return summary_from_callgraph_report(report, root=_package_root(report))


def _composed_paths(
    project_report: dict[str, Any],
    package_reports: list[dict[str, Any]],
    targets: set[str],
    *,
    max_depth: int,
    max_paths: int,
) -> list[dict[str, Any]]:
    summaries = {
        _package_root(report): _summary_from_report(report)
        for report in package_reports
    }
    report = ReachabilityQueryEngine(
        _usage_index(project_report),
        summaries,
        targets,
        max_depth=max_depth,
        max_paths=max_paths,
    ).check_reachability()
    return [
        {
            "kind": "composed_supply_chain",
            "target": path.vulnerable_target,
            "path": path.tpl_chain,
        }
        for path in report.paths
    ]


def _write_report(data: dict[str, Any], output: Optional[Path]) -> None:
    if output is None:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[green]Report written:[/green] {output}")


def _print_paths(paths: list[dict[str, Any]], sample: int) -> None:
    table = Table(title="Reachable Paths", show_header=True, box=box.ASCII)
    table.add_column("#", justify="right")
    table.add_column("Kind")
    table.add_column("Target")
    table.add_column("Path")
    for i, item in enumerate(paths[:sample], start=1):
        table.add_row(str(i), item["kind"], item["target"], " -> ".join(item["path"]))
    if paths:
        console.print(table)
    else:
        console.print("[yellow]No reachable path found.[/yellow]")


def _write_json(data: dict[str, Any], output: Optional[Path]) -> None:
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    if output is None:
        console.print_json(payload)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload, encoding="utf-8")
    console.print(f"[green]Report written:[/green] {output}")


def _print_check_result(data: dict[str, Any], *, explain: bool, sample: int) -> None:
    verdict = data["verdict"]
    style = {
        Verdict.REACHABLE.value: "red",
        Verdict.NOT_REACHABLE.value: "green",
        Verdict.POTENTIALLY_REACHABLE.value: "yellow",
        Verdict.UNKNOWN.value: "yellow",
    }.get(verdict, "white")
    table = Table(title="Transitive Reachability", show_header=True, box=box.ASCII)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Verdict", f"[{style}]{verdict}[/{style}]")
    table.add_row("Project", data["project"])
    table.add_row("Vulnerable targets", ", ".join(data["vulnerable_targets"]) or "-")
    table.add_row("Hit set", ", ".join(data["hit_set"]) or "-")
    table.add_row("Usage index", str(len(data["usage_index"])))
    table.add_row("Loaded summaries", ", ".join(data["loaded_summaries"]) or "-")
    table.add_row("Used summaries", ", ".join(data.get("used_summaries", [])) or "-")
    table.add_row("Unresolved targets", str(len(data["unresolved_targets"])))
    table.add_row("Paths", str(len(data["paths"])))
    table.add_row("Query time", f"{data['query_time_ms']:.1f} ms")
    console.print(table)

    if explain and data["paths"]:
        path_table = Table(title="Reachable Paths", show_header=True, box=box.ASCII)
        path_table.add_column("#", justify="right")
        path_table.add_column("Target")
        path_table.add_column("Path")
        for i, item in enumerate(data["paths"][:sample], start=1):
            path_table.add_row(str(i), item["target"], " -> ".join(item["path"]))
        console.print(path_table)


@app.command(name="paths")
def paths(
    project_report: Path = typer.Option(..., "--project-report", help="JSON from callgraph project"),
    target: list[str] = typer.Option(..., "--target", help="Vulnerable/internal/external target to reach"),
    package_report: Optional[list[Path]] = typer.Option(
        None,
        "--package-report",
        help="Optional JSON from callgraph package; repeat to compose supply-chain paths",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write reachable path JSON"),
    max_depth: int = typer.Option(25, "--max-depth", min=1),
    max_paths: int = typer.Option(50, "--max-paths", min=1),
    sample: int = typer.Option(20, "--sample", min=0),
) -> None:
    """Find concrete paths from a project call graph report to target symbols."""
    project = _load_json(project_report)
    package_paths = package_report or []
    packages = [_load_json(path) for path in package_paths]
    targets = set(target)

    project_paths = _find_graph_paths(project, targets, max_depth=max_depth, max_paths=max_paths)
    composed_paths = (
        _composed_paths(
            project,
            packages,
            targets,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        if packages
        else []
    )
    all_paths = (project_paths + composed_paths)[:max_paths]

    data = {
        "project_report": str(project_report),
        "package_reports": [str(path) for path in package_paths],
        "targets": sorted(targets),
        "is_reachable": bool(all_paths),
        "paths": all_paths,
    }
    _write_report(data, output)
    _print_paths(all_paths, sample)


@app.command(name="check")
def check(
    project: Path = typer.Option(..., "--project", help="Project source root to analyze"),
    vf: Optional[list[str]] = typer.Option(None, "--vf", help="Vulnerable function target; repeatable"),
    vf_file: Optional[Path] = typer.Option(None, "--vf-file", help="JSON/JSONL vulnerable function targets"),
    package_report: Optional[list[str]] = typer.Option(
        None,
        "--package-report",
        help="Package summary report as ROOT=PATH; repeat to enable transitive traversal",
    ),
    explain: bool = typer.Option(False, "--explain", help="Print representative reachable paths"),
    fmt: Literal["table", "json"] = typer.Option("table", "--format", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON result to file"),
    max_depth: int = typer.Option(25, "--max-depth", min=1),
    max_paths: int = typer.Option(100, "--max-paths", min=1),
    sample: int = typer.Option(20, "--sample", min=0, help="Number of paths to display in table mode"),
) -> None:
    """Check project-to-package transitive reachability to vulnerable functions."""
    targets = set(vf or [])
    if vf_file:
        try:
            targets.update(read_vulnerable_targets(vf_file))
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1)

    try:
        summaries = load_package_report_summaries(package_report or [])
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    result = check_transitive_reachability(
        project,
        targets,
        summaries=summaries,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    data = result.to_dict(explain=True)
    if fmt == "json" or output is not None:
        _write_json(data, output)
    else:
        _print_check_result(data, explain=explain, sample=sample)
