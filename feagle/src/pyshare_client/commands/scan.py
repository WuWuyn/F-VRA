from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

import typer
from rich import box
from rich.table import Table

from pyshare_client.dependencies.resolver import resolve_dependency_graph
from pyshare_client.output.display import console, print_scan_result
from pyshare_client.project_analysis.project_graph import build_project_graph
from pyshare_client.reachability.service import check_transitive_reachability, query_with_cache
from pyshare_client.storage import ClientCache, default_client_cache
from pyshare_core.models import LibrarySummary, OutputFormat, Verdict

app = typer.Typer(help="Scan a local project using server advisory data and local reachability analysis.")


def _api_root(raw: str) -> str:
    value = raw.rstrip("/")
    return value if value.endswith("/api") else f"{value}/api"


def _post_json(api_url: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{_api_root(api_url)}{path}",
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"server returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not reach F-VRA API at {api_url}: {exc.reason}") from exc


def _summary_from_api(summary: dict[str, Any]) -> LibrarySummary:
    return LibrarySummary(
        inner_summary={str(key): set(values) for key, values in (summary.get("inner_summary") or {}).items()},
        outer_summary={str(key): set(values) for key, values in (summary.get("outer_summary") or {}).items()},
        inner_paths={
            str(key): {str(target): list(path) for target, path in values.items()}
            for key, values in (summary.get("inner_paths") or {}).items()
        },
        outer_paths={
            str(key): {str(target): list(path) for target, path in values.items()}
            for key, values in (summary.get("outer_paths") or {}).items()
        },
        analysis_warnings=summary.get("analysis_warnings") or {},
        api_aliases={str(key): str(value) for key, value in (summary.get("api_aliases") or {}).items()},
    )


def _dependency_payload(project: Path) -> tuple[dict[str, Any], int, int]:
    graph = resolve_dependency_graph(project)
    direct = sum(1 for dep in graph.dependencies if dep.direct)
    payload = {
        "dependencies": [
            {
                "ecosystem": dep.ecosystem,
                "name": dep.name,
                "normalizedName": dep.normalized_name,
                "version": dep.version,
                "direct": dep.direct,
                "dev": dep.dev,
                "dependencies": dep.dependencies,
                "purl": dep.purl,
            }
            for dep in graph.dependencies
        ]
    }
    return payload, direct, len(graph.dependencies) - direct


def _usage_roots(project: Path) -> list[str]:
    _graph, usage_index = build_project_graph(project)
    return sorted({
        node.identity_string.split(".", 1)[0].replace("_", "-").lower()
        for node in usage_index
        if node.identity_string
    })


def _scan_with_server(project: Path, cve_ids: list[str], api_url: str, *, max_depth: int, max_paths: int) -> dict[str, Any]:
    dependency_payload, direct, transitive = _dependency_payload(project)
    usage_roots = _usage_roots(project)
    plan = _post_json(api_url, "/cli/scan-plan", {
        **dependency_payload,
        "cveIds": cve_ids,
        "usageRoots": usage_roots,
    })
    summaries = {
        str(item["root"]): _summary_from_api(item.get("summary") or {})
        for item in plan.get("packageSummaries") or []
    }
    findings: list[dict[str, Any]] = []
    for match in plan.get("matches") or []:
        targets = {str(target) for target in match.get("vulnerableFunctions") or [] if target}
        if not targets:
            findings.append({**match, "verdict": Verdict.UNKNOWN.value, "paths": [], "pathCount": 0})
            continue
        result = check_transitive_reachability(project, targets, summaries=summaries, max_depth=max_depth, max_paths=max_paths)
        findings.append({
            **match,
            "verdict": result.verdict.value,
            "paths": [
                {
                    "projectApi": path.project_api,
                    "target": path.vulnerable_target,
                    "path": path.tpl_chain,
                    "usedSummaries": path.used_summaries,
                }
                for path in result.paths
            ],
            "pathCount": len(result.paths),
            "usedSummaries": result.used_summaries,
            "warnings": result.analysis_warnings,
            "queryTimeMs": result.query_time_ms,
        })
    return {
        "project": str(project.resolve()),
        "apiUrl": _api_root(api_url),
        "cveIds": cve_ids,
        "dependencies": len(dependency_payload["dependencies"]),
        "directDependencies": direct,
        "transitiveDependencies": transitive,
        "loadedSummaries": sorted(summaries),
        "warnings": plan.get("warnings") or [],
        "findings": findings,
    }


def _print_server_scan(data: dict[str, Any], *, explain: bool) -> None:
    table = Table(title="F-VRA Scan", show_header=True, box=box.ASCII)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Project", data["project"])
    table.add_row("Dependencies", str(data["dependencies"]))
    table.add_row("Direct / transitive", f"{data['directDependencies']} / {data['transitiveDependencies']}")
    table.add_row("Loaded summaries", ", ".join(data["loadedSummaries"]) or "-")
    table.add_row("Findings", str(len(data["findings"])))
    console.print(table)

    findings = Table(title="Findings", show_header=True, box=box.ASCII)
    findings.add_column("CVE")
    findings.add_column("Package")
    findings.add_column("Severity")
    findings.add_column("Verdict")
    findings.add_column("Paths", justify="right")
    for finding in data["findings"]:
        findings.add_row(
            finding["advisoryId"],
            f"{finding['package']}@{finding['version']}",
            finding.get("severity", ""),
            finding["verdict"],
            str(finding["pathCount"]),
        )
    if data["findings"]:
        console.print(findings)
    else:
        console.print("[green]No matching advisories found for this dependency inventory.[/green]")

    if explain:
        for finding in data["findings"]:
            for path in finding.get("paths", [])[:5]:
                console.print(f"[bold]{finding['advisoryId']}[/bold]: " + " -> ".join(path["path"]))
    for warning in data.get("warnings") or []:
        console.print(f"[yellow]warning:[/yellow] {warning}")


@app.callback(invoke_without_command=True)
def scan(
    cve: Optional[list[str]] = typer.Option(None, "--cve", help="Optional CVE/advisory filter; omit to scan all matching advisories from the F-VRA API."),
    vf: str = typer.Option("", "--vf", "--target", help="Debug/local mode vulnerable function target."),
    project: Path = typer.Option(Path("."), "--project", help="Local project root to scan."),
    portfolio: Optional[Path] = typer.Option(None, "--portfolio", help="YAML file with multiple project paths for offline debug mode."),
    explain: bool = typer.Option(False, "--explain", help="Show reachable paths."),
    fmt: OutputFormat = typer.Option(OutputFormat.table, "--format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON result to file."),
    api_url: str = typer.Option(os.getenv("F_VRA_API_URL", "http://localhost:8081/api"), "--api-url", help="F-VRA API URL."),
    offline: bool = typer.Option(False, "--offline", help="Use legacy local VF scan instead of querying server advisory DB."),
    cache_dir: Optional[Path] = typer.Option(None, "--cache-dir", help="Debug/local mode client cache root."),
    fail_on: bool = typer.Option(False, "--fail-on-affected", help="Exit code 1 if any finding is reachable."),
    max_depth: int = typer.Option(25, "--max-depth", min=1),
    max_paths: int = typer.Option(100, "--max-paths", min=1),
) -> None:
    """Scan a local project against all matching server advisories, then run local reachability."""
    cve_ids = cve or []
    if offline or vf:
        if not vf:
            console.print("[red]Error:[/red] --offline requires --vf/--target.")
            raise typer.Exit(1)
        _legacy_local_scan(cve_ids[0] if cve_ids else "LOCAL-VF", vf, project, portfolio, explain, fmt, output, cache_dir, fail_on)
        return
    if not project.exists() or not project.is_dir():
        console.print(f"[red]Error:[/red] project does not exist or is not a directory: {project}")
        raise typer.Exit(1)

    try:
        data = _scan_with_server(project, cve_ids, api_url, max_depth=max_depth, max_paths=max_paths)
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if fmt == OutputFormat.json or output is not None:
        payload = json.dumps(data, indent=2)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(payload, encoding="utf-8")
            console.print(f"[green]Report written:[/green] {output}")
        else:
            console.print_json(payload)
    elif fmt == OutputFormat.table:
        _print_server_scan(data, explain=explain)
    else:
        console.print("[dim]SARIF output: not implemented yet[/dim]")

    if fail_on and any(finding["verdict"] == Verdict.REACHABLE.value for finding in data["findings"]):
        raise typer.Exit(1)


def _legacy_local_scan(
    cve_id: str,
    vf: str,
    project: Path,
    portfolio: Optional[Path],
    explain: bool,
    fmt: OutputFormat,
    output: Optional[Path],
    cache_dir: Optional[Path],
    fail_on: bool,
) -> None:
    projects = _resolve_projects(project, portfolio)
    cache = ClientCache(cache_dir) if cache_dir else default_client_cache()
    for proj in projects:
        result = query_with_cache(cve_id=cve_id, project=proj, vf=vf, explain=explain, cache=cache)
        if fmt == OutputFormat.table:
            print_scan_result(result, explain=explain)
        elif fmt == OutputFormat.json:
            data = _legacy_to_dict(result)
            if output:
                output.write_text(json.dumps(data, indent=2))
            else:
                console.print_json(json.dumps(data))
        elif fmt == OutputFormat.sarif:
            console.print("[dim]SARIF output: not implemented yet[/dim]")
        if fail_on and result.verdict == Verdict.AFFECTED:
            raise typer.Exit(1)


def _resolve_projects(project: Path, portfolio: Optional[Path]) -> list[Path]:
    if portfolio and portfolio.exists():
        import yaml
        data = yaml.safe_load(portfolio.read_text())
        return [Path(p["path"]) for p in data.get("projects", [])]
    return [project]


def _legacy_to_dict(result) -> dict[str, Any]:
    return {
        "cve_id": result.cve_id,
        "project": str(result.project),
        "verdict": result.verdict.value,
        "vf": result.vf,
        "entry_points": result.entry_points,
        "hit_set": result.hit_set,
        "call_chain": result.call_chain,
        "query_time_ms": result.query_time_ms,
        "llm_invoked": result.llm_invoked,
    }
