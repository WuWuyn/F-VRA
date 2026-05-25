import json
import typer
from pathlib import Path
from typing import Optional
from pyshare.cli._display import console, print_scan_result
from pyshare.pipeline import reachability_query
from pyshare.core.models import OutputFormat, Verdict

app = typer.Typer(help="[Online] Check if a project is affected by a CVE.")


@app.callback(invoke_without_command=True)
def scan(
    cve:            str            = typer.Option(...,        "--cve",
                                        help="CVE ID, e.g. CVE-2024-35195"),
    project:        Path           = typer.Option(Path("."),  "--project",
                                        help="Project root (default: current dir)"),
    vf:             str            = typer.Option("",         "--vf",
                                        help="Override vulnerable function qname "
                                             "(dev/testing -- skips CVE cache lookup)"),
    app_pkgs:       Optional[str]  = typer.Option(None,       "--app-pkg",
                                        help="Comma-separated app package names "
                                             "(override auto-detect)"),
    no_jarvis:      bool           = typer.Option(False,      "--no-jarvis",
                                        help="Don't auto-run JARVIS; require existing "
                                             "JSON in project"),
    vfarche_result: Optional[Path] = typer.Option(None,       "--vfarche-result",
                                        help="Path to a VFArCHE-format JSON file "
                                             "(top_function field) to use as vf source"),
    portfolio:      Optional[Path] = typer.Option(None,       "--portfolio",
                                        help="YAML file with multiple project paths"),
    explain:        bool           = typer.Option(False,      "--explain",
                                        help="Show call chain (requires Neo4j)"),
    fmt:            OutputFormat   = typer.Option(OutputFormat.table, "--format"),
    output:         Optional[Path] = typer.Option(None,       "--output",
                                        help="Write result to file"),
    fail_on:        bool           = typer.Option(False,      "--fail-on-affected",
                                        help="Exit code 1 if AFFECTED (for CI)"),
):
    projects = _resolve_projects(project, portfolio)
    pkgs_set = {p.strip() for p in app_pkgs.split(",")} if app_pkgs else None
    is_portfolio = portfolio is not None

    results = []
    any_affected = False
    for proj in projects:
        result = reachability_query.query(
            cve_id=cve, project=proj, vf=vf, explain=explain,
            app_packages=pkgs_set, no_jarvis=no_jarvis,
            vfarche_result=vfarche_result,
        )
        results.append(result)
        if result.verdict == Verdict.AFFECTED:
            any_affected = True

        if fmt == OutputFormat.table:
            print_scan_result(result, explain=explain)
        elif fmt == OutputFormat.json and not is_portfolio:
            data = _to_dict(result)
            if output:
                output.write_text(json.dumps(data, indent=2))
            else:
                console.print_json(json.dumps(data))
        elif fmt == OutputFormat.sarif:
            console.print("[dim]SARIF output: not implemented yet[/dim]")

    if is_portfolio:
        if fmt == OutputFormat.table:
            _print_portfolio_summary(results)
        elif fmt == OutputFormat.json:
            payload = {
                "cve_id": cve,
                "total_projects": len(results),
                "affected":     sum(1 for r in results if r.verdict == Verdict.AFFECTED),
                "not_affected": sum(1 for r in results if r.verdict == Verdict.NOT_AFFECTED),
                "unknown":      sum(1 for r in results if r.verdict == Verdict.UNKNOWN),
                "projects": [_to_dict(r) for r in results],
            }
            if output:
                output.write_text(json.dumps(payload, indent=2))
            else:
                console.print_json(json.dumps(payload))

    if fail_on and any_affected:
        raise typer.Exit(1)


def _resolve_projects(project: Path, portfolio: Optional[Path]) -> list[Path]:
    if portfolio and portfolio.exists():
        import yaml
        data = yaml.safe_load(portfolio.read_text())
        return [Path(p["path"]) for p in data.get("projects", [])]
    return [project]


def _print_portfolio_summary(results: list) -> None:
    """Aggregated summary table for portfolio scans."""
    from rich.table import Table

    affected = [r for r in results if r.verdict == Verdict.AFFECTED]
    unknown  = [r for r in results if r.verdict == Verdict.UNKNOWN]

    style = "red" if affected else ("yellow" if unknown else "green")

    table = Table(title="Portfolio summary", show_header=True,
                  header_style="bold", border_style=style)
    table.add_column("Verdict", width=14)
    table.add_column("Project")
    table.add_column("Entries", justify="right")
    table.add_column("Time (ms)", justify="right")

    for r in results:
        if r.verdict == Verdict.AFFECTED:
            verdict_cell = "[red]⚠ AFFECTED[/red]"
        elif r.verdict == Verdict.NOT_AFFECTED:
            verdict_cell = "[green]✓ NOT_AFFECTED[/green]"
        else:
            verdict_cell = "[yellow]? UNKNOWN[/yellow]"
        table.add_row(
            verdict_cell,
            str(r.project),
            str(len(r.entry_points)),
            f"{r.query_time_ms:.0f}",
        )
    console.print(table)
    console.print(
        f"[bold]Total[/bold]: {len(results)} project(s)  •  "
        f"[red]{len(affected)} AFFECTED[/red]  •  "
        f"[green]{sum(1 for r in results if r.verdict == Verdict.NOT_AFFECTED)} NOT_AFFECTED[/green]  •  "
        f"[yellow]{len(unknown)} UNKNOWN[/yellow]"
    )


def _to_dict(result) -> dict:
    return {
        "cve_id":        result.cve_id,
        "project":       str(result.project),
        "verdict":       result.verdict.value,
        "vf":            result.vf,
        "entry_points":  result.entry_points,
        "hit_set":       result.hit_set,
        "call_chain":    result.call_chain,
        "query_time_ms": result.query_time_ms,
        "llm_invoked":   result.llm_invoked,
    }
