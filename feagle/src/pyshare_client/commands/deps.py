from __future__ import annotations

import json
from pathlib import Path

import typer
from rich import box
from rich.table import Table

from pyshare_client.dependencies.callgraph_builder import build_dependency_callgraphs
from pyshare_client.dependencies.resolver import resolve_dependency_graph
from pyshare_client.output.display import console

app = typer.Typer(help="Resolve Python dependencies and build package call graphs.")


@app.command(name="resolve")
def resolve(
    project: Path = typer.Argument(Path("."), help="Project root containing Python dependency files"),
    output: Path = typer.Option(Path("pyshare-dependencies.json"), "--output", "-o", help="Write dependency graph JSON"),
    file: list[Path] = typer.Option(
        None,
        "--file",
        "-f",
        help="Dependency manifest/lockfile to parse; repeat to override auto-discovery",
    ),
    include_dev: bool = typer.Option(False, "--include-dev", help="Include dev/optional dependency groups when present"),
) -> None:
    """Resolve Python dependencies from manifests and lockfiles."""
    if not project.exists():
        console.print(f"[red]Error:[/red] project does not exist: {project}")
        raise typer.Exit(1)

    artifact = resolve_dependency_graph(project, files=file or None, include_dev=include_dev)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(artifact.model_dump(mode="json"), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    direct = sum(1 for dep in artifact.dependencies if dep.direct)
    locked = sum(1 for dep in artifact.dependencies if dep.version)
    table = Table(title="Dependency Resolve", show_header=True, box=box.ASCII)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Project", str(project.resolve()))
    table.add_row("Output", str(output))
    table.add_row("Source files", str(len(artifact.source_files)))
    table.add_row("Dependencies", str(len(artifact.dependencies)))
    table.add_row("Direct", str(direct))
    table.add_row("Locked versions", str(locked))
    table.add_row("Warnings", str(len(artifact.analysis_warnings.get("warnings", []))))
    console.print(table)


@app.command(name="build-callgraphs")
def build_callgraphs(
    dependency_report: Path = typer.Option(
        ...,
        "--dependency-report",
        "--deps-report",
        help="JSON from `pyshare deps resolve`",
    ),
    output_dir: Path = typer.Option(..., "--output-dir", help="Directory for package callgraph JSON files"),
    limit: int = typer.Option(0, "--limit", min=0, help="Max unique packages to build; 0 means all"),
) -> None:
    """Build package call graph reports from a PyShare dependency graph."""
    if not dependency_report.exists():
        console.print(f"[red]Error:[/red] dependency report does not exist: {dependency_report}")
        raise typer.Exit(1)

    try:
        result = build_dependency_callgraphs(dependency_report, output_dir, limit=limit)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] invalid dependency report: {exc}")
        raise typer.Exit(1)

    table = Table(title="Dependency Callgraph Build", show_header=True, box=box.ASCII)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Dependency report", str(result.dependency_report))
    table.add_row("Resolver", result.resolver)
    table.add_row("Output dir", str(result.output_dir))
    table.add_row("Unique packages", str(result.unique_packages))
    table.add_row("Built", str(result.built))
    table.add_row("Skipped", str(result.skipped))
    console.print(table)
