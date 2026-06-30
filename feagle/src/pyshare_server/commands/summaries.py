from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from pyshare_server.storage import ServerFileDb, default_server_filedb
from pyshare_server.summaries.service import (
    package_summary_artifact_from_report,
    package_summary_key,
)

app = typer.Typer(help="Ingest package summary artifacts into the server file DB.")
console = Console(legacy_windows=False)


@app.command(name="ingest")
def ingest(
    package_report: Path = typer.Option(..., "--package-report", help="Package callgraph JSON report"),
    package: Optional[str] = typer.Option(None, "--package", help="Override package name"),
    version: Optional[str] = typer.Option(None, "--version", help="Override package version"),
    store: Optional[Path] = typer.Option(None, "--store", help="Server file DB root"),
) -> None:
    """Convert a package callgraph report into a PackageSummaryArtifact."""
    if not package_report.exists():
        console.print(f"[red]Error:[/red] package report does not exist: {package_report}")
        raise typer.Exit(1)
    try:
        report = json.loads(package_report.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/red] invalid package report JSON: {exc}")
        raise typer.Exit(1)

    artifact = package_summary_artifact_from_report(
        report,
        package=package,
        version=version,
        source_path=str(package_report),
    )
    key = package_summary_key(artifact.package)
    db: ServerFileDb = ServerFileDb(store) if store else default_server_filedb()
    db.put_package_summary(key, artifact)
    console.print(f"[green]Package summary stored:[/green] {key}")
