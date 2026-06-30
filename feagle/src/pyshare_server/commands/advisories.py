from __future__ import annotations

import typer
from rich.console import Console

from pyshare_api.db import SessionLocal, create_schema
from pyshare_server.advisories import sync_advisories

app = typer.Typer(help="Sync OSV/GHSA advisory data into the F-VRA database.")
console = Console()


@app.command("sync")
def sync(
    source: str = typer.Option("osv", "--source", help="Advisory source: osv or ghsa."),
    ecosystem: str = typer.Option("pypi", "--ecosystem", help="Package ecosystem to import."),
    limit: int = typer.Option(500, "--limit", min=1, help="Maximum records to import."),
) -> None:
    create_schema()
    with SessionLocal() as session:
        count = sync_advisories(session, source=source, ecosystem=ecosystem, limit=limit)
    console.print(f"[green]Imported {count} {source.upper()} advisory record(s).[/green]")
