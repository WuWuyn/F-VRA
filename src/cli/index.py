import typer
from pyshare.cli._display import console, print_index_result, make_progress
from pyshare.pipeline import callgraph_builder, pcsg_indexer
from pyshare.core.models import IndexResult

app = typer.Typer(help="[Offline] Build PCSG index for a PyPI library.")


@app.callback(invoke_without_command=True)
def index(
    package_version: str  = typer.Argument(..., metavar="pkg==version",
                                help="e.g. requests==2.31.0"),
    force:  bool = typer.Option(False, "--force",  help="Rebuild even if index exists"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM type oracle"),
    neo4j:  bool = typer.Option(False, "--neo4j",  help="Also write to Neo4j"),
):
    if "==" not in package_version:
        console.print("[red]Error:[/red] use format pkg==version")
        raise typer.Exit(1)
    pkg, ver = package_version.split("==", 1)

    with make_progress() as progress:
        t1 = progress.add_task("Downloading source...", total=None)
        graph = callgraph_builder.build(pkg, ver)
        progress.update(t1, description="[green]Call graph built[/green]")

        t2 = progress.add_task("Computing PCSG index...", total=None)
        idx = pcsg_indexer.index(pkg, ver, graph)
        progress.update(t2, description="[green]Index saved[/green]")

    result = IndexResult(
        package=pkg, version=ver,
        functions=graph.get("functions", 0),
        api_count=idx.get("api_count", 0),
        elapsed_s=idx.get("elapsed_s", 0.0),
    )
    print_index_result(result)
