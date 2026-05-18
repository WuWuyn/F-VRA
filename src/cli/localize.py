import typer
from pyshare.cli._display import console, print_localize_result
from pyshare.pipeline import cve_localization

app = typer.Typer(help="[Online] Map a CVE to its vulnerable function.")


@app.callback(invoke_without_command=True)
def localize(
    cve_id:   str  = typer.Argument(..., help="e.g. CVE-2024-35195"),
    top_k:    int  = typer.Option(3,     "--top-k",    help="Number of candidates"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip local cache"),
):
    console.print(f"Localizing [bold]{cve_id}[/bold]...")
    result = cve_localization.localize(cve_id, top_k=top_k)
    print_localize_result(result)
