import typer
from pyshare.cli import eval as eval_cmd, index, localize, scan, status

app = typer.Typer(
    name="pyshare",
    help="Vulnerability Reachability Analysis for Python/PyPI",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(index.app,    name="index")
app.add_typer(localize.app, name="localize")
app.add_typer(scan.app,     name="scan")
app.add_typer(status.app,   name="status")
app.add_typer(eval_cmd.app, name="eval")

if __name__ == "__main__":
    app()
