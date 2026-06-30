import typer

from pyshare_client.commands import callgraph, deps, eval as eval_cmd, index, reachability, scan, status

app = typer.Typer(
    name="pyshare",
    help="Client-side project scanning and reachability tools",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
debug_app = typer.Typer(
    name="debug",
    help="Debug internals: dependency resolution, call graph construction, package summaries, and reachability probes.",
    no_args_is_help=True,
)

app.add_typer(index.app, name="index")
app.add_typer(deps.app, name="deps")
app.add_typer(callgraph.app, name="callgraph")
app.add_typer(reachability.app, name="reachability")
app.add_typer(scan.app, name="scan")
app.add_typer(status.app, name="status")
app.add_typer(eval_cmd.app, name="eval")

debug_app.add_typer(index.app, name="index")
debug_app.add_typer(deps.app, name="deps")
debug_app.add_typer(callgraph.app, name="callgraph")
debug_app.add_typer(reachability.app, name="reachability")
debug_app.add_typer(status.app, name="status")
debug_app.add_typer(eval_cmd.app, name="eval")
app.add_typer(debug_app, name="debug")


if __name__ == "__main__":
    app()
