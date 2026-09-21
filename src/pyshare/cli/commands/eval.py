"""Expose the research harness through the main ``pyshare`` command."""
from __future__ import annotations

import typer

from pyshare.evaluation import cli as evaluation_cli


app = typer.Typer(
    help="Run the integrated CVE-to-vulnerable-function evaluation harness.",
    invoke_without_command=True,
    add_completion=False,
)


def _invoke(argv: list[str]) -> None:
    """Forward arguments to the canonical argparse implementation."""
    try:
        code = evaluation_cli.main(argv)
    except SystemExit as exc:
        code = int(exc.code or 0)
    if code:
        raise typer.Exit(code)


@app.callback()
def eval_command(ctx: typer.Context) -> None:
    """Run datasets, methods, validation, metrics, and ablations."""
    if ctx.invoked_subcommand is None:
        _invoke(["--help"])


_PASSTHROUGH = {
    "allow_extra_args": True,
    "ignore_unknown_options": True,
    "help_option_names": [],
}


def _forward(name: str, ctx: typer.Context) -> None:
    _invoke([name, *ctx.args])


@app.command("prepare-data", context_settings=_PASSTHROUGH)
def prepare_data(ctx: typer.Context) -> None:
    """Build the normalized evaluation master dataset."""
    _forward("prepare-data", ctx)


@app.command("smoke", context_settings=_PASSTHROUGH)
def smoke(ctx: typer.Context) -> None:
    """Run offline structural and regression checks."""
    _forward("smoke", ctx)


@app.command("list", context_settings=_PASSTHROUGH)
def list_methods(ctx: typer.Context) -> None:
    """List methods, variants, and ablation axes."""
    _forward("list", ctx)


@app.command("doctor", context_settings=_PASSTHROUGH)
def doctor(ctx: typer.Context) -> None:
    """Check method dependencies, keys, and services."""
    _forward("doctor", ctx)


@app.command("run", context_settings=_PASSTHROUGH)
def run(ctx: typer.Context) -> None:
    """Run one or more localization methods."""
    _forward("run", ctx)


@app.command("validate", context_settings=_PASSTHROUGH)
def validate(ctx: typer.Context) -> None:
    """Validate normalized prediction files."""
    _forward("validate", ctx)


@app.command("metrics", context_settings=_PASSTHROUGH)
def metrics(ctx: typer.Context) -> None:
    """Compute evaluation metrics."""
    _forward("metrics", ctx)


@app.command("stats", context_settings=_PASSTHROUGH)
def stats(ctx: typer.Context) -> None:
    """Run paired significance tests."""
    _forward("stats", ctx)


@app.command("ablation", context_settings=_PASSTHROUGH)
def ablation(ctx: typer.Context) -> None:
    """Run an ablation axis."""
    _forward("ablation", ctx)
