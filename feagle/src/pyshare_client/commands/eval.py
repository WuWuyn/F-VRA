import typer
from pathlib import Path
from typing import Optional
from enum import Enum
from pyshare_client.output.display import console

app = typer.Typer(help="[Research] Run evaluation on PyBM-Python benchmark.")


class Baseline(str, Enum):
    sca    = "sca"
    pycg   = "pycg"
    jarvis = "jarvis"
    all    = "all"


class ReportFormat(str, Enum):
    csv   = "csv"
    latex = "latex"


@app.callback(invoke_without_command=True)
def eval(
    benchmark: Path           = typer.Option(Path("./benchmark"), "--benchmark"),
    baseline:  Baseline       = typer.Option(Baseline.all,        "--baseline"),
    output:    Optional[Path] = typer.Option(None,                "--output"),
    fmt:       ReportFormat   = typer.Option(ReportFormat.csv,    "--format"),
):
    console.print("[dim]Evaluation: not implemented yet[/dim]")
    console.print(f"  benchmark : {benchmark}")
    console.print(f"  baseline  : {baseline.value}")
    console.print(f"  format    : {fmt.value}")
