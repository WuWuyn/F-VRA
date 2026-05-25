from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn, BarColumn
from rich.tree import Tree
from pyshare.core.models import IndexResult, LocalizeResult, ScanResult, Verdict

console = Console()


def make_progress() -> Progress:
    """Return a Rich Progress instance for long-running tasks."""
    return Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    )


def print_index_result(result: IndexResult) -> None:
    table = Table(title=f"Index: {result.package}=={result.version}", show_header=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Package", f"{result.package}=={result.version}")
    table.add_row("Functions", str(result.functions))
    table.add_row("API count", str(result.api_count))
    table.add_row("Elapsed (s)", f"{result.elapsed_s:.2f}")
    table.add_row("Cached", str(result.cached))
    console.print(table)


def print_localize_result(result: LocalizeResult) -> None:
    table = Table(title=f"Localize: {result.cve_id}", show_header=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("CVE ID", result.cve_id)
    table.add_row("Mode", result.mode)
    table.add_row("Vulnerable function", f"[bold yellow]{result.vf}[/bold yellow]" if result.vf else "[dim]—[/dim]")
    table.add_row("Score", f"{result.score:.3f}")
    table.add_row("Candidates", ", ".join(result.candidates) if result.candidates else "[dim]none[/dim]")
    table.add_row("Cached", str(result.cached))
    console.print(table)


def print_scan_result(result: ScanResult, explain: bool = False) -> None:
    if result.verdict == Verdict.AFFECTED:
        style, icon = "red", "⚠  AFFECTED"
    elif result.verdict == Verdict.NOT_AFFECTED:
        style, icon = "green", "✓  NOT AFFECTED"
    else:
        style, icon = "yellow", "?  UNKNOWN"

    lines = [
        f"CVE: {result.cve_id}",
        f"Project: {result.project}",
    ]
    if result.vf:
        lines.append(f"vf: [bold yellow]{result.vf}[/bold yellow]")
    if result.entry_points:
        lines.append(f"Affected entries ({len(result.entry_points)}):")
        for ep in result.entry_points[:5]:
            lines.append(f"  • {ep}")
        if len(result.entry_points) > 5:
            lines.append(f"  ... (+{len(result.entry_points) - 5} more)")
    lines.append(f"Query time: {result.query_time_ms:.1f} ms")
    lines.append(f"LLM invoked: {result.llm_invoked}")

    # For UNKNOWN, surface the reason from call_chain[0] (set by
    # reachability_query._unknown helper).
    if result.verdict == Verdict.UNKNOWN and result.call_chain:
        lines.append("")
        lines.append(f"[dim]{result.call_chain[0]}[/dim]")

    console.print(Panel("\n".join(lines), title=icon, border_style=style))

    # --explain: show the call chain as a tree (only for AFFECTED).
    if explain and result.verdict == Verdict.AFFECTED and result.call_chain:
        tree = Tree("[bold]Call chain[/bold]")
        node = tree
        for fn in result.call_chain:
            node = node.add(fn)
        console.print(tree)
