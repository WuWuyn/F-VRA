from pathlib import Path

from pyshare.pipeline.project_scanner.jarvis_parser import (
    CallEdge,
    CallGraph,
    FuncKind,
    FunctionNode,
    auto_detect_app_packages,
    classify,
    detect_entries,
    parse_jarvis,
    prune,
)
from pyshare.pipeline.project_scanner.jarvis_runner import (
    discover_entry_modules,
    run_jarvis,
)


def scan(project: Path, library: str) -> dict:
    # TODO: implement — builds UI(P,L) and GP
    return {"entry_points": [], "boundary_apis": []}


__all__ = [
    "CallEdge",
    "CallGraph",
    "FuncKind",
    "FunctionNode",
    "auto_detect_app_packages",
    "classify",
    "detect_entries",
    "discover_entry_modules",
    "parse_jarvis",
    "prune",
    "run_jarvis",
    "scan",
]
