from pathlib import Path

from .scanner import EntryPointScanner, scan_project

__all__ = ["EntryPointScanner", "scan_project", "scan"]

def scan(project: Path, library: str) -> dict:
    # TODO: implement — builds UI(P,L) and GP
    return {"entry_points": [], "boundary_apis": []}
