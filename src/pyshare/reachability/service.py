from __future__ import annotations

from pathlib import Path

from pyshare.core.models import ScanResult, Verdict


def query(cve_id: str, project: Path, vf: str, explain: bool = False) -> ScanResult:
    return ScanResult(
        cve_id=cve_id,
        project=project,
        verdict=Verdict.UNKNOWN,
        vf=vf,
    )
