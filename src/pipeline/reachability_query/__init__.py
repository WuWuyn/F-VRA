from pathlib import Path
from pyshare.core.models import ScanResult, Verdict

def query(cve_id: str, project: Path, vf: str, explain: bool = False) -> ScanResult:
    # TODO: implement — Phase 4 set operations
    return ScanResult(cve_id=cve_id, project=project, verdict=Verdict.UNKNOWN)
