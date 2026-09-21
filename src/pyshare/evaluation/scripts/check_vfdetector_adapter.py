"""Standalone checks for the VFDetector evaluation adapter."""
from __future__ import annotations

import csv
import tempfile
from pathlib import Path

from pyshare.evaluation.adapters.vfdetector_adapter import (
    _ranked_item,
    parse_results,
    to_vfdetector,
)


def test_ranked_item_normalizes_file_id_to_benchmark_qualified_name() -> None:
    item = _ranked_item("pkg/mod.py::Service.buggy", 0.42)
    assert item["func_id"] == "pkg.mod.Service.buggy", item
    assert item["qualified_name"] == "pkg.mod.Service.buggy", item
    assert item["file_path"] == "pkg/mod.py", item
    assert item["function_name"] == "buggy", item


def test_to_vfdetector_prefers_benchmark_qualified_gt() -> None:
    rec = {
        "advisory_id": "CVE-X",
        "repo_url": "https://github.com/o/r",
        "description": "desc",
        "vulnerable_ref": "vuln",
        "patches": [{"role": "canonical_fix", "sha": "fix"}],
        "root_cause_functions": [
            {
                "file_path": "pkg/mod.py",
                "function_name": "buggy",
                "qualified_name": "pkg.mod.Service.buggy",
            }
        ],
    }
    out = to_vfdetector(rec)
    assert out is not None
    assert out["all_functions"] == ["pkg.mod.Service.buggy"], out
    assert out["vulnerable_ref"] == "vuln", out


def test_parse_results_keeps_last_retry_row_and_normalizes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "results.csv"
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["cve_id", "top10", "truth_functions"],
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerow({
                "cve_id": "CVE-X",
                "top10": "pkg/mod.py::Old.fn:0.1",
                "truth_functions": "pkg.mod.Service.buggy",
            })
            writer.writerow({
                "cve_id": "CVE-X",
                "top10": "pkg/mod.py::Service.buggy:0.9",
                "truth_functions": "pkg.mod.Service.buggy",
            })
        records = parse_results(path)
    assert len(records) == 1, records
    ranked = records[0]["ranked_functions"]
    assert ranked[0]["func_id"] == "pkg.mod.Service.buggy", ranked
    assert records[0]["ground_truth"] == ["pkg.mod.Service.buggy"], records


def _run_all() -> None:
    checks = [
        v for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]
    for check in checks:
        check()
        print(f"  PASS {check.__name__.replace('test_', 'check_', 1)}")
    print(f"\n{len(checks)} vfdetector-adapter checks passed.")


if __name__ == "__main__":
    _run_all()
