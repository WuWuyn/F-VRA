"""Single-file storage for Phase 1 ICL extractor outputs.

Each ICL level (direct / s-icl / p-icl) keeps ONE JSON file keyed by CVE id,
for example results/evaluation/adapters/vffinder/native_output/direct_phase1.json, instead of one
file per CVE. This keeps runtime artifacts out of methods/ while preserving the
incremental checkpoint/resume contract: after every CVE the whole file is
rewritten atomically (temp file + os.replace), and resume skips CVE ids already
present in the file.

File shape:
    {
      "CVE-2011-2185": { "cve_id": ..., "attack_vector": [...], ... },
      "CVE-2011-4104": { ... },
      ...
    }
"""
import json
import os
from pathlib import Path

from pyshare.evaluation.methods.vffinder import config

# Map an ICL level to its single output JSON file.
_LEVEL_FILE = {
    "direct": "direct_phase1.json",
    "s-icl": "sicl_phase1.json",
    "p-icl": "picl_phase1.json",
}


def phase1_path(level: str) -> Path:
    """Path to the single Phase 1 output file for `level`."""
    return config.OUTPUT_DIR / _LEVEL_FILE[level]


def errors_path(level: str) -> Path:
    """Path to the per-level error log, sibling of the output file."""
    p = phase1_path(level)
    return p.with_name(p.stem + "_errors.log")


def load_phase1(level: str) -> dict:
    """Return {cve_id: record}. Empty dict if the file does not exist yet."""
    path = phase1_path(level)
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_record(level: str, record: dict) -> Path:
    """Insert/update one CVE record and atomically rewrite the whole file.

    Re-reads the file each call so a crash mid-run never loses earlier CVEs and
    resume always sees a consistent on-disk snapshot.
    """
    path = phase1_path(level)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = load_phase1(level)
    data[record["cve_id"]] = record
    tmp_path = path.with_name(f".{path.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)
    return path
