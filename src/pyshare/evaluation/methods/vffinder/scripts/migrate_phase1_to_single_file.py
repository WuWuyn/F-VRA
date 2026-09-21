"""One-shot migration: per-CVE Phase 1 files -> one JSON file per level.

Phase 1 outputs used to be stored as one JSON file per CVE under the configured
output directory's {direct,sicl,picl}_phase1/ subdirectories. They are now
stored as a single file per level (direct_phase1.json, ...) keyed by CVE id;
see vffinder.extraction.phase1_store.

This script folds any legacy per-CVE directory into its single file. It is
idempotent and additive: existing entries in the single file are kept; per-CVE
records are merged in (per-CVE wins on conflict, since those are the raw LLM
outputs). Safe to re-run after a resumed legacy run adds more per-CVE files.

It does NOT delete the legacy directories. Verify the merged file first, then
remove them by hand:

    $out = "evaluation\\artifacts\\vffinder"
    Remove-Item "$out\\direct_phase1", "$out\\sicl_phase1", "$out\\picl_phase1" `
        -Recurse -Force

Usage:
    python -m pyshare.evaluation.methods.vffinder.scripts.migrate_phase1_to_single_file
"""
import json
import os
import sys
from pathlib import Path


from pyshare.evaluation.methods.vffinder import config
from pyshare.evaluation.methods.vffinder.extraction import phase1_store

# level -> legacy per-CVE directory name
LEGACY_DIRS = {
    "direct": "direct_phase1",
    "s-icl": "sicl_phase1",
    "p-icl": "picl_phase1",
}


def migrate_level(level: str, dir_name: str) -> None:
    src = config.OUTPUT_DIR / dir_name
    dest = phase1_store.phase1_path(level)
    if not src.is_dir():
        print(f"{dir_name}: no legacy directory, skipping")
        return

    data = phase1_store.load_phase1(level)  # keep anything already migrated
    before = len(data)
    added = 0
    for p in sorted(src.glob("*.json")):
        rec = json.load(open(p, encoding="utf-8"))
        cve_id = rec.get("cve_id")
        if not cve_id:
            print(f"  WARN: {p.name} has no cve_id, skipping")
            continue
        if cve_id not in data:
            added += 1
        data[cve_id] = rec

    # Single atomic write of the whole merged file (temp + os.replace).
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, dest)
    print(f"{dir_name}: {before} existing + {added} new = {len(data)} records "
          f"-> {dest}")


def main() -> None:
    for level, dir_name in LEGACY_DIRS.items():
        migrate_level(level, dir_name)
    print("\nDone. Verify the *_phase1.json files, then delete the legacy "
          "per-CVE directories (see this script's docstring).")


if __name__ == "__main__":
    main()
