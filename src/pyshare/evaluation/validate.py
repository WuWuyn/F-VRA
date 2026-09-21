"""Validate normalized prediction files before computing metrics."""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from pyshare.evaluation.paths import DEFAULT_MASTER, PROJECT_ROOT, RESULTS_ROOT


HERE = Path(__file__).resolve().parent
REPO_ROOT = PROJECT_ROOT
DEFAULT_PRED_DIR = RESULTS_ROOT / "predictions"

REQUIRED_RECORD = {
    "cve_id",
    "group_id",
    "method",
    "variant",
    "experiment_group",
    "axis",
    "ranked_functions",
    "ground_truth",
}
REQUIRED_RANKED = {"func_id", "score"}


def _load_master(master: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    with master.open(encoding="utf-8-sig") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            cid = rec.get("advisory_id") or rec.get("cve_id")
            if cid:
                rows[cid] = rec
    return rows


def _iter_prediction_records(pred_dir: Path):
    files = _prediction_files(pred_dir)
    for path in files:
        with path.open(encoding="utf-8-sig") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    yield path, lineno, json.loads(line)
                except json.JSONDecodeError as exc:
                    yield path, lineno, {"__json_error__": str(exc)}


def _prediction_files(pred_dir: Path) -> list[Path]:
    """Normalized predictions are <method>.jsonl; _*.jsonl are runner artifacts."""
    return sorted(
        path for path in pred_dir.glob("*.jsonl")
        if not path.name.startswith("_") and not path.name.endswith('_failures.jsonl')
    )


def validate_predictions(pred_dir: Path, master: Path) -> dict:
    """Validate prediction JSONL files and return a machine-readable summary."""
    master_rows = _load_master(master)
    files = _prediction_files(pred_dir)
    errors: list[str] = []
    warnings: list[str] = []
    seen: Counter = Counter()
    by_config: Counter = Counter()
    empty_by_config: Counter = Counter()
    no_gt_by_config: Counter = Counter()
    cves_by_config: dict[tuple[str, str], set[str]] = defaultdict(set)

    if not files:
        errors.append(f"no prediction files found in {pred_dir}")

    for path, lineno, rec in _iter_prediction_records(pred_dir):
        loc = f"{path}:{lineno}"
        if "__json_error__" in rec:
            errors.append(f"{loc}: invalid JSON: {rec['__json_error__']}")
            continue

        missing = REQUIRED_RECORD - set(rec)
        if missing:
            errors.append(f"{loc}: missing required fields {sorted(missing)}")

        method = rec.get("method", "?")
        variant = rec.get("variant", "?")
        cid = rec.get("cve_id", "?")
        key = (method, variant, cid)
        seen[key] += 1
        by_config[(method, variant)] += 1
        cves_by_config[(method, variant)].add(cid)

        if cid not in master_rows:
            warnings.append(f"{loc}: cve_id not present in master: {cid}")

        ranked = rec.get("ranked_functions")
        if not isinstance(ranked, list):
            errors.append(f"{loc}: ranked_functions must be a list")
        elif not ranked:
            empty_by_config[(method, variant)] += 1
        else:
            for idx, item in enumerate(ranked[:10], 1):
                if not isinstance(item, dict):
                    errors.append(f"{loc}: ranked_functions[{idx}] must be an object")
                    continue
                item_missing = REQUIRED_RANKED - set(item)
                if item_missing:
                    errors.append(
                        f"{loc}: ranked_functions[{idx}] missing {sorted(item_missing)}"
                    )

        gt = rec.get("ground_truth")
        if not isinstance(gt, list):
            errors.append(f"{loc}: ground_truth must be a list")
        elif not gt:
            no_gt_by_config[(method, variant)] += 1

    duplicates = {k: n for k, n in seen.items() if n > 1}
    for (method, variant, cid), count in sorted(duplicates.items()):
        warnings.append(
            f"duplicate prediction record kept by metrics last-write rule: "
            f"{method}/{variant}/{cid} appears {count} times"
        )

    for cfg, total in sorted(by_config.items()):
        method, variant = cfg
        empty = empty_by_config[cfg]
        no_gt = no_gt_by_config[cfg]
        coverage = len(cves_by_config[cfg])
        if empty:
            warnings.append(f"{method}/{variant}: {empty}/{total} records have empty rankings")
        if no_gt:
            warnings.append(f"{method}/{variant}: {no_gt}/{total} records have empty ground_truth")
        if coverage < len(master_rows):
            warnings.append(
                f"{method}/{variant}: covers {coverage}/{len(master_rows)} master CVEs"
            )

    if files and not by_config:
        errors.append(f"prediction files in {pred_dir} contain zero records")

    return {
        "pred_dir": str(pred_dir),
        "master": str(master),
        "files": [str(f) for f in files],
        "records": sum(by_config.values()),
        "configs": {
            f"{m}/{v}": {
                "records": by_config[(m, v)],
                "cves": len(cves_by_config[(m, v)]),
                "empty": empty_by_config[(m, v)],
                "no_gt": no_gt_by_config[(m, v)],
            }
            for m, v in sorted(by_config)
        },
        "errors": errors,
        "warnings": warnings,
    }


def print_validation(summary: dict) -> None:
    print(f"Prediction dir: {summary['pred_dir']}")
    print(f"Master: {summary['master']}")
    print(f"Files: {len(summary['files'])}")
    print(f"Records: {summary['records']}")
    if summary["configs"]:
        print("\nConfigs:")
        for name, row in summary["configs"].items():
            print(
                f"  {name}: records={row['records']} cves={row['cves']} "
                f"empty={row['empty']} no_gt={row['no_gt']}"
            )
    if summary["warnings"]:
        print("\nWarnings:")
        for warning in summary["warnings"]:
            print(f"  WARN {warning}")
    if summary["errors"]:
        print("\nErrors:")
        for error in summary["errors"]:
            print(f"  ERROR {error}")
    print("\nValidation " + ("FAILED" if summary["errors"] else "passed"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate normalized prediction JSONL files.")
    ap.add_argument("--pred-dir", type=Path, default=DEFAULT_PRED_DIR)
    ap.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    args = ap.parse_args(argv)

    summary = validate_predictions(args.pred_dir, args.master)
    print_validation(summary)
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
