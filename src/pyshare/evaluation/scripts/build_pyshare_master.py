"""Build the evaluation master from PyShare's finalized benchmark and severity data."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable
from pyshare.evaluation.paths import PROJECT_ROOT


REPO_ROOT = PROJECT_ROOT
DEFAULT_BENCHMARK = REPO_ROOT / "data" / "final" / "vf_benchmark_finalized.jsonl"
DEFAULT_SEVERITY = REPO_ROOT / "data" / "final" / "severity_sources.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "processed" / "cve_to_vf_evaluation.jsonl"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8-sig") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _key(row: dict[str, Any]) -> str:
    return str(row.get("group_id") or row.get("cve_id") or row.get("advisory_id") or "")


def _vulnerable_ref(row: dict[str, Any]) -> str | None:
    if row.get("vulnerable_ref"):
        return str(row["vulnerable_ref"])
    for patch in row.get("patches") or []:
        if patch.get("parent_sha"):
            return str(patch["parent_sha"])
    return None


def _normalize_function(function: dict[str, Any]) -> dict[str, Any]:
    result = dict(function)
    qualified_name = result.get("qualified_name")
    if not result.get("function_name") and qualified_name:
        result["function_name"] = str(qualified_name).rsplit(".", 1)[-1]
    result["file_path"] = result.get("file_path") or None
    return result


def build_records(
    benchmark_rows: Iterable[dict[str, Any]],
    severity_rows: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    severities = {_key(row): row for row in severity_rows if _key(row)}
    records: list[dict[str, Any]] = []
    warnings: list[str] = []

    for source in benchmark_rows:
        key = _key(source)
        severity = severities.get(key)
        record = dict(source)
        cve_id = record.get("advisory_id") or record.get("cve_id")
        record["advisory_id"] = cve_id
        record["cve_id"] = cve_id
        record["vulnerable_ref"] = _vulnerable_ref(record)
        record["root_cause_functions"] = [
            _normalize_function(function)
            for function in (record.get("root_cause_functions") or [])
        ]

        if severity is None:
            warnings.append(f"{key}: missing severity metadata")
            record["severity"] = None
            record["cwes"] = []
        else:
            record["severity"] = {
                name: value for name, value in severity.items() if name != "group_id"
            }
            record["cwes"] = list(severity.get("cwe_union") or [])

        if not record.get("vulnerable_ref"):
            warnings.append(f"{key}: missing vulnerable_ref and patch parent_sha")
        if not record["root_cause_functions"]:
            warnings.append(f"{key}: no root_cause_functions")
        for function in record["root_cause_functions"]:
            if not function.get("file_path"):
                warnings.append(
                    f"{key}: no file path for {function.get('qualified_name')}"
                )

        records.append(record)

    benchmark_keys = {_key(row) for row in records}
    for key in sorted(set(severities) - benchmark_keys):
        warnings.append(f"{key}: severity metadata has no benchmark record")
    return records, warnings


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def build_master(benchmark: Path, severity: Path, output: Path) -> int:
    records, warnings = build_records(read_jsonl(benchmark), read_jsonl(severity))
    write_jsonl(output, records)
    print(f"Built {len(records)} evaluation records -> {output}")
    if warnings:
        print(f"Warnings: {len(warnings)} (showing up to 20)")
        for warning in warnings[:20]:
            print(f"  - {warning}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--severity", type=Path, default=DEFAULT_SEVERITY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    return build_master(args.benchmark, args.severity, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
