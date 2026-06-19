"""Filter raw GitHub repo metadata by Q3 thresholds.

Tool nay doc file raw metadata tu GitHub Search API, tinh Q3 cho 3 truong:
- stargazers_count
- forks_count
- size

Sau do xuat ra file JSON moi, chi giu cac repo co ca 3 gia tri deu >= Q3.
File raw goc khong bi thay doi.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_INPUT = "github_search_raw_repos.json"
DEFAULT_OUTPUT = "github_search_raw_repos_q3_filtered.json"


def load_json_list(path: Path) -> list[dict[str, Any]]:
    """Doc JSON list va kiem tra dinh dang co ban."""

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON list in {path}")

    records: list[dict[str, Any]] = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Expected object at item {index} in {path}")
        records.append(item)
    return records


def percentile(values: list[float], p: float) -> float:
    """Tinh percentile theo cach noi suy gan voi pandas/numpy mac dinh."""

    if not values:
        raise ValueError("Cannot calculate percentile from empty values")

    ordered = sorted(values)
    position = (len(ordered) - 1) * p
    lower_index = int(position)
    upper_index = min(lower_index + 1, len(ordered) - 1)
    fraction = position - lower_index

    lower = ordered[lower_index]
    upper = ordered[upper_index]
    return lower + (upper - lower) * fraction


def numeric_values(records: list[dict[str, Any]], field: str) -> list[float]:
    """Lay cac gia tri numeric cua mot field."""

    values: list[float] = []
    for record in records:
        value = record.get(field)
        if isinstance(value, (int, float)):
            values.append(float(value))
    return values


def filter_by_q3(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, float]]:
    """Loc repo co stars, forks va size deu >= Q3."""

    thresholds = {
        "stargazers_count": percentile(numeric_values(records, "stargazers_count"), 0.75),
        "forks_count": percentile(numeric_values(records, "forks_count"), 0.75),
        "size": percentile(numeric_values(records, "size"), 0.75),
    }

    filtered = [
        record
        for record in records
        if isinstance(record.get("stargazers_count"), (int, float))
        and isinstance(record.get("forks_count"), (int, float))
        and isinstance(record.get("size"), (int, float))
        and record["stargazers_count"] >= thresholds["stargazers_count"]
        and record["forks_count"] >= thresholds["forks_count"]
        and record["size"] >= thresholds["size"]
    ]

    return filtered, thresholds


def write_json(data: list[dict[str, Any]], path: Path) -> None:
    """Ghi JSON output."""

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def parse_args() -> argparse.Namespace:
    """Doc tham so command line."""

    parser = argparse.ArgumentParser(
        description="Filter raw GitHub repository metadata by Q3 thresholds of stars, forks, and size."
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help=f"Input raw JSON. Default: {DEFAULT_INPUT}")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"Output filtered JSON. Default: {DEFAULT_OUTPUT}")
    return parser.parse_args()


def main() -> int:
    """Entry point."""

    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    records = load_json_list(input_path)
    filtered, thresholds = filter_by_q3(records)
    write_json(filtered, output_path)

    print(f"Input repos: {len(records)}")
    print(f"Q3 stars: {thresholds['stargazers_count']}")
    print(f"Q3 forks: {thresholds['forks_count']}")
    print(f"Q3 size: {thresholds['size']} KB")
    print(f"Filtered repos: {len(filtered)}")
    print(f"Filtered rate: {len(filtered) / len(records):.6f}")
    print(f"Output: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
