from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from pyshare.core.models import ExternalNode, LibrarySummary  # noqa: E402
from pyshare.reachability.engine import ReachabilityQueryEngine  # noqa: E402


def _resolve(path_value: str) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else REPO_ROOT / path


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _to_set_map(raw: dict[str, list[str]]) -> dict[str, set[str]]:
    return {key: set(values) for key, values in raw.items()}


def _load_summary(path: Path) -> LibrarySummary:
    payload = _load_json(path)
    summary = payload["summary"]
    return LibrarySummary(
        inner_summary=_to_set_map(summary.get("inner_summary", {})),
        outer_summary=_to_set_map(summary.get("outer_summary", {})),
    )


def _load_usage_index(config: dict[str, Any]) -> list[ExternalNode]:
    nodes: list[ExternalNode] = []
    for item in config["usage_index"]:
        nodes.append(
            ExternalNode(
                file_path=item["file_path"],
                function_name=item["function_name"],
                qualified_name=item["qualified_name"],
                target_module=item["target_module"],
                target_name=item["target_name"],
            )
        )
    return nodes


def _report_to_dict(report: Any, config: dict[str, Any]) -> dict[str, Any]:
    return {
        "experiment": config["name"],
        "is_vulnerable": report.is_vulnerable,
        "path_count": len(report.paths),
        "paths": [
            {
                "project_api": path.project_api,
                "tpl_chain": path.tpl_chain,
                "vulnerable_target": path.vulnerable_target,
            }
            for path in report.paths
        ],
    }


def run(config_path: Path) -> int:
    config = _load_json(config_path)
    summaries = {
        package: _load_summary(_resolve(path))
        for package, path in config["summaries"].items()
    }
    vf_annotation = _load_json(_resolve(config["vf_annotation"]))
    vulnerabilities = set(vf_annotation["vulnerable_functions"])

    report = ReachabilityQueryEngine(
        _load_usage_index(config),
        summaries,
        vulnerabilities,
    ).check_reachability()

    output = _resolve(config["output"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(_report_to_dict(report, config), indent=2),
        encoding="utf-8",
    )

    expected = config.get("expected", {})
    expected_path = expected.get("path")
    observed_paths = [path.tpl_chain for path in report.paths]
    ok = report.is_vulnerable == expected.get("is_vulnerable", True)
    if expected_path:
        ok = ok and expected_path in observed_paths

    status = "PASS" if ok else "FAIL"
    print(f"{status} {config['name']}")
    print(f"report: {output.relative_to(REPO_ROOT)}")
    for path in observed_paths:
        print(" -> ".join(path))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the mock transitive VF experiment.")
    parser.add_argument(
        "--config",
        type=Path,
        default=REPO_ROOT / "configs" / "mock_transitive.json",
        help="Path to experiment config JSON.",
    )
    args = parser.parse_args()
    return run(args.config)


if __name__ == "__main__":
    raise SystemExit(main())
