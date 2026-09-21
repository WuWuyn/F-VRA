from pyshare.evaluation.scripts.build_pyshare_master import build_records


def test_build_records_joins_finalized_benchmark_and_severity() -> None:
    benchmark = [{
        "advisory_id": "CVE-2026-1",
        "group_id": "CVE-2026-1::demo",
        "package_name": "demo",
        "description": "unsafe load",
        "repo_url": "https://github.com/example/demo",
        "vulnerable_ref": None,
        "patches": [{"sha": "fix", "parent_sha": "parent", "role": "canonical_fix"}],
        "root_cause_functions": [{
            "qualified_name": "demo.parser.load",
            "file_path": "demo/parser.py",
            "label": "root_cause_vf",
        }],
    }]
    severity = [{
        "group_id": "CVE-2026-1::demo",
        "cwe_union": ["CWE-20"],
        "sources": [{"source": "GHSA", "severity_level": "HIGH"}],
        "epss": {"score": 0.25},
    }]

    records, warnings = build_records(benchmark, severity)

    assert warnings == []
    assert records[0]["vulnerable_ref"] == "parent"
    assert records[0]["cwes"] == ["CWE-20"]
    assert records[0]["severity"]["epss"] == {"score": 0.25}
    assert records[0]["root_cause_functions"][0]["function_name"] == "load"
