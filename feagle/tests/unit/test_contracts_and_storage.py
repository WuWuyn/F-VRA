from __future__ import annotations

import json

import pytest

from pyshare_core.models import (
    AnalysisFingerprint,
    Evidence,
    LibrarySummary,
    PackageIdentity,
    PackageSummaryArtifact,
    ProjectGraphArtifact,
    ProjectIdentity,
    ScanReport,
    Verdict,
    VulnerabilityRecord,
    VulnerableEntity,
)
from pyshare_client.storage import ClientCache
from pyshare_server.storage import ServerFileDb


def test_contracts_round_trip_and_reject_schema_mismatch():
    record = VulnerabilityRecord(
        cve_id="CVE-X",
        package="demo",
        entities=[
            VulnerableEntity(
                package="demo",
                name="demo.vulnerable",
                evidence=[Evidence(source="test", detail="unit evidence", confidence=0.9)],
            )
        ],
    )

    restored = VulnerabilityRecord.model_validate_json(record.model_dump_json())

    assert restored == record
    with pytest.raises(ValueError):
        VulnerabilityRecord.model_validate({"schema_version": "999", "cve_id": "CVE-X", "package": "demo"})


def test_sqlite_json_server_store_round_trips_vulnerability_and_summary(tmp_path):
    store = ServerFileDb(tmp_path / "server")
    record = VulnerabilityRecord(cve_id="CVE-X", package="demo")
    summary = PackageSummaryArtifact(
        package=PackageIdentity(name="demo", normalized_name="demo", version="1.0.0"),
        fingerprint=AnalysisFingerprint(scanner_version="test", config_hash="abc"),
        summary=LibrarySummary(inner_summary={"demo.api": {"demo.sink"}}),
    )

    store.put_vulnerability(record)
    store.put_package_summary("demo==1.0.0", summary)

    assert store.get_vulnerability("CVE-X") == record
    assert store.get_package_summary("demo==1.0.0") == summary
    assert store.list("vulnerability") == ["CVE-X"]
    assert store.list("package-summary") == ["demo==1.0.0"]


def test_client_cache_round_trips_project_package_and_scan_report(tmp_path):
    cache = ClientCache(tmp_path / "client")
    project = ProjectGraphArtifact(
        project=ProjectIdentity(root="/workspace/demo", fingerprint="demo"),
        usage_index=["requests.get"],
        graph={"edges_detail": []},
    )
    summary = PackageSummaryArtifact(
        package=PackageIdentity(name="requests", normalized_name="requests", version="2.31.0"),
        summary=LibrarySummary(outer_summary={"requests.get": {"urllib3.request"}}),
    )
    report = ScanReport(
        scan_id="scan-1",
        cve_id="CVE-X",
        project=project.project,
        verdict=Verdict.POTENTIALLY_REACHABLE,
    )

    cache.put_project("project-key", project)
    cache.put_package_summary("requests==2.31.0", summary)
    cache.put_scan_report(report)

    assert cache.get_project("project-key") == project
    assert cache.get_package_summary("requests==2.31.0") == summary
    assert cache.get_scan_report("scan-1") == report


def test_client_cache_treats_corrupt_payload_as_miss(tmp_path):
    cache = ClientCache(tmp_path / "client")
    project = ProjectGraphArtifact(project=ProjectIdentity(root="/workspace/demo", fingerprint="demo"))
    cache.put_project("project-key", project)
    payload = next((tmp_path / "client" / "projects").rglob("project-graph.json"))
    payload.write_text("{not json", encoding="utf-8")

    assert cache.get_project("project-key") is None

