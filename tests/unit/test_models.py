from pathlib import Path
import pytest
from pyshare.core.models import (
    Verdict,
    OutputFormat,
    IndexResult,
    LocalizeResult,
    ScanResult,
)


class TestVerdict:
    def test_values(self):
        assert Verdict.AFFECTED == "AFFECTED"
        assert Verdict.NOT_AFFECTED == "NOT_AFFECTED"
        assert Verdict.UNKNOWN == "UNKNOWN"


class TestIndexResult:
    def test_defaults(self):
        r = IndexResult(package="requests", version="2.31.0")
        assert r.functions == 0
        assert r.api_count == 0
        assert r.elapsed_s == 0.0
        assert r.cached is False

    def test_fields(self):
        r = IndexResult(package="requests", version="2.31.0", functions=42, cached=True)
        assert r.functions == 42
        assert r.cached is True


class TestLocalizeResult:
    def test_defaults(self):
        r = LocalizeResult(cve_id="CVE-2024-35195", package="requests")
        assert r.vf == ""
        assert r.score == 0.0
        assert r.mode == "unknown"
        assert r.candidates == []
        assert r.cached is False


class TestScanResult:
    def test_defaults(self):
        r = ScanResult(cve_id="CVE-2024-35195", project=Path("."))
        assert r.verdict == Verdict.UNKNOWN
        assert r.entry_points == []
        assert r.hit_set == []
        assert r.call_chain == []
        assert r.llm_invoked is False

    def test_affected(self):
        r = ScanResult(
            cve_id="CVE-2024-35195",
            project=Path("."),
            verdict=Verdict.AFFECTED,
            vf="requests.sessions.Session.request",
            hit_set=["myapp.client.fetch_data"],
        )
        assert r.verdict == Verdict.AFFECTED
        assert "myapp.client.fetch_data" in r.hit_set
