from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pyshare_api.db.models import AdvisoryAffectedPackage, Base, RawAdvisorySource, SeverityRecord, VulnerableEntity
from pyshare_api.db.repository import version_is_affected
from pyshare_server.advisories import ingest_osv_record


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return Session()


def test_ingest_osv_record_persists_advisory_package_ranges_and_vulnerable_entities():
    session = make_session()
    ingest_osv_record(
        session,
        {
            "id": "PYSEC-TEST-1",
            "aliases": ["CVE-TEST-1", "GHSA-TEST-1"],
            "summary": "test advisory",
            "details": "details",
            "published": "2026-01-01T00:00:00Z",
            "modified": "2026-01-02T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {"cwe_ids": ["CWE-79"]},
            "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "Flask"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.3.3"}]}],
                    "database_specific": {"functions": ["flask.render_template"]},
                }
            ],
        },
    )

    affected = session.query(AdvisoryAffectedPackage).one()
    assert affected.normalized_name == "flask"
    assert affected.fixed_versions == ["2.3.3"]
    assert session.query(VulnerableEntity).one().name == "flask.render_template"
    assert session.query(RawAdvisorySource).count() == 1
    assert session.query(SeverityRecord).count() == 1


def test_version_is_affected_respects_fixed_version_boundary():
    assert version_is_affected("2.3.2", [">=2.3.0"], ["2.3.3"]) is True
    assert version_is_affected("2.3.3", [">=2.3.0"], ["2.3.3"]) is False
