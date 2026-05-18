from pathlib import Path
from pyshare.core.config import Settings


class TestSettings:
    def test_defaults(self):
        s = Settings()
        assert s.neo4j_uri == "bolt://localhost:7687"
        assert s.neo4j_user == "neo4j"
        assert isinstance(s.index_dir, Path)
        assert isinstance(s.cve_cache_dir, Path)

    def test_index_dir_default(self):
        s = Settings()
        assert s.index_dir == Path.home() / ".pyshare" / "index"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("NEO4J_URI", "bolt://remotehost:7687")
        s = Settings()
        assert s.neo4j_uri == "bolt://remotehost:7687"
