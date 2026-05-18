import pytest
from typer.testing import CliRunner
from pyshare.cli.main import app

runner = CliRunner()


class TestCLIHelp:
    def test_root_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "index" in result.output
        assert "localize" in result.output
        assert "scan" in result.output
        assert "status" in result.output
        assert "eval" in result.output

    def test_index_help(self):
        result = runner.invoke(app, ["index", "--help"])
        assert result.exit_code == 0
        assert "pkg==version" in result.output

    def test_localize_help(self):
        result = runner.invoke(app, ["localize", "--help"])
        assert result.exit_code == 0
        assert "CVE" in result.output

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--cve" in result.output

    def test_status_help(self):
        result = runner.invoke(app, ["status", "--help"])
        assert result.exit_code == 0

    def test_eval_help(self):
        result = runner.invoke(app, ["eval", "--help"])
        assert result.exit_code == 0


class TestIndexCommand:
    def test_missing_version_separator(self):
        result = runner.invoke(app, ["index", "requests"])
        assert result.exit_code != 0

    def test_valid_format_runs(self):
        result = runner.invoke(app, ["index", "requests==2.31.0"])
        assert result.exit_code == 0


class TestScanCommand:
    def test_missing_cve_flag(self):
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0

    def test_valid_scan_unknown(self, tmp_path):
        result = runner.invoke(app, ["scan", "--cve", "CVE-2024-35195",
                                     "--project", str(tmp_path)])
        assert result.exit_code == 0

    def test_fail_on_affected_not_triggered_when_unknown(self, tmp_path):
        result = runner.invoke(app, ["scan", "--cve", "CVE-2024-35195",
                                     "--project", str(tmp_path),
                                     "--fail-on-affected"])
        assert result.exit_code == 0


class TestLocalizeCommand:
    def test_localize_stub(self):
        result = runner.invoke(app, ["localize", "CVE-2024-35195"])
        assert result.exit_code == 0
        assert "CVE-2024-35195" in result.output


class TestStatusCommand:
    def test_status_no_index(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pyshare.core.config.settings.index_dir", tmp_path / "nonexistent")
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
