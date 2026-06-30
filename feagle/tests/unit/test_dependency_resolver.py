import json
import subprocess

from pyshare_client.commands import deps
import pyshare_client.dependencies.resolver as resolver
from pyshare_client.dependencies.callgraph_builder import source_root_for_record
from pyshare_client.dependencies.resolver import _infer_direct_from_requirements_freeze, resolve_dependency_graph
from pyshare_core.models import DependencyRecord


def test_dependency_resolver_prefers_lockfile_versions_and_marks_direct(tmp_path):
    project = tmp_path / "app"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        """
        [project]
        dependencies = [
          "requests>=2.31",
          "Jinja2==3.1.2",
        ]
        """,
        encoding="utf-8",
    )
    (project / "poetry.lock").write_text(
        """
        [[package]]
        name = "requests"
        version = "2.31.0"
        category = "main"
        optional = false
        python-versions = ">=3.8"
        dependencies = { certifi = ">=2017.4.17", urllib3 = ">=1.21.1" }

        [[package]]
        name = "certifi"
        version = "2024.2.2"
        category = "main"
        optional = false
        python-versions = ">=3.6"
        """,
        encoding="utf-8",
    )

    artifact = resolve_dependency_graph(project)
    by_name = {item.normalized_name: item for item in artifact.dependencies}

    assert [item.normalized_name for item in artifact.dependencies].count("requests") == 1
    assert by_name["requests"].version == "2.31.0"
    assert by_name["requests"].direct is True
    assert by_name["requests"].dependencies == ["certifi", "urllib3"]
    assert by_name["certifi"].version == "2024.2.2"
    assert by_name["certifi"].direct is False
    assert artifact.resolver == "pyshare-static"


def test_dependency_resolver_reads_requirements_and_pipfile_lock(tmp_path):
    project = tmp_path / "app"
    project.mkdir()
    (project / "requirements.txt").write_text(
        "flask==3.0.0\n"
        "PyYAML>=6\n"
        "-r extra.txt\n",
        encoding="utf-8",
    )
    (project / "extra.txt").write_text("markupsafe==2.1.5\n", encoding="utf-8")
    (project / "Pipfile.lock").write_text(
        json.dumps(
            {
                "default": {
                    "cryptography": {"version": "==42.0.0"},
                },
                "develop": {
                    "pytest": {"version": "==8.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    artifact = resolve_dependency_graph(project, include_dev=True)
    by_name = {item.normalized_name: item for item in artifact.dependencies}

    assert by_name["flask"].version == "3.0.0"
    assert by_name["pyyaml"].specifier == ">=6"
    assert by_name["markupsafe"].version == "2.1.5"
    assert by_name["cryptography"].version == "42.0.0"
    assert by_name["pytest"].dev is True


def test_dependency_resolver_reads_uv_lock(tmp_path):
    project = tmp_path / "app"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        """
        [project]
        dependencies = ["httpx>=0.27"]
        """,
        encoding="utf-8",
    )
    (project / "uv.lock").write_text(
        """
        [[package]]
        name = "httpx"
        version = "0.27.0"
        dependencies = [
          { name = "httpcore" },
        ]

        [[package]]
        name = "httpcore"
        version = "1.0.5"
        """,
        encoding="utf-8",
    )

    artifact = resolve_dependency_graph(project)
    by_name = {item.normalized_name: item for item in artifact.dependencies}

    assert by_name["httpx"].version == "0.27.0"
    assert by_name["httpx"].direct is True
    assert by_name["httpx"].dependencies == ["httpcore"]
    assert by_name["httpcore"].direct is False


def test_requirements_freeze_direct_inference_uses_imports_and_dependency_edges(tmp_path):
    project = tmp_path / "app"
    project.mkdir()
    (project / "app.py").write_text("from flask import Flask\n", encoding="utf-8")

    records = [
        DependencyRecord(name="Flask", normalized_name="flask", version="2.3.2", dependencies=["jinja2", "werkzeug"]),
        DependencyRecord(name="Jinja2", normalized_name="jinja2", version="3.1.2", dependencies=["markupsafe"]),
        DependencyRecord(name="MarkupSafe", normalized_name="markupsafe", version="2.1.1", dependencies=[]),
        DependencyRecord(name="Werkzeug", normalized_name="werkzeug", version="2.2.3", dependencies=[]),
        DependencyRecord(name="pytest", normalized_name="pytest", version="7.2.0", dependencies=[]),
    ]

    by_name = {item.normalized_name: item for item in _infer_direct_from_requirements_freeze(project, records)}

    assert by_name["flask"].direct is True
    assert by_name["pytest"].direct is True
    assert by_name["jinja2"].direct is False
    assert by_name["markupsafe"].direct is False
    assert by_name["werkzeug"].direct is False


def test_pip_report_preserves_requirements_as_direct_dependencies(tmp_path, monkeypatch):
    project = tmp_path / "app"
    project.mkdir()
    (project / "requirements.txt").write_text("requests\nflask\n", encoding="utf-8")

    def fake_run(command, cwd, text, capture_output, check, timeout):
        report_path = command[command.index("--report") + 1]
        payload = {
            "install": [
                {
                    "requested": True,
                    "metadata": {
                        "name": "requests",
                        "version": "2.31.0",
                        "requires_dist": ["urllib3<3,>=1.21.1", "certifi>=2017.4.17"],
                    },
                },
                {"requested": False, "metadata": {"name": "urllib3", "version": "2.0.7", "requires_dist": []}},
                {"requested": False, "metadata": {"name": "certifi", "version": "2024.2.2", "requires_dist": []}},
                {"requested": True, "metadata": {"name": "Flask", "version": "3.0.0", "requires_dist": ["Werkzeug>=3.0.0"]}},
                {"requested": False, "metadata": {"name": "Werkzeug", "version": "3.0.1", "requires_dist": []}},
            ]
        }
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(resolver.subprocess, "run", fake_run)

    artifact = resolve_dependency_graph(project)
    by_name = {item.normalized_name: item for item in artifact.dependencies}

    assert by_name["requests"].direct is True
    assert by_name["flask"].direct is True
    assert by_name["urllib3"].direct is False
    assert by_name["certifi"].direct is False
    assert by_name["werkzeug"].direct is False


def test_dependency_command_docs_describe_manifest_lockfile_flow():
    source = deps.app.info.help + deps.resolve.__doc__ + deps.build_callgraphs.__doc__

    assert "manifest" in source.lower()
    assert "lockfile" in source.lower()


def test_dependency_callgraph_builder_does_not_treat_empty_source_as_workspace():
    record = DependencyRecord(name="missing", normalized_name="missing", version="1.0.0")

    assert source_root_for_record(record) is None
