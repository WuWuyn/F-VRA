import sys
import types

from pyshare_client.package_analysis.callgraph import LibraryAnalyzer
from pyshare_client.callgraph.type_graph import FunctionTypeGraph, TypeGraphState
from pyshare_server.analysis.callgraph_pruning import apply_llm_pruning
from pyshare_client.package_analysis.summary import build_library_summary
from pyshare_client.project_analysis.entrypoints import scan_project
from pyshare_client.project_analysis.project_graph import build_project_graph


def test_package_analysis_records_static_exports_and_unresolved_dynamic_exports(tmp_path):
    package = tmp_path / "tiny_pkg"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .helpers import public\n"
        "from .starred import *\n"
        "from . import assigned_mod\n"
        "assigned = assigned_mod.target\n"
        "def __getattr__(name):\n"
        "    raise AttributeError(name)\n",
        encoding="utf-8",
    )
    (package / "helpers.py").write_text(
        "def public():\n"
        "    return sink()\n\n"
        "def sink():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (package / "starred.py").write_text(
        "__all__ = ['wild']\n"
        "def wild():\n"
        "    return None\n\n"
        "def hidden():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (package / "assigned_mod.py").write_text(
        "def target():\n"
        "    return None\n",
        encoding="utf-8",
    )
    subpackage = package / "subpkg"
    subpackage.mkdir()
    (subpackage / "__init__.py").write_text("from .impl import exposed\n", encoding="utf-8")
    (subpackage / "impl.py").write_text(
        "def exposed():\n"
        "    return None\n",
        encoding="utf-8",
    )

    analyzer = LibraryAnalyzer()
    analyzer.build_library_graph(package)

    assert analyzer.index is not None
    assert analyzer.index.public_api_aliases() == {
        "assigned": "assigned_mod.target",
        "public": "helpers.public",
        "subpkg.exposed": "subpkg.impl.exposed",
        "wild": "starred.wild",
    }
    assert analyzer.index.public_export_warnings()
    assert "module __getattr__" in analyzer.index.public_export_warnings()[0]["reason"]


def test_infercg_candidate_generation_uses_name_arity_and_metadata(tmp_path):
    package = tmp_path / "candidates"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "mod.py").write_text(
        "class Worker:\n"
        "    def run(self, value):\n"
        "        return value\n\n"
        "def caller(obj, value):\n"
        "    return factory().run(value)\n",
        encoding="utf-8",
    )

    graph = LibraryAnalyzer().build_library_graph(package)
    candidates = graph.metadata["candidate_edges"]

    assert any(
        candidate["callee"] == "mod.Worker.run"
        and candidate["resolver"] == "coarse_name_arity"
        and candidate["arity"] == 1
        and candidate["receiver"] == "factory()"
        and "def caller" in candidate["caller_source"]
        and "def run" in candidate["callee_source"]
        for candidate in candidates
    )


def test_infercg_candidate_generation_caps_large_fanout(tmp_path):
    package = tmp_path / "fanout"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    methods = "\n".join(
        f"class C{i}:\n    def run(self, value):\n        return value\n"
        for i in range(25)
    )
    (package / "mod.py").write_text(
        f"{methods}\n"
        "def caller(obj, value):\n"
        "    return factory().run(value)\n",
        encoding="utf-8",
    )

    graph = LibraryAnalyzer().build_library_graph(package)

    assert any(
        candidate["status"] == "too_many_candidates"
        and "exceeds cap" in candidate["reason"]
        for candidate in graph.metadata["candidate_edges"]
    )


def test_llm_pruning_keeps_candidates_in_final_edges_and_prunes_invalid_json(monkeypatch):
    calls = iter([
        '{"decision": "keep", "confidence": 0.91, "reason": "direct call"}',
        'not json',
    ])

    def fake_chat(*args, **kwargs):
        return next(calls)

    monkeypatch.setitem(sys.modules, "pyshare_server.localization.providers.llm_client", types.SimpleNamespace(chat=fake_chat))
    report = {
        "edges_detail": [],
        "candidate_edges": [
            {
                "caller": "mod.caller",
                "callee": "mod.Worker.run",
                "file_path": "mod.py",
                "line_number": 5,
                "call_expr": "obj.run(value)",
                "arity": 1,
                "receiver": "obj",
                "caller_source": "def caller(obj, value):\n    return obj.run(value)",
                "callee_source": "def run(self, value):\n    return value",
            },
            {
                "caller": "mod.caller",
                "callee": "mod.Other.run",
                "file_path": "mod.py",
                "line_number": 5,
                "call_expr": "obj.run(value)",
                "arity": 1,
            },
        ],
    }

    apply_llm_pruning(report, model="mock", threshold=0.75, limit=0)

    assert report["llm_kept_edges"][0]["callee"] == "mod.Worker.run"
    assert report["llm_kept_edges"][0]["edge_type"] == "llm_candidate"
    assert report["final_edges_detail"][0]["callee"] == "mod.Worker.run"
    assert report["llm_pruned_edges"][0]["callee"] == "mod.Other.run"


def test_package_analysis_builds_callgraph_and_summary():
    analyzer = LibraryAnalyzer()
    graph = analyzer.build_library_graph("tests/fixtures/sample_app")
    summary = build_library_summary(graph, analyzer.index.public_api)

    edges = {(edge.caller.qualified_name, edge.callee.qualified_name) for edge in graph.edges}

    assert ("pkg.lib.public_api", "pkg.lib.Client.fetch") in edges
    assert ("pkg.lib.Client.fetch", "requests.get") in edges
    assert "requests.get" in summary.outer_summary["pkg.lib.public_api"]
    assert "pkg.lib.Client.fetch" in summary.inner_summary["pkg.lib.public_api"]
    assert summary.inner_paths["pkg.lib.public_api"]["pkg.lib.Client.fetch"] == [
        "pkg.lib.public_api",
        "pkg.lib.Client.fetch",
    ]
    assert summary.outer_paths["pkg.lib.public_api"]["requests.get"] == [
        "pkg.lib.public_api",
        "pkg.lib.Client.fetch",
        "requests.get",
    ]
    assert analyzer.index.symbol_tables
    assert {edge.callee.qualified_name for edge in graph.external_edges} == {"requests.get", "requests.post"}
    assert ("pkg.lib.public_api", "pkg.lib.Client.fetch") in {
        (edge.caller.qualified_name, edge.callee.qualified_name) for edge in graph.internal_edges
    }
    assert any(call["call_expr"] == "Client()" for call in graph.metadata["unresolved_calls"])
    assert any(
        edge["callee"] == "pkg.lib.Client" and edge["resolver"] == "coarse_class_name_arity"
        for edge in graph.metadata["candidate_edges"]
    )


def test_project_analysis_discovers_entrypoint_and_reachable_usage_only():
    entrypoints = scan_project("tests/fixtures/sample_app")
    graph, usage_index = build_project_graph("tests/fixtures/sample_app")

    assert [entry.entry_type.value for entry in entrypoints] == ["main"]
    assert {node.identity_string for node in usage_index} == {"requests.get"}

    edges = {(edge.caller.qualified_name, edge.callee.qualified_name) for edge in graph.edges}
    assert ("pkg.app.main", "pkg.lib.public_api") in edges
    assert ("pkg.lib.unused_api", "requests.post") not in edges
    assert {edge.callee.qualified_name for edge in graph.external_edges} == {"requests.get"}
    assert any(call["call_expr"] == "Client()" for call in graph.metadata["unresolved_calls"])
    assert any(
        edge["callee"] == "pkg.lib.Client" and edge["resolver"] == "coarse_class_name_arity"
        for edge in graph.metadata["candidate_edges"]
    )


def test_type_graph_state_records_updates_and_joins():
    left = TypeGraphState()
    left.strong_update("client", {"pkg.Client"}, reason="constructor")
    right = TypeGraphState()
    right.strong_update("client", {"pkg.BackupClient"}, reason="constructor")

    joined = TypeGraphState.join(left, right)
    assert joined.get("client") == {"pkg.Client", "pkg.BackupClient"}

    graph = FunctionTypeGraph("pkg.main")
    graph.record_parameter_flow("client", {"pkg.Client"}, caller="pkg.entry")
    graph.record_return_flow({"pkg.Response"}, reason="return annotation")

    assert graph.entry_types["client"] == {"pkg.Client"}
    assert graph.return_types == {"pkg.Response"}


def test_type_flow_uses_annotations_return_inference_and_self_attributes(tmp_path):
    package = tmp_path / "typed_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "mod.py").write_text(
        "class Client:\n"
        "    def request(self):\n"
        "        return None\n\n"
        "def make_client() -> Client:\n"
        "    return Client()\n\n"
        "def from_return():\n"
        "    client = make_client()\n"
        "    return client.request()\n\n"
        "def from_annotation(client: Client):\n"
        "    return client.request()\n\n"
        "class Service:\n"
        "    def __init__(self):\n"
        "        self.client = Client()\n"
        "    def run(self):\n"
        "        return self.client.request()\n",
        encoding="utf-8",
    )

    analyzer = LibraryAnalyzer()
    graph = analyzer.build_library_graph(package)
    edges = {(edge.caller.qualified_name, edge.callee.qualified_name) for edge in graph.edges}

    assert analyzer.index.class_attribute_types["mod.Service"]["self.client"] == {"mod.Client"}
    assert ("mod.from_return", "mod.Client.request") in edges
    assert ("mod.from_annotation", "mod.Client.request") in edges
    assert ("mod.Service.run", "mod.Client.request") in edges


def test_project_type_flow_propagates_callsite_argument_types(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "__init__.py").write_text("", encoding="utf-8")
    (project / "app.py").write_text(
        "class Client:\n"
        "    def request(self):\n"
        "        return None\n\n"
        "def use(client):\n"
        "    return client.request()\n\n"
        "def main():\n"
        "    c = Client()\n"
        "    return use(c)\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    graph, _usage_index = build_project_graph(project)
    edges = {(edge.caller.qualified_name, edge.callee.qualified_name) for edge in graph.edges}

    assert ("app.main", "app.use") in edges
    assert ("app.use", "app.Client.request") in edges
    assert graph.metadata["parameter_type_facts"][0]["parameter"] == "client"


def test_project_type_flow_uses_interprocedural_return_and_external_models(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "import sqlite3\n\n"
        "def get_db():\n"
        "    return sqlite3.connect('app.db')\n\n"
        "def main():\n"
        "    connection = get_db()\n"
        "    rows = connection.execute('SELECT 1').fetchall()\n"
        "    connection.close()\n"
        "    return rows\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)
    usage_targets = {node.identity_string for node in usage_index}
    unresolved = graph.metadata.get("unresolved_calls", [])

    assert "sqlite3.connect" in usage_targets
    assert "sqlite3.Connection.execute" in usage_targets
    assert "sqlite3.Cursor.fetchall" in usage_targets
    assert "sqlite3.Connection.close" in usage_targets
    assert not any(call["call_expr"] == "connection.execute('SELECT 1')" for call in unresolved)
    assert not any(call["call_expr"] == "connection.execute('SELECT 1').fetchall()" for call in unresolved)
    assert not any(call["call_expr"] == "connection.close()" for call in unresolved)
    assert any(
        fact["function"] == "app.get_db"
        and "external:sqlite3.Connection" in fact["types"]
        for fact in graph.metadata["return_type_facts"]
    )
    assert any(
        fact["function"] == "app.main"
        and fact["target"] == "connection"
        and "external:sqlite3.Connection" in fact["types"]
        for fact in graph.metadata["assignment_type_facts"]
    )
    assert any(
        fact["target"] == "sqlite3.Connection.execute"
        for fact in graph.metadata["external_model_facts"]
    )
    assert any(
        fact["target"] == "sqlite3.Connection.close"
        for fact in graph.metadata["external_model_facts"]
    )


def test_project_usage_index_resolves_chained_external_module_calls(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "import jinja2\n"
        "from jinja2 import utils\n"
        "from sqlalchemy.orm import sessionmaker\n\n"
        "def main():\n"
        "    jinja2.utils.urlize('https://example.test')\n"
        "    utils.urlize('https://example.test')\n"
        "    sessionmaker()\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    _graph, usage_index = build_project_graph(project)
    usage_targets = {node.identity_string for node in usage_index}

    assert "jinja2.utils.urlize" in usage_targets
    assert "sqlalchemy.orm.sessionmaker" in usage_targets


def test_project_entrypoints_include_cherrypy_exposed_methods(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "import cherrypy\n"
        "import jinja2\n\n"
        "class Root:\n"
        "    @cherrypy.expose\n"
        "    def index(self):\n"
        "        return jinja2.utils.urlize('https://example.test')\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)
    entrypoints = {
        node.qualified_name
        for node in graph.internal_nodes
        if node.entry_type.value == "web"
    }

    assert "app.Root.index" in entrypoints
    assert {node.identity_string for node in usage_index} == {"jinja2.utils.urlize"}


def test_project_entrypoints_include_jinja_globals_exported_functions(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "import jinja2\n\n"
        "env = jinja2.Environment()\n\n"
        "def canonicalUrl(url):\n"
        "    return jinja2.utils.urlize(url)\n\n"
        "def main():\n"
        "    env.globals.update(globals())\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)
    entrypoints = {
        node.qualified_name
        for node in graph.internal_nodes
        if node.entry_type.value == "web"
    }

    assert "app.canonicalUrl" in entrypoints
    assert "jinja2.utils.urlize" in {node.identity_string for node in usage_index}


def test_project_graph_records_entrypoint_fallback_usage(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "import requests\n\n"
        "def public_task():\n"
        "    return requests.get('https://example.test')\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)

    assert graph.metadata["entrypoint_fallback_used"] is True
    assert graph.metadata["entry_points"] == ["app.public_task"]
    assert {node.identity_string for node in usage_index} == {"requests.get"}


def _usage_edges(graph):
    return {edge.callee.identity_string: edge for edge in graph.external_edges}


def test_project_usage_index_resolves_external_constructor_receiver(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "from extlib import Client\n\n"
        "def main():\n"
        "    client = Client()\n"
        "    client.request()\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)
    usage = _usage_edges(graph)

    assert "extlib.Client.request" in {node.identity_string for node in usage_index}
    assert usage["extlib.Client.request"].edge_type == "confirmed_type"
    assert usage["extlib.Client.request"].resolver == "external_constructor_receiver"


def test_project_usage_index_keeps_fluent_chain_methods_as_potential(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "def main():\n"
        "    session.query(Task).filter_by(done=False).order_by('name').all()\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)
    usage = _usage_edges(graph)
    targets = {node.identity_string for node in usage_index}

    assert {"query", "filter_by", "order_by", "all"}.issubset(targets)
    assert usage["order_by"].edge_type == "potential_pattern"
    assert usage["order_by"].resolver == "factory_unknown_receiver"


def test_project_usage_index_keeps_factory_loader_method_as_potential(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "from factorylib import load\n\n"
        "def main():\n"
        "    model = load('model.bin')\n"
        "    model.predict([1, 2, 3])\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)
    usage = _usage_edges(graph)

    assert "predict" in {node.identity_string for node in usage_index}
    assert usage["predict"].edge_type == "potential_pattern"
    assert usage["predict"].resolver == "factory_unknown_receiver"


def test_project_usage_index_propagates_context_manager_binding(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "from factorylib import make_session\n\n"
        "def main():\n"
        "    with make_session() as session:\n"
        "        session.query('Task')\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)
    usage = _usage_edges(graph)

    assert "query" in {node.identity_string for node in usage_index}
    assert usage["query"].edge_type == "potential_pattern"
    assert usage["query"].resolver == "factory_unknown_receiver"


def test_project_public_surface_mode_is_explicit(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "lib.py").write_text(
        "import yaml\n\n"
        "def load_config(text):\n"
        "    return yaml.load(text)\n",
        encoding="utf-8",
    )

    app_graph, app_usage = build_project_graph(project)
    public_graph, public_usage = build_project_graph(project, project_mode="public_surface")

    assert app_graph.metadata["project_mode"] == "application"
    assert public_graph.metadata["project_mode"] == "public_surface"
    assert {node.identity_string for node in app_usage} == {"yaml.load"}
    assert {node.identity_string for node in public_usage} == {"yaml.load"}


def test_project_index_reads_embedded_python_source_literals(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "generator.py").write_text(
        "files = {\n"
        "  'generated/diagnosis.py': '''\n"
        "from factorylib import load\n"
        "model = load('model.bin')\n"
        "def diagnose(data):\n"
        "    return model.predict(data)\n"
        "if __name__ == '__main__':\n"
        "    diagnose([1])\n"
        "'''\n"
        "}\n",
        encoding="utf-8",
    )

    graph, usage_index = build_project_graph(project)
    usage = _usage_edges(graph)

    assert "predict" in {node.identity_string for node in usage_index}
    assert usage["predict"].edge_type == "potential_pattern"
