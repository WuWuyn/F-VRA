"""Smoke tests for the JARVIS JSON parser.

Pins current invariants so refactors don't silently break classification,
entry detection, or pruning. Uses small handcrafted fixtures (so tests
don't depend on a real JARVIS install) plus one optional integration
fixture against the operation-deploy/server.py output if present.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyshare.pipeline.project_scanner import jarvis_parser
from pyshare.pipeline.project_scanner.jarvis_parser import (
    CallEdge,
    FuncKind,
    FunctionNode,
    auto_detect_app_packages,
    classify,
    detect_entries,
    parse_jarvis,
    prune,
)


# ---------------------------------------------------------------------
# classify()
# ---------------------------------------------------------------------

class TestClassify:
    app_pkgs = frozenset({"myapp"})

    @pytest.mark.parametrize("qname,expected", [
        # builtins
        ("<builtin>.print", FuncKind.BUILTIN),
        ("<builtin>.frozenset", FuncKind.BUILTIN),
        # type methods
        ("<str>.split", FuncKind.TYPE_METHOD),
        ("<map>.items", FuncKind.TYPE_METHOD),
        ("<list>.append", FuncKind.TYPE_METHOD),
        # unresolved bare names
        ("append", FuncKind.UNRESOLVED),
        ("extend", FuncKind.UNRESOLVED),
        ("pop", FuncKind.UNRESOLVED),
        ("index", FuncKind.UNRESOLVED),
        # stdlib
        ("os.path.join", FuncKind.STDLIB),
        ("json.dumps", FuncKind.STDLIB),
        ("asyncio.tasks.sleep", FuncKind.STDLIB),
        # tpl (not in stdlib_module_names)
        ("aiohttp.web.run_app", FuncKind.TPL),
        ("requests.sessions.Session.request", FuncKind.TPL),
        ("yarl._url.URL.build", FuncKind.TPL),
        # app
        ("myapp.main", FuncKind.APP),
        ("myapp.api.client.fetch_data", FuncKind.APP),
    ])
    def test_classification(self, qname, expected):
        assert classify(qname, self.app_pkgs) == expected

    def test_lambda_keeps_classification_of_root(self):
        # collections.<lambda1> is a nested lambda within stdlib collections
        assert classify("collections.<lambda1>", self.app_pkgs) == FuncKind.STDLIB


# ---------------------------------------------------------------------
# parse_jarvis() — small handcrafted fixture
# ---------------------------------------------------------------------

@pytest.fixture
def tiny_jarvis_json(tmp_path: Path) -> Path:
    """A minimal JARVIS output covering all the edge cases in real
    output: module-level entry, app -> tpl boundary, unresolved bare
    names, builtins, type methods, empty callee, lambda."""
    data = {
        "myapp": ["myapp.main"],
        "myapp.main": [
            "aiohttp.web.run_app",
            "<builtin>.print",
            "append",
        ],
        "myapp.handler": [
            "aiohttp.web_ws.WebSocketResponse.prepare",
            "<map>.items",
            "myapp.helper",
            "",  # empty callee artifact — must be dropped
        ],
        "myapp.helper": ["json.dumps"],
        "aiohttp.web.run_app": [],
        "aiohttp.web_ws.WebSocketResponse.prepare": [],
        "json.dumps": [],
        # JARVIS also emits stdlib module-level entries, like:
        "json": ["json.dumps"],
        "<builtin>.print": [],
        "<map>.items": [],
        "append": [],
    }
    p = tmp_path / "jarvis.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


class TestParseJarvis:
    def test_module_level_caller_is_skipped(self, tiny_jarvis_json):
        # The "myapp": [...] caller is module-level and shouldn't appear
        # as a node — it's not a real function call.
        cg = parse_jarvis(tiny_jarvis_json, {"myapp"})
        assert "myapp" not in cg.nodes

    def test_empty_callee_dropped(self, tiny_jarvis_json):
        cg = parse_jarvis(tiny_jarvis_json, {"myapp"})
        assert "" not in cg.nodes
        for e in cg.edges:
            assert e.caller and e.callee

    def test_classification_applied(self, tiny_jarvis_json):
        cg = parse_jarvis(tiny_jarvis_json, {"myapp"})
        assert cg.nodes["myapp.main"].kind == FuncKind.APP
        assert cg.nodes["aiohttp.web.run_app"].kind == FuncKind.TPL
        assert cg.nodes["json.dumps"].kind == FuncKind.STDLIB
        assert cg.nodes["<builtin>.print"].kind == FuncKind.BUILTIN
        assert cg.nodes["<map>.items"].kind == FuncKind.TYPE_METHOD
        assert cg.nodes["append"].kind == FuncKind.UNRESOLVED

    def test_auto_detect_when_app_packages_none(self, tiny_jarvis_json):
        cg = parse_jarvis(tiny_jarvis_json, None)
        # myapp should be auto-detected as app (json is stdlib so excluded)
        assert cg.nodes["myapp.main"].kind == FuncKind.APP
        assert cg.nodes["json.dumps"].kind == FuncKind.STDLIB


# ---------------------------------------------------------------------
# auto_detect_app_packages()
# ---------------------------------------------------------------------

class TestAutoDetect:
    def test_includes_real_app(self):
        raw = {
            "myapp": ["myapp.main"],
            "myapp.main": [],
        }
        assert auto_detect_app_packages(raw) == {"myapp"}

    def test_excludes_stdlib(self):
        raw = {
            "myapp": ["myapp.main"],
            "os": ["os._fspath"],
            "json": ["json.dumps"],
            "asyncio": ["asyncio.tasks.sleep"],
        }
        # stdlib modules are filtered, only myapp remains.
        assert auto_detect_app_packages(raw) == {"myapp"}

    def test_excludes_bare_unresolved(self):
        # "append" is a no-dot key but its callees don't start with
        # "append." -- so it isn't a real package.
        raw = {"append": [], "myapp": ["myapp.main"]}
        assert auto_detect_app_packages(raw) == {"myapp"}

    def test_excludes_angle_keys(self):
        raw = {"<builtin>.print": [], "myapp": ["myapp.x"]}
        assert auto_detect_app_packages(raw) == {"myapp"}


# ---------------------------------------------------------------------
# detect_entries() + prune()
# ---------------------------------------------------------------------

class TestEntriesAndPrune:
    def test_entry_heuristic_top_level_lowercase_only(self, tiny_jarvis_json):
        cg = parse_jarvis(tiny_jarvis_json, {"myapp"})
        cg = detect_entries(cg, {"myapp"})
        entries = {n.qname for n in cg.nodes.values() if n.is_entry}
        # myapp.main, myapp.handler, myapp.helper all qualify
        # (2 segments, second segment lowercase, kind=APP).
        assert entries == {"myapp.main", "myapp.handler", "myapp.helper"}

    def test_class_methods_not_marked_entry(self, tmp_path: Path):
        # 3-segment qnames (class methods) should NOT be entries.
        data = {
            "myapp.Player.send": [],
            "myapp.main": [],
        }
        p = tmp_path / "j.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        cg = parse_jarvis(p, {"myapp"})
        cg = detect_entries(cg, {"myapp"})
        entries = {n.qname for n in cg.nodes.values() if n.is_entry}
        assert entries == {"myapp.main"}
        assert not cg.nodes["myapp.Player.send"].is_entry

    def test_prune_drops_noise_kinds(self, tiny_jarvis_json):
        cg = parse_jarvis(tiny_jarvis_json, {"myapp"})
        cg = detect_entries(cg, {"myapp"})
        cg = prune(cg)
        kinds = {n.kind for n in cg.nodes.values()}
        assert FuncKind.BUILTIN not in kinds
        assert FuncKind.TYPE_METHOD not in kinds
        assert FuncKind.UNRESOLVED not in kinds

    def test_prune_keeps_only_reachable(self, tmp_path: Path):
        # An orphan stdlib node not reachable from any app entry
        # should be dropped.
        data = {
            "myapp.main": ["json.dumps"],
            "json.dumps": [],
            "json.loads": [],  # orphan — no edge from app
        }
        p = tmp_path / "j.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        cg = parse_jarvis(p, {"myapp"})
        cg = prune(cg)
        assert "json.dumps" in cg.nodes
        assert "json.loads" not in cg.nodes


# ---------------------------------------------------------------------
# Stats lock-in against real JARVIS output (skip if not available)
# ---------------------------------------------------------------------

_REAL_JSON = Path(r"E:\2026 WorkSpace\Graph\jarvis_runs\mode3_aw.json")


@pytest.mark.skipif(not _REAL_JSON.exists(),
                    reason="reference JARVIS output not present")
class TestRealJarvisOutput:
    """Lock in the numbers reported in conversation so refactors don't
    silently change parser semantics."""

    def test_raw_node_count(self):
        cg = parse_jarvis(_REAL_JSON, {"server"})
        assert len(cg.nodes) == 1227  # raw, no prune
        assert len(cg.edges) == 2001

    def test_after_prune(self):
        cg = parse_jarvis(_REAL_JSON, {"server"})
        cg = detect_entries(cg, {"server"})
        cg = prune(cg)
        assert len(cg.nodes) == 151
        assert len(cg.edges) == 179

    def test_entries_for_server(self):
        cg = parse_jarvis(_REAL_JSON, {"server"})
        cg = detect_entries(cg, {"server"})
        entries = {n.qname for n in cg.nodes.values() if n.is_entry}
        assert entries == {"server.main", "server.ws_handler", "server.health"}
