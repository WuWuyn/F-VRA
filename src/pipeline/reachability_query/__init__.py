"""Online reachability query -- Phase 4 orchestration.

Wires CLI ``scan`` command end-to-end:
    1. Resolve vf from CVE cache, VFArCHE output, or --vf override
    2. Compute project identity (project_id, commit_sha)
    3. Ensure the project graph is loaded in Neo4j (parse JARVIS json + write)
    4. Run reachability query
    5. Optionally retrieve shortest path via path_explainer
    6. Return ScanResult

vf resolution priority (first match wins):
    a) ``vf`` argument (dev override, --vf flag on CLI)
    b) ``--vfarche-result <path>`` style override (caller passes file directly)
    c) ``~/.pyshare/cve/<CVE-ID>.json`` per README convention
       (populated by ``pyshare localize``, LocalizeResult-shaped:
        {"cve_id":..., "vf":"qname", ...})
    d) ``vfarche_results.json`` next to the project, written directly by
       cve_localization.VFArCHE.analyze() with ``top_function`` field

Failures degrade to Verdict.UNKNOWN with the error captured in
``call_chain[0]``.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from pyshare.core.config import settings
from pyshare.core.models import ScanResult, Verdict
from pyshare.pipeline.project_scanner.direct_caller import find_direct_callers


def query(
    cve_id: str,
    project: Path,
    vf: str = "",
    explain: bool = False,
    *,
    app_packages: Optional[set[str]] = None,
    no_jarvis: bool = False,
    vfarche_result: Optional[Path] = None,
) -> ScanResult:
    """Determine whether ``project`` is affected by ``cve_id``."""
    t0 = time.perf_counter()
    result = ScanResult(cve_id=cve_id, project=project)

    if not vf:
        vf = _resolve_vf(cve_id, project=project,
                         vfarche_result=vfarche_result)
    if not vf:
        return _unknown(result, t0,
                        f"No vf for {cve_id}. Tried cache "
                        f"({settings.cve_cache_dir}/{cve_id}.json) and "
                        f"VFArCHE output. Pass --vf to override.")
    result.vf = vf

    project_id = _project_id(project)
    commit_sha = _project_commit(project)

    try:
        from pyshare.graph import (
            init_schema, project_graph, reachability, path_explainer,
        )
    except ImportError as e:
        return _unknown(result, t0, f"Neo4j driver not available: {e}")

    try:
        if not project_graph.exists(project_id, commit_sha):
            _index_project(project, project_id, commit_sha, vf=vf,
                           app_packages=app_packages, no_jarvis=no_jarvis)
    except FileNotFoundError as e:
        return _unknown(result, t0, str(e))
    except RuntimeError as e:
        # JARVIS subprocess exited non-zero. Fall back to AST-only graph.
        if vf:
            try:
                _index_project_ast_only(project, project_id, commit_sha, vf)
                result.call_chain = [
                    f"[note] JARVIS failed; using AST-only fallback. "
                    f"{str(e)[:200]}"
                ]
            except Exception as fallback_err:
                return _unknown(result, t0,
                                f"JARVIS failed and AST fallback errored: "
                                f"{fallback_err}")
        else:
            return _unknown(result, t0, f"JARVIS failed: {str(e)[:300]}")
    except Exception as e:
        return _unknown(result, t0,
                        f"Neo4j unreachable ({settings.neo4j_uri}): {e}")

    try:
        affected_entries = reachability.get_affected_entries(
            project_id, commit_sha, vf,
        )
    except Exception as e:
        return _unknown(result, t0, f"Query failed: {e}")

    if affected_entries:
        result.verdict = Verdict.AFFECTED
        result.entry_points = [e["entry"] for e in affected_entries]
        result.hit_set = [vf]

        if explain:
            chain = path_explainer.explain(
                project_id, commit_sha,
                affected_entries[0]["entry"], vf,
            )
            if chain:
                result.call_chain = [n["qname"] for n in chain]
    else:
        result.verdict = Verdict.NOT_AFFECTED

    result.query_time_ms = (time.perf_counter() - t0) * 1000
    return result


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _unknown(result: ScanResult, t0: float, reason: str) -> ScanResult:
    result.verdict = Verdict.UNKNOWN
    result.call_chain = [f"[reason] {reason}"]
    result.query_time_ms = (time.perf_counter() - t0) * 1000
    return result


def _resolve_vf(cve_id: str, *, project: Path,
                vfarche_result: Optional[Path]) -> str:
    """Multi-source vf resolution."""
    # (b) Caller-provided VFArCHE file path
    if vfarche_result and vfarche_result.is_file():
        v = _read_vfarche_top_function(vfarche_result)
        if v:
            return v

    # (c) ~/.pyshare/cve/<CVE-ID>.json (LocalizeResult shape)
    cache_path = settings.cve_cache_dir / f"{cve_id}.json"
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            if data.get("vf"):
                return data["vf"]
        except (json.JSONDecodeError, OSError):
            pass

    # (d) VFArCHE output next to project (or its parent)
    for candidate in (
        project / "vfarche_results.json",
        project / ".pyshare" / "vfarche_results.json",
        project.parent / "vfarche_results.json",
    ):
        v = _read_vfarche_top_function(candidate)
        if v:
            return v

    return ""


def _read_vfarche_top_function(p: Path) -> str:
    if not p.is_file():
        return ""
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get("top_function") or ""
    except (json.JSONDecodeError, OSError):
        return ""


def _project_id(project: Path) -> str:
    return project.resolve().name


def _project_commit(project: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "HEAD"


def _index_project(
    project: Path,
    project_id: str,
    commit_sha: str,
    *,
    vf: str = "",
    app_packages: Optional[set[str]] = None,
    no_jarvis: bool = False,
) -> None:
    from pyshare.graph import init_schema, project_graph
    from pyshare.pipeline.project_scanner import jarvis_parser, run_jarvis

    json_path = _find_jarvis_output(project)
    if not json_path:
        if no_jarvis:
            raise FileNotFoundError(
                f"No JARVIS JSON found for {project} and --no-jarvis was "
                f"passed. Place jarvis.json under the project root or "
                f"remove --no-jarvis to auto-run."
            )
        json_path = run_jarvis(project)

    if app_packages:
        app_pkgs = set(app_packages)
    else:
        app_pkgs = _detect_app_packages_from_fs(project)
        if not app_pkgs:
            import json as _json
            raw = _json.loads(json_path.read_text(encoding="utf-8"))
            app_pkgs = jarvis_parser.auto_detect_app_packages(raw)
    if not app_pkgs:
        raise ValueError(
            f"Could not determine app packages for {project}. "
            f"Pass them explicitly with --app-pkg."
        )

    cg = jarvis_parser.parse_jarvis(json_path, app_pkgs, project_id=project_id)
    cg = jarvis_parser.detect_entries(cg, app_pkgs)
    cg = jarvis_parser.prune(cg)

    if vf:
        _augment_with_direct_callers(cg, project, vf, app_pkgs)

    init_schema()
    project_graph.write(cg, project_id=project_id, commit_sha=commit_sha)


def _index_project_ast_only(project: Path, project_id: str,
                              commit_sha: str, vf: str) -> None:
    """Fallback when JARVIS subprocess fails: AST-only minimal graph."""
    from pyshare.graph import init_schema, project_graph
    from pyshare.pipeline.project_scanner.jarvis_parser import (
        CallEdge, CallGraph, FuncKind, FunctionNode, classify,
    )

    callers = find_direct_callers(project, vf, None)
    nodes: dict[str, FunctionNode] = {}
    edges: list[CallEdge] = []

    if callers:
        nodes[vf] = FunctionNode(
            qname=vf, kind=classify(vf, frozenset()), is_entry=False,
        )
        for dc in callers:
            if dc.qname in nodes:
                continue
            nodes[dc.qname] = FunctionNode(
                qname=dc.qname, kind=FuncKind.APP, is_entry=True,
            )
            edges.append(CallEdge(caller=dc.qname, callee=vf))

    cg = CallGraph(nodes=nodes, edges=edges, project_id=project_id)
    init_schema()
    project_graph.write(cg, project_id=project_id, commit_sha=commit_sha)


def _augment_with_direct_callers(cg, project: Path, vf: str,
                                  app_packages: set[str]) -> None:
    """Inject synthetic <app_func> -> <vf> edges for direct callers."""
    from pyshare.pipeline.project_scanner.jarvis_parser import (
        CallEdge, FuncKind, FunctionNode, classify,
    )

    callers = find_direct_callers(project, vf, app_packages)
    if not callers:
        return

    if vf not in cg.nodes:
        cg.nodes[vf] = FunctionNode(
            qname=vf,
            kind=classify(vf, frozenset(app_packages)),
            is_entry=False,
        )

    incoming = {e.callee for e in cg.edges}
    existing_edges = {(e.caller, e.callee) for e in cg.edges}
    from dataclasses import replace

    for dc in callers:
        if dc.qname not in cg.nodes:
            cg.nodes[dc.qname] = FunctionNode(
                qname=dc.qname, kind=FuncKind.APP, is_entry=False,
            )
        node = cg.nodes[dc.qname]
        parts = dc.qname.split(".")
        is_topish = (len(parts) == 2 and parts[1][:1].islower())
        is_orphan = (dc.qname not in incoming)

        if not node.is_entry and node.kind == FuncKind.APP and (
                is_topish or is_orphan):
            cg.nodes[dc.qname] = replace(node, is_entry=True)

        if (dc.qname, vf) not in existing_edges:
            cg.edges.append(CallEdge(caller=dc.qname, callee=vf))
            existing_edges.add((dc.qname, vf))


def _find_jarvis_output(project: Path) -> Optional[Path]:
    for c in (
        project / "jarvis.json",
        project / ".pyshare" / "jarvis.json",
        project / "deploy_jarvis.json",
    ):
        if c.exists():
            return c
    return None


_SKIP_TOP_FILES = {"setup", "conftest", "manage"}
_SKIP_TOP_DIRS = {"tests", "test", "docs", "doc", "examples", "scripts",
                  ".venv", "venv", "env", "build", "dist", "__pycache__"}


def _detect_app_packages_from_fs(project: Path) -> set[str]:
    pkgs: set[str] = set()
    if not project.is_dir():
        return pkgs
    for child in project.iterdir():
        name = child.name
        if name.startswith((".", "_")):
            continue
        if child.is_dir():
            if name in _SKIP_TOP_DIRS:
                continue
            if (child / "__init__.py").exists():
                pkgs.add(name)
        elif child.is_file() and child.suffix == ".py":
            stem = child.stem
            if stem in _SKIP_TOP_FILES or stem.startswith("_"):
                continue
            pkgs.add(stem)
    return pkgs
