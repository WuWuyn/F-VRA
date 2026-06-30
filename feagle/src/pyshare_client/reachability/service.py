from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any, Mapping, Sequence, Set

from pyshare_core.models import (
    AnalysisFingerprint,
    EntryPointType,
    LibrarySummary,
    PackageIdentity,
    PackageSummaryArtifact,
    ProjectGraphArtifact,
    ProjectIdentity,
    ReachabilityPath,
    ScanReport,
    ScanResult,
    Verdict,
)
from pyshare_client.package_analysis.callgraph import LibraryAnalyzer
from pyshare_client.package_analysis.summary import build_library_summary
from pyshare_client.project_analysis.project_graph import build_project_graph
from pyshare_client.reachability.engine import ReachabilityQueryEngine
from pyshare_client.storage import ClientCache


@dataclass
class TransitiveReachabilityResult:
    project: Path
    verdict: Verdict
    vulnerable_targets: list[str]
    hit_set: list[str] = field(default_factory=list)
    paths: list[ReachabilityPath] = field(default_factory=list)
    usage_index: list[str] = field(default_factory=list)
    loaded_summaries: list[str] = field(default_factory=list)
    used_summaries: list[str] = field(default_factory=list)
    unresolved_targets: list[str] = field(default_factory=list)
    unresolved_target_related: list[str] = field(default_factory=list)
    unresolved_unrelated: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    analysis_warnings: dict[str, Any] = field(default_factory=dict)
    query_time_ms: float = 0.0

    def to_dict(self, *, explain: bool = True) -> dict[str, Any]:
        paths = [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in self.paths
        ]
        if not explain and paths:
            paths = paths[:1]
        return {
            "project": str(self.project),
            "verdict": self.verdict.value,
            "vulnerable_targets": self.vulnerable_targets,
            "hit_set": self.hit_set,
            "paths": paths,
            "usage_index": self.usage_index,
            "loaded_summaries": self.loaded_summaries,
            "used_summaries": self.used_summaries,
            "unresolved_targets": self.unresolved_targets,
            "unresolved_target_related": self.unresolved_target_related,
            "unresolved_unrelated": self.unresolved_unrelated,
            "entry_points": self.entry_points,
            "analysis_warnings": self.analysis_warnings,
            "query_time_ms": self.query_time_ms,
        }


def _edge_rows(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("final_edges_detail") or report.get("edges_detail") or []
    return [row for row in rows if row.get("caller") and row.get("callee")]


def _matches_qualified_suffix(value: str, suffix: str) -> bool:
    return value == suffix or value.endswith(f".{suffix}")


def _root_module(dotted: str) -> str:
    return dotted.split(".", 1)[0] if dotted else ""


def _leaf_name(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1] if dotted else ""


def _target_related_symbol(
    symbol: str,
    targets: Set[str],
    summary_roots: set[str],
) -> bool:
    symbol = str(symbol or "").strip()
    if not symbol:
        return False
    symbol_root = _root_module(symbol)
    symbol_leaf = _leaf_name(symbol)
    for target in targets:
        target = str(target or "").strip()
        if not target:
            continue
        if _matches_qualified_suffix(symbol, target) or _matches_qualified_suffix(target, symbol):
            return True
        if symbol_leaf and symbol_leaf == _leaf_name(target) and ("." not in symbol or "." not in target):
            return True
        if symbol_root and symbol_root == _root_module(target):
            return True
    return symbol_root in summary_roots and any(_root_module(target) == symbol_root for target in targets)


def _usage_roots(usage_index: Sequence[Any]) -> set[str]:
    roots: set[str] = set()
    for item in usage_index:
        identity = getattr(item, "identity_string", item)
        root = _root_module(str(identity or ""))
        if root:
            roots.add(root)
    return roots


def _potential_usage_symbols(graph: Any) -> set[str]:
    out: set[str] = set()
    for edge in getattr(graph, "external_edges", []):
        if str(getattr(edge, "edge_type", "")).startswith("potential"):
            identity = getattr(edge.callee, "identity_string", "")
            if identity:
                out.add(identity)
    return out


def _graph_warning_related_items(
    graph_metadata: Mapping[str, Any] | None,
    targets: Set[str],
    summary_roots: set[str],
) -> list[dict[str, Any]]:
    if not graph_metadata:
        return []
    related: list[dict[str, Any]] = []
    for item in graph_metadata.get("unresolved_calls") or []:
        probes = [
            str(item.get("call_name", "")),
            str(item.get("call_expr", "")).split("(", 1)[0],
            ".".join(part for part in (str(item.get("receiver", "")), str(item.get("call_name", ""))) if part),
        ]
        if any(_target_related_symbol(probe, targets, summary_roots) for probe in probes):
            related.append(item)
    for item in graph_metadata.get("candidate_edges") or []:
        probes = [str(item.get("callee", "")), str(item.get("caller", ""))]
        if any(_target_related_symbol(probe, targets, summary_roots) for probe in probes):
            related.append(item)
    return related


def _summary_warning_related_roots(
    summaries: Mapping[str, LibrarySummary],
    usage_index: Sequence[Any],
    targets: Set[str],
) -> list[str]:
    roots = _usage_roots(usage_index)
    target_roots = {_root_module(target) for target in targets if _root_module(target)}
    return sorted(
        root
        for root, summary in summaries.items()
        if summary.analysis_warnings and (root in roots or root in target_roots)
    )


def classify_reachability_uncertainty(
    report: Any,
    targets: Set[str],
    summaries: Mapping[str, LibrarySummary],
    usage_index: Sequence[Any],
    graph_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Partition incomplete analysis evidence into target-related and unrelated."""
    summary_roots = set(summaries)
    transitive_frontier = set(getattr(report, "unresolved_frontier", []) or [])
    target_related: list[str] = []
    unrelated: list[str] = []
    for target in getattr(report, "unresolved_targets", []) or []:
        if target in transitive_frontier or _target_related_symbol(target, targets, summary_roots):
            target_related.append(target)
        else:
            unrelated.append(target)
    return {
        "unresolved_target_related": sorted(set(target_related)),
        "unresolved_unrelated": sorted(set(unrelated)),
        "summary_warning_roots": _summary_warning_related_roots(summaries, usage_index, targets),
        "graph_warning_related": _graph_warning_related_items(graph_metadata, targets, summary_roots),
    }


def decide_reachability_verdict(
    report: Any,
    targets: Set[str],
    summaries: Mapping[str, LibrarySummary],
    usage_index: Sequence[Any],
    *,
    graph_metadata: Mapping[str, Any] | None = None,
    potential_usage_symbols: set[str] | None = None,
) -> tuple[Verdict, dict[str, Any]]:
    uncertainty = classify_reachability_uncertainty(
        report,
        targets,
        summaries,
        usage_index,
        graph_metadata,
    )
    potential_symbols = potential_usage_symbols or set()
    if getattr(report, "is_vulnerable", False):
        if any(path.project_api in potential_symbols for path in getattr(report, "paths", [])):
            return Verdict.POTENTIALLY_REACHABLE, uncertainty
        return Verdict.REACHABLE, uncertainty
    if (
        uncertainty["unresolved_target_related"]
        or uncertainty["summary_warning_roots"]
        or uncertainty["graph_warning_related"]
    ):
        return Verdict.POTENTIALLY_REACHABLE, uncertainty
    return Verdict.NOT_REACHABLE, uncertainty


def _summary_key(summary: LibrarySummary, target: str) -> str | None:
    keys = set(summary.inner_summary) | set(summary.outer_summary)
    if target in keys:
        return target
    matches = [
        key
        for key in keys
        if _matches_qualified_suffix(key, target) or _matches_qualified_suffix(target, key)
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _alias_keys(alias: str, root: str | None) -> list[str]:
    alias = alias.strip(".")
    if not alias:
        return []
    keys = [alias]
    if root:
        root = root.strip(".")
        parts = alias.split(".")
        if root in parts:
            index = parts.index(root)
            rooted = ".".join(parts[index:])
            if rooted and rooted not in keys:
                keys.append(rooted)
        if root and not _matches_qualified_suffix(alias, root) and not alias.startswith(f"{root}."):
            keys.append(f"{root}.{alias}")
    return keys


def _expand_public_api_aliases(
    summary: LibrarySummary,
    aliases: Mapping[str, Any],
    *,
    root: str | None,
) -> None:
    for raw_alias, raw_target in aliases.items():
        alias = str(raw_alias).strip()
        target = str(raw_target).strip()
        if not alias or not target:
            continue
        canonical = _summary_key(summary, target)
        if canonical is None:
            continue
        for key in _alias_keys(alias, root):
            summary.api_aliases.setdefault(key, canonical)
            summary.inner_summary.setdefault(key, set()).update(summary.inner_summary.get(canonical, set()))
            summary.inner_summary[key].add(canonical)
            summary.outer_summary.setdefault(key, set()).update(summary.outer_summary.get(canonical, set()))
            canonical_inner_paths = summary.inner_paths.get(canonical, {})
            canonical_outer_paths = summary.outer_paths.get(canonical, {})
            summary.inner_paths.setdefault(key, {}).update(canonical_inner_paths)
            summary.outer_paths.setdefault(key, {}).update(canonical_outer_paths)
            summary.inner_paths[key].setdefault(canonical, [key, canonical])


def summary_from_callgraph_report(
    report: Mapping[str, Any],
    *,
    root: str | None = None,
) -> LibrarySummary:
    """Build a LibrarySummary from a package callgraph JSON report."""
    edges = _edge_rows(report)
    adjacency: dict[str, list[tuple[str, str]]] = {}
    callers: set[str] = set()
    for edge in edges:
        caller = str(edge["caller"])
        callee = str(edge["callee"])
        callee_type = str(edge.get("callee_type", "internal"))
        callers.add(caller)
        adjacency.setdefault(caller, []).append((callee, callee_type))

    summary = LibrarySummary()
    for api in sorted(callers):
        queue = [api]
        paths = {api: [api]}
        visited = {api}
        inner: set[str] = set()
        outer: set[str] = set()
        inner_paths = summary.inner_paths.setdefault(api, {})
        outer_paths = summary.outer_paths.setdefault(api, {})
        while queue:
            node = queue.pop(0)
            for nxt, callee_type in adjacency.get(node, []):
                if callee_type == "external":
                    outer.add(nxt)
                    outer_paths.setdefault(nxt, [*paths[node], nxt])
                    continue
                if nxt in visited:
                    continue
                visited.add(nxt)
                paths[nxt] = [*paths[node], nxt]
                inner.add(nxt)
                inner_paths.setdefault(nxt, paths[nxt])
                queue.append(nxt)
        summary.inner_summary[api] = inner
        summary.outer_summary[api] = outer
    aliases = report.get("public_api_aliases", {})
    if isinstance(aliases, Mapping):
        _expand_public_api_aliases(summary, aliases, root=root)
    summary.analysis_warnings = {
        key: report.get(key, [])
        for key in ("candidate_edges", "unresolved_public_exports", "unresolved_calls")
        if report.get(key)
    }
    return summary


def load_package_report_summaries(specs: Sequence[str]) -> dict[str, LibrarySummary]:
    """Load ROOT=package-report.json specs into a summary map."""
    summaries: dict[str, LibrarySummary] = {}
    for spec in specs:
        root, sep, raw_path = spec.partition("=")
        if not sep or not root.strip() or not raw_path.strip():
            raise ValueError(
                "package report must use ROOT=PATH, for example "
                "alpha=./alpha-callgraph-package.json"
            )
        path = Path(raw_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"package report does not exist: {path}")
        report = json.loads(path.read_text(encoding="utf-8-sig"))
        summaries[root.strip()] = summary_from_callgraph_report(report, root=root.strip())
    return summaries


def read_vulnerable_targets(path: str | Path) -> set[str]:
    """Read vulnerable function targets from a JSON list/object or JSONL file."""
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"VF file does not exist: {source}")
    text = source.read_text(encoding="utf-8-sig").strip()
    if not text:
        return set()

    def add_from_item(item: Any, out: set[str]) -> None:
        if isinstance(item, str) and item.strip():
            out.add(item.strip())
        elif isinstance(item, Mapping):
            for key in ("qualified_name", "vf", "target", "name"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    out.add(value.strip())
                    return

    targets: set[str] = set()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                add_from_item(json.loads(line), targets)
            except json.JSONDecodeError:
                targets.add(line)
        return targets

    if isinstance(payload, list):
        for item in payload:
            add_from_item(item, targets)
    elif isinstance(payload, Mapping):
        for key in ("vulnerabilities", "vfs", "targets"):
            items = payload.get(key)
            if isinstance(items, list):
                for item in items:
                    add_from_item(item, targets)
                break
        else:
            add_from_item(payload, targets)
    else:
        add_from_item(payload, targets)
    return targets


def _entry_points(graph) -> list[str]:
    return sorted(
        node.qualified_name or node.function_name
        for node in graph.internal_nodes
        if node.entry_type != EntryPointType.UNKNOWN
    )


def _analysis_warnings(graph) -> dict[str, Any]:
    return {
        key: graph.metadata.get(key, [])
        for key in ("unresolved_calls", "candidate_edges", "skipped_files")
        if graph.metadata.get(key)
    }


def _node_name(node: Any) -> str:
    return getattr(node, "qualified_name", "") or getattr(node, "function_name", "")


def _project_callers_by_target(graph: Any) -> dict[str, list[str]]:
    callers: dict[str, set[str]] = {}
    for edge in getattr(graph, "external_edges", []) or []:
        target = getattr(edge.callee, "identity_string", "") or _node_name(edge.callee)
        caller = _node_name(edge.caller)
        if not target or not caller:
            continue
        callers.setdefault(target, set()).add(caller)
    return {target: sorted(values) for target, values in callers.items()}


def _with_project_callers(paths: Sequence[ReachabilityPath], graph: Any) -> list[ReachabilityPath]:
    callers_by_target = _project_callers_by_target(graph)
    expanded: list[ReachabilityPath] = []
    seen: set[tuple[str, ...]] = set()

    for path in paths:
        if not path.tpl_chain:
            continue
        first_hop = path.tpl_chain[0]
        callers = callers_by_target.get(first_hop, [])
        if not callers:
            key = tuple(path.tpl_chain)
            if key not in seen:
                seen.add(key)
                expanded.append(path)
            continue

        for caller in callers:
            chain = path.tpl_chain if path.tpl_chain[0] == caller else [caller, *path.tpl_chain]
            key = tuple(chain)
            if key in seen:
                continue
            seen.add(key)
            expanded.append(
                ReachabilityPath(
                    project_api=caller,
                    tpl_chain=chain,
                    vulnerable_target=path.vulnerable_target,
                    used_summaries=list(path.used_summaries),
                )
            )

    return expanded


def _graph_artifact(project: Path, graph, usage_index) -> ProjectGraphArtifact:
    edges = [
        {
            "caller": _node_name(edge.caller),
            "callee": _node_name(edge.callee),
            "callee_type": "external" if edge.callee.is_external else "internal",
            "edge_type": getattr(edge, "edge_type", "confirmed_static"),
            "confidence": getattr(edge, "confidence", 1.0),
            "resolver": getattr(edge, "resolver", "static"),
            "reason": getattr(edge, "reason", ""),
            "call_expr": getattr(edge, "call_expr", ""),
            "line_number": getattr(edge, "line_number", 0),
        }
        for edge in graph.edges
    ]
    resolved = project.resolve()
    project_id = ProjectIdentity(root=str(resolved), fingerprint=str(resolved))
    return ProjectGraphArtifact(
        project=project_id,
        fingerprint=AnalysisFingerprint(python_version=f"{sys.version_info.major}.{sys.version_info.minor}"),
        entry_points=_entry_points(graph),
        usage_index=sorted(node.identity_string for node in usage_index),
        graph={
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "edges_detail": edges,
            "metadata": graph.metadata,
        },
        analysis_warnings=_analysis_warnings(graph),
    )


def _project_cache_key(project: Path) -> str:
    resolved = project.resolve()
    return f"{resolved}|py={sys.version_info.major}.{sys.version_info.minor}|scanner=0.3.0|config=default"


def _normalize_name(name: str) -> str:
    return name.replace("_", "-").lower()


def _source_for_root(root: str) -> tuple[Path | None, str, str]:
    wanted = root.replace("-", "_").lower()
    for dist in metadata.distributions():
        name = dist.metadata.get("Name", dist.name or "")
        top_level = ""
        try:
            top_level = dist.read_text("top_level.txt") or ""
        except Exception:
            top_level = ""
        tops = [line.strip() for line in top_level.splitlines() if line.strip()]
        if wanted not in {top.lower() for top in tops} and wanted != name.replace("-", "_").lower():
            continue
        files = list(dist.files or [])
        for top in tops or [root]:
            package_init = f"{top}/__init__.py"
            module_file = f"{top}.py"
            for file in files:
                posix = file.as_posix()
                if posix == package_init:
                    return Path(dist.locate_file(file).parent), name, dist.version or ""
                if posix == module_file:
                    return Path(dist.locate_file(file)), name, dist.version or ""
    return None, root, ""


def _package_key(identity: PackageIdentity) -> str:
    return f"{identity.normalized_name or _normalize_name(identity.name)}=={identity.version}"


def _build_package_summary(root: str) -> tuple[str, PackageSummaryArtifact] | None:
    source, package, version = _source_for_root(root)
    if source is None or not source.exists():
        return None
    analysis_root = source if source.is_dir() else source.parent
    analyzer = LibraryAnalyzer()
    graph = analyzer.build_library_graph(analysis_root)
    public_apis = analyzer.index.public_api if analyzer.index is not None else []
    summary = build_library_summary(graph, public_apis)
    identity = PackageIdentity(
        name=package or root,
        normalized_name=_normalize_name(package or root),
        version=version,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}",
    )
    artifact = PackageSummaryArtifact(
        package=identity,
        fingerprint=AnalysisFingerprint(python_version=f"{sys.version_info.major}.{sys.version_info.minor}"),
        summary=summary,
        source_path=str(analysis_root),
        provenance={"source": "installed_distribution", "root": root},
    )
    return _package_key(identity), artifact


def _load_or_build_summaries(usage_index, cache: ClientCache) -> dict[str, LibrarySummary]:
    summaries: dict[str, LibrarySummary] = {}
    roots = sorted({node.target_module.split(".", 1)[0] for node in usage_index if node.target_module})
    for root in roots:
        cached_keys = [key for key in cache.list("package-summary") if key.startswith(f"{_normalize_name(root)}==")]
        artifact = cache.get_package_summary(cached_keys[0]) if cached_keys else None
        if artifact is None:
            built = _build_package_summary(root)
            if built is None:
                continue
            key, artifact = built
            cache.put_package_summary(key, artifact)
        summaries[root] = artifact.summary
    return summaries


def query_with_cache(
    cve_id: str,
    project: Path,
    vf: str,
    explain: bool = False,
    *,
    cache: ClientCache,
    vulnerabilities: Set[str] | None = None,
    max_depth: int = 25,
    max_paths: int = 100,
) -> ScanResult:
    started = time.perf_counter()
    targets = set(vulnerabilities or ())
    if vf:
        targets.add(vf)
    if not targets:
        return ScanResult(
            cve_id=cve_id,
            project=project,
            verdict=Verdict.UNKNOWN,
            query_time_ms=(time.perf_counter() - started) * 1000,
        )

    graph, usage_index = build_project_graph(project)
    cache.put_project(_project_cache_key(project), _graph_artifact(project, graph, usage_index))
    summaries = _load_or_build_summaries(usage_index, cache)
    report = ReachabilityQueryEngine(
        usage_index,
        summaries,
        targets,
        max_depth=max_depth,
        max_paths=max_paths,
    ).check_reachability()

    verdict, _uncertainty = decide_reachability_verdict(
        report,
        targets,
        summaries,
        usage_index,
        graph_metadata=graph.metadata,
        potential_usage_symbols=_potential_usage_symbols(graph),
    )
    report.paths = _with_project_callers(report.paths, graph)

    result = ScanResult(
        cve_id=cve_id,
        project=project,
        verdict=verdict,
        vf=vf or (sorted(targets)[0] if len(targets) == 1 else ""),
        entry_points=_entry_points(graph),
        hit_set=sorted({path.vulnerable_target for path in report.paths}),
        call_chain=report.paths[0].tpl_chain if report.paths and explain else [],
        query_time_ms=(time.perf_counter() - started) * 1000,
    )
    scan_id = f"{cve_id}:{_project_cache_key(project)}:{','.join(sorted(targets))}"
    cache.put_scan_report(
        ScanReport(
            scan_id=scan_id,
            cve_id=cve_id,
            project=ProjectIdentity(root=str(project.resolve()), fingerprint=str(project.resolve())),
            verdict=result.verdict,
            vulnerable_targets=sorted(targets),
            hit_set=result.hit_set,
        paths=[{"path": path.tpl_chain, "target": path.vulnerable_target} for path in report.paths],
        unresolved_targets=report.unresolved_targets,
        loaded_summaries=sorted(summaries),
            query_time_ms=result.query_time_ms,
        )
    )
    return result


def _summary_warnings(summaries: Mapping[str, LibrarySummary]) -> dict[str, Any]:
    return {
        root: summary.analysis_warnings
        for root, summary in summaries.items()
        if summary.analysis_warnings
    }


def check_transitive_reachability(
    project: str | Path,
    vulnerabilities: Set[str],
    *,
    summaries: Mapping[str, LibrarySummary] | None = None,
    max_depth: int = 25,
    max_paths: int = 100,
) -> TransitiveReachabilityResult:
    """Run project-to-package transitive vulnerable-function reachability."""
    started = time.perf_counter()
    project_path = Path(project)
    targets = {target for target in vulnerabilities if target}

    if not targets:
        return TransitiveReachabilityResult(
            project=project_path,
            verdict=Verdict.UNKNOWN,
            vulnerable_targets=[],
            query_time_ms=(time.perf_counter() - started) * 1000,
        )

    graph, usage_index = build_project_graph(project_path)
    summary_map = dict(summaries or {})
    report = ReachabilityQueryEngine(
        usage_index,
        summary_map,
        targets,
        max_depth=max_depth,
        max_paths=max_paths,
    ).check_reachability()

    summary_warnings = _summary_warnings(summary_map)

    verdict, uncertainty = decide_reachability_verdict(
        report,
        targets,
        summary_map,
        usage_index,
        graph_metadata=graph.metadata,
        potential_usage_symbols=_potential_usage_symbols(graph),
    )
    report.paths = _with_project_callers(report.paths, graph)

    return TransitiveReachabilityResult(
        project=project_path,
        verdict=verdict,
        vulnerable_targets=sorted(targets),
        hit_set=sorted({path.vulnerable_target for path in report.paths}),
        paths=report.paths,
        usage_index=sorted(node.identity_string for node in usage_index),
        loaded_summaries=sorted(summary_map),
        used_summaries=report.used_summaries,
        unresolved_targets=report.unresolved_targets,
        unresolved_target_related=uncertainty["unresolved_target_related"],
        unresolved_unrelated=uncertainty["unresolved_unrelated"],
        entry_points=_entry_points(graph),
        analysis_warnings={
            **_analysis_warnings(graph),
            **({"package_summaries": summary_warnings} if summary_warnings else {}),
            **({"target_related_summary_warnings": uncertainty["summary_warning_roots"]} if uncertainty["summary_warning_roots"] else {}),
            **({"target_related_graph_warnings": uncertainty["graph_warning_related"]} if uncertainty["graph_warning_related"] else {}),
        },
        query_time_ms=(time.perf_counter() - started) * 1000,
    )


def query(
    cve_id: str,
    project: Path,
    vf: str,
    explain: bool = False,
    *,
    summaries: Mapping[str, LibrarySummary] | None = None,
    vulnerabilities: Set[str] | None = None,
    max_depth: int = 25,
    max_paths: int = 100,
) -> ScanResult:
    """Run direct or transitive vulnerable-function reachability."""
    started = time.perf_counter()
    targets = set(vulnerabilities or ())
    if vf:
        targets.add(vf)

    if not targets:
        return ScanResult(
            cve_id=cve_id,
            project=project,
            verdict=Verdict.UNKNOWN,
            query_time_ms=(time.perf_counter() - started) * 1000,
        )

    graph, usage_index = build_project_graph(project)
    report = ReachabilityQueryEngine(
        usage_index,
        dict(summaries or {}),
        targets,
        max_depth=max_depth,
        max_paths=max_paths,
    ).check_reachability()

    entry_points = _entry_points(graph)
    verdict, _uncertainty = decide_reachability_verdict(
        report,
        targets,
        dict(summaries or {}),
        usage_index,
        graph_metadata=graph.metadata,
        potential_usage_symbols=_potential_usage_symbols(graph),
    )
    report.paths = _with_project_callers(report.paths, graph)

    return ScanResult(
        cve_id=cve_id,
        project=project,
        verdict=verdict,
        vf=vf or (sorted(targets)[0] if len(targets) == 1 else ""),
        entry_points=entry_points,
        hit_set=sorted({path.vulnerable_target for path in report.paths}),
        call_chain=report.paths[0].tpl_chain if report.paths and explain else [],
        query_time_ms=(time.perf_counter() - started) * 1000,
    )
