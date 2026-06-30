from __future__ import annotations

import os
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from pyshare_api.db import SessionLocal, create_schema
from pyshare_api.db.models import SeverityRecord
from pyshare_api.db.repository import FvraRepository, normalize_name
from pyshare_api.package_sources import fetch_package_source, pypi_cache_root
from pyshare_client.dependencies.resolver import resolve_dependency_graph
from pyshare_client.project_analysis.project_graph import build_project_graph
from pyshare_client.package_analysis.callgraph import LibraryAnalyzer
from pyshare_client.package_analysis.summary import build_library_summary
from pyshare_client.reachability.service import check_transitive_reachability
from pyshare_core.models import EntryPointType, LibrarySummary
from pyshare_core.models import Verdict


def artifact_root() -> Path:
    return Path(os.getenv("F_VRA_ARTIFACT_ROOT", "./var/artifacts")).resolve()


def checkout_root() -> Path:
    return Path(os.getenv("F_VRA_CHECKOUT_ROOT", "./var/checkouts")).resolve()


def _run(args: list[str], cwd: Path | None = None, *, timeout: int = 180) -> str:
    completed = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True, timeout=timeout)
    return completed.stdout.strip()


def _clone_project(repo_url: str, branch: str, job_id: str) -> tuple[Path, str]:
    target = checkout_root() / job_id
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    args = ["git", "clone", "--depth", "1"]
    if branch:
        args.extend(["--branch", branch])
    args.extend([repo_url, str(target)])
    try:
        _run(args, timeout=int(os.getenv("F_VRA_GIT_TIMEOUT_SECONDS", "180")))
    except subprocess.CalledProcessError:
        _run(["git", "clone", repo_url, str(target)], timeout=int(os.getenv("F_VRA_GIT_TIMEOUT_SECONDS", "180")))
        if branch:
            _run(["git", "checkout", branch], cwd=target)
    commit = _run(["git", "rev-parse", "HEAD"], cwd=target)
    return target, commit


def _graph_payload(project_path: Path, graph: Any, usage_index: Any) -> dict[str, Any]:
    edges = [
        {
            "caller": getattr(edge.caller, "qualified_name", "") or getattr(edge.caller, "function_name", ""),
            "callee": getattr(edge.callee, "qualified_name", "") or getattr(edge.callee, "function_name", "") or getattr(edge.callee, "identity_string", ""),
            "callee_type": "external" if edge.callee.is_external else "internal",
            "edge_type": getattr(edge, "edge_type", "confirmed_static"),
            "confidence": getattr(edge, "confidence", 1.0),
            "resolver": getattr(edge, "resolver", "static"),
            "call_expr": getattr(edge, "call_expr", ""),
            "line_number": getattr(edge, "line_number", 0),
        }
        for edge in graph.edges
    ]
    return {
        "project_root": str(project_path),
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "usage_index": sorted(node.identity_string for node in usage_index),
        "edges_detail": edges,
        "metadata": graph.metadata,
    }


def _package_summary_payload(package: str, version: str, vulnerable_entities: list[str], status: str = "not_built") -> dict[str, Any]:
    return {
        "package": package,
        "version": version,
        "summary": {
            "inner_summary": {},
            "outer_summary": {},
            "inner_paths": {},
            "outer_paths": {},
            "analysis_warnings": {"status": status},
        },
        "vulnerable_entities": vulnerable_entities,
    }


def _summary_from_payload(payload: dict[str, Any]) -> LibrarySummary:
    summary = payload.get("summary") or {}
    return LibrarySummary(
        inner_summary={str(key): set(values) for key, values in (summary.get("inner_summary") or {}).items()},
        outer_summary={str(key): set(values) for key, values in (summary.get("outer_summary") or {}).items()},
        inner_paths={
            str(key): {str(target): list(path) for target, path in values.items()}
            for key, values in (summary.get("inner_paths") or {}).items()
        },
        outer_paths={
            str(key): {str(target): list(path) for target, path in values.items()}
            for key, values in (summary.get("outer_paths") or {}).items()
        },
        analysis_warnings=summary.get("analysis_warnings") or {},
        api_aliases={str(key): str(value) for key, value in (summary.get("api_aliases") or {}).items()},
    )


def _read_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _summary_payload_is_reusable(payload: dict[str, Any]) -> bool:
    warnings = (payload.get("summary") or {}).get("analysis_warnings") or {}
    status = warnings.get("status", "")
    return status not in {"not_built", "not_built_in_worker_mvp", "source_unavailable"}


def _dependency_root(dependency: Any) -> str:
    return normalize_name(getattr(dependency, "normalized_name", "") or getattr(dependency, "package_name", "") or getattr(dependency, "name", "")).replace("-", "_")


def _dependency_package_name(dependency: Any) -> str:
    return str(getattr(dependency, "package_name", "") or getattr(dependency, "name", "") or getattr(dependency, "normalized_name", ""))


def _dependency_summary_key(dependency: Any) -> str:
    ecosystem = str(getattr(dependency, "ecosystem", "pypi") or "pypi")
    package = normalize_name(_dependency_package_name(dependency))
    version = str(getattr(dependency, "version", "") or "")
    return f"{ecosystem}:{package}:{version}:py{sys.version_info.major}.{sys.version_info.minor}:0.3.0"


def _summary_dependencies(dependencies: list[Any], usage_index: Any, matches: list[tuple[Any, Any, Any, list[Any]]]) -> list[Any]:
    by_name = {
        normalize_name(getattr(dep, "normalized_name", "") or _dependency_package_name(dep)): dep
        for dep in dependencies
    }
    wanted = {
        normalize_name(getattr(dep, "normalized_name", "") or _dependency_package_name(dep))
        for _advisory, _affected, dep, _entities in matches
    }
    usage_roots = {
        normalize_name(str(getattr(node, "identity_string", "")).split(".", 1)[0])
        for node in usage_index
        if getattr(node, "identity_string", "")
    }
    wanted.update(root for root in usage_roots if root in by_name)

    changed = True
    while changed:
        changed = False
        for name, dep in by_name.items():
            child_names = {normalize_name(str(item)) for item in getattr(dep, "dependencies", []) or []}
            if name not in wanted and child_names.intersection(wanted):
                wanted.add(name)
                changed = True

    return [dep for name, dep in by_name.items() if name in wanted]


def _load_or_build_package_summary(repo: FvraRepository, job_id: str, dependency: Any, vulnerable_entities: list[Any] | None = None) -> tuple[str, Any | None]:
    package_name = _dependency_package_name(dependency)
    version = str(getattr(dependency, "version", "") or "")
    ecosystem = str(getattr(dependency, "ecosystem", "pypi") or "pypi")
    normalized = normalize_name(getattr(dependency, "normalized_name", "") or package_name)
    root = normalized.replace("-", "_")
    key = _dependency_summary_key(dependency)
    existing_summary_artifact = repo.get_artifact(kind="package-summary", reusable_key=key)
    package_graph_id = ""
    summary = None

    if existing_summary_artifact is not None:
        payload = _read_json(existing_summary_artifact.storage_uri)
        if _summary_payload_is_reusable(payload):
            summary = _summary_from_payload(payload)
            node_count = existing_summary_artifact.node_count
            edge_count = existing_summary_artifact.edge_count
            package_artifact = existing_summary_artifact
        else:
            existing_summary_artifact = None

    if existing_summary_artifact is None:
        built = _package_analysis(package_name, version)
        if built is None:
            payload = _package_summary_payload(
                package_name,
                version,
                sorted(entity.name for entity in vulnerable_entities or [] if getattr(entity, "name", "")),
                status="source_unavailable",
            )
            node_count = 0
            edge_count = 0
        else:
            package_graph_payload, payload, summary, analyzed_package, analyzed_version = built
            node_count = len(summary.inner_summary)
            edge_count = sum(len(values) for values in summary.inner_summary.values()) + sum(len(values) for values in summary.outer_summary.values())
            package_graph = repo.upsert_artifact(
                kind="package-call-graph",
                reusable_key=f"{key}:graph",
                payload=package_graph_payload,
                storage_root=artifact_root(),
                node_count=int(package_graph_payload["nodes"]),
                edge_count=int(package_graph_payload["edges"]),
                metadata={"package": analyzed_package, "version": analyzed_version},
            )
            repo.link_scan_artifact(job_id, package_graph.id)
            package_graph_id = package_graph.id
        package_artifact = repo.upsert_artifact(
            kind="package-summary",
            reusable_key=key,
            payload=payload,
            storage_root=artifact_root(),
            node_count=node_count,
            edge_count=edge_count,
            metadata={"package": package_name, "version": version},
        )

    package_version = repo.upsert_package_version(
        ecosystem=ecosystem,
        normalized_name=normalized,
        version=version,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}",
    )
    if package_graph_id:
        repo.link_package_artifact(package_version.id, package_graph_id)
    repo.link_package_artifact(package_version.id, package_artifact.id)
    repo.link_scan_artifact(job_id, package_artifact.id)
    return root, summary


def _package_analysis(package_name: str, version: str) -> tuple[dict[str, Any], dict[str, Any], Any, str, str] | None:
    source = fetch_package_source(package_name, version, cache_root=pypi_cache_root())
    if source is None or not source.exists():
        return None
    analysis_root = source if source.is_dir() else source.parent
    analyzer = LibraryAnalyzer()
    graph = analyzer.build_library_graph(analysis_root)
    public_apis = analyzer.index.public_api if analyzer.index is not None else []
    summary = build_library_summary(graph, public_apis)
    if analyzer.index is not None:
        package_root = normalize_name(package_name).replace("-", "_")
        for alias, target in analyzer.index.public_api_aliases().items():
            canonical = target
            for key in set(summary.inner_summary) | set(summary.outer_summary):
                if key == target or key.endswith("." + target) or target.endswith("." + key):
                    canonical = key
                    break
            alias_keys = [alias]
            parts = alias.split(".")
            if package_root in parts:
                rooted = ".".join(parts[parts.index(package_root):])
                if rooted not in alias_keys:
                    alias_keys.append(rooted)
            for key in alias_keys:
                summary.api_aliases.setdefault(key, canonical)
                summary.inner_summary.setdefault(key, set()).add(canonical)
                summary.inner_summary[key].update(summary.inner_summary.get(canonical, set()))
                summary.outer_summary.setdefault(key, set()).update(summary.outer_summary.get(canonical, set()))
                summary.inner_paths.setdefault(key, {}).update(summary.inner_paths.get(canonical, {}))
                summary.outer_paths.setdefault(key, {}).update(summary.outer_paths.get(canonical, {}))
                summary.inner_paths[key].setdefault(canonical, [key, canonical])
    graph_payload = {
        "package": package_name,
        "version": version,
        "source_path": str(analysis_root),
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "edges_detail": [
            {
                "caller": getattr(edge.caller, "qualified_name", "") or getattr(edge.caller, "function_name", ""),
                "callee": getattr(edge.callee, "qualified_name", "") or getattr(edge.callee, "function_name", "") or getattr(edge.callee, "identity_string", ""),
                "callee_type": "external" if edge.callee.is_external else "internal",
                "edge_type": getattr(edge, "edge_type", "confirmed_static"),
                "confidence": getattr(edge, "confidence", 1.0),
                "resolver": getattr(edge, "resolver", "static"),
                "call_expr": getattr(edge, "call_expr", ""),
                "line_number": getattr(edge, "line_number", 0),
            }
            for edge in graph.edges
        ],
        "metadata": graph.metadata,
    }
    summary_payload = {
        "package": package_name,
        "version": version,
            "summary": {
                "inner_summary": {key: sorted(values) for key, values in summary.inner_summary.items()},
                "outer_summary": {key: sorted(values) for key, values in summary.outer_summary.items()},
                "inner_paths": summary.inner_paths,
                "outer_paths": summary.outer_paths,
                "analysis_warnings": summary.analysis_warnings,
                "api_aliases": summary.api_aliases,
            },
        "source_path": str(analysis_root),
    }
    return graph_payload, summary_payload, summary, package_name, version


def _node_name(node: Any) -> str:
    return getattr(node, "qualified_name", "") or getattr(node, "function_name", "")


def _edge_callee_name(edge: Any) -> str:
    return getattr(edge.callee, "identity_string", "") or _node_name(edge.callee)


def _entry_names(graph: Any) -> list[str]:
    entries = [
        _node_name(node)
        for node in graph.internal_nodes
        if getattr(node, "entry_type", EntryPointType.UNKNOWN) != EntryPointType.UNKNOWN
    ]
    if entries:
        return sorted(set(entries))
    incoming = {_node_name(edge.callee) for edge in graph.internal_edges}
    roots = [_node_name(node) for node in graph.internal_nodes if _node_name(node) not in incoming]
    return sorted(set(roots))


def _shortest_internal_path(graph: Any, target: str) -> list[str]:
    if not target:
        return []
    adjacency: dict[str, list[str]] = {}
    for edge in graph.internal_edges:
        caller = _node_name(edge.caller)
        callee = _node_name(edge.callee)
        if caller and callee:
            adjacency.setdefault(caller, []).append(callee)
    queue: list[list[str]] = [[entry] for entry in _entry_names(graph)]
    seen = {path[0] for path in queue}
    while queue:
        path = queue.pop(0)
        if path[-1] == target:
            return path
        for nxt in sorted(adjacency.get(path[-1], [])):
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append([*path, nxt])
    return [target]


def _edge_lookup(graph: Any) -> dict[tuple[str, str], Any]:
    lookup: dict[tuple[str, str], Any] = {}
    for edge in graph.edges:
        caller = _node_name(edge.caller)
        callee = _edge_callee_name(edge)
        if caller and callee:
            lookup.setdefault((caller, callee), edge)
    return lookup


def _source_context(file_path: str, line_number: int, *, radius: int = 2) -> tuple[str, int]:
    if not file_path or line_number <= 0:
        return "", 0
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return "", 0
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except UnicodeDecodeError:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return "", 0
    except OSError:
        return "", 0
    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)
    if start > end:
        return "", 0
    snippet = "\n".join(
        f"{number:>4} {'>' if number == line_number else ' '} {lines[number - 1]}"
        for number in range(start, end + 1)
    )
    return snippet, start


def _path_warnings(result: Any, chain: list[str] | None = None) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    chain_names = set(chain or [])
    for key, value in (result.analysis_warnings or {}).items():
        if isinstance(value, list):
            for item in value[:20]:
                if isinstance(item, dict) and chain_names:
                    caller = str(item.get("caller") or "")
                    if caller and caller not in chain_names:
                        continue
                warnings.append({"type": key, "detail": item})
        else:
            warnings.append({"type": key, "detail": value})
    return warnings[:50]


def _path_nodes(graph: Any, chain: list[str], package_name: str, target: str) -> list[dict[str, Any]]:
    edges = _edge_lookup(graph)
    internal_names = {_node_name(node) for node in graph.internal_nodes}
    target_root = normalize_name(package_name).replace("-", "_")
    nodes: list[dict[str, Any]] = []
    for index, name in enumerate(chain):
        next_name = chain[index + 1] if index + 1 < len(chain) else ""
        edge = edges.get((name, next_name))
        kind = "application"
        package_label = ""
        if name == target:
            kind = "vulnerable"
            package_label = package_name
        elif index > 0 and name.split(".", 1)[0] == target_root:
            kind = "package_api" if index == 1 or (index > 0 and chain[index - 1] in internal_names) else "package_internal"
            package_label = package_name
        elif index == len(chain) - 1 and index > 0:
            kind = "package_internal"
            package_label = package_name
        elif index > 0 and "." in name and name not in internal_names:
            kind = "package_api" if index == 1 or (index > 0 and chain[index - 1] in internal_names) else "package_internal"
            root = name.split(".", 1)[0]
            package_label = package_name if root in {"src", "lib"} else root.replace("_", "-")
        file_path = getattr(edge.caller, "file_path", "") if edge is not None else ""
        line_number = int(getattr(edge, "line_number", 0) or 0) if edge is not None else 0
        snippet, snippet_start = _source_context(file_path, line_number)
        nodes.append(
            {
                "name": name,
                "kind": kind,
                "package": package_label,
                "file": file_path,
                "line": line_number,
                "callExpr": getattr(edge, "call_expr", "") if edge is not None else "",
                "sourceSnippet": snippet,
                "sourceStartLine": snippet_start,
                "confidence": float(getattr(edge, "confidence", 1.0) or 0.0) if edge is not None else 1.0,
            }
        )
    return nodes


def _full_chain(graph: Any, chain: list[str]) -> list[str]:
    if not chain:
        return []
    app_prefix = _shortest_internal_path(graph, chain[0])
    if app_prefix and app_prefix[-1] == chain[0]:
        return [*app_prefix[:-1], *chain]
    return chain


def process_one() -> bool:
    create_schema()
    with SessionLocal() as session:
        repo = FvraRepository(session)
        job = repo.claim_next_scan_job()
        if job is None:
            return False
        try:
            step = "load_project"
            project = repo.get_project(job.project_id)
            if project is None:
                raise RuntimeError(f"Project not found: {job.project_id}")

            step = "clone"
            repo.heartbeat_scan(job, step=step)
            project_path, commit = _clone_project(project.repo_url, job.branch, job.id)
            job.commit_sha = commit
            session.commit()

            step = "dependencies"
            repo.heartbeat_scan(job, step=step)
            dependency_graph = resolve_dependency_graph(project_path)
            revision = repo.upsert_project_revision(
                project_id=project.id,
                branch=job.branch,
                commit_sha=commit,
                dependency_fingerprint=dependency_graph.project.fingerprint,
                analyzer_version=dependency_graph.fingerprint.scanner_version,
            )
            repo.replace_dependencies(
                revision.id,
                [
                    {
                        "package_name": dep.name,
                        "normalized_name": dep.normalized_name,
                        "version": dep.version,
                        "ecosystem": dep.ecosystem,
                        "direct": dep.direct,
                        "dev": dep.dev,
                        "purl": dep.purl,
                    }
                    for dep in dependency_graph.dependencies
                ],
            )

            step = "project_graph"
            repo.heartbeat_scan(job, step=step)
            graph, usage_index = build_project_graph(project_path)
            graph_payload = _graph_payload(project_path, graph, usage_index)
            project_artifact = repo.upsert_artifact(
                kind="project-call-graph",
                reusable_key=f"{project.id}:{commit}:{dependency_graph.project.fingerprint}",
                payload=graph_payload,
                storage_root=artifact_root(),
                analyzer_version=dependency_graph.fingerprint.scanner_version,
                node_count=graph_payload["nodes"],
                edge_count=graph_payload["edges"],
                metadata={"project_id": project.id, "commit_sha": commit},
            )
            repo.link_project_artifact(revision.id, project_artifact.id)
            repo.link_scan_artifact(job.id, project_artifact.id)

            step = "match_advisories"
            repo.heartbeat_scan(job, step=step)
            repo.clear_scan_results(job.id)
            matches = repo.matching_vulnerabilities(revision.id, list(job.requested_cve_ids))
            summary_map: dict[str, Any] = {}
            entities_by_dependency = {
                _dependency_summary_key(dependency): entities
                for _advisory, _affected, dependency, entities in matches
            }
            for dependency in _summary_dependencies(list(dependency_graph.dependencies), usage_index, matches):
                step = f"package_summary:{_dependency_package_name(dependency)}"
                repo.heartbeat_scan(job, step=step)
                root, summary = _load_or_build_package_summary(
                    repo,
                    job.id,
                    dependency,
                    entities_by_dependency.get(_dependency_summary_key(dependency), []),
                )
                if summary is not None:
                    summary_map[root] = summary

            step = "reachability"
            repo.heartbeat_scan(job, step=step)
            for advisory, affected, dependency, entities in matches:
                targets = {entity.name for entity in entities if entity.name}
                result = check_transitive_reachability(project_path, targets, summaries=summary_map)
                paths = []
                for path in result.paths:
                    chain = _full_chain(graph, path.tpl_chain)
                    paths.append(
                        {
                            "project_api": path.project_api,
                            "target": path.vulnerable_target,
                            "path": chain,
                            "used_summaries": path.used_summaries,
                            "nodes": _path_nodes(graph, chain, dependency.package_name, path.vulnerable_target),
                            "warnings": _path_warnings(result, chain),
                        }
                    )
                fixed_versions = [str(item) for item in affected.fixed_versions]
                severity_records = list(session.query(SeverityRecord).filter_by(advisory_id=advisory.id))
                severity = severity_records[0].severity if severity_records and severity_records[0].severity else ("High" if targets else "Medium")
                score = 8.0 if severity == "High" else 5.0
                if severity_records and severity_records[0].score is not None:
                    score = float(severity_records[0].score)
                warnings = _path_warnings(result)
                evidence_status = "complete" if paths and all(path.get("nodes") for path in paths) else ("partial" if paths or warnings else "unavailable")
                for target in sorted(targets) or [""]:
                    repo.add_scan_finding(
                        scan_id=job.id,
                        advisory_id=advisory.canonical_id,
                        package_name=dependency.package_name,
                        package_version=dependency.version,
                        vulnerable_function=target,
                        verdict=result.verdict.value if targets else Verdict.UNKNOWN.value,
                        severity=severity,
                        summary=advisory.description or advisory.title or advisory.canonical_id,
                        fixed_version=fixed_versions[0] if fixed_versions else "",
                        score=score,
                        paths=[path for path in paths if not target or path.get("target") == target],
                        evidence_status=evidence_status,
                    )
            repo.mark_scan_completed(job)
            return True
        except Exception as exc:
            repo.mark_scan_failed(job, str(exc), step=locals().get("step", job.failure_step))
            return True


def run_forever(poll_interval: float = 2.0) -> None:
    while True:
        processed = process_one()
        if not processed:
            time.sleep(poll_interval)


if __name__ == "__main__":
    run_forever(float(os.getenv("F_VRA_WORKER_POLL_INTERVAL", "2")))
