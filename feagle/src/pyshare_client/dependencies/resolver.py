from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from pyshare_client.dependencies.installed import installed_distributions
from pyshare_client.dependencies.parsers import (
    LOCKFILE_NAMES,
    MANIFEST_NAMES,
    direct_names_from_pyproject,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject,
    parse_requirements,
    parse_setup_py,
    parse_uv_lock,
    purl,
    requirement_parts,
)
from pyshare_core.models import (
    AnalysisFingerprint,
    DependencyGraphArtifact,
    DependencyRecord,
    ProjectIdentity,
)


def project_fingerprint(project: Path, files: list[Path]) -> str:
    digest = hashlib.sha256()
    digest.update(str(project.resolve()).encode("utf-8", errors="ignore"))
    for path in sorted(files, key=lambda item: item.as_posix()):
        digest.update(path.as_posix().encode("utf-8", errors="ignore"))
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:16]


def discover_dependency_files(project: Path) -> list[Path]:
    files: list[Path] = []
    for name in LOCKFILE_NAMES + MANIFEST_NAMES:
        path = project / name
        if path.exists():
            files.append(path)
    files.extend(sorted(project.glob("requirements*.txt")))
    return list(dict.fromkeys(files))


def dedupe_records(records: list[DependencyRecord]) -> list[DependencyRecord]:
    merged: dict[tuple[str, str], DependencyRecord] = {}
    for record in records:
        key = (record.normalized_name, record.version or record.specifier)
        existing = merged.get(key)
        if existing is None:
            merged[key] = record
            continue
        merged[key] = existing.model_copy(
            update={
                "direct": existing.direct or record.direct,
                "dev": existing.dev and record.dev,
                "source_file": existing.source_file if existing.version else record.source_file,
                "source_type": existing.source_type if existing.version else record.source_type,
                "source_path": existing.source_path or record.source_path,
                "dependencies": sorted(set(existing.dependencies) | set(record.dependencies)),
            }
        )
    return sorted(merged.values(), key=lambda item: (not item.direct, item.normalized_name, item.version, item.specifier))


def _pip_report_requirements(project: Path, selected_files: list[Path]) -> list[str]:
    requirements: list[str] = []
    for path in selected_files:
        if path.name.startswith("requirements") and path.suffix == ".txt":
            requirements.extend(["-r", str(path)])
        elif path.name == "pyproject.toml":
            requirements.append(str(project))
        elif path.name == "setup.py":
            requirements.append(str(project))
    return requirements


def _imported_top_level_modules(project: Path) -> set[str]:
    modules: set[str] = set()
    skipped_dirs = {".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "node_modules"}
    for path in project.rglob("*.py"):
        if any(part in skipped_dirs for part in path.relative_to(project).parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0].strip()
                    if root:
                        modules.add(root.replace("_", "-").lower())
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                root = node.module.split(".", 1)[0].strip()
                if root:
                    modules.add(root.replace("_", "-").lower())
    return modules


def _looks_like_imported_package(normalized_name: str, imports: set[str]) -> bool:
    candidates = {normalized_name, normalized_name.replace("-", "_").lower()}
    if "-" in normalized_name:
        candidates.add(normalized_name.split("-", 1)[0])
    normalized_imports = {item.replace("_", "-").lower() for item in imports}
    return bool(candidates & normalized_imports)


def _infer_direct_from_requirements_freeze(project: Path, records: list[DependencyRecord]) -> list[DependencyRecord]:
    names = {record.normalized_name for record in records}
    referenced = {
        dependency
        for record in records
        for dependency in record.dependencies
        if dependency in names
    }
    imports = _imported_top_level_modules(project)
    inferred: list[DependencyRecord] = []
    for record in records:
        direct = record.normalized_name not in referenced or _looks_like_imported_package(record.normalized_name, imports)
        inferred.append(record.model_copy(update={"direct": direct}))
    return inferred


def _requires_dist_names(requirements: list[str]) -> list[str]:
    names: list[str] = []
    for requirement in requirements:
        parts = requirement_parts(str(requirement))
        if parts:
            names.append(parts[0])
    return sorted({name.replace("_", "-").lower() for name in names})


def _enrich_records_from_pypi_metadata(records: list[DependencyRecord], warnings: list[str]) -> list[DependencyRecord]:
    if os.getenv("F_VRA_PYPI_METADATA", "1").lower() in {"0", "false", "no"}:
        warnings.append("PyPI metadata enrichment disabled by F_VRA_PYPI_METADATA")
        return records

    enriched: list[DependencyRecord] = []
    for record in records:
        if record.dependencies or not record.version:
            enriched.append(record)
            continue
        quoted_name = urllib.parse.quote(record.normalized_name)
        quoted_version = urllib.parse.quote(record.version)
        url = f"https://pypi.org/pypi/{quoted_name}/{quoted_version}/json"
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
            requires_dist = (payload.get("info") or {}).get("requires_dist") or []
        except Exception as exc:
            warnings.append(f"PyPI metadata lookup failed for {record.normalized_name}=={record.version}: {exc}")
            enriched.append(record)
            continue
        enriched.append(record.model_copy(update={"dependencies": _requires_dist_names(requires_dist)}))
    return enriched


def _resolve_with_pip_report(project: Path, selected_files: list[Path], direct_names: set[str]) -> tuple[list[DependencyRecord], list[str]]:
    if os.getenv("F_VRA_PIP_RESOLVE", "1").lower() in {"0", "false", "no"}:
        return [], ["pip resolver disabled by F_VRA_PIP_RESOLVE"]
    requirements = _pip_report_requirements(project, selected_files)
    if not requirements:
        return [], []
    with tempfile.TemporaryDirectory(prefix="fvra-pip-report-") as tmp:
        report_path = Path(tmp) / "report.json"
        command = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--report",
            str(report_path),
            *requirements,
        ]
        try:
            subprocess.run(command, cwd=project, text=True, capture_output=True, check=True, timeout=120)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return [], [f"pip dependency resolution failed: {exc}"]

    records: list[DependencyRecord] = []
    for item in payload.get("install") or []:
        metadata = item.get("metadata") or {}
        name = str(metadata.get("name") or "")
        version = str(metadata.get("version") or "")
        if not name or name.lower() == "python":
            continue
        norm = name.replace("_", "-").lower()
        dependencies = []
        for requirement in metadata.get("requires_dist") or []:
            dep_name = str(requirement).split(";", 1)[0].strip().split(" ", 1)[0].split("[", 1)[0]
            if dep_name:
                dependencies.append(dep_name)
        records.append(
            DependencyRecord(
                name=name,
                normalized_name=norm,
                version=version,
                specifier=f"=={version}" if version else "",
                direct=norm in direct_names or bool(item.get("requested")),
                dev=False,
                source_file=str(selected_files[0]) if selected_files else "",
                source_type="pip-report",
                source_path="",
                dependencies=sorted({dep.replace("_", "-").lower() for dep in dependencies}),
                purl=purl(name, version),
            )
        )
    requirements_only = selected_files and all(path.name.startswith("requirements") and path.suffix == ".txt" for path in selected_files)
    if requirements_only and not direct_names:
        records = _infer_direct_from_requirements_freeze(project, records)
    return records, []


def resolve_dependency_graph(
    project: Path,
    *,
    files: list[Path] | None = None,
    include_dev: bool = False,
) -> DependencyGraphArtifact:
    project = project.resolve()
    selected_files = [path.resolve() for path in (files or discover_dependency_files(project))]
    installed = installed_distributions()
    direct_names: set[str] = set()
    pyproject = project / "pyproject.toml"
    if pyproject.exists():
        direct_names = direct_names_from_pyproject(pyproject, include_dev=include_dev)

    records: list[DependencyRecord] = []
    warnings: list[str] = []
    has_lockfile = any(path.name in LOCKFILE_NAMES for path in selected_files)
    for path in selected_files:
        if not path.exists():
            warnings.append(f"missing dependency file: {path}")
            continue
        try:
            if path.name == "poetry.lock":
                records.extend(
                    parse_poetry_lock(path, direct_names=direct_names, include_dev=include_dev, installed=installed)
                )
            elif path.name == "uv.lock":
                records.extend(parse_uv_lock(path, direct_names=direct_names, include_dev=include_dev, installed=installed))
            elif path.name == "Pipfile.lock":
                records.extend(parse_pipfile_lock(path, include_dev=include_dev, installed=installed))
            elif path.name == "pyproject.toml":
                if not has_lockfile:
                    records.extend(parse_pyproject(path, include_dev=include_dev, installed=installed))
            elif path.name == "setup.py":
                records.extend(parse_setup_py(path, include_dev=include_dev, installed=installed))
            elif path.name.startswith("requirements") and path.suffix == ".txt":
                records.extend(parse_requirements(path, include_dev=include_dev, installed=installed))
        except Exception as exc:
            warnings.append(f"failed to parse {path}: {exc}")

    if not has_lockfile:
        manifest_direct_names = {record.normalized_name for record in records if record.direct}
        pip_records, pip_warnings = _resolve_with_pip_report(project, selected_files, direct_names | manifest_direct_names)
        warnings.extend(pip_warnings)
        if pip_records:
            records = pip_records
        elif records and all(path.name.startswith("requirements") and path.suffix == ".txt" for path in selected_files):
            records = _enrich_records_from_pypi_metadata(records, warnings)
            records = _infer_direct_from_requirements_freeze(project, records)

    return DependencyGraphArtifact(
        project=ProjectIdentity(root=str(project), fingerprint=project_fingerprint(project, selected_files)),
        fingerprint=AnalysisFingerprint(python_version=f"{sys.version_info.major}.{sys.version_info.minor}"),
        source_files=[str(path) for path in selected_files if path.exists()],
        dependencies=dedupe_records(records),
        analysis_warnings={"warnings": warnings} if warnings else {},
    )
