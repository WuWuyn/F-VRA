from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from pyshare_core.config import settings
from pyshare_localization.models import MetadataSource


@dataclass
class ResolvedMetadata:
    cve_id: str | None
    description: str = ""
    cwe_id: str | None = None
    references: list[str] = field(default_factory=list)
    patch_urls: list[str] = field(default_factory=list)
    source: MetadataSource = "unknown"
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class PatchFileChange:
    file_path: str
    old_lines: set[int] = field(default_factory=set)
    new_lines: set[int] = field(default_factory=set)
    added: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    hunk_headers: list[str] = field(default_factory=list)


@dataclass
class PatchAnalysis:
    files: list[PatchFileChange]
    called_names: set[str] = field(default_factory=set)
    changed_names: set[str] = field(default_factory=set)
    changed_globals: set[str] = field(default_factory=set)
    changed_imports: set[str] = field(default_factory=set)
    hunk_symbols: set[str] = field(default_factory=set)


_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_\.]*)\s*\(")
_NAME = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=")
_HUNK = re.compile(r"@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@\s*(.*)")
_DEF_CLASS = re.compile(r"\b(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
_IMPORT_FROM = re.compile(r"^\s*from\s+[\w\.]+\s+import\s+(.+)")
_IMPORT = re.compile(r"^\s*import\s+(.+)")


def _looks_like_patch(url: str) -> bool:
    lowered = url.lower()
    return (
        lowered.endswith((".patch", ".diff"))
        or "/commit/" in lowered
        or "/pull/" in lowered
        or "patch" in lowered
    )


def _get_json(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json()
    except (requests.RequestException, ValueError):
        return None
    return None


def resolve_osv(cve_id: str) -> ResolvedMetadata | None:
    data = _get_json(f"https://api.osv.dev/v1/vulns/{cve_id}")
    if not data:
        return None
    references = [item.get("url", "") for item in data.get("references", []) if item.get("url")]
    aliases = data.get("aliases", [])
    resolved_cve = next((alias for alias in aliases if alias.startswith("CVE-")), cve_id)
    return ResolvedMetadata(
        cve_id=resolved_cve,
        description=data.get("details") or data.get("summary") or "",
        references=references,
        patch_urls=[url for url in references if _looks_like_patch(url)],
        source="OSV",
        raw=data,
    )


def resolve_nvd(cve_id: str) -> ResolvedMetadata | None:
    headers = {}
    if key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = key
    data = _get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        headers=headers,
    )
    vulnerabilities = (data or {}).get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next(
        (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
        "",
    )
    references = [item.get("url", "") for item in cve.get("references", []) if item.get("url")]
    weaknesses = cve.get("weaknesses", [])
    cwe_id = None
    for weakness in weaknesses:
        for item in weakness.get("description", []):
            value = item.get("value", "")
            if value.startswith("CWE-"):
                cwe_id = value
                break
    return ResolvedMetadata(
        cve_id=cve_id,
        description=description,
        cwe_id=cwe_id,
        references=references,
        patch_urls=[url for url in references if _looks_like_patch(url)],
        source="NVD",
        raw=cve,
    )


def resolve_metadata(cve_id: str) -> ResolvedMetadata:
    return resolve_osv(cve_id) or resolve_nvd(cve_id) or ResolvedMetadata(cve_id=cve_id)


def download_patch(url: str) -> tuple[str, str] | None:
    headers = {"Accept": "application/vnd.github.patch"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    urls = [url]
    lowered = url.lower().rstrip("/")
    if "github.com/" in lowered and ("/commit/" in lowered or "/pull/" in lowered):
        if not lowered.endswith((".patch", ".diff")):
            urls.insert(0, url.rstrip("/") + ".patch")

    for candidate_url in urls:
        try:
            response = requests.get(candidate_url, headers=headers, timeout=20)
            if response.status_code == 200 and "@@" in response.text:
                return response.text, candidate_url
        except requests.RequestException:
            continue
    return None


def _normalise_path(raw: str) -> str:
    value = raw.strip().split("\t", 1)[0]
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return value.replace("\\", "/")


def parse_patch_text(text: str) -> PatchAnalysis:
    files: list[PatchFileChange] = []
    current: PatchFileChange | None = None
    old_line = new_line = 0

    for line in text.splitlines():
        if line.startswith("+++ "):
            path = _normalise_path(line[4:])
            if path != "/dev/null":
                current = PatchFileChange(file_path=path)
                files.append(current)
            continue
        match = _HUNK.match(line)
        if match:
            old_line, new_line = int(match.group(1)), int(match.group(2))
            if current is not None:
                current.hunk_headers.append(match.group(3).strip())
            continue
        if current is None or line.startswith(("diff ", "index ", "--- ")):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current.new_lines.add(new_line)
            current.added.append(line[1:])
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            current.old_lines.add(old_line)
            current.deleted.append(line[1:])
            old_line += 1
        else:
            current.context.append(line[1:] if line.startswith(" ") else line)
            old_line += 1
            new_line += 1

    changed_text = "\n".join(
        line for change in files for line in [*change.added, *change.deleted]
    )
    hunk_symbols = {
        match.group(1)
        for change in files
        for header in change.hunk_headers
        if (match := _DEF_CLASS.search(header))
    }
    called_names = {match.group(1).split(".")[-1] for match in _CALL.finditer(changed_text)}
    changed_names = set(_NAME.findall(changed_text))
    changed_imports: set[str] = set()
    for line in changed_text.splitlines():
        if match := _IMPORT_FROM.match(line):
            changed_imports.update(
                part.strip().split(" as ", 1)[0].split(".")[-1]
                for part in match.group(1).split(",")
                if part.strip()
            )
        elif match := _IMPORT.match(line):
            changed_imports.update(
                part.strip().split(" as ", 1)[0].split(".")[0]
                for part in match.group(1).split(",")
                if part.strip()
            )
    changed_globals = {
        match.group(1)
        for line in changed_text.splitlines()
        if (match := _ASSIGN.match(line))
        and (match.group(1).isupper() or "_" in match.group(1))
    }
    return PatchAnalysis(
        files=files,
        called_names=called_names,
        changed_names=changed_names,
        changed_globals=changed_globals,
        changed_imports=changed_imports,
        hunk_symbols=hunk_symbols,
    )


def load_patch(path: str | Path) -> tuple[PatchAnalysis, str]:
    patch_path = Path(path).resolve()
    return parse_patch_text(patch_path.read_text(encoding="utf-8", errors="ignore")), str(patch_path)


def _repo_name(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    return re.sub(r"\.git$", "", name)


def github_repo_url_from_reference(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None

    owner, repo = parts[0], re.sub(r"\.git$", "", parts[1])
    if not owner or not repo:
        return None
    return f"https://github.com/{owner}/{repo}.git"


def github_repo_urls_from_references(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    repos: list[str] = []
    for url in urls:
        repo_url = github_repo_url_from_reference(url)
        if repo_url and repo_url not in seen:
            seen.add(repo_url)
            repos.append(repo_url)
    return repos


def github_commit_from_reference(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    try:
        commit_index = parts.index("commit")
    except ValueError:
        return None
    if commit_index + 1 >= len(parts):
        return None

    commit = re.sub(r"\.(patch|diff)$", "", parts[commit_index + 1], flags=re.I)
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", commit):
        return None
    return commit


def github_commit_from_references(urls: list[str]) -> str | None:
    for url in urls:
        commit = github_commit_from_reference(url)
        if commit:
            return commit
    return None


def clone_or_update(repo_url: str, commit: str | None = None) -> Path:
    name = _repo_name(repo_url)
    dest = settings.repo_cache_dir / name
    settings.repo_cache_dir.mkdir(parents=True, exist_ok=True)

    if not dest.exists():
        subprocess.run(
            ["git", "clone", "--progress", repo_url, str(dest)],
            check=True,
        )

    if commit:
        subprocess.run(["git", "-C", str(dest), "fetch", "--all", "--progress"], check=False)
        subprocess.run(
            ["git", "-C", str(dest), "checkout", commit],
            check=True,
        )

    return dest
