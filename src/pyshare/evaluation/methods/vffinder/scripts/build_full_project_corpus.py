"""Build a FULL-PROJECT function corpus by cloning each repo at its commit.

Why this exists
---------------
`build_function_corpus_from_jsonl.py` only emits the vulnerable function plus
the patch-touched sibling names listed in `all_functions` (median 1 per CVE).
That makes the retrieval candidate pool ~2 functions/CVE, so Top@1 is trivially
high and NOT comparable to the paper (which ranks within ALL functions of the
vulnerable product). This script reconstructs the paper's setting: for every
(repo, commit) it parses *every* function in the source package and emits one
FunctionEntity each, with `func_id = "<path>::<func_name>"` so it matches the
ground-truth convention exactly.

Scope ("vulnerable product")
----------------------------
For each commit we keep only files under the top-level package directory(ies)
that contain the vulnerable file(s) (e.g. `synapse/`, `airflow/`). Test, docs
and example directories are excluded. This mirrors the shipped library code a
downstream depends on, and guarantees the ground-truth file is in scope.

Usage (from the directory containing vffinder/):
    python -m pyshare.evaluation.methods.vffinder.scripts.build_full_project_corpus
    python -m pyshare.evaluation.methods.vffinder.scripts.build_full_project_corpus --limit-repos 3   # pilot
    python -m pyshare.evaluation.methods.vffinder.scripts.build_full_project_corpus --inline          # + invocation augmentation
"""

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


from pyshare.evaluation.methods.vffinder import config
from pyshare.evaluation.methods.vffinder.corpus.function_corpus import (
    parse_python_source,
    build_call_graph,
    inline_expand,
)
from pyshare.evaluation.methods.vffinder.scripts.build_function_corpus_from_jsonl import (
    _library_tag_from_package,
    load_jsonl,
)

DEFAULT_JSONL = config.DATA_DIR / "from_master.jsonl"
DEFAULT_OUTPUT = config.OUTPUT_DIR / "function_corpus_fullproject.json"
REPO_CACHE = config.OUTPUT_DIR / "repos_cache"

# Directory segments that are NOT part of the shipped product.
EXCLUDE_SEGMENTS = {
    "test", "tests", "testing", "_test", "_tests",
    "docs", "doc", "examples", "example", "samples", "sample",
    "benchmark", "benchmarks", "bench",
    ".git", ".tox", ".github", "build", "dist", "node_modules", "__pycache__",
}


def _run_git(args: list[str], cwd: Path | None = None) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None,
        capture_output=True, text=True,
    )
    return proc.returncode, (proc.stdout + proc.stderr)


def _repo_name(repo_url: str) -> str:
    return repo_url.rstrip("/").split("/")[-1].replace(".git", "")


def ensure_clone(repo_url: str) -> Path | None:
    """Mirror-fetch the repo objects into the cache (NO working tree).

    We never check out a working tree — files are read straight from the git
    object store with `git cat-file` — so Windows-illegal paths (e.g. test
    fixtures with ':' in the name) can't break the clone, and no thousands of
    files are written to disk per commit.
    """
    REPO_CACHE.mkdir(parents=True, exist_ok=True)
    dest = REPO_CACHE / _repo_name(repo_url)
    if (dest / ".git").is_dir() or (dest / "HEAD").is_file():
        return dest
    print(f"  cloning {repo_url} (no checkout) ...", flush=True)
    code, out = _run_git(["clone", "--quiet", "--no-checkout", repo_url, str(dest)])
    if code != 0:
        print(f"  ERROR cloning {repo_url}: {out.strip()[:300]}", file=sys.stderr)
        return None
    return dest


def _have_commit(repo_dir: Path, sha: str) -> bool:
    code, _ = _run_git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo_dir)
    if code == 0:
        return True
    _run_git(["fetch", "--quiet", "origin", sha], cwd=repo_dir)
    code, _ = _run_git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo_dir)
    return code == 0


def _in_scope(rel_path: str, scope_prefixes: set[str]) -> bool:
    parts = rel_path.split("/")
    if parts[0] not in scope_prefixes:
        return False
    return not any(seg in EXCLUDE_SEGMENTS for seg in parts)


def list_scope_py(repo_dir: Path, sha: str,
                  scope_prefixes: set[str]) -> list[str]:
    """List in-scope .py paths in the tree at `sha` (no checkout)."""
    code, out = _run_git(["ls-tree", "-r", "--name-only", sha], cwd=repo_dir)
    if code != 0:
        return []
    paths = []
    for line in out.splitlines():
        p = line.strip()
        if p.endswith(".py") and _in_scope(p, scope_prefixes):
            paths.append(p)
    return paths


def read_blobs(repo_dir: Path, sha: str, paths: list[str]) -> dict[str, str]:
    """Read many blobs at once via `git cat-file --batch` (one subprocess)."""
    if not paths:
        return {}
    proc = subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=str(repo_dir),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    request = "".join(f"{sha}:{p}\n" for p in paths).encode("utf-8")
    out, _ = proc.communicate(request)

    result: dict[str, str] = {}
    pos = 0
    for p in paths:
        nl = out.find(b"\n", pos)
        if nl == -1:
            break
        header = out[pos:nl].decode("utf-8", "ignore")
        pos = nl + 1
        parts = header.split(" ")
        # header is "<oid> <type> <size>" on success, or "<rev> missing"
        if len(parts) != 3 or parts[1] != "blob":
            continue
        size = int(parts[2])
        result[p] = out[pos:pos + size].decode("utf-8", "ignore")
        pos += size + 1  # skip blob bytes + trailing newline
    return result


def parse_commit_corpus(repo_dir: Path,
                        sha: str,
                        scope_prefixes: set[str],
                        library: str,
                        stem: bool,
                        inline: bool) -> list[dict]:
    """Parse every in-scope .py function in the tree at `sha` (read from git)."""
    paths = list_scope_py(repo_dir, sha, scope_prefixes)
    blobs = read_blobs(repo_dir, sha, paths)
    entities = []
    for rel_path, source_text in blobs.items():
        entities.extend(parse_python_source(source_text, rel_path, stem=stem))

    if inline and entities:
        cg = build_call_graph(entities)
        entities = inline_expand(entities, cg)

    # Rewrite func_id to GT convention (path::leaf_name, no class qualifier),
    # tag library, drop heavy source field. Dedupe on the GT-style id.
    out: list[dict] = []
    seen: set[str] = set()
    for fe in entities:
        gt_id = f"{fe.module}::{fe.name}"
        if gt_id in seen:
            continue
        seen.add(gt_id)
        out.append({
            "func_id": gt_id,
            "name": fe.name,
            "module": fe.module,
            "class_name": fe.class_name,
            "params": fe.params,
            "param_types": fe.param_types,
            "entities": fe.entities,
            "library": library,
        })
    return out


def _atomic_write_json(path: Path, data) -> None:
    """Write JSON to a temp file in the same dir, then atomically replace.

    A power-off mid-write can only ever corrupt the throwaway *.tmp; the real
    checkpoint at `path` is either the previous good state or the new one,
    never a half-written file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomic on Windows + POSIX


def _progress_path(output_path: Path) -> Path:
    return output_path.with_suffix(output_path.suffix + ".progress.json")


def _load_checkpoint(output_path: Path) -> tuple[list[dict], set[str], set[str]]:
    """Resume state: (all_funcs, func_index, done_repo_urls).

    Reads the partial corpus written so far plus the sidecar progress file that
    records which repo URLs were fully processed. Both must agree for a resume;
    if either is missing/unreadable we start clean.
    """
    prog = _progress_path(output_path)
    if not (output_path.is_file() and prog.is_file()):
        return [], set(), set()
    try:
        with open(output_path, encoding="utf-8") as f:
            all_funcs = json.load(f)
        with open(prog, encoding="utf-8") as f:
            done = set(json.load(f).get("done_repos", []))
    except (json.JSONDecodeError, OSError):
        return [], set(), set()
    func_index = {fn["func_id"] for fn in all_funcs}
    return all_funcs, func_index, done


def build(jsonl_path: Path, output_path: Path, stem: bool, inline: bool,
          limit_repos: int | None, only: list[str] | None = None,
          resume: bool = True) -> None:
    records = load_jsonl(jsonl_path)
    print(f"{len(records)} records loaded")

    # Group by (repo_url, commit_sha): collect vf_file scope + library tag.
    commits: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"vf_files": set(), "library": "", "cves": set()})
    for r in records:
        key = (r["repo_url"], r["commit_sha"])
        commits[key]["vf_files"].add(r.get("vf_file", ""))
        commits[key]["library"] = _library_tag_from_package(r.get("packages") or [])
        commits[key]["cves"].add(r["cve_id"])

    # Group commits by repo so we clone once.
    by_repo: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for (url, sha), meta in commits.items():
        by_repo[url].append((sha, meta))

    repos = list(by_repo.items())
    if only:
        repos = [(u, v) for u, v in repos
                 if any(s.lower() in u.lower() for s in only)]
    if limit_repos:
        repos = repos[:limit_repos]
    print(f"Processing {len(repos)} repos / "
          f"{sum(len(v) for _, v in repos)} commits "
          f"(stem={stem}, inline={inline})\n")

    all_funcs: list[dict] = []
    func_index: set[str] = set()
    done_repos: set[str] = set()
    failed: list[str] = []

    if resume:
        all_funcs, func_index, done_repos = _load_checkpoint(output_path)
        if done_repos:
            print(f"Resuming: {len(done_repos)} repo(s) already done, "
                  f"{len(all_funcs)} funcs in checkpoint\n")

    for ri, (url, commit_list) in enumerate(repos, 1):
        if url in done_repos:
            print(f"[{ri}/{len(repos)}] {url} -- SKIP (checkpointed)")
            continue
        print(f"[{ri}/{len(repos)}] {url} ({len(commit_list)} commit)")
        repo_dir = ensure_clone(url)
        if repo_dir is None:
            failed.append(url)
            continue
        for sha, meta in commit_list:
            if not _have_commit(repo_dir, sha):
                print(f"  ERROR commit {sha[:10]} unavailable", file=sys.stderr)
                failed.append(f"{url}@{sha[:10]}")
                continue
            scope = {f.split("/")[0] for f in meta["vf_files"] if f}
            funcs = parse_commit_corpus(
                repo_dir, sha, scope, meta["library"], stem, inline)
            added = 0
            for fn in funcs:
                if fn["func_id"] in func_index:
                    continue
                func_index.add(fn["func_id"])
                all_funcs.append(fn)
                added += 1
            print(f"    {sha[:10]}  scope={sorted(scope)}  "
                  f"+{added} funcs (cve={sorted(meta['cves'])})")

        # Checkpoint after each repo: an interrupted run resumes from here.
        done_repos.add(url)
        _atomic_write_json(output_path, all_funcs)
        _atomic_write_json(_progress_path(output_path),
                           {"done_repos": sorted(done_repos)})
        print(f"    [checkpoint] {len(all_funcs)} funcs, "
              f"{len(done_repos)} repo(s) done", flush=True)

    _atomic_write_json(output_path, all_funcs)
    print(f"\nWrote {len(all_funcs)} functions -> {output_path}")
    if failed:
        print(f"FAILED ({len(failed)}): {failed}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jsonl", default=str(DEFAULT_JSONL))
    ap.add_argument("--output", default=str(DEFAULT_OUTPUT))
    ap.add_argument("--no-stem", action="store_true")
    ap.add_argument("--inline", action="store_true",
                    help="enable call-graph invocation augmentation (slower)")
    ap.add_argument("--limit-repos", type=int, default=None,
                    help="process only the first N repos (pilot)")
    ap.add_argument("--only", default=None,
                    help="comma-separated substrings; process only matching repo URLs")
    ap.add_argument("--no-resume", action="store_true",
                    help="ignore any existing checkpoint and rebuild from scratch")
    args = ap.parse_args()

    build(
        jsonl_path=Path(args.jsonl),
        output_path=Path(args.output),
        stem=not args.no_stem,
        inline=args.inline,
        limit_repos=args.limit_repos,
        only=[s.strip() for s in args.only.split(",")] if args.only else None,
        resume=not args.no_resume,
    )


if __name__ == "__main__":
    main()
