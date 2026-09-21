"""fetch_repo.py — clone a repo and checkout the vulnerable snapshot (doc §11 step 3).

The master benchmark gives `vulnerable_ref` (the vulnerable state directly — a
commit sha or a release tag). We clone blob-filtered and check it out. Clones are
cached by repo slug and reused across groups/runs.

CLI:
    python -m pyshare.evaluation.scripts.fetch_repo --repo-url URL --ref REF --dest DIR
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

DEFAULT_CLONE_TIMEOUT = 900
DEFAULT_GIT_TIMEOUT = 600


def slugify(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")[:120]


def _git(args: list[str], cwd: Path | None = None,
         timeout: int = DEFAULT_GIT_TIMEOUT) -> tuple[int, str]:
    try:
        proc = subprocess.run(["git", *args], cwd=cwd,
                              capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, f"git_timeout after {timeout}s: git {' '.join(args[:2])}"
    except OSError as e:
        return 127, f"git_exec_failed: {e}"
    out = (proc.stdout or b"").decode("utf-8", "replace")
    err = (proc.stderr or b"").decode("utf-8", "replace")
    return proc.returncode, (out + err).strip()


def _is_partial_clone(dest: Path) -> bool:
    """True if `dest` was cloned with --filter (blob:none etc.) — its blobs are
    not all local, so reading source from the object store would silently miss
    files. We re-clone such caches in full (see ensure_repo_cloned)."""
    rc, _ = _git(["config", "--get", "remote.origin.partialclonefilter"], cwd=dest)
    return rc == 0


def ensure_repo_cloned(repo_url: str, ref: str, dest: Path,
                       clone_timeout: int = DEFAULT_CLONE_TIMEOUT) -> str | None:
    """Clone the repo with FULL blobs and NO working tree, and make `ref`
    available locally. Returns None on success, else an error string.

    Unlike ensure_repo_at_ref we deliberately never check out a working tree:
    some repos contain paths NTFS cannot create (reserved names like `aux/`,
    filenames with `:`), which makes `git checkout` fail on Windows. Source is
    read straight from the git object store instead (`read_py_sources`), so it
    works on every OS. The clone is full (no `--filter=blob:none`) so every blob
    is local and reading is offline + fast — a previously blob-filtered cache is
    detected and re-cloned in full."""
    if (dest / ".git").exists() and _is_partial_clone(dest):
        shutil.rmtree(dest, ignore_errors=True)     # stale blob-filtered cache
    if not (dest / ".git").exists():
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        rc, out = _git(["clone", "--no-checkout", repo_url, str(dest)],
                       timeout=clone_timeout)
        if rc != 0:
            return f"clone_failed: {out[:300]}"

    # Is the ref already known (a fetched sha or a tag)?
    rc, _ = _git(["cat-file", "-e", f"{ref}^{{commit}}"], cwd=dest)
    if rc != 0:
        rc, out = _git(["fetch", "origin", ref], cwd=dest, timeout=clone_timeout)
        if rc != 0:
            rc2, out2 = _git(["fetch", "--tags", "origin"], cwd=dest, timeout=clone_timeout)
            if rc2 != 0:
                return f"fetch_failed: {out[:200]} | tags: {out2[:200]}"
    return None


def read_py_sources(dest: Path, ref: str) -> dict[str, str] | None:
    """Read every .py blob at `ref` into {path: source}, straight from the git
    object store (no working tree, so NTFS-illegal paths can't break it).
    Returns None if the tree can't be listed (bad ref)."""
    rc, out = _git(["ls-tree", "-r", "--name-only", ref], cwd=dest)
    if rc != 0:
        return None
    paths = [p.strip() for p in out.splitlines() if p.strip().endswith(".py")]
    if not paths:
        return {}
    # One `git cat-file --batch` reads all blobs; parse the stream by byte offsets.
    proc = subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=str(dest),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    request = "".join(f"{ref}:{p}\n" for p in paths).encode("utf-8")
    blob, _ = proc.communicate(request)

    sources: dict[str, str] = {}
    pos = 0
    for p in paths:
        nl = blob.find(b"\n", pos)
        if nl == -1:
            break
        header = blob[pos:nl].decode("utf-8", "ignore").split(" ")
        pos = nl + 1
        if len(header) != 3 or header[1] != "blob":   # "<oid> missing" etc. -> skip
            continue
        size = int(header[2])
        sources[p] = blob[pos:pos + size].decode("utf-8", "ignore")
        pos += size + 1                                # skip blob bytes + trailing \n
    return sources


def ensure_repo_at_ref(repo_url: str, ref: str, dest: Path,
                       clone_timeout: int = DEFAULT_CLONE_TIMEOUT) -> str | None:
    """Clone (if needed) and checkout `ref`. Returns None on success, else error.

    `ref` is `vulnerable_ref` — a commit sha OR a tag. We try to check it out
    directly; if it's not present we fetch it first."""
    if not (dest / ".git").exists():
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        rc, out = _git(["clone", "--filter=blob:none", "--no-checkout", repo_url, str(dest)],
                       timeout=clone_timeout)
        if rc != 0:
            return f"clone_failed: {out[:300]}"

    # Is the ref already known (a fetched sha or a tag)?
    rc, _ = _git(["cat-file", "-e", f"{ref}^{{commit}}"], cwd=dest)
    if rc != 0:
        rc, out = _git(["fetch", "origin", ref], cwd=dest, timeout=clone_timeout)
        if rc != 0:
            # tags may need an explicit fetch of all tags
            rc2, out2 = _git(["fetch", "--tags", "origin"], cwd=dest, timeout=clone_timeout)
            if rc2 != 0:
                return f"fetch_failed: {out[:200]} | tags: {out2[:200]}"

    rc, out = _git(["checkout", "--force", ref], cwd=dest)
    if rc != 0:
        return f"checkout_failed: {out[:300]}"
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Clone + checkout a vulnerable ref.")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--ref", required=True, help="vulnerable_ref (sha or tag).")
    ap.add_argument("--dest", type=Path, required=True)
    args = ap.parse_args()

    err = ensure_repo_at_ref(args.repo_url, args.ref, args.dest)
    if err:
        raise SystemExit(f"ERROR: {err}")
    print(f"OK: {args.repo_url} @ {args.ref} -> {args.dest}")


if __name__ == "__main__":
    main()
