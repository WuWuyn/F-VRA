"""
Run VFDetector evaluation over a JSONL of CVE entries.

Two input modes (use exactly one):
  --src RAW.jsonl   : raw CVE JSONL; filter Python-only and pick --n diverse samples
  --samples FILE    : pre-curated JSONL (one CVE per line, will eval every row)

For each selected CVE entry:
  1. Clone repo (NO working tree) into <workspaces>/<slug>/
  2. Read the .py source at the PARENT of commit_sha (vulnerable state) straight
     from the git object store — no checkout, so Windows/NTFS-illegal paths
     (`aux/`, names with `:`) can't break it
  3. Run vfdetector pipeline in-process over that source
  4. Compare top-K function names against ground-truth `all_functions`
  5. Compute rank_of_truth and Hit@K

Usage:
  # One-shot from raw JSONL (run ALL rows: disable the per-repo cap)
  python -m pyshare.evaluation.methods.vfdetector.runner --src data/YOUR_FILE.jsonl --n 90
  python -m pyshare.evaluation.methods.vfdetector.runner --src raw.jsonl --n 100 --top-k 20

  # Pre-curated workflow (evaluation adapters use this path)
  python -m pyshare.evaluation.methods.vfdetector.runner --samples data/pilot_samples.jsonl
  python -m pyshare.evaluation.methods.vfdetector.runner --resume          # skip CVEs already in --results

Crash / failure safety:
  * Every completed CVE is flushed to --results immediately (a live checkpoint).
  * A failing CVE is skipped, never aborts the run, and is logged to --failures
    (failures.jsonl) in the same schema as --samples.
  * Re-run only the failures later:  python -m pyshare.evaluation.methods.vfdetector.runner --samples output/failures.jsonl
  * Resume an interrupted run:        python -m pyshare.evaluation.methods.vfdetector.runner --resume
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:  # tqdm is not a vfdetector dependency — degrade to plain prints
    tqdm = None

HERE = Path(__file__).resolve().parent
VFDETECTOR_ROOT = HERE.parent


def load_runtime_dependencies() -> None:
    """Import dependencies only after argparse has handled --help."""
    global FunctionExtractor, clean_text, rank_functions, process_cve

    from pyshare.evaluation.methods.vfdetector.core.code_processor import FunctionExtractor, clean_text
    from pyshare.evaluation.methods.vfdetector.core.ranker import rank_functions
    from pyshare.evaluation.methods.vfdetector.core.report_processor import process_cve

DEFAULT_SAMPLES = VFDETECTOR_ROOT / "data" / "pilot_samples.jsonl"
DEFAULT_RESULTS = VFDETECTOR_ROOT / "output" / "results.csv"
DEFAULT_SUMMARY = VFDETECTOR_ROOT / "output" / "summary.json"
DEFAULT_FAILURES = VFDETECTOR_ROOT / "output" / "failures.jsonl"
DEFAULT_WORKSPACES = VFDETECTOR_ROOT / "workspaces"
DEFAULT_TOP_K = 10
DEFAULT_HIT_AT = (1, 5, 10)
DEFAULT_CLONE_TIMEOUT = 900
DEFAULT_GIT_TIMEOUT = 600

# Ablation knob (eval-design doc Section 8 "Description expansion"): WordNet
# synonym expansion on the SOURCE-code corpora (paper 3.2). Default ON, matching
# the paper; the ablation harness sets VFDET_EXPAND=0 to measure the lexical-gap
# contribution. Report corpus (process_cve) is always lemmatize-only (paper 3.3).
EXPAND_SYNONYMS = os.environ.get("VFDET_EXPAND", "1") != "0"

FIELDNAMES = [
    "cve_id", "repo", "commit_sha", "vf_file", "truth_functions",
    "rank_of_truth", "hit_at_1", "hit_at_5", "hit_at_10",
    "top10", "clone_secs", "detect_secs", "error",
]


def slugify(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")[:120]


def module_path(rel_path: str) -> str:
    """Convert a repo-relative Python path to the benchmark module prefix."""
    path = rel_path.replace("\\", "/").strip("/")
    if path.endswith(".py"):
        path = path[:-3]
    return path.replace("/", ".")


def load_native_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def is_valid_native_record(rec: dict) -> bool:
    return (
        rec.get("vf_file", "").endswith(".py")
        and bool(rec.get("description"))
        and bool(rec.get("all_functions"))
        and bool(rec.get("repo_url"))
        and bool(rec.get("commit_sha"))
    )


def run_git(args: list[str], cwd: Path | None = None,
            timeout: int = DEFAULT_GIT_TIMEOUT) -> tuple[int, str]:
    cmd = ["git"]
    if cwd is not None:
        cmd.extend(["-c", f"safe.directory={Path(cwd).resolve()}"])
    cmd.extend(args)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # Treat a hung git as a recoverable per-CVE failure (exit code 124,
        # the conventional `timeout` code) instead of letting it crash the run.
        return 124, f"git_timeout after {timeout}s: git {' '.join(args[:2])}"
    except OSError as e:
        return 127, f"git_exec_failed: {e}"
    out = (proc.stdout or b"").decode("utf-8", errors="replace")
    err = (proc.stderr or b"").decode("utf-8", errors="replace")
    return proc.returncode, (out + err).strip()


def ensure_repo_cloned(repo_url: str, commit_sha: str, dest: Path,
                       clone_timeout: int = DEFAULT_CLONE_TIMEOUT) -> str | None:
    """Clone the repo (NO working tree) and make `commit_sha` available locally.

    Returns None on success or an error string. We deliberately do NOT check out a
    working tree: some repos contain paths Windows/NTFS cannot create (reserved
    names like `aux/`, or filenames with `:`), which made `git checkout` fail for
    those CVEs. Source is read straight from the git object store
    (`read_py_sources`), so it works on every OS. The clone is full (no
    `--filter=blob:none`) so blobs are local and reading is offline + fast."""
    if not (dest / ".git").exists():
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        rc, out = run_git(["clone", "--no-checkout", repo_url, str(dest)],
                          timeout=clone_timeout)
        if rc != 0:
            return f"clone_failed: {out[:300]}"

    rc, _ = run_git(["cat-file", "-e", f"{commit_sha}^{{commit}}"], cwd=dest)
    if rc != 0:
        rc, out = run_git(["fetch", "origin", commit_sha], cwd=dest, timeout=clone_timeout)
        if rc != 0:
            return f"fetch_failed: {out[:300]}"
    return None


def resolve_vuln_ref(dest: Path, commit_sha: str) -> tuple[str, str]:
    """Vulnerable state = PARENT of the fix commit; fall back to the fix itself
    if it is a root commit. Returns (ref, note) — note is the benign
    'checkout_used_*' marker (kept for summary back-compat) or ''."""
    rc, _ = run_git(["rev-parse", "--verify", "-q", f"{commit_sha}~1"], cwd=dest)
    if rc == 0:
        return f"{commit_sha}~1", ""
    return commit_sha, "checkout_used_fix_commit_no_parent"


def choose_vuln_ref(sample: dict, dest: Path) -> tuple[str, str]:
    """Prefer benchmark vulnerable_ref; fall back to parent-of-fix inputs."""
    ref = (sample.get("vulnerable_ref") or "").strip()
    if ref:
        return ref, ""
    return resolve_vuln_ref(dest, sample["commit_sha"])


def read_py_sources(dest: Path, ref: str) -> dict[str, str] | None:
    """Read every .py blob at `ref` into {path: source} — straight from git, no
    working tree. Returns None if the tree can't be listed."""
    rc, out = run_git(["ls-tree", "-r", "--name-only", ref], cwd=dest)
    if rc != 0:
        return None
    paths = [p.strip() for p in out.splitlines() if p.strip().endswith(".py")]
    if not paths:
        return {}
    # One `git cat-file --batch` process reads all blobs; parse by byte offsets.
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
        pos += size + 1                                # skip blob bytes + newline
    return sources


# WordNet synonym expansion on the source corpus (paper 3.2) is vfdetector's
# lexical-gap lever and the §8 "description expansion" ablation axis: the harness
# sets VFDET_EXPAND=0 to turn it off. Default on.
EXPAND_SYNONYMS = os.environ.get("VFDET_EXPAND", "1") != "0"


def detect(
    sources: dict[str, str],
    cve_description: str,
    top_k: int,
) -> list[tuple[str, str, float]]:
    entries: list[tuple[str, str, list[str]]] = []
    for fp, source in sources.items():
        if not source:
            continue
        try:
            functions = FunctionExtractor(source).extract()
        except SyntaxError:
            continue
        for fname, fsrc in functions.items():
            # Source-code corpora get WordNet synonym expansion (paper 3.2);
            # the report corpus (process_cve) stays lemmatize-only (paper 3.3).
            tokens = clean_text(fsrc, expand_synonyms=EXPAND_SYNONYMS)
            entries.append((fp, fname, tokens))

    if not entries:
        return []

    cve_corpus = process_cve(cve_description)
    function_corpora = [tokens for _, _, tokens in entries]
    ranked = rank_functions(cve_corpus, function_corpora, top_k=top_k)
    return [
        (f"{entries[idx][0]}::{entries[idx][1]}", entries[idx][0], round(score, 6))
        for idx, score in ranked
    ]


def _candidate_aliases(func_id: str) -> set[str]:
    """Equivalent ids for native CSV hit checks.

    The normalized evaluation layer uses benchmark qualified_names, but the
    native CSV stores compact `file.py::Class.method` ids. Keep aliases here so
    the native summary is still informative without changing the detector score.
    """
    if "::" not in func_id:
        return {func_id, func_id.split(".")[-1]}

    file_path, qualified = func_id.split("::", 1)
    bare = qualified.split(".")[-1]
    full_qualified = f"{module_path(file_path)}.{qualified}"
    return {func_id, qualified, full_qualified, bare}


def _truth_aliases(truth_names: set[str]) -> set[str]:
    aliases: set[str] = set()
    for truth in truth_names:
        aliases.add(truth)
        qualified = truth.split("::", 1)[-1]
        aliases.add(qualified)
        aliases.add(qualified.split(".")[-1])
    return aliases


def find_rank(top_results: list[tuple[str, str, float]], truth_names: set[str]) -> int:
    truth_aliases = _truth_aliases(truth_names)
    for i, (func_id, _, _) in enumerate(top_results, start=1):
        if _candidate_aliases(func_id) & truth_aliases:
            return i
    return 0


def load_existing(results_csv: Path) -> dict[str, dict]:
    """Return {cve_id: row} for rows already successfully evaluated."""
    if not results_csv.exists():
        return {}
    out: dict[str, dict] = {}
    with results_csv.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            err = row.get("error", "")
            if err and not err.startswith("checkout_used"):
                continue
            out[row["cve_id"]] = row
    return out


def init_row(sample: dict, clone_secs: float = 0.0, error: str = "") -> dict:
    """Build the base result row for one CVE, with metric fields zeroed.

    Shared by the all-in-one harness and the staged step scripts so every
    results.csv row has the same shape (FIELDNAMES)."""
    truth_names = set(sample.get("all_functions") or [])
    return {
        "cve_id": sample["cve_id"],
        "repo": sample["repo_url"].replace("https://github.com/", ""),
        "commit_sha": sample["commit_sha"],
        "vf_file": sample["vf_file"],
        "truth_functions": "|".join(sorted(truth_names)),
        "clone_secs": round(clone_secs, 1),
        "error": error or "",
        "rank_of_truth": 0,
        "hit_at_1": 0,
        "hit_at_5": 0,
        "hit_at_10": 0,
        "top10": "",
        "detect_secs": 0.0,
    }


def compute_summary(rows: list[dict]) -> dict:
    """Aggregate per-CVE rows into Hit@K / MRR. Rows whose `error` is a real
    failure (not the `checkout_used...` note) are excluded from the denominator."""
    evaluated = [r for r in rows if not (r["error"] and not r["error"].startswith("checkout_used"))]
    n = len(evaluated)
    if n == 0:
        return {"total_samples": len(rows), "evaluated": 0, "errors": len(rows)}
    hits = {k: sum(int(r[f"hit_at_{k}"]) for r in evaluated) for k in DEFAULT_HIT_AT}
    mrr_sum = sum(1.0 / int(r["rank_of_truth"]) for r in evaluated if int(r["rank_of_truth"]) > 0)
    return {
        "total_samples": len(rows),
        "evaluated": n,
        "errors": len(rows) - n,
        "hit_at_1_pct": round(100 * hits[1] / n, 1),
        "hit_at_5_pct": round(100 * hits[5] / n, 1),
        "hit_at_10_pct": round(100 * hits[10] / n, 1),
        "mrr": round(mrr_sum / n, 4),
    }


def open_results_writer(results_csv: Path, resume: bool):
    """Open results.csv for incremental, crash-safe appending (a checkpoint).

    Returns (file_handle, DictWriter). Callers should write + flush each CVE's
    row the moment it completes (see `checkpoint_row`) so an interrupted run
    always leaves a valid CSV that --resume can continue from.

    On --resume with an existing file we append, keeping prior rows and their
    header; otherwise we truncate and write a fresh header."""
    is_append = resume and results_csv.exists()
    fh = results_csv.open("a" if is_append else "w", newline="", encoding="utf-8")
    writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
    if not is_append:
        writer.writeheader()
        fh.flush()
    return fh, writer


def checkpoint_row(fh, writer, row: dict) -> None:
    """Append one result row and force it to disk immediately."""
    writer.writerow(row)
    fh.flush()
    os.fsync(fh.fileno())


def is_real_failure(error: str) -> bool:
    """True if `error` is an actual failure worth retrying (not the benign
    `checkout_used...` note and not empty)."""
    return bool(error) and not error.startswith("checkout_used")


def log_failure(fail_fh, sample: dict, error: str, stage: str) -> None:
    """Append a failed CVE to the failures log, then force it to disk.

    The line is the ORIGINAL sample dict (so the file is itself a valid
    --samples input you can re-run) plus `_error`/`_stage` annotations."""
    record = dict(sample)
    record["_error"] = error
    record["_stage"] = stage
    fail_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    fail_fh.flush()
    os.fsync(fail_fh.fileno())


def write_summary(rows: list[dict], summary_path: Path) -> dict:
    summary = compute_summary(rows)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n========= SUMMARY =========")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print(f"Wrote: {summary_path}")
    return summary


def evaluate_cve(sample: dict, workspaces: Path, top_k: int) -> tuple[dict, str]:
    """Clone + rank one CVE. NEVER raises — any failure becomes a recorded error.

    Returns (row, stage) where stage is "" on success, or the stage that failed
    ("clone" / "detect" / "unexpected") so the caller can log it for a later retry."""
    repo_url = sample["repo_url"]
    commit_sha = sample["commit_sha"]
    truth_names = set(sample.get("all_functions") or [])
    slug = slugify(repo_url.replace("https://github.com/", ""))
    dest = workspaces / slug

    try:
        t0 = time.time()
        fetch_ref = (sample.get("vulnerable_ref") or "").strip() or commit_sha
        err = ensure_repo_cloned(repo_url, fetch_ref, dest)
        clone_secs = time.time() - t0
        if err:
            return init_row(sample, clone_secs, err), "clone"

        ref, note = choose_vuln_ref(sample, dest)
        row = init_row(sample, clone_secs, note)   # note: benign checkout_used_* or ""

        sources = read_py_sources(dest, ref)
        if sources is None:
            row["error"] = "ls_tree_failed"
            return row, "clone"

        t1 = time.time()
        try:
            top = detect(sources, sample["description"], top_k)
        except Exception as e:  # noqa: BLE001 - record any detector failure, keep going
            row["error"] = f"detect_failed: {type(e).__name__}: {e}"
            return row, "detect"
        row["detect_secs"] = round(time.time() - t1, 1)

        rank = find_rank(top, truth_names)
        row["rank_of_truth"] = rank
        for k in DEFAULT_HIT_AT:
            row[f"hit_at_{k}"] = int(0 < rank <= k)
        row["top10"] = "|".join(f"{n}:{sc:.3f}" for n, _, sc in top[:DEFAULT_TOP_K])
        return row, ""
    except Exception as e:  # noqa: BLE001 - absolute backstop: nothing aborts the run
        row = init_row(sample, error=f"unexpected: {type(e).__name__}: {e}")
        return row, "unexpected"


def main() -> None:
    ap = argparse.ArgumentParser()
    src_group = ap.add_mutually_exclusive_group()
    src_group.add_argument("--src", type=Path, default=None,
                           help="Raw native CVE JSONL; filters to valid Python rows.")
    src_group.add_argument(
        "--samples",
        type=Path,
        default=None,
        help=(
            f"Pre-curated CVE JSONL "
            f"(default: {DEFAULT_SAMPLES.name} if --src not given)."
        ),
    )
    ap.add_argument("--n", type=int, default=20,
                    help="With --src: number of samples to pick (default: 20).")
    ap.add_argument("--results", type=Path, default=DEFAULT_RESULTS,
                    help=f"Output CSV path (default: {DEFAULT_RESULTS.name}).")
    ap.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY,
                    help=f"Output JSON summary path (default: {DEFAULT_SUMMARY.name}).")
    ap.add_argument("--failures", type=Path, default=DEFAULT_FAILURES,
                    help=f"JSONL log of failed CVEs, re-runnable via --samples "
                         f"(default: {DEFAULT_FAILURES.name}).")
    ap.add_argument("--workspaces", type=Path, default=DEFAULT_WORKSPACES,
                    help=f"Directory for cached repo clones (default: {DEFAULT_WORKSPACES.name}/).")
    ap.add_argument("--limit", type=int, default=None,
                    help="With --samples: process only first N rows (default: all).")
    ap.add_argument("--top-k", type=int, default=DEFAULT_TOP_K,
                    help=f"Number of ranked functions to consider (default: {DEFAULT_TOP_K}).")
    ap.add_argument("--resume", action="store_true",
                    help="Skip CVEs already successfully evaluated in --results.")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite --results if it already exists without --resume.")
    args = ap.parse_args()

    load_runtime_dependencies()

    if args.src is not None:
        rows = load_native_jsonl(args.src)
        samples = [row for row in rows if is_valid_native_record(row)][: args.n]
        print(f"\nSelected {len(samples)} valid Python samples from {args.src.name} "
              f"(n={args.n})")
    else:
        samples_path = args.samples or DEFAULT_SAMPLES
        samples = load_native_jsonl(samples_path)
        if args.limit:
            samples = samples[:args.limit]

    args.workspaces.mkdir(parents=True, exist_ok=True)
    for output_path in (args.results, args.summary, args.failures):
        output_path.parent.mkdir(parents=True, exist_ok=True)
    if args.results.exists() and not args.resume and not args.force:
        raise SystemExit(
            f"Refusing to overwrite existing results CSV without --resume or --force: "
            f"{args.results}"
        )

    print(f"Synonym expansion (VFDET_EXPAND): {'ON' if EXPAND_SYNONYMS else 'OFF'}")
    existing = load_existing(args.results) if args.resume else {}
    if existing:
        print(f"Resume: {len(existing)} CVEs already evaluated, will skip those.")

    # Incremental checkpoint: every completed CVE is flushed to results.csv right
    # away, so an interrupted run leaves a valid file that --resume can continue.
    # Failures never abort the run — they are logged to --failures for a later retry.
    fh, writer = open_results_writer(args.results, args.resume)
    fail_fh = args.failures.open("w", encoding="utf-8")
    rows: list[dict] = list(existing.values())  # carried over for the final summary
    failed = 0
    progress = tqdm(samples, desc="vfdetector", unit="cve") if tqdm else samples
    # tqdm.write keeps log lines from shredding the bar; plain print without it.
    say = tqdm.write if tqdm else print
    try:
        for idx, s in enumerate(progress, 1):
            cve_id = s["cve_id"]
            if tqdm:
                progress.set_postfix_str(cve_id)   # show which CVE is in flight
            if cve_id in existing:
                say(f"[{idx}/{len(samples)}] {cve_id}  (cached, skipping)")
                continue

            say(f"[{idx}/{len(samples)}] {cve_id}  {s['repo_url']}  @ {s['commit_sha'][:10]}")
            row, stage = evaluate_cve(s, args.workspaces, args.top_k)
            rows.append(row)
            checkpoint_row(fh, writer, row)

            if is_real_failure(row["error"]):
                failed += 1
                log_failure(fail_fh, s, row["error"], stage)
                say(f"  FAIL [{stage}]: {row['error']}  (logged -> {args.failures.name})")
            else:
                say(f"  clone={row['clone_secs']}s  detect={row['detect_secs']}s  "
                    f"rank={row['rank_of_truth'] or 'MISS'}")
    except KeyboardInterrupt:
        print(f"\nInterrupted. Checkpoint saved to {args.results} "
              f"({len(rows)} rows). Re-run with --resume to continue.")
    finally:
        if tqdm:
            progress.close()
        fh.close()
        fail_fh.close()

    print(f"\nWrote: {args.results}  ({len(rows)} rows, {failed} failed).")
    if failed:
        print(f"Failures logged to {args.failures} -- re-run them with:\n"
              f"  python {Path(__file__).name} --samples {args.failures}")
    write_summary(rows, args.summary)


if __name__ == "__main__":
    main()
