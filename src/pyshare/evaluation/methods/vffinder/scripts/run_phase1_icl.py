"""Run the Phase 1 ICL Extractor at a chosen level (direct / s-icl / p-icl).

The extractor turns each CVE description into structured Attack Vector (AV) and
Root Cause (RC) phrases. Three levels are supported, matching the paper:

    direct  - instruction + description only, no demonstrations
    s-icl   - + demonstrations chosen by semantic embedding cosine
    p-icl   - + demonstrations chosen by constituency-pattern autoencoder cosine

CVE descriptions are loaded from a JSON dataset file (no longer hardcoded), so
the dataset can be extended without touching this script. Each entry carries a
`role`: 'eval' or 'casepool'. In the full leave-one-out setup every CVE is eval
and `rebuild_case_pool.py --include-all` lets the retriever use all other CVEs
as demonstrations.

Resume on crash: results for a level are written to ONE JSON file keyed by CVE
id (direct_phase1.json, sicl_phase1.json, picl_phase1.json in the configured
output directory), rewritten
atomically after each CVE. By default a CVE already present in that file is
skipped. So if a run is interrupted (quota, network, crash), just run the SAME
command again — it continues where it left off without re-calling the LLM for
finished CVEs. Pass --force to redo all.

Usage:
    python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level direct --eval-only
    python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level s-icl --cve CVE-2020-28493
    python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level p-icl --all
    python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level p-icl --all --force
"""
import argparse, json, sys, traceback
from datetime import datetime, timezone
from pathlib import Path

from tqdm import tqdm

from pyshare.evaluation.methods.vffinder import config
from pyshare.evaluation.methods.vffinder.extraction.icl_extractor import extract_cve, load_nlp
from pyshare.evaluation.methods.vffinder.extraction.case_pool import (
    load_case_pool, SICLRetriever, PICLRetriever)
from pyshare.evaluation.methods.vffinder.extraction import phase1_store

# Dataset of CVE descriptions. Lives in the data directory so it can be edited
# or swapped without changing code (see config.DATA_DIR).
CVE_DATASET_PATH = config.DATA_DIR / "cve_descriptions.json"


def load_cve_dataset(path: Path) -> tuple[dict[str, str], set[str]]:
    """Load the CVE description dataset.

    Returns:
        descriptions: {cve_id: description text}
        extra_cves:   set of cve_ids whose role is 'casepool' (not evaluated)
    """
    if not path.exists():
        print(f"CVE dataset not found: {path}\n"
              f"Copy sample_data/cve_descriptions.json into {config.DATA_DIR}",
              file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    descriptions: dict[str, str] = {}
    extra_cves: set[str] = set()
    for cve_id, entry in raw.items():
        if cve_id.startswith("_"):  # skip "_comment" keys
            continue
        descriptions[cve_id] = entry["description"]
        if entry.get("role") == "casepool":
            extra_cves.add(cve_id)
    return descriptions, extra_cves


def _log_error(log_path: Path, cve_id: str, level: str, exc: Exception) -> None:
    """Append a full traceback for one failed CVE to the error log.

    Failures are appended (never overwritten) so a record survives across
    interrupted/resumed runs. The CVE has no output JSON, so the default
    resume path will retry it automatically on the next run.
    """
    ts = datetime.now(timezone.utc).isoformat()
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"\n===== {ts} | {level} | {cve_id} =====\n")
        f.write(f"{exc.__class__.__name__}: {exc}\n")
        f.write(traceback.format_exc())


def run(cve_id: str, description: str, level: str, retriever, nlp):
    """Extract one CVE and persist the result into the level's single JSON file."""
    print(f"\n[{level.upper()}] {cve_id} ...")
    entity = extract_cve(cve_id, description, nlp, level=level,
                         retriever=retriever)
    record = {
        "cve_id": entity.cve_id,
        "description": entity.description,
        "level": level,
        "attack_vector": entity.attack_vector,
        "root_cause": entity.root_cause,
        "class_names": entity.class_names,
        "key_entities": entity.key_entities,
        "llm_model": config.validate_llm_model(),
        "llm_temperature": config.TEMPERATURE,
    }
    # Atomic write of the whole level file (temp + os.replace), so a crash
    # mid-write never leaves a partial JSON that resume would misread.
    out_path = phase1_store.save_record(level, record)
    print(f"  AV: {entity.attack_vector}")
    print(f"  RC: {entity.root_cause}")
    print(f"  Saved -> {out_path}")
    return record


def _retriever_fire_counters(level: str, retriever) -> dict:
    base = {
        "component": "phase1_extraction",
        "level": level,
        "llm_model": config.validate_llm_model(),
        "llm_temperature": config.TEMPERATURE,
    }
    if retriever is None:
        return base
    if hasattr(retriever, "fire_counters"):
        base.update(retriever.fire_counters())
    else:
        base["case_pool_size"] = len(getattr(retriever, "pool", []) or [])
        base["retriever"] = type(retriever).__name__
    return base


def _write_component_counters(level: str, retriever, counters: dict) -> None:
    path = config.OUTPUT_DIR / f"{level.replace('-', '_')}_phase1_counters.json"
    payload = _retriever_fire_counters(level, retriever)
    payload.update(counters)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"Component counters -> {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", choices=["direct", "s-icl", "p-icl"], required=True)
    parser.add_argument("--cve", help="Single CVE ID to run")
    parser.add_argument("--all", action="store_true", help="Run all CVEs (incl. extras)")
    parser.add_argument("--eval-only", action="store_true",
                        help="Run only the 8 evaluation CVEs")
    parser.add_argument("--extras-only", action="store_true",
                        help="Run only the extra case-pool CVEs")
    parser.add_argument("--case-pool",
                        default=str(config.OUTPUT_DIR / "case_pool.json"))
    # Resume is the DEFAULT: a CVE whose output JSON already exists is skipped,
    # so a quota- or crash-interrupted run continues cheaply without re-calling
    # the LLM for finished CVEs. Use --force to re-run everything.
    parser.add_argument("--force", action="store_true",
                        help="Re-run every CVE even if its output JSON already "
                             "exists (disables the default resume behaviour).")
    parser.add_argument("--skip-existing", action="store_true",
                        help=argparse.SUPPRESS)  # deprecated: now the default
    args = parser.parse_args()

    if not args.cve and not args.all and not args.eval_only and not args.extras_only:
        print("Specify --cve ID, --all, --eval-only, or --extras-only")
        sys.exit(1)

    model = config.validate_llm_model()
    print(f"LLM model: {model} | temperature={config.TEMPERATURE}")

    # Load the CVE dataset and split it into evaluation vs case-pool CVEs.
    cve_descriptions, extra_cves = load_cve_dataset(CVE_DATASET_PATH)
    eval_cves = set(cve_descriptions.keys()) - extra_cves

    print("Loading spaCy ...")
    nlp = load_nlp()

    # Pick the demonstration retriever for this level.
    # 'direct' uses no retriever; s-icl selects demos by semantic cosine and
    # p-icl by grammatical-pattern cosine over the labeled case pool.
    if args.level == "direct":
        retriever = None
    else:
        print(f"Loading case pool from {args.case_pool} ...")
        pool = load_case_pool(Path(args.case_pool))
        print(f"  {len(pool)} entries")
        if args.level == "s-icl":
            # S-ICL: semantic cosine over UAE sentence embeddings (paper baseline).
            from ..retrieval.retrieval import SemanticEmbedder
            print("Loading UAE embedding model for S-ICL demo selection ...")
            retriever = SICLRetriever(pool, SemanticEmbedder())
        else:
            # P-ICL: constituency-parse pattern embedding (paper §4.1.2). Builds
            # its own benepar parser + pattern autoencoder fitted on the pool.
            print("Building P-ICL pattern embedder (benepar parse over pool) ...")
            retriever = PICLRetriever(pool)

    run_counters = {
        "dataset_cves": len(cve_descriptions),
        "eval_cves": len(eval_cves),
        "casepool_cves": len(extra_cves),
        "requested_cves": 0,
        "processed": 0,
        "skipped_existing": 0,
        "failed": 0,
    }
    _write_component_counters(args.level, retriever, run_counters)

    out_path = phase1_store.phase1_path(args.level)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # CVE ids already in the level file are skipped (resume); track in-run
    # additions too so the same CVE isn't reprocessed within one invocation.
    existing = set(phase1_store.load_phase1(args.level).keys())

    # Resolve which CVEs to process from the CLI flags.
    if args.cve:
        cves = [args.cve]
    elif args.eval_only:
        cves = sorted(eval_cves)
    elif args.extras_only:
        cves = sorted(extra_cves)
    else:
        cves = list(cve_descriptions.keys())

    total = len(cves)
    run_counters["requested_cves"] = total
    done = skipped = 0
    failed: list[str] = []          # CVEs that raised; retried on next run
    error_log = phase1_store.errors_path(args.level)
    progress = tqdm(cves, desc=f"phase1 [{args.level}]", unit="cve", total=total)
    for cve_id in progress:
        desc = cve_descriptions.get(cve_id)
        if not desc:
            print(f"No description for {cve_id}, skipping.")
            continue
        if not args.force and cve_id in existing:
            skipped += 1
            run_counters["skipped_existing"] = skipped
            continue
        try:
            run(cve_id, desc, args.level, retriever, nlp)
            existing.add(cve_id)
            done += 1
            run_counters["processed"] = done
        except KeyboardInterrupt:
            # Let the user stop the whole run on purpose.
            raise
        except Exception as exc:  # noqa: BLE001 — one bad CVE must not kill the run
            failed.append(cve_id)
            run_counters["failed"] = len(failed)
            _log_error(error_log, cve_id, args.level, exc)
            print(f"  ERROR on {cve_id}: {exc.__class__.__name__}: {exc} "
                  f"-> logged, skipping (will retry on next run)")

    progress.close()
    print(f"\nDone. {done} processed, {skipped} skipped (existing), "
          f"{len(failed)} failed. Outputs in {out_path}")
    _write_component_counters(args.level, retriever, run_counters)
    if failed:
        print(f"Failed CVEs (re-run the SAME command to retry them): "
              f"{', '.join(failed)}")
        print(f"Details appended to {error_log}")


if __name__ == "__main__":
    main()
