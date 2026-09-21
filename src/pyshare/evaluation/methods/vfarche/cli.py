import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vfarche")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="Run pipeline on a CVE dataset")
    r.add_argument("--dataset", required=True, help="Path to CSV/JSON/JSONL CVE dataset")
    r.add_argument("--cve", help="Process only this CVE id (default: all)")
    r.add_argument("--no-cache", action="store_true", help="Re-parse repo, ignore cached funcs")
    r.add_argument("--resume", action="store_true", help="Skip CVEs that already have saved top-k results in the current MongoDB database")
    r.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Log a failed CVE and continue with the remaining dataset records",
    )
    r.add_argument(
        "--failure-log",
        help="JSONL path for per-CVE failures (used with --continue-on-error)",
    )
    r.add_argument("--skip-llm", action="store_true", help="Stop after BM25 (no LLM cost)")
    r.add_argument(
        "--rerank",
        choices=["chat", "embedding", "pairwise"],
        default="chat",
        help="Rerank method: chat score, embedding cosine, or pairwise Swiss tournament. Default: chat.",
    )
    r.add_argument(
        "--candidate-selection",
        choices=["auto", "tracker", "codebert", "bm25"],
        default=os.environ.get("VFARCHE_SELECTION", "auto"),
        help="Candidate selector before ranking. auto uses Tracker for PATCH-PRESENT and CodeBERT for PATCH-ABSENT.",
    )
    r.add_argument(
        "--codebert-checkpoint",
        default=os.environ.get("VFARCHE_CODEBERT_CHECKPOINT"),
        help="Local fine-tuned CodeBERT checkpoint for PATCH-ABSENT selection.",
    )
    r.add_argument("--tracker-top-k", type=int, default=None, help="Candidate-selection top-k before ranking")
    r.add_argument("--expand-description", action="store_true", help="Expand CVE text with CWE/PRF context before ranking")
    r.add_argument("--limit", type=int, help="Process at most this many CVEs")
    r.add_argument(
        "--provider",
        choices=["openai", "openrouter"],
        help="Override LLM_PROVIDER from .env",
    )
    r.add_argument(
        "--model",
        help="Override chat model (e.g. gpt-4o, meta-llama/llama-3.3-70b-instruct:free)",
    )
    r.add_argument(
        "--embedding-model",
        help="Override embedding model (e.g. nvidia/llama-nemotron-embed-vl-1b-v2:free)",
    )

    d = sub.add_parser("dataset-info", help="Summarize benchmark/dataset coverage")
    d.add_argument("--dataset", required=True, help="Path to CSV/JSON/JSONL CVE dataset")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # MUST set env BEFORE importing config (which is read at import time).
    if getattr(args, "provider", None):
        os.environ["LLM_PROVIDER"] = args.provider
    if getattr(args, "model", None):
        os.environ["LLM_MODEL_OVERRIDE"] = args.model
    if getattr(args, "embedding_model", None):
        os.environ["EMBEDDING_MODEL_OVERRIDE"] = args.embedding_model

    # Now safe to import modules that read config/env.
    from pyshare.evaluation.methods.vfarche.data.load_cve import load

    def warn_mongo_unavailable(action: str, exc: Exception) -> None:
        print(f"  warning: could not {action}: {exc}", file=sys.stderr)
        print("  hint: start MongoDB with `docker compose up -d mongo` to enable persistence.", file=sys.stderr)

    def run_one(
        cve: dict,
        *,
        use_cache: bool,
        skip_llm: bool,
        rerank: str,
        expand: bool,
        resume: bool,
        candidate_selection: str,
        codebert_checkpoint: str | None,
        tracker_top_k: int | None,
    ) -> None:
        from pyshare.evaluation.methods.vfarche.config import (
            BM25_TOP_K,
            LLM_BASE_URL,
            EMBEDDING_BASE_URL,
            EMBEDDING_MODEL,
            LLM_MODEL,
            LLM_PROVIDER,
            LLM_TOP_K,
        )
        from pyshare.evaluation.methods.vfarche.parser.python_parser import parse_repo
        from pyshare.evaluation.methods.vfarche.parser.repo_cloner import clone_or_update
        from pyshare.evaluation.methods.vfarche.ranking.bm25_rank import rank_bm25
        from pyshare.evaluation.methods.vfarche.retrieval import select_candidates
        from pymongo.errors import PyMongoError
        from pyshare.evaluation.methods.vfarche.storage.mongo import (
            cache_functions,
            delete_topk,
            load_cached_functions,
            load_topk,
            save_topk,
        )

        cid = cve["cve_id"]
        from pyshare.evaluation.methods.vfarche.llm import usage
        usage.reset()
        started = time.perf_counter()
        print(f"\n=== {cid} | {cve['repo_url']} ===")

        selector_k = tracker_top_k or BM25_TOP_K
        checkpoint_path = (
            str(Path(codebert_checkpoint).resolve()) if codebert_checkpoint else None
        )
        run_signature = {
            "schema_version": 2,
            "repo_url": cve['repo_url'],
            "vulnerable_ref": cve.get('vulnerable_ref'),
            "fix_commit": cve.get('fix_commit'),
            "description": cve['description'],
            "cwes": cve.get('cwes', []),
            "base_url": EMBEDDING_BASE_URL if rerank == 'embedding' else LLM_BASE_URL,
            "candidate_selection": candidate_selection,
            "codebert_checkpoint": checkpoint_path,
            "tracker_top_k": selector_k,
            "description_expansion": expand,
            "rerank": None if skip_llm else rerank,
            "provider": None if skip_llm else LLM_PROVIDER,
            "model": (
                None
                if skip_llm
                else EMBEDDING_MODEL
                if rerank == "embedding"
                else LLM_MODEL
            ),
        }

        if resume:
            try:
                saved = load_topk(cid)
            except PyMongoError as exc:
                warn_mongo_unavailable("check resume checkpoint in MongoDB", exc)
                saved = None
            if (
                saved
                and "topk" in saved
                and saved.get("run_signature") == run_signature
            ):
                print(f"  checkpoint found: skip existing top-{len(saved['topk'])}")
                return
            if saved and saved.get("topk"):
                print("  checkpoint uses a different configuration: recomputing")
                try:
                    delete_topk(cid)
                except PyMongoError as exc:
                    warn_mongo_unavailable("invalidate stale top-k checkpoint", exc)
                    raise
        else:
            # A forced recomputation must not export a stale result if the new
            # attempt fails before save_topk completes.
            try:
                delete_topk(cid)
            except PyMongoError as exc:
                warn_mongo_unavailable("clear old top-k before recomputing", exc)
                raise

        repo_path = clone_or_update(cve["repo_url"], cve.get("vulnerable_ref") or cve.get("patch_commit"))
        print(f"  cloned/checked out at: {repo_path}")

        funcs = None
        if use_cache:
            try:
                funcs = load_cached_functions(cid)
            except PyMongoError as exc:
                warn_mongo_unavailable("load cached functions from MongoDB", exc)
        if funcs is None:
            funcs = parse_repo(repo_path)
            if use_cache:
                try:
                    cache_functions(cid, funcs)
                except PyMongoError as exc:
                    warn_mongo_unavailable("cache parsed functions in MongoDB", exc)
        print(f"  total functions parsed: {len(funcs)}")

        description = cve["description"]
        if expand:
            from pyshare.evaluation.methods.vfarche.retrieval import expand_description
            description = expand_description(
                cve,
                corpus_texts=[
                    f"{f.get('qualname', '')} {f.get('docstring', '')} {f.get('body', '')}"
                    for f in funcs
                ],
            )
            print("  description expansion: on")

        selected, selector_label = select_candidates(
            cve=cve,
            repo_path=repo_path,
            funcs=funcs,
            description=description,
            mode=candidate_selection,
            top_k=selector_k,
            codebert_checkpoint=codebert_checkpoint,
        )
        print(f"  candidate selection={selector_label} top-{len(selected)}")

        if selector_label == "bm25-fallback":
            bm25_top = selected[:BM25_TOP_K]
        else:
            bm25_top = rank_bm25(description, selected, top_k=min(BM25_TOP_K, len(selected)))
        print(f"  BM25 over candidates top-{len(bm25_top)} computed")

        if skip_llm:
            final = bm25_top[:LLM_TOP_K]
        elif rerank == "embedding":
            from pyshare.evaluation.methods.vfarche.llm.embedding import describe
            from pyshare.evaluation.methods.vfarche.ranking.embedding_rank import rerank_with_embedding
            print(f"  rerank=embedding | {describe()}")
            final = rerank_with_embedding(description, bm25_top, top_k=LLM_TOP_K)
        elif rerank == "pairwise":
            from pyshare.evaluation.methods.vfarche.llm.client import describe
            from pyshare.evaluation.methods.vfarche.ranking.llm_compare import rerank_with_pairwise
            print(f"  rerank=pairwise | {describe()}")
            final = rerank_with_pairwise(description, bm25_top, top_k=LLM_TOP_K)
        else:  # chat
            from pyshare.evaluation.methods.vfarche.llm.client import describe
            from pyshare.evaluation.methods.vfarche.ranking.llm_compare import rerank_with_llm
            print(f"  rerank=chat | {describe()}")
            final = rerank_with_llm(description, bm25_top, top_k=LLM_TOP_K)

        print(f"  rerank top-{len(final)} computed")
        telemetry = {**usage.snapshot(), 'runtime_secs': time.perf_counter() - started}
        print(f"  runtime={telemetry['runtime_secs']:.2f}s tokens={telemetry['tokens']} "
              f"api_calls={telemetry['api_calls']}")

        try:
            save_topk(
                cve_id=cid,
                repo=cve["repo_url"],
                total_funcs=len(funcs),
                topk=[
                    {
                        "rank": i + 1,
                        "name": f["name"],
                        "qualname": f["qualname"],
                        "file": f["file"],
                        "start_line": f["start_line"],
                        "bm25_score": f.get("bm25_score"),
                        "tracker_score": f.get("tracker_score"),
                        "tracker_reasons": f.get("tracker_reasons"),
                        "codebert_selector_score": f.get("codebert_selector_score"),
                        "candidate_selector": selector_label,
                        "llm_score": f.get("llm_score"),
                        "embedding_score": f.get("embedding_score"),
                        "swiss_score": f.get("swiss_score"),
                        "pairwise_score": f.get("pairwise_score"),
                    }
                    for i, f in enumerate(final)
                ],
                run_signature=run_signature,
                telemetry=telemetry,
            )
            print(f"  saved top-{len(final)} to MongoDB.")
        except PyMongoError as exc:
            warn_mongo_unavailable("save top-k results to MongoDB", exc)
            raise  # an unpersisted result is a failure, not a checkpoint

        if cve["fixed_funcs"]:
            names = {f["name"] for f in final}
            qnames = {f["qualname"] for f in final}
            hits = [n for n in cve["fixed_funcs"] if n in names or n in qnames]
            print(f"  ground-truth hits: {hits} / {cve['fixed_funcs']}")

    if args.cmd == "run":
        cves = load(args.dataset)
        if args.cve:
            cves = [c for c in cves if c["cve_id"] == args.cve]
            if not cves:
                print(f"CVE {args.cve} not found in dataset", file=sys.stderr)
                return 1
        if args.limit:
            cves = cves[: args.limit]
        failure_log = Path(args.failure_log).resolve() if args.failure_log else None
        if failure_log:
            failure_log.parent.mkdir(parents=True, exist_ok=True)
            failure_log.write_text("", encoding="utf-8")
        completed = 0
        failures = 0
        for cve in cves:
            try:
                run_one(
                    cve,
                    use_cache=not args.no_cache,
                    skip_llm=args.skip_llm,
                    rerank=args.rerank,
                    expand=args.expand_description,
                    resume=args.resume,
                    candidate_selection=args.candidate_selection,
                    codebert_checkpoint=args.codebert_checkpoint,
                    tracker_top_k=args.tracker_top_k,
                )
                completed += 1
            except Exception as exc:  # one bad repository/API response must not lose the batch
                if not args.continue_on_error:
                    raise
                failures += 1
                cid = cve.get("cve_id", "unknown")
                print(
                    f"\n  ERROR: {cid} failed: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                print("  continuing with the next CVE...", file=sys.stderr)
                if failure_log:
                    failure = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "cve_id": cid,
                        "repo_url": cve.get("repo_url"),
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                    with failure_log.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(failure, ensure_ascii=False) + "\n")
                        fh.flush()
        print(
            f"\nRun summary: completed/checkpointed={completed}, "
            f"failed/skipped={failures}, total={len(cves)}"
        )
        if failures and failure_log:
            print(f"Failure log: {failure_log}")
    elif args.cmd == "dataset-info":
        cves = load(args.dataset)
        with_patch = sum(1 for c in cves if c.get("has_patch"))
        with_truth = sum(1 for c in cves if c.get("fixed_funcs") or c.get("vf_file"))
        cwes = sorted({cwe for c in cves for cwe in (c.get("cwes") or [])})
        repos = sorted({c["repo_url"] for c in cves})
        print(f"CVEs: {len(cves)}")
        print(f"with patch: {with_patch}")
        print(f"without patch: {len(cves) - with_patch}")
        print(f"with ground truth: {with_truth}")
        print(f"unique repos: {len(repos)}")
        print(f"unique CWEs: {len(cwes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
