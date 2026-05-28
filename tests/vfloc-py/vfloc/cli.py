import argparse
import os
import sys


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vfloc")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="Run pipeline on a CVE dataset")
    r.add_argument("--dataset", required=True, help="Path to CSV/JSON/JSONL CVE dataset")
    r.add_argument("--cve", help="Process only this CVE id (default: all)")
    r.add_argument("--no-cache", action="store_true", help="Re-parse repo, ignore cached funcs")
    r.add_argument("--skip-llm", action="store_true", help="Stop after BM25 (no LLM cost)")
    r.add_argument(
        "--rerank",
        choices=["chat", "embedding"],
        default="chat",
        help="LLM rerank method: 'chat' (score 0-10) or 'embedding' (cosine sim). Default: chat.",
    )
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

    # Now safe to import the rest
    from config import BM25_TOP_K, LLM_TOP_K
    from vfloc.data.load_cve import load
    from vfloc.parser.python_parser import parse_repo
    from vfloc.parser.repo_cloner import clone_or_update
    from vfloc.ranking.bm25_rank import rank_bm25
    from vfloc.storage.mongo import cache_functions, load_cached_functions, save_topk

    def run_one(cve: dict, *, use_cache: bool, skip_llm: bool, rerank: str) -> None:
        cid = cve["cve_id"]
        print(f"\n=== {cid} | {cve['repo_url']} ===")

        funcs = load_cached_functions(cid) if use_cache else None
        if funcs is None:
            repo_path = clone_or_update(cve["repo_url"], cve.get("patch_commit"))
            print(f"  cloned/checked out at: {repo_path}")
            funcs = parse_repo(repo_path)
            cache_functions(cid, funcs)
        print(f"  total functions parsed: {len(funcs)}")

        bm25_top = rank_bm25(cve["description"], funcs, top_k=BM25_TOP_K)
        print(f"  BM25 top-{len(bm25_top)} computed")

        if skip_llm:
            final = bm25_top[:LLM_TOP_K]
        elif rerank == "embedding":
            from vfloc.llm.embedding import describe
            from vfloc.ranking.embedding_rank import rerank_with_embedding
            print(f"  rerank=embedding | {describe()}")
            final = rerank_with_embedding(cve["description"], bm25_top, top_k=LLM_TOP_K)
        else:  # chat
            from vfloc.llm.client import describe
            from vfloc.ranking.llm_compare import rerank_with_llm
            print(f"  rerank=chat | {describe()}")
            final = rerank_with_llm(cve["description"], bm25_top, top_k=LLM_TOP_K)

        print(f"  rerank top-{len(final)} computed")

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
                    "llm_score": f.get("llm_score"),
                    "embedding_score": f.get("embedding_score"),
                }
                for i, f in enumerate(final)
            ],
        )
        print(f"  saved top-{len(final)} to MongoDB.")

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
        for cve in cves:
            run_one(
                cve,
                use_cache=not args.no_cache,
                skip_llm=args.skip_llm,
                rerank=args.rerank,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
