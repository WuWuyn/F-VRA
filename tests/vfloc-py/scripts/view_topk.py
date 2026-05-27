"""Print top-k results for one or all CVEs from MongoDB."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import COLLECTION_NAME
from vfloc.storage.mongo import get_db


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cve", help="Only show this CVE id")
    p.add_argument("--limit", type=int, default=20, help="Max ranks to show per CVE")
    args = p.parse_args()

    q = {"cve_id": args.cve} if args.cve else {}
    cursor = get_db()[COLLECTION_NAME].find(q)

    found = False
    for doc in cursor:
        found = True
        print(f"\n=== {doc['cve_id']}  |  repo: {doc['repo']}  |  total funcs: {doc['total_funcs']}")
        for item in doc.get("topk", [])[: args.limit]:
            scores = []
            if item.get("embedding_score") is not None:
                scores.append(f"emb={item['embedding_score']:.3f}")
            if item.get("llm_score") is not None:
                scores.append(f"llm={item['llm_score']:.2f}")
            if item.get("bm25_score") is not None:
                scores.append(f"bm25={item['bm25_score']:.2f}")
            print(f"  #{item['rank']:>3}  {item['qualname']}  [{item['file']}:{item['start_line']}]  {' '.join(scores)}")

    if not found:
        print("No documents. Run `python -m vfloc.cli run --dataset ...` first.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
