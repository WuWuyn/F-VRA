from pymongo import MongoClient
from pymongo.errors import DocumentTooLarge

from pyshare.evaluation.methods.vfarche.config import MONGO_URI, MONGO_DB, COLLECTION_NAME

_client = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI)
    return _client


def get_db():
    return get_client()[MONGO_DB]


def save_topk(
    cve_id: str,
    repo: str,
    total_funcs: int,
    topk: list[dict],
    run_signature: dict | None = None,
    telemetry: dict | None = None,
) -> None:
    coll = get_db()[COLLECTION_NAME]
    coll.create_index("cve_id")
    coll.update_one(
        {"cve_id": cve_id},
        {
            "$set": {
                "repo": repo,
                "total_funcs": total_funcs,
                "topk": topk,
                "run_signature": run_signature,
                "telemetry": telemetry or {},
            }
        },
        upsert=True,
    )


def load_topk(cve_id: str) -> dict | None:
    return get_db()[COLLECTION_NAME].find_one({"cve_id": cve_id})


def delete_topk(cve_id: str) -> None:
    """Remove one stale result before recomputing it under a new config."""
    get_db()[COLLECTION_NAME].delete_one({"cve_id": cve_id})


def load_all_topk() -> dict[str, list[dict]]:
    coll = get_db()[COLLECTION_NAME]
    rankings: dict[str, list[dict]] = {}
    for doc in coll.find({}):
        rankings[doc["cve_id"]] = doc.get("topk") or []
    return rankings


def cache_functions(cve_id: str, funcs: list[dict]) -> None:
    coll = get_db()["func_cache"]
    coll.create_index("cve_id")
    try:
        coll.update_one(
            {"cve_id": cve_id},
            {"$set": {"funcs": funcs}},
            upsert=True,
        )
    except DocumentTooLarge:
        # Large repos overflow MongoDB's 16 MB per-document limit. The function
        # cache is only a parse-time optimization, so skip it here and let the
        # next run re-parse — never let it abort the pipeline.
        # TODO(shared-candidates): replace this Mongo func_cache with the on-disk
        # function corpus (evaluation/scripts/extract_functions.py), which has no
        # size limit and is shared across methods. See harness design option D.
        print(f"  [cache] skipped (function corpus too large for Mongo): {cve_id}")


def load_cached_functions(cve_id: str) -> list[dict] | None:
    doc = get_db()["func_cache"].find_one({"cve_id": cve_id})
    return doc["funcs"] if doc else None
