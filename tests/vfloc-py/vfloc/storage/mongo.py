from pymongo import MongoClient

from config import MONGO_URI, MONGO_DB, COLLECTION_NAME

_client = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI)
    return _client


def get_db():
    return get_client()[MONGO_DB]


def save_topk(cve_id: str, repo: str, total_funcs: int, topk: list[dict]) -> None:
    coll = get_db()[COLLECTION_NAME]
    coll.create_index("cve_id")
    coll.update_one(
        {"cve_id": cve_id},
        {
            "$set": {
                "repo": repo,
                "total_funcs": total_funcs,
                "topk": topk,
            }
        },
        upsert=True,
    )


def load_topk(cve_id: str) -> dict | None:
    return get_db()[COLLECTION_NAME].find_one({"cve_id": cve_id})


def cache_functions(cve_id: str, funcs: list[dict]) -> None:
    coll = get_db()["func_cache"]
    coll.create_index("cve_id")
    coll.update_one(
        {"cve_id": cve_id},
        {"$set": {"funcs": funcs}},
        upsert=True,
    )


def load_cached_functions(cve_id: str) -> list[dict] | None:
    doc = get_db()["func_cache"].find_one({"cve_id": cve_id})
    return doc["funcs"] if doc else None
