import csv
import json
from pathlib import Path


REQUIRED = {"cve_id", "description", "repo_url"}


def _normalize(raw: dict) -> dict:
    """Normalize a raw record from any of the supported schemas into the canonical one."""
    # The new dataset uses commit_sha + all_functions. The old/simple schema
    # uses patch_commit + fixed_funcs (comma-separated string).
    cve_id = (raw.get("cve_id") or "").strip()
    description = (raw.get("description") or "").strip()
    repo_url = (raw.get("repo_url") or "").strip()
    patch_commit = (raw.get("patch_commit") or raw.get("commit_sha") or "").strip() or None

    fixed_funcs: list[str]
    if "all_functions" in raw and isinstance(raw["all_functions"], list):
        fixed_funcs = [str(x).strip() for x in raw["all_functions"] if str(x).strip()]
    elif isinstance(raw.get("fixed_funcs"), list):
        fixed_funcs = [str(x).strip() for x in raw["fixed_funcs"] if str(x).strip()]
    else:
        fixed_funcs = [s.strip() for s in (raw.get("fixed_funcs") or "").split(",") if s.strip()]

    vf_file = (raw.get("vf_file") or "").strip() or None

    return {
        "cve_id": cve_id,
        "description": description,
        "repo_url": repo_url,
        "patch_commit": patch_commit,
        "fixed_funcs": fixed_funcs,
        "vf_file": vf_file,
    }


def _read_rows(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        rows: list[dict] = []
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else [data]
    # CSV / TSV
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load(path: str | Path) -> list[dict]:
    """Load CVE dataset from CSV / JSON / JSONL.

    Supports two schemas (auto-detected per field):
      - canonical: cve_id, description, repo_url, patch_commit, fixed_funcs
      - new       : cve_id, description, repo_url, commit_sha, all_functions, vf_file

    Rows sharing the same cve_id are merged (their fixed_funcs are union-ed).
    """
    path = Path(path)
    raw_rows = _read_rows(path)

    merged: dict[str, dict] = {}
    for raw in raw_rows:
        rec = _normalize(raw)
        missing = REQUIRED - {k for k, v in rec.items() if v}
        if missing:
            raise ValueError(f"Row missing required field(s) {missing}: {raw}")

        cid = rec["cve_id"]
        if cid not in merged:
            merged[cid] = {**rec, "fixed_funcs": list(rec["fixed_funcs"])}
        else:
            seen = set(merged[cid]["fixed_funcs"])
            for fn in rec["fixed_funcs"]:
                if fn not in seen:
                    merged[cid]["fixed_funcs"].append(fn)
                    seen.add(fn)
            # keep the first non-null commit/vf_file we saw
            merged[cid]["patch_commit"] = merged[cid]["patch_commit"] or rec["patch_commit"]
            merged[cid]["vf_file"] = merged[cid]["vf_file"] or rec["vf_file"]

    return list(merged.values())
