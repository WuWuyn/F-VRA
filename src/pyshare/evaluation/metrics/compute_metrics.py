"""compute_metrics.py — score VF-localization predictions (doc Section 7 + 7.1 + 17).

Reads the normalized prediction files written by the auto-run harness
(`results/predictions/<method>.jsonl`, one record per (CVE, variant)) and computes
the ranking metrics the empirical study calls for, per advisory group then
aggregated per (method, variant) — and, with --master, stratified by mapping_type
(doc RQ4: do multi-VF cases hurt a method?).

Metrics (doc Section 7, multi-label rule 7.1, pseudocode appendix B):
  - Hit@k       : 1 if top-k contains >=1 ground-truth VF.
  - Recall@k    : |top-k ∩ GT| / |GT|          (matters for multi-VF groups).
  - AllVF@k     : 1 if top-k contains ALL GT VFs (strict multi-VF metric).
  - Precision@k : true positives in top-k / |top-k|  (top-k as the predicted set).
  - F1@k        : harmonic mean of Precision@k and Recall@k (doc §7 Set P/R/F1).
  - MRR         : mean reciprocal rank of the first GT VF.
  - MAP         : mean average precision over the ranking (multi-VF, doc §7).
  - nDCG@k      : rank-discounted gain, ideal-normalized (doc §7 optional).
  - Effort@1st  : mean rank of the first GT hit (manual effort to FIRST VF).
  - Effort@all  : mean rank covering EVERY GT, over groups where all were found
                  (manual effort to ALL VFs; all_found = how many such groups).
RQ5 practicality (doc §7) — runtime_s_mean / tokens_mean / cost_mean are reported
ONLY when the method adapter logged per-CVE runtime_secs / tokens / cost in its
prediction records. vfdetector logs true per-CVE detect time; vffinder is batch,
so it logs an amortized per-CVE wall-clock (deflated under --resume); LLM
token/cost is adapter-specific and not yet wired.

Read-only over the prediction files; never re-runs a method.

Matching (`match_tier`). The methods emit func_ids at different granularities, so
matching is TIERED and the weakest tier used is reported for transparency:
  - "exact"     : identical func_id.
  - "file+name" : same function name AND same file, where "same file" means the
                  paths are equal or one is a /-boundary suffix of the other
                  ("src/a/b.py" vs "a/b.py"; \\ and / are normalized). When BOTH
                  ids carry a file and the paths clearly diverge, the name match
                  is rejected — this prevents common-name false positives (e.g.
                  two classes' `save`).
  - "name-only" : function names match but the file CANNOT confirm it: an id has
                  no file (vfdetector bare names, vfarche Class.method), or the
                  files share only a basename under different directories (two
                  Django apps' models.py — collision-prone, NOT confirmation).
                  Groups whose hit rests on this tier are counted as `weak` and
                  a warning is printed. The clean fix is a shared qualified_name
                  key (doc Section 11 step 8), deferred to the shared-candidates
                  work.
Groups with an empty ground_truth are excluded from all metrics (nothing to find)
and reported separately.

Input hygiene (doc 7: ONE group per advisory). The methods checkpoint their
native output as append-only logs (e.g. vfdetector's results.csv re-appends a
row each time a previously-failed CVE is retried under --resume), so the same
(method, variant, cve_id) can occur several times in a prediction file. Loading
dedups keeping the LAST record — the newest state, the same rule the native
readers use — and prints how many stale records were dropped. Counting them as
separate groups would weight retried CVEs multiple times in every average.

Groups whose prediction list is EMPTY (the method produced no ranking at all —
in practice an infra failure such as a clone/checkout error, not a ranking miss)
STAY in the denominator as misses (the practitioner got nothing to review) and
are reported in the `n_empty` column, so infra robustness stays visible
separately from ranking quality.

Usage:
  python -m pyshare.evaluation.cli metrics --pred-dir results/evaluation/predictions
  python -m pyshare.evaluation.cli metrics --pred-dir results/evaluation/predictions --master data/...jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from pyshare.evaluation.paths import PROJECT_ROOT, RESULTS_ROOT

HERE = Path(__file__).resolve().parent
EVAL_ROOT = HERE.parent
REPO_ROOT = PROJECT_ROOT
DEFAULT_PRED_DIR = RESULTS_ROOT / "predictions"
DEFAULT_OUT = RESULTS_ROOT / "metrics" / "metrics_summary.csv"
DEFAULT_STRAT_OUT = RESULTS_ROOT / "metrics" / "metrics_by_mapping.csv"
DEFAULT_KS = (1, 5, 10)


# ─────────────────────────── matching ──────────────────────────────────────


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _parse(func_id: str) -> tuple[str | None, str]:
    """Split a func_id into (file_path_or_None, bare_function_name).

    "a/b.py::C.foo" -> ("a/b.py", "foo");  "C.foo" -> (None, "foo");
    "foo" -> (None, "foo")."""
    if "::" in func_id:
        path, rest = func_id.split("::", 1)
        return (path or None), rest.split(".")[-1]
    return None, func_id.split(".")[-1]


def _norm_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _files_compatible(fa: str | None, fb: str | None):
    """Same file -> True; clearly different -> False; unconfirmable -> None.

    True only when the paths are equal or one is a /-boundary suffix of the
    other (same file seen from a deeper root, e.g. "src/a/b.py" vs "a/b.py").
    Same BASENAME under different directories (two apps' models.py) is NOT
    confirmation — that's exactly the common-name collision this guard exists
    for — so it degrades to None and the match counts as weak "name-only"."""
    if fa is None or fb is None:
        return None
    fa, fb = _norm_path(fa), _norm_path(fb)
    if fa == fb or fa.endswith("/" + fb) or fb.endswith("/" + fa):
        return True
    if _basename(fa) == _basename(fb):
        return None
    return False


def match_tier(pred_id: str, gt_id: str) -> str | None:
    """Return the strength of the match, or None if they don't refer to the same fn."""
    if pred_id == gt_id:
        return "exact"
    pf, pn = _parse(pred_id)
    gf, gn = _parse(gt_id)
    if pn != gn:
        return None
    comp = _files_compatible(pf, gf)
    if comp is True:
        return "exact" if pred_id == gt_id else "file+name"
    if comp is None:
        return "name-only"
    return None  # both have files but they are different files -> not a match


def matches(pred_id: str, gt_id: str) -> bool:
    return match_tier(pred_id, gt_id) is not None


_TIER_RANK = {"exact": 3, "file+name": 2, "name-only": 1}


def _best_tier(pred_id: str, gt_ids: list[str]) -> str | None:
    best = None
    for g in gt_ids:
        t = match_tier(pred_id, g)
        if t and (best is None or _TIER_RANK[t] > _TIER_RANK[best]):
            best = t
    return best


# ─────────────────────────── scoring (doc 7.1 / appendix B) ────────────────


def score_group(ranked_ids: list[str], gt_ids: list[str], ks, *, exact_only=False) -> dict:
    """Score one (CVE, variant) record. Returns metrics + diagnostics.

    `n_gt == 0` marks a group with no ground truth (excluded by aggregate).
    GT ids are deduplicated so a repeated entry can't inflate the Recall/AllVF
    denominator."""
    gt = list(dict.fromkeys(g for g in gt_ids if g))
    tier_for = (lambda p, g: 'exact' if p == g else None) if exact_only else match_tier
    out: dict = {"n_gt": len(gt), "n_pred": len(ranked_ids)}

    # MRR + effort-to-first + whether that first hit rests on a weak (name-only) match.
    rr, first_rank, weak = 0.0, None, 0
    for i, pid in enumerate(ranked_ids, start=1):
        tier = ('exact' if pid in gt else None) if exact_only else _best_tier(pid, gt)
        if tier:
            rr, first_rank = 1.0 / i, i
            weak = 1 if tier == "name-only" else 0
            break
    out["rr"] = rr
    out["first_hit_rank"] = first_rank
    out["weak_hit"] = weak

    # Average precision over the ranking (each GT credited once) + the rank at
    # which ALL GT are covered = manual effort to find EVERY VF (doc §7 Manual
    # Effort "tới tất cả VFs"; None if the ranking never covers all of them).
    matched: set[str] = set()
    hits, sum_prec = 0, 0.0
    all_rank = None
    for i, pid in enumerate(ranked_ids, start=1):
        for g in gt:
            if g not in matched and tier_for(pid, g):
                matched.add(g)
                hits += 1
                sum_prec += hits / i
                break
        if gt and all_rank is None and len(matched) == len(gt):
            all_rank = i
    out["ap"] = (sum_prec / len(gt)) if gt else 0.0
    out["all_hit_rank"] = all_rank

    for k in ks:
        topk = ranked_ids[:k]
        covered = sum(1 for g in gt if any(tier_for(p, g) for p in topk))
        # set true positives: distinct predicted items in top-k that hit some GT.
        tp = sum(1 for p in topk if any(tier_for(p, g) for g in gt))
        out[f"hit@{k}"] = 1.0 if covered > 0 else 0.0
        out[f"recall@{k}"] = covered / len(gt) if gt else 0.0
        out[f"allvf@{k}"] = 1.0 if (gt and covered == len(gt)) else 0.0
        # Set Precision/F1 over top-k as the predicted set (doc §7); Recall = recall@k.
        prec = tp / len(topk) if topk else 0.0
        rec = out[f"recall@{k}"]
        out[f"precision@{k}"] = prec
        out[f"f1@{k}"] = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        # nDCG@k: each GT credited once at its first matching rank within top-k.
        dcg, seen = 0.0, set()
        for i, pid in enumerate(topk, start=1):
            for g in gt:
                if g not in seen and tier_for(pid, g):
                    seen.add(g)
                    dcg += 1.0 / math.log2(i + 1)
                    break
        idcg = (
            sum(1.0 / math.log2(i + 1) for i in range(1, min(k, len(gt)) + 1))
            if gt
            else 0.0
        )
        out[f"ndcg@{k}"] = (dcg / idcg) if idcg else 0.0
    return out


def _func_ids(record: dict) -> list[str]:
    return [r.get("func_id", "") for r in record.get("ranked_functions", [])]


# ─────────────────────────── loading + aggregation ─────────────────────────


def dedup_records(records: list[dict]) -> tuple[list[dict], dict[tuple, int]]:
    """Keep the LAST record per (method, variant, cve_id) — doc 7: one group per
    advisory. Prediction files parsed from append-only checkpoint logs may
    contain one stale record per retry of the same CVE; the last write is the
    newest state. Returns (unique_records, {(method, variant): n_dropped})."""
    by_key: dict[tuple, dict] = {}
    dropped: dict[tuple, int] = defaultdict(int)
    for rec in records:
        key = (rec.get("method", "?"), rec.get("variant", "?"), rec.get("cve_id", "?"))
        if key in by_key:
            dropped[key[:2]] += 1
        by_key[key] = rec
    return list(by_key.values()), dict(dropped)


def load_predictions(pred_dir: Path) -> list[dict]:
    records = []
    for f in sorted(
        path for path in pred_dir.glob("*.jsonl")
        if not path.name.startswith("_") and not path.name.endswith('_failures.jsonl')
    ):
        with f.open(encoding="utf-8-sig") as fh:
            records.extend(json.loads(line) for line in fh if line.strip())
    records, dropped = dedup_records(records)
    for (m, v), n in sorted(dropped.items()):
        print(
            f"  NOTE: {m}/{v}: dropped {n} stale duplicate record(s) for retried "
            f"CVEs (kept the newest per cve_id)."
        )
    return records


def per_group_scores(records: list[dict], ks) -> list[dict]:
    """One scored row per (method, variant, cve) — basis for aggregation + stats."""
    out = []
    for rec in records:
        s = score_group(_func_ids(rec), rec.get("ground_truth", []), ks,
                        exact_only=rec.get('match_policy') == 'exact')
        out.append(
            {
                "method": rec.get("method", "?"),
                "variant": rec.get("variant", "?"),
                "cve_id": rec.get("cve_id", "?"),
                # RQ5 practicality (doc §7) — present only if the adapter logged it.
                "runtime_secs": rec.get("runtime_secs"),
                "tokens": rec.get("tokens"),
                "cost": rec.get("cost"),
                **s,
            }
        )
    return out


def load_master_meta(path: Path) -> dict[str, dict]:
    """{cve_id: {mapping_type, evidence}} from the master benchmark, for strata."""
    meta = {}
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            cid = r.get("advisory_id") or r.get("cve_id")
            if cid:
                meta[cid] = {
                    "mapping_type": r.get("mapping_type", "unknown"),
                    "evidence": r.get("ground_truth_evidence", "unknown"),
                }
    return meta


def _avg(scores: list[dict], ks) -> dict:
    """Average metrics over groups, EXCLUDING groups with empty ground truth."""
    scored = [s for s in scores if s["n_gt"] > 0]
    n = len(scored)
    row = {"n_groups": n, "n_no_gt": len(scores) - n}
    if not n:
        return row
    row["mrr"] = round(sum(s["rr"] for s in scored) / n, 4)
    row["map"] = round(sum(s["ap"] for s in scored) / n, 4)
    for k in ks:
        for m in ("hit", "recall", "allvf", "precision", "f1", "ndcg"):
            row[f"{m}@{k}"] = round(sum(s[f"{m}@{k}"] for s in scored) / n, 4)
    hit_ranks = [s["first_hit_rank"] for s in scored if s["first_hit_rank"] is not None]
    row["effort@1st"] = round(sum(hit_ranks) / len(hit_ranks), 2) if hit_ranks else None
    # Manual effort to find ALL VFs (doc §7): mean rank covering every GT, over the
    # groups where all were found; all_found shows how many that is.
    all_ranks = [s["all_hit_rank"] for s in scored if s["all_hit_rank"] is not None]
    row["effort@all"] = round(sum(all_ranks) / len(all_ranks), 2) if all_ranks else None
    row["all_found"] = len(all_ranks)
    row["misses"] = n - len(hit_ranks)
    row["n_empty"] = sum(1 for s in scored if s["n_pred"] == 0)  # no ranking at all
    row["weak"] = sum(s["weak_hit"] for s in scored)  # hits relying on name-only match
    # RQ5 practicality — mean of whatever the adapters logged (omitted if none did).
    for fld, label, nd in (
        ("runtime_secs", "runtime_s_mean", 2),
        ("tokens", "tokens_mean", 1),
        ("cost", "cost_mean", 4),
    ):
        vals = [s[fld] for s in scored if s.get(fld) is not None]
        if vals:
            row[label] = round(sum(vals) / len(vals), nd)
    return row


def aggregate(records: list[dict], ks) -> list[dict]:
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for s in per_group_scores(records, ks):
        buckets[(s["method"], s["variant"])].append(s)
    return [
        {"method": m, "variant": v, **_avg(sc, ks)}
        for (m, v), sc in sorted(buckets.items())
    ]


def stratified(
    records: list[dict], ks, meta: dict, by: str = "mapping_type"
) -> list[dict]:
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for s in per_group_scores(records, ks):
        stratum = meta.get(s["cve_id"], {}).get(by, "unknown")
        buckets[(s["method"], s["variant"], stratum)].append(s)
    return [
        {"method": m, "variant": v, by: st, **_avg(sc, ks)}
        for (m, v, st), sc in sorted(buckets.items())
    ]


# ─────────────────────────── output ────────────────────────────────────────


def print_table(rows: list[dict], cols: list[str]) -> None:
    if not rows:
        print("(no rows)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    fmt = (
        lambda vals: "| "
        + " | ".join(str(v).ljust(widths[c]) for c, v in zip(cols, vals))
        + " |"
    )
    print(fmt(cols))
    print("|" + "|".join("-" * (widths[c] + 2) for c in cols) + "|")
    for r in rows:
        print(fmt([r.get(c, "") for c in cols]))


def write_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    cols: list[str] = []
    for r in rows:  # union of keys, preserving first-seen order
        for k in r:
            if k not in cols:
                cols.append(k)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def metric_cols(ks, lead: list[str]) -> list[str]:
    return (
        lead
        + ["n_groups", "mrr", "map"]
        + [f"hit@{k}" for k in ks]
        + [f"recall@{k}" for k in ks]
        + [f"allvf@{k}" for k in ks]
        + [f"precision@{k}" for k in ks]
        + [f"f1@{k}" for k in ks]
        + [f"ndcg@{k}" for k in ks]
        + [
            "effort@1st",
            "effort@all",
            "all_found",
            "runtime_s_mean",
            "tokens_mean",
            "cost_mean",
            "misses",
            "n_empty",
            "weak",
            "n_no_gt",
        ]
    )


def _warn_weak(rows: list[dict]) -> None:
    weak = [r for r in rows if r.get("weak")]
    if weak:
        print(
            "\n  WARNING: some hits rest on weak 'name-only' matches (collision-prone):"
        )
        for r in weak:
            print(
                f"    {r['method']}/{r['variant']}: {r['weak']}/{r['n_groups']} groups"
            )
        print(
            "  -> treat those numbers as an upper bound; a shared qualified_name key fixes it."
        )
    empty = [r for r in rows if r.get("n_empty")]
    if empty:
        print(
            "  NOTE: groups where the method produced NO ranking (infra failures, "
            "counted as misses): "
            + ", ".join(f"{r['method']}/{r['variant']}={r['n_empty']}" for r in empty)
        )
    nogt = [r for r in rows if r.get("n_no_gt")]
    if nogt:
        print(
            "  NOTE: groups with empty ground_truth were excluded: "
            + ", ".join(f"{r['method']}/{r['variant']}={r['n_no_gt']}" for r in nogt)
        )


def run_metrics(
    pred_dir: Path = DEFAULT_PRED_DIR,
    master: Path | None = None,
    ks: list[int] | tuple[int, ...] = DEFAULT_KS,
    out: Path = DEFAULT_OUT,
    strat_out: Path = DEFAULT_STRAT_OUT,
) -> list[dict]:
    """Callable entry point used by evaluation.cli."""
    records = load_predictions(pred_dir)
    if not records:
        raise SystemExit(f"No prediction files in {pred_dir}. Run the harness first.")
    print(f"Loaded {len(records)} prediction records.\n")

    rows = aggregate(records, ks)
    print("=== Overall (per method/variant) ===")
    print_table(rows, metric_cols(ks, ["method", "variant"]))
    write_csv(rows, out)
    print(f"\nWrote {out}")
    _warn_weak(rows)

    if master:
        meta = load_master_meta(master)
        srows = stratified(records, ks, meta, by="mapping_type")
        print("\n=== Stratified by mapping_type (RQ4) ===")
        print_table(srows, metric_cols(ks, ["method", "variant", "mapping_type"]))
        write_csv(srows, strat_out)
        print(f"\nWrote {strat_out}")
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Compute ranking metrics over predictions."
    )
    ap.add_argument("--pred-dir", type=Path, default=DEFAULT_PRED_DIR)
    ap.add_argument(
        "--master",
        type=Path,
        default=None,
        help="Master JSONL — enables stratified breakdown by mapping_type.",
    )
    ap.add_argument("--ks", type=int, nargs="+", default=list(DEFAULT_KS))
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--strat-out", type=Path, default=DEFAULT_STRAT_OUT)
    args = ap.parse_args()

    records = load_predictions(args.pred_dir)
    if not records:
        raise SystemExit(
            f"No prediction files in {args.pred_dir}. Run the harness first."
        )
    print(f"Loaded {len(records)} prediction records.\n")

    rows = aggregate(records, args.ks)
    print("=== Overall (per method/variant) ===")
    print_table(rows, metric_cols(args.ks, ["method", "variant"]))
    write_csv(rows, args.out)
    print(f"\nWrote {args.out}")
    _warn_weak(rows)

    if args.master:
        meta = load_master_meta(args.master)
        srows = stratified(records, args.ks, meta, by="mapping_type")
        print("\n=== Stratified by mapping_type (RQ4) ===")
        print_table(srows, metric_cols(args.ks, ["method", "variant", "mapping_type"]))
        write_csv(srows, args.strat_out)
        print(f"\nWrote {args.strat_out}")


if __name__ == "__main__":
    main()
