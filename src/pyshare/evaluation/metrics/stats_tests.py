"""stats_tests.py — paired significance testing between methods (doc Section 7.2).

Metrics are measured on the SAME advisory groups, so method comparisons must be
PAIRED. For every pair of (method, variant) configurations this computes, over
their shared CVEs, on a chosen per-group metric (default the reciprocal rank rr):

  - Wilcoxon signed-rank test  -> p-value (is the difference real?)
  - matched-pairs rank-biserial correlation -> effect size (how big?)
  - paired bootstrap 95% CI of the mean difference (a - b)
  - Holm-Bonferroni correction across all pairwise tests (multiple comparisons)

Doc 7.2 asks for exactly these (paired test, effect size, bootstrap CI, Holm).
Reproducible: bootstrap uses a fixed seed.

Usage:
  python -m pyshare.evaluation.cli stats --pred-dir results/evaluation/predictions --metric rr
  python -m pyshare.evaluation.cli stats --pred-dir results/evaluation/predictions --metric recall@10
"""
from __future__ import annotations

import argparse
import itertools
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import rankdata, wilcoxon

from pyshare.evaluation.metrics.compute_metrics import (
    DEFAULT_KS,
    DEFAULT_PRED_DIR,
    load_predictions,
    per_group_scores,
)

BOOTSTRAP_N = 2000
SEED = 42
MIN_RELIABLE_N = 6   # below this, a paired test is not trustworthy (doc 7.2)


def rank_biserial(diffs: np.ndarray) -> float:
    """Matched-pairs effect size from non-zero paired differences, in [-1, 1]."""
    nz = diffs[diffs != 0]
    if nz.size == 0:
        return 0.0
    ranks = rankdata(np.abs(nz))
    w_pos = ranks[nz > 0].sum()
    w_neg = ranks[nz < 0].sum()
    total = w_pos + w_neg
    return float((w_pos - w_neg) / total) if total else 0.0


def bootstrap_ci(diffs: np.ndarray, n: int = BOOTSTRAP_N, seed: int = SEED):
    """Percentile 95% CI of the mean of paired differences."""
    if diffs.size == 0:
        return (None, None)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, diffs.size, size=(n, diffs.size))
    means = diffs[idx].mean(axis=1)
    lo, hi = np.percentile(means, [2.5, 97.5])
    return (round(float(lo), 4), round(float(hi), 4))


def compare_pair(a: dict, b: dict) -> dict | None:
    """Compare two {cve_id: value} maps on their shared CVEs."""
    shared = sorted(set(a) & set(b))
    if not shared:
        return None
    va = np.array([a[c] for c in shared], dtype=float)
    vb = np.array([b[c] for c in shared], dtype=float)
    diffs = va - vb
    try:
        with warnings.catch_warnings():       # silence tiny-n normal-approx noise
            warnings.simplefilter("ignore")
            p = float(wilcoxon(va, vb, zero_method="wilcox").pvalue)
        if np.isnan(p):
            p = 1.0
    except ValueError:                        # all-zero diffs / too few pairs
        p = 1.0
    return {
        "n_shared": len(shared),
        "mean_a": round(float(va.mean()), 4),
        "mean_b": round(float(vb.mean()), 4),
        "mean_diff": round(float(diffs.mean()), 4),
        "p_value": p,
        "rank_biserial": round(rank_biserial(diffs), 4),
        "ci95": bootstrap_ci(diffs),
    }


def holm_bonferroni(results: list[dict], alpha: float) -> None:
    """Annotate each result with Holm-adjusted significance (in place)."""
    m = len(results)
    order = sorted(range(m), key=lambda i: results[i]["p_value"])
    for rank, i in enumerate(order):
        thresh = alpha / (m - rank)
        results[i]["holm_thresh"] = round(thresh, 5)
        results[i]["significant"] = results[i]["p_value"] <= thresh


def run_stats(
    pred_dir: Path = DEFAULT_PRED_DIR,
    metric: str = "rr",
    ks: list[int] | tuple[int, ...] = DEFAULT_KS,
    alpha: float = 0.05,
) -> list[dict]:
    """Callable entry point used by evaluation.cli."""
    records = load_predictions(pred_dir)
    if not records:
        raise SystemExit(f"No prediction files in {pred_dir}.")
    scores = per_group_scores(records, ks)
    if metric not in scores[0]:
        raise SystemExit(
            f"Unknown metric '{metric}'. Available: "
            f"{[k for k in scores[0] if k not in ('method','variant','cve_id','first_hit_rank')]}"
        )

    by_config: dict[tuple, dict] = defaultdict(dict)
    for s in scores:
        if s["n_gt"] > 0:
            by_config[(s["method"], s["variant"])][s["cve_id"]] = s[metric]

    configs = sorted(by_config)
    results = []
    for (ca, cb) in itertools.combinations(configs, 2):
        cmp = compare_pair(by_config[ca], by_config[cb])
        if cmp:
            results.append({"A": f"{ca[0]}/{ca[1]}", "B": f"{cb[0]}/{cb[1]}", **cmp})

    if not results:
        print("No method pairs share any CVE â€” run methods on the same dataset to compare.")
        return []

    holm_bonferroni(results, alpha)
    for r in results:
        r["reliable"] = r["n_shared"] >= MIN_RELIABLE_N

    print(
        f"Paired comparison on metric '{metric}' (alpha={alpha}, "
        f"Holm-corrected, bootstrap n={BOOTSTRAP_N}; reliable = n_shared>={MIN_RELIABLE_N})\n"
    )
    cols = ["A", "B", "n_shared", "mean_a", "mean_b", "mean_diff",
            "ci95", "p_value", "rank_biserial", "holm_thresh", "significant", "reliable"]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in results)) for c in cols}
    fmt = lambda vals: "| " + " | ".join(str(v).ljust(widths[c]) for c, v in zip(cols, vals)) + " |"
    print(fmt(cols))
    print("|" + "|".join("-" * (widths[c] + 2) for c in cols) + "|")
    for r in results:
        print(fmt([r.get(c, "") for c in cols]))
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Paired significance tests between methods.")
    ap.add_argument("--pred-dir", type=Path, default=DEFAULT_PRED_DIR)
    ap.add_argument("--metric", default="rr",
                    help="Per-group metric to compare (rr, recall@10, hit@10, ...).")
    ap.add_argument("--ks", type=int, nargs="+", default=list(DEFAULT_KS))
    ap.add_argument("--alpha", type=float, default=0.05)
    args = ap.parse_args()

    records = load_predictions(args.pred_dir)
    if not records:
        raise SystemExit(f"No prediction files in {args.pred_dir}.")
    scores = per_group_scores(records, args.ks)
    if args.metric not in scores[0]:
        raise SystemExit(f"Unknown metric '{args.metric}'. Available: "
                         f"{[k for k in scores[0] if k not in ('method','variant','cve_id','first_hit_rank')]}")

    # {(method,variant): {cve_id: value}} — exclude groups with empty ground truth.
    by_config: dict[tuple, dict] = defaultdict(dict)
    for s in scores:
        if s["n_gt"] > 0:
            by_config[(s["method"], s["variant"])][s["cve_id"]] = s[args.metric]

    configs = sorted(by_config)
    results = []
    for (ca, cb) in itertools.combinations(configs, 2):
        cmp = compare_pair(by_config[ca], by_config[cb])
        if cmp:
            results.append({"A": f"{ca[0]}/{ca[1]}", "B": f"{cb[0]}/{cb[1]}", **cmp})

    if not results:
        print("No method pairs share any CVE — run methods on the same dataset to compare.")
        return

    holm_bonferroni(results, args.alpha)
    for r in results:                        # mark pairs with too few shared groups
        r["reliable"] = r["n_shared"] >= MIN_RELIABLE_N

    print(f"Paired comparison on metric '{args.metric}' (alpha={args.alpha}, "
          f"Holm-corrected, bootstrap n={BOOTSTRAP_N}; reliable = n_shared>={MIN_RELIABLE_N})\n")
    cols = ["A", "B", "n_shared", "mean_a", "mean_b", "mean_diff",
            "ci95", "p_value", "rank_biserial", "holm_thresh", "significant", "reliable"]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in results)) for c in cols}
    fmt = lambda vals: "| " + " | ".join(str(v).ljust(widths[c]) for c, v in zip(cols, vals)) + " |"
    print(fmt(cols))
    print("|" + "|".join("-" * (widths[c] + 2) for c in cols) + "|")
    for r in results:
        print(fmt([r.get(c, "") for c in cols]))


if __name__ == "__main__":
    main()
