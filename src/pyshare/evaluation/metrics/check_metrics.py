"""Standalone checks for the metric layer (compute_metrics + stats_tests).

Run:
  python -m pyshare.evaluation.metrics.check_metrics
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import numpy as np

from pyshare.evaluation.metrics import compute_metrics as cm
from pyshare.evaluation.metrics import stats_tests as st

KS = (1, 5, 10)


# ── matching tiers ──────────────────────────────────────────────────────────

def test_match_exact_and_bare():
    assert cm.match_tier("generate_js", "generate_js") == "exact"

def test_match_file_plus_name_same_file():
    assert cm.match_tier("a/b.py::foo", "a/b.py::foo") == "exact"
    # class-qualified pred vs file::name gt, same file, same leaf name
    assert cm.match_tier("a/b.py::C.foo", "a/b.py::foo") == "file+name"

def test_match_rejects_same_name_different_file():
    # the key false-positive guard: both carry a file, files differ -> no match
    assert cm.match_tier("a/x.py::save", "a/y.py::save") is None

def test_match_path_prefix_tolerated():
    assert cm.match_tier("src/a/b.py::foo", "a/b.py::foo") == "file+name"

def test_match_backslash_normalized():
    assert cm.match_tier("a\\b.py::foo", "a/b.py::foo") == "file+name"

def test_match_suffix_requires_slash_boundary():
    # "xa/b.py" is NOT the same file as "a/b.py" — only basename agrees -> weak
    assert cm.match_tier("xa/b.py::foo", "a/b.py::foo") == "name-only"

def test_match_same_basename_different_dirs_is_weak():
    # two apps' models.py: basename agreement is no confirmation -> weak tier
    assert cm.match_tier("app1/models.py::save", "app2/models.py::save") == "name-only"

def test_match_name_only_when_no_file():
    # vfarche style (Class.method) vs bare gt name -> name-only (weak)
    assert cm.match_tier("ServerConfig.foo", "foo") == "name-only"

def test_match_different_names():
    assert cm.match_tier("a/b.py::foo", "a/b.py::bar") is None


# ── score_group: single / multi / miss / empty ──────────────────────────────

def test_score_single_hit_rank1():
    s = cm.score_group(["foo", "bar"], ["foo"], KS)
    assert s["rr"] == 1.0 and s["hit@1"] == 1.0 and s["first_hit_rank"] == 1
    assert s["recall@1"] == 1.0 and s["allvf@1"] == 1.0 and s["weak_hit"] == 0

def test_score_hit_rank3_not_in_top1():
    s = cm.score_group(["a", "b", "foo"], ["foo"], KS)
    assert s["rr"] == round(1 / 3, 4) or abs(s["rr"] - 1 / 3) < 1e-9
    assert s["hit@1"] == 0.0 and s["hit@5"] == 1.0 and s["first_hit_rank"] == 3

def test_score_multi_vf_partial_recall():
    # two GT; only one in top-5 -> recall 0.5, allvf 0, hit 1
    s = cm.score_group(["a/f.py::g1", "x", "y", "z", "w"], ["a/f.py::g1", "a/f.py::g2"], KS)
    assert s["hit@5"] == 1.0 and s["recall@5"] == 0.5 and s["allvf@5"] == 0.0

def test_score_multi_vf_all_found():
    s = cm.score_group(["g1", "g2", "z"], ["g1", "g2"], KS)
    assert s["recall@5"] == 1.0 and s["allvf@5"] == 1.0

def test_score_miss():
    s = cm.score_group(["a", "b"], ["foo"], KS)
    assert s["rr"] == 0.0 and s["hit@10"] == 0.0 and s["first_hit_rank"] is None

def test_score_empty_gt_flagged():
    s = cm.score_group(["a"], [], KS)
    assert s["n_gt"] == 0

def test_weak_hit_marked_for_name_only():
    s = cm.score_group(["Cls.foo"], ["foo"], KS)
    assert s["hit@1"] == 1.0 and s["weak_hit"] == 1

def test_duplicate_gt_entries_do_not_inflate_denominator():
    s = cm.score_group(["foo"], ["foo", "foo"], KS)
    assert s["n_gt"] == 1 and s["recall@1"] == 1.0 and s["allvf@1"] == 1.0

def test_average_precision():
    # GT g1,g2 at ranks 1 and 3 -> AP = (1/1 + 2/3)/2
    s = cm.score_group(["g1", "x", "g2"], ["g1", "g2"], KS)
    assert abs(s["ap"] - (1.0 + 2 / 3) / 2) < 1e-9


# ── new §7 metrics: nDCG, effort-to-all, set precision/F1 ────────────────────

def test_ndcg_perfect_and_discounted():
    import math
    assert cm.score_group(["foo"], ["foo"], KS)["ndcg@5"] == 1.0   # hit at rank 1
    # single GT at rank 3: dcg = 1/log2(4)=0.5, idcg = 1/log2(2)=1 -> 0.5
    s = cm.score_group(["a", "b", "foo"], ["foo"], KS)
    assert abs(s["ndcg@5"] - (1 / math.log2(4))) < 1e-9

def test_effort_to_all_vf():
    # both GT found -> rank covering ALL = 3; first hit = 1
    s = cm.score_group(["g1", "x", "g2"], ["g1", "g2"], KS)
    assert s["all_hit_rank"] == 3 and s["first_hit_rank"] == 1
    # only one of two GT ever found -> all_hit_rank None (effort-to-all undefined)
    s2 = cm.score_group(["g1", "x", "y"], ["g1", "g2"], KS)
    assert s2["all_hit_rank"] is None

def test_set_precision_and_f1():
    # top-5 = ["g1","x"] (2 items), one correct -> P@5=0.5, R@5=1.0, F1=2*.5*1/1.5
    s = cm.score_group(["g1", "x"], ["g1"], KS)
    assert s["precision@1"] == 1.0 and s["f1@1"] == 1.0
    assert s["precision@5"] == 0.5 and abs(s["f1@5"] - (2 * 0.5 * 1.0 / 1.5)) < 1e-9

def test_effort_all_aggregated_and_counted():
    records = [_rec("c1", ["g1", "x", "g2"], ["g1", "g2"]),  # all found @3
               _rec("c2", ["g1", "y"], ["g1", "g2"])]        # never all -> excluded
    r = cm.aggregate(records, KS)[0]
    assert r["all_found"] == 1 and r["effort@all"] == 3.0


# ── RQ5 practicality: runtime/tokens/cost only when logged ───────────────────

def test_runtime_aggregated_only_when_present():
    with_rt = [{**_rec("c1", ["foo"], ["foo"]), "runtime_secs": 2.0},
               {**_rec("c2", ["foo"], ["foo"]), "runtime_secs": 4.0}]
    r = cm.aggregate(with_rt, KS)[0]
    assert r["runtime_s_mean"] == 3.0 and "tokens_mean" not in r
    # no runtime logged -> column absent entirely
    r2 = cm.aggregate([_rec("c1", ["foo"], ["foo"])], KS)[0]
    assert "runtime_s_mean" not in r2


# ── aggregation excludes empty-GT groups ─────────────────────────────────────

def test_aggregate_excludes_empty_gt():
    records = [
        {"method": "m", "variant": "v", "cve_id": "c1",
         "ranked_functions": [{"func_id": "foo"}], "ground_truth": ["foo"]},
        {"method": "m", "variant": "v", "cve_id": "c2",
         "ranked_functions": [{"func_id": "x"}], "ground_truth": []},
    ]
    rows = cm.aggregate(records, KS)
    assert len(rows) == 1
    r = rows[0]
    assert r["n_groups"] == 1 and r["n_no_gt"] == 1 and r["mrr"] == 1.0


# ── dedup + empty-prediction reporting ──────────────────────────────────────

def _rec(cve, funcs, gt, variant="v"):
    return {"method": "m", "variant": variant, "cve_id": cve,
            "ranked_functions": [{"func_id": f} for f in funcs], "ground_truth": gt}

def test_dedup_keeps_last_record_per_group():
    old = _rec("c1", ["x"], ["foo"])           # stale retry: miss
    new = _rec("c1", ["foo"], ["foo"])         # newest state: hit
    other_variant = _rec("c1", [], ["foo"], variant="w")  # different variant -> kept
    recs, dropped = cm.dedup_records([old, new, other_variant])
    assert len(recs) == 2 and dropped == {("m", "v"): 1}
    mv = next(r for r in cm.aggregate(recs, KS) if r["variant"] == "v")
    assert mv["n_groups"] == 1 and mv["mrr"] == 1.0    # scored on the NEWEST record

def test_load_predictions_dedups_across_lines():
    with tempfile.TemporaryDirectory() as td:
        lines = [_rec("c1", ["x"], ["g"]), _rec("c1", ["g"], ["g"])]
        (Path(td) / "m.jsonl").write_text(
            "\n".join(json.dumps(r) for r in lines), encoding="utf-8")
        out = cm.load_predictions(Path(td))
    assert len(out) == 1
    assert out[0]["ranked_functions"][0]["func_id"] == "g"

def test_empty_prediction_is_counted_as_miss_and_reported():
    records = [_rec("c1", [], ["foo"]),        # infra failure: no ranking at all
               _rec("c2", ["foo"], ["foo"])]
    r = cm.aggregate(records, KS)[0]
    assert r["n_groups"] == 2                  # stays in the denominator
    assert r["n_empty"] == 1 and r["misses"] == 1
    assert r["hit@10"] == 0.5


# ── stats: rank-biserial, bootstrap determinism, Holm ────────────────────────

def test_rank_biserial_sign():
    assert st.rank_biserial(np.array([1.0, 2.0, 3.0])) == 1.0      # a always > b
    assert st.rank_biserial(np.array([-1.0, -2.0])) == -1.0
    assert st.rank_biserial(np.array([0.0, 0.0])) == 0.0

def test_bootstrap_deterministic():
    d = np.array([0.2, 0.4, -0.1, 0.5, 0.3, 0.1])
    assert st.bootstrap_ci(d) == st.bootstrap_ci(d)               # fixed seed

def test_holm_orders_and_flags():
    res = [{"p_value": 0.001}, {"p_value": 0.20}, {"p_value": 0.04}]
    st.holm_bonferroni(res, alpha=0.05)
    assert res[0]["significant"] is True       # 0.001 <= 0.05/3
    assert res[1]["significant"] is False      # 0.20 not significant
    # thresholds increase as p-values get larger (Holm step-down)
    assert res[0]["holm_thresh"] < res[1]["holm_thresh"]

def test_compare_pair_no_overlap():
    assert st.compare_pair({"c1": 1.0}, {"c2": 1.0}) is None


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  PASS {fn.__name__.replace('test_', 'check_', 1)}")
    print(f"\n{len(fns)} checks passed.")


if __name__ == "__main__":
    _run_all()
