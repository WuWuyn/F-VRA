# Metric layer

Scores the normalized predictions in `../results/predictions/*.jsonl` against
ground truth. Read-only: it never re-runs a method. Implements the ranking
metrics of the empirical-study design (Section 7 / 7.1 / 7.2 / appendix B).

## Files

| File | Purpose |
|---|---|
| `compute_metrics.py` | Per-group → per-(method,variant) metrics; optional stratification by `mapping_type` (RQ4). |
| `stats_tests.py` | Paired significance between methods: Wilcoxon, rank-biserial effect size, bootstrap 95% CI, Holm-Bonferroni (Section 7.2). |
| `check_metrics.py` | 26 standalone checks (matching tiers, multi-VF scoring, AP, dedup, empty-prediction reporting, Holm, bootstrap). |

## Metrics

Full doc Section 7 coverage:

| Metric | Meaning |
|---|---|
| `Hit@k` | top-k contains ≥1 GT VF |
| `Recall@k` | fraction of GT VFs in top-k (multi-VF) |
| `AllVF@k` | top-k contains **all** GT VFs (strict multi-VF) |
| `Precision@k` / `F1@k` | top-k as predicted set vs GT (doc §7 Set P/R/F1) |
| `MRR` | reciprocal rank of first GT VF |
| `MAP` | mean average precision over the ranking |
| `nDCG@k` | rank-discounted, ideal-normalized (doc §7 optional) |
| `Effort@1st` | mean rank of first GT hit (effort to first VF) |
| `Effort@all` | mean rank covering every GT, over `all_found` groups (effort to **all** VFs) |
| `runtime_s_mean` / `tokens_mean` / `cost_mean` | RQ5 practicality — reported **only** when the adapter logged per-CVE `runtime_secs` / `tokens` / `cost` in its prediction records. vfdetector logs true per-CVE detect time. vffinder runs in batch (no native per-CVE timer), so it reports an **amortized** per-CVE wall-clock = (shared-pipeline time + that variant's retrieval time) ÷ #CVEs — representative only on a fresh full run, deflated under `--resume`. vfarche runtime + all LLM token/cost are not yet wired |

See the `compute_metrics.py` docstring for exact definitions (doc 7.1 multi-label rule).

## Usage

```powershell
pip install -r ../requirements.txt        # numpy, scipy

# overall table + stratified-by-mapping_type table
pyshare eval metrics --pred-dir results/evaluation/predictions

# paired significance test on a chosen per-group metric
pyshare eval stats --pred-dir results/evaluation/predictions --metric rr

# standalone checks
python -m pyshare.evaluation.metrics.check_metrics
```

## Matching (read this before trusting cross-method numbers)

Func_ids differ by method (vfdetector: bare name; vffinder: `file.py::name`;
vfarche: `Class.method`). `match_tier` is tiered:

- **exact** / **file+name** — strong. "Same file" requires path equality or a
  `/`-boundary suffix (`src/a/b.py` vs `a/b.py`; `\` and `/` normalized). When
  both ids carry a file and the paths clearly diverge, the name match is
  **rejected** (prevents common-name false positives like two classes' `save`).
- **name-only** — weak; used when an id lacks a file to confirm with, **or** the
  files agree only on basename under different directories (two Django apps'
  `models.py` is not confirmation). Groups whose hit rests on this are counted
  in the `weak` column and a warning is printed. Treat those as an upper bound.

Groups with empty `ground_truth` are excluded (reported as `n_no_gt`).

## Input hygiene

- **Duplicate records** for the same (method, variant, cve) — the methods'
  native checkpoint logs re-append a row each time a failed CVE is retried
  under `--resume` — are deduplicated at load, keeping the **last** record
  (newest state, same rule as the native readers). A NOTE is printed with the
  number of stale records dropped. Without this, retried CVEs would be weighted
  multiple times in every average.
- **Empty predictions** (`n_empty` column): groups where the method produced
  *no ranking at all* — in practice infra failures (e.g. `git checkout` fails on
  Windows for repos with `aux/` dirs or `:` in filenames), not ranking misses.
  They **stay in the denominator as misses** (the practitioner got nothing),
  but are reported separately so infra robustness doesn't masquerade as ranking
  quality. Re-running those CVEs on Linux/WSL would convert them into real
  rankings.

**For a fair cross-method comparison** the methods must be run on the *same*
dataset, and ideally predictions normalized to a shared `qualified_name` key
(doc Section 11 step 8) — deferred to the shared-candidates work. `stats_tests.py`
pairs methods only on their shared CVEs and flags pairs with `n_shared < 6` as
`reliable = False`.
