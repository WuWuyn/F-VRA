# Evaluation Harness

This directory orchestrates the empirical study for three VF-localization
methods: **vfdetector**, **vffinder**, and **vfarche**. A single master benchmark
feeds all methods; each adapter converts the input, runs the method's native
pipeline, and normalizes output into one prediction contract.

## Command reference (cheat sheet)

Every command runs from the **repository root** unless noted. Full details and
prerequisites are in the sections below; this is the quick lookup. `<master>` =
`data/processed/cve_to_vf_evaluation.jsonl` (generated from PyShare data and used
by default).

### 1. Prepare PyShare data and inspect the harness

```powershell
pyshare eval prepare-data
pyshare eval smoke
pyshare eval list
```

`prepare-data` joins `data/final/vf_benchmark_finalized.jsonl` with
`data/final/severity_sources.jsonl` into the generated default master. Run it
whenever either source changes.

### 2. Run a single method (Python driver directly)

Use this when you want one method under a specific interpreter/env. Run each
method from inside its own activated environment (see **Prerequisites**).

```powershell
pyshare eval run --methods vfdetector --sample-size 2
pyshare eval run --methods vffinder --sample-size 2
pyshare eval run --methods vfarche --sample-size 2
# point at an interpreter without activating:
python -m pyshare.evaluation.run_methods --methods vfdetector --python-bin C:/path/to/venv/Scripts/python.exe
```

Outputs → `results/evaluation/predictions/<method>.jsonl`.

### 3. Compute metrics (read-only, never re-runs a method)

Scores the prediction files. Needs `pip install -r configs/evaluation/requirements/harness.txt`
(numpy, scipy) once.

```powershell
# overall table + (with --master) stratified-by-mapping_type table
python -m pyshare.evaluation.metrics.compute_metrics --master data/processed/cve_to_vf_evaluation.jsonl
# score a different prediction dir (e.g. an ablation output) or custom k's:
python -m pyshare.evaluation.metrics.compute_metrics --pred-dir results/evaluation/ablation/vfdetector__synonym_expansion --ks 1 5 10

# paired significance test between methods on one per-group metric
python -m pyshare.evaluation.metrics.stats_tests --metric rr        # or recall@10, hit@10, ap, ...

# self-checks for the metric layer (no pytest needed)
python -m pyshare.evaluation.metrics.check_metrics
```

Writes `results/evaluation/metrics_summary.csv` (and
`metrics_by_mapping.csv` when `--master` is given).

### 4. Run an ablation sweep (one method, several configs)

Sweeps a config axis, labels each run with a `variant`, then auto-computes
metrics + significance over the variants.

```powershell
python -m pyshare.evaluation.run_ablation --list                                          # what's available
python -m pyshare.evaluation.run_ablation --method vfdetector --axis synonym_expansion     # no-expand vs expand (§8 description expansion)

# vffinder function-representation (§8 #4): sig / sig+body / sig+body+calls.
# vffinder llm_ranking (§8 #5): pointwise (Algorithm 1) vs pairwise (LLM tournament).
# Both need VFFinder dependencies and its LLM key:
pyshare eval ablation --method vffinder --axis function_representation
pyshare eval ablation --method vffinder --axis llm_ranking
```

Outputs → `results/evaluation/ablation/<method>__<axis>/` (each with its own
`metrics_summary.csv` — sweeps never overwrite the main run's metrics or each
other) plus the printed tables. `.\run.ps1` now auto-runs **every** axis of each
requested method in step 3 (vfdetector `synonym_expansion`; vffinder
`function_representation` + `llm_ranking` under the conda env; vfarche's
`rerank_strategy` + `description_expansion` only when vfarche is in `-Methods`).
The vffinder sweeps are heavier (corpus re-embed / LLM calls) — to skip step 3
entirely, simply omit the ablation command.

### 5. Run on WSL (Linux) — optional

vfdetector **no longer needs WSL**. It used to `git checkout` the vulnerable
snapshot, which failed on NTFS for repos with Windows-illegal paths (`aux/...`
reserved name, filenames with `:` like `...2015-11-19T07:27:46-05:00.data`, or
airflow task-log dirs). It now reads `.py` source **straight from the git object
store** (`git cat-file`), never materialising a working tree — so those repos
work on Windows too. `run.ps1` runs the full pipeline on Windows as-is.

WSL is still fine if you prefer it (e.g. faster git on native ext4). `run.ps1` is
PowerShell, so on WSL call the Python stages directly:

```bash
# in WSL Ubuntu, from the repo root, with the vfdetector venv activated
python -m pyshare.evaluation.run_methods --methods vfdetector
python -m pyshare.evaluation.metrics.compute_metrics --master data/processed/cve_to_vf_evaluation.jsonl
python -m pyshare.evaluation.run_ablation --method vfdetector --axis synonym_expansion
```

`VFDET_WORKSPACES` (default `eval/workspaces/`) just relocates the clone cache —
e.g. to a native ext4 path under WSL for faster git — it is no longer required
for correctness.

## Architecture

See [DESIGN.md](DESIGN.md) for the code-structure design. In short:
`pyshare.evaluation` owns orchestration, metrics, ablation, and the method
packages while keeping each native implementation isolated.

```text
src/pyshare/evaluation/
|-- cli.py                     # canonical reproduce/check command
|-- run_methods.py             # Python driver
|-- adapters/
|   |-- base.py                # MethodAdapter ABC + shared helpers
|   |-- vfdetector_adapter.py  # convert -> native runner -> results CSV
|   |-- vffinder_adapter.py    # convert -> native VFFinder pipeline
|   `-- vfarche_adapter.py     # convert -> native CLI -> MongoDB export
|-- methods/                   # VFDetector, VFFinder and VFArCHE source
|-- metrics/                   # metric layer
`-- scripts/                   # shared-candidate preprocessing

configs/evaluation/methods.manifest.json
results/evaluation/predictions/  # generated <method>.jsonl outputs
```

The method source trees live inside the PyShare package:

```text
src/pyshare/evaluation/methods/vfdetector/
src/pyshare/evaluation/methods/vffinder/
src/pyshare/evaluation/methods/vfarche/
```

Only canonical method ids are supported: `vfdetector`, `vffinder`, and
`vfarche`.

## Prediction Contract

Each line of `results/predictions/<method>.jsonl` is one `(CVE, variant)` record:

```json
{"cve_id": "CVE-2020-26257",
 "method": "vffinder",
 "variant": "p-icl",
 "ranked_functions": [{"func_id": "...py::fn", "score": 0.91}],
 "ground_truth": ["...py::fn"]}
```

- `ranked_functions` is ordered best-first.
- `score` may be `null` when native output has no numeric score.
- variants: `default` for `vfdetector`; `direct`, `s-icl`, `p-icl` for
  `vffinder`; `skip-llm`, `chat`, `embedding`, or `pairwise` for `vfarche`.

## Per-Method Pipelines

| Method | Native pipeline | Output parsed |
|---|---|---|
| `vfdetector` | `python -m pyshare.evaluation.methods.vfdetector.runner` clones the vulnerable snapshot and ranks functions by tVSM | native results CSV exported by the adapter |
| `vffinder` | runs corpus prep, Direct/S-ICL/P-ICL extraction, corpus rebuilds, and retrieval | `results/evaluation/adapters/vffinder/native_output/retrieval_results_{all,sicl,picl}.json` |
| `vfarche` | `python -m pyshare.evaluation.methods.vfarche.cli run --dataset <jsonl>` clones, parses, ranks by BM25, and optionally reranks | MongoDB `topk_results` exported by the adapter |

## Prerequisites

Install each method in its own environment:

```powershell
pip install -r configs\evaluation\requirements\vfdetector.txt
pip install -r configs\evaluation\requirements\vfarche.txt
pip install -r configs\evaluation\requirements\vffinder.txt
```

Install the NLTK corpora used by VFDetector/VFFinder once:

```powershell
python -c "import nltk; [nltk.download(x) for x in ('punkt','punkt_tab','stopwords','wordnet','omw-1.4','averaged_perceptron_tagger','averaged_perceptron_tagger_eng')]"
```

- `vfdetector`: Python venv; no LLM key.
- `vffinder`: VFFinder dependencies plus an LLM API key in the root `.env`.
- `vfarche`: Python venv plus MongoDB (`docker compose -f
  configs/evaluation/vfarche/docker-compose.yml up -d mongo`). LLM reranking requires an API key in
  the root `.env`; default adapter mode is BM25-only via `--skip-llm`.

## Usage

Preferred unified CLI from the repository root:

```powershell
pyshare eval prepare-data
pyshare eval smoke
pyshare eval doctor
pyshare eval list
pyshare eval run --methods vfdetector --sample-size 5
pyshare eval validate --pred-dir results/evaluation/predictions
pyshare eval metrics --pred-dir results/evaluation/predictions
pyshare eval stats --pred-dir results/evaluation/predictions --metric rr
```

Main predictions and ablation predictions share the same JSONL contract; metrics
and stats only need the correct `--pred-dir`.

```powershell
pyshare eval list --ablation
pyshare eval ablation --method vfarche --axis description_expansion --sample-size 5
pyshare eval metrics --pred-dir results/evaluation/ablation/vfarche__description_expansion
pyshare eval stats --pred-dir results/evaluation/ablation/vfarche__description_expansion --metric rr
```

Driver flags:

- `--master PATH`: master benchmark JSONL.
- `--methods NAME...`: methods to run, default `vfdetector vffinder vfarche`.
- `--out-dir PATH`: output directory for prediction JSONL files.
- `--python-bin PATH`: interpreter for native subprocess calls.
- `--sample-size N` / `--limit N`: select the first N master benchmark records
  for every requested method or ablation variant.

## Outputs And Resume

- `results/predictions/vfdetector.jsonl`
- `results/predictions/vffinder.jsonl`
- `results/predictions/vfarche.jsonl`

Native intermediates are runtime artifacts ignored by git. Adapter-converted
inputs live under `results/evaluation/adapters/<method>/`. `vfdetector` keeps
native workspaces/output under `src/pyshare/evaluation/methods/vfdetector/`; `vffinder` writes runtime
corpora/checkpoints/retrieval output under `results/evaluation/adapters/vffinder/native_output/`;
`vfarche` caches parsed functions and top-k results in MongoDB plus `repo_cache/`.

## Metrics

Metric computation is read-only over normalized prediction files:

```powershell
pyshare eval metrics --pred-dir results/evaluation/predictions
pyshare eval stats --pred-dir results/evaluation/predictions --metric rr
```

See [`metrics/README.md`](metrics/README.md) for matching tiers, multi-VF
metrics, and paired significance testing.

## Smoke Check

Run the evaluation checks with plain Python:

```powershell
pyshare eval smoke
```

This validates the manifest, method registry, method folders, metric checks,
ablation runner checks, and command entrypoints. It does not run full pipelines.
