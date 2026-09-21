# VFArCHE Method

This method contains the Python VFArCHE implementation used by the shared
evaluation harness. The active pipeline clones the vulnerable repository,
parses Python functions, selects candidates with a paper-style PATCH-PRESENT
Tracker when a fix commit is available, falls back to the PATCH-ABSENT
CodeBERT selector when a fine-tuned checkpoint is provided, ranks candidates
with BM25, optionally reranks with OpenRouter/OpenAI-compatible LLM or
embedding calls, stores top-k rows in MongoDB, and lets the adapter export
normalized predictions.

## Active Layout

```text
src/pyshare/evaluation/methods/vfarche/
  vfarche/         implementation package
  config.py        method constants
  docker-compose.yml
```

Debug scripts, native ablation, and method-local metrics were removed. Ablation,
metrics, validation, and stats are handled by `pyshare eval`.

## Environment

MongoDB is required for the current VFArCHE storage path:

```powershell
cd C:\Capstone\pyshare
docker compose -f configs\evaluation\vfarche\docker-compose.yml up -d mongo
cd ../..
```

For LLM variants, create the repository-root `.env` from `.env.example` and
provide the provider key there. BM25-only runs use `--skip-llm` through the
adapter and do not need an LLM key.

## Reproduce Commands

Run from the repository root:

```powershell
pyshare eval run --methods vfarche
pyshare eval validate --pred-dir results/evaluation/predictions
pyshare eval metrics --pred-dir results/evaluation/predictions
```

### Resumable full run on Windows

From the repository root, the full runner enables description expansion,
pairwise LLM reranking, MongoDB checkpoints, and per-CVE error isolation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\run_vfarche_full.ps1" -Bootstrap -Limit 2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\run_vfarche_full.ps1"
```

`-Bootstrap` is only needed to create `.venv` and install dependencies the
first time. Successful CVEs are checkpointed after each result and skipped on
the next run when the configuration matches. A failed CVE is written to
`results/evaluation/vfarche_full/logs/vfarche_failures.jsonl`; the same run continues
with the next CVE, and a later run retries only failures. Use `-NoResume` to
recompute successful CVEs or `-StopOnError` for fail-fast debugging.

Per-CVE checkpoints retain `runtime_secs` (checkout through ranking, excluding
the final database write), provider-reported token totals and successful API
response counts. The adapter exports these to predictions and metrics. Missing
provider usage remains unknown, not zero; cost is not inferred from token counts.
Resume preserves the original measurement. Checkpoints from before telemetry
and the pairwise orientation fix are recomputed once (signature version 2).

VFArCHE predictions now use exact `file.py::Class.method` identifiers for both
predictions and ground truth; legacy predictions keep their legacy matching rules.
The original pilot metrics must be regenerated from a new run.

Embedding mode uses `OPENAI_EMBEDDING_MODEL` (or the OpenRouter equivalent).
For a separate embedding service, explicitly set `EMBEDDING_BASE_URL` and
`EMBEDDING_API_KEY`. Quat Mo currently exposes `qwen3-embedding`; chat model
`qwen3-coder` is not an embedding model. HTTP 401/403 and other permanent errors
fail without repeated requests; transient 429/5xx/network errors are retried.

Pilot:

```powershell
pyshare eval run --methods vfarche --sample-size 2
```

Ablation:

```powershell
pyshare eval ablation --method vfarche --axis description_expansion --sample-size 2
pyshare eval metrics --pred-dir results/evaluation/ablation/vfarche__description_expansion
pyshare eval stats --pred-dir results/evaluation/ablation/vfarche__description_expansion --metric rr
```

## Native Debug Command

The adapter converts the benchmark into
`results/evaluation/adapters/vfarche/from_master.jsonl` and calls:

```powershell
cd C:\Capstone\pyshare
python -m pyshare.evaluation.methods.vfarche.cli run --dataset results\evaluation\adapters\vfarche\from_master.jsonl --skip-llm
```

Candidate selection knobs:

```powershell
python -m pyshare.evaluation.methods.vfarche.cli run --dataset results\evaluation\adapters\vfarche\from_master.jsonl --candidate-selection auto --skip-llm
python -m pyshare.evaluation.methods.vfarche.cli run --dataset patch_absent.jsonl --candidate-selection codebert --codebert-checkpoint output/codebert-vfarche
```

`auto` uses Tracker for PATCH-PRESENT records that include both
`vulnerable_ref` and `fix_commit`. For PATCH-ABSENT records, it uses the local
fine-tuned CodeBERT checkpoint if provided. Without that checkpoint, the
pipeline labels the run as `bm25-fallback` rather than pretending base CodeBERT
matches the paper classifier.

## CodeBERT Training

Build supervised pairs from Tracker output:

```powershell
cd C:\Capstone\pyshare
python -m pyshare.evaluation.methods.vfarche.scripts.build_codebert_training_data --dataset results\evaluation\adapters\vfarche\from_master.jsonl --out output/codebert/train.jsonl
```

Install optional training dependencies and fine-tune:

```powershell
pip install -r configs/evaluation/requirements/vfarche-codebert.txt
python -m pyshare.evaluation.methods.vfarche.scripts.train_codebert_classifier --train output/codebert/train.jsonl --out output/codebert-vfarche
```

Adapter inputs, `repo_cache/`, MongoDB contents, and exported predictions are
runtime artifacts and are ignored by git.

## Paper Gaps

Current VFArCHE is a Python adaptation of the paper architecture. It now has
PATCH-PRESENT Tracker candidate selection, a PATCH-ABSENT CodeBERT inference
path, and scripts to train the CodeBERT classifier from Tracker output. Remaining
paper-faithfulness caveats: the Tracker uses Python AST call/reference expansion
instead of JavaParser inter-procedural data-flow; the CodeBERT mode requires a
locally trained checkpoint; query expansion uses an offline CWE/PRF/LSA
approximation when scikit-learn is available.
