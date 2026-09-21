# VFFinder Method

This method contains the Python VFFinder implementation used by the shared
evaluation harness. It builds CVE description corpora, extracts AV/RC entities
with Direct/S-ICL/P-ICL prompting, builds a function corpus, and retrieves
candidate vulnerable functions with priority semantic retrieval.

## Active Layout

```text
src/pyshare/evaluation/methods/vffinder/
  vffinder/        implementation package
  requirements.txt
```

Adapter/native input files are created under
`results/evaluation/adapters/vffinder`. Phase-1 LLM checkpoints, retrieval files,
corpora, and embedding caches are runtime artifacts and default to
`results/evaluation/adapters/vffinder/native_output` outside the method source tree.

## Environment

Create the repository-root `.env` from the shared template and provide an API
key there:

```powershell
Copy-Item .env.example .env
```

The default reproduction path uses an OpenAI-compatible chat API for Phase 1
extraction and local `sentence-transformers` embeddings for semantic retrieval.
P-ICL also requires spaCy plus benepar models as noted in `requirements.txt`.

## Reproduce Commands

Run from the repository root:

```powershell
pyshare eval run --methods vffinder
pyshare eval validate --pred-dir results/evaluation/predictions
pyshare eval metrics --pred-dir results/evaluation/predictions
```

Pilot:

```powershell
pyshare eval run --methods vffinder --sample-size 2
```

The adapter writes normalized predictions for three variants:

```text
vffinder/direct
vffinder/s-icl
vffinder/p-icl
```

## Native Debug Commands

The adapter converts the benchmark into
`results/evaluation/adapters/vffinder/from_master.jsonl`.
It builds the repo-wide corpus from the repository root:

```powershell
python -m pyshare.evaluation.scripts.build_vffinder_corpus --master results/evaluation/adapters/vffinder/_corpus_master_subset.jsonl --out results/evaluation/adapters/vffinder/native_output/function_corpus_all.json
```

Then it runs these native modules from `src/pyshare/evaluation/methods/vffinder/`:

```powershell
python -m pyshare.evaluation.methods.vffinder.scripts.prepare_webapp_data --jsonl results\evaluation\adapters\vffinder\from_master.jsonl
python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level direct --all
python -m pyshare.evaluation.methods.vffinder.scripts.rebuild_case_pool --include-all
python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level s-icl --eval-only
python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level p-icl --eval-only
python -m pyshare.evaluation.methods.vffinder.scripts.rebuild_corpus_direct
python -m pyshare.evaluation.methods.vffinder.scripts.rebuild_corpus_icl --level s-icl
python -m pyshare.evaluation.methods.vffinder.scripts.rebuild_corpus_icl --level p-icl
$out = Resolve-Path results\evaluation\adapters\vffinder\native_output
python -m pyshare.evaluation.methods.vffinder.retrieval.retrieval --desc-corpus "$out\description_corpus.json" --func-corpus "$out\function_corpus_all.json" --output "$out\retrieval_results_all.json" --top-k 10
python -m pyshare.evaluation.methods.vffinder.retrieval.retrieval --desc-corpus "$out\description_corpus_s_icl.json" --func-corpus "$out\function_corpus_all.json" --output "$out\retrieval_results_sicl.json" --top-k 10
python -m pyshare.evaluation.methods.vffinder.retrieval.retrieval --desc-corpus "$out\description_corpus_p_icl.json" --func-corpus "$out\function_corpus_all.json" --output "$out\retrieval_results_picl.json" --top-k 10
```

Metrics are not computed inside the method packages; use `pyshare eval metrics`
on the normalized prediction directory.

## 9. Fidelity And Adaptations

Faithful VFFinder components:

- The pipeline keeps the paper's four stages: ICL-enhanced extraction,
  description corpus generation, function corpus generation, and priority
  semantic retrieval.
- Direct/S-ICL/P-ICL all run through the same leave-one-out case-pool flow; the
  query CVE is excluded from demonstrations.
- Description preprocessing keeps the source/paper steps: AV/RC tokenization,
  identifier splitting, POS noun/verb/adjective filtering, WordNet deduplication,
  vendor/product/version exclusion, Porter stemming, and TF-IDF entity weights.
- Function corpus generation ranks over repo-wide Python functions at the
  vulnerable ref and includes local entities plus caller-parameter and
  callee-inline augmentation.
- Retrieval follows Algorithm 1 by scoring each description entity against the
  best matching function entity, applying threshold `theta`, weighting by TF-IDF,
  and concatenating class-priority results before non-priority results.

Adaptations:

- Java/Soot/source generators are replaced with Python AST plus a best-effort
  import/same-class/name resolver. This is stronger than name-only matching but
  not equivalent to Java bytecode dispatch.
- Stanford parser is replaced with spaCy + benepar for constituency parsing.
- The unreleased P-ICL autoencoder artifact is replaced with a local GRU
  sequence autoencoder trained on case-pool pattern sequences.
- `WhereIsAI/UAE-Large-V1` replaces the paper's `angle-llama-7b` embedding model
  for CPU practicality while preserving normalized semantic cosine retrieval.
- The case pool is LLM-direct labeled over the Python benchmark, not the
  author's human-labeled Java/CPVD pool.

Extensions off by default:

- `--bm25-top-k > 0` enables a BM25 shortlist. Default `0` ranks the full pool.
- `--rank-strategy pairwise` enables an LLM tournament re-rank. Default
  `pointwise` keeps Algorithm 1 only.

Artifact status:

- Local output is currently stale/mixed after fidelity-sensitive fixes. Rebuild
  the function corpus, rerun missing Phase 1 outputs, rebuild description
  corpora, rerun retrieval for all three variants, then evaluate before using
  metrics as final research results.
