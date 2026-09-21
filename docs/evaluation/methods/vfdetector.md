# VFDetector Method

This method contains the Python-adapted VFDetector implementation used by the
shared evaluation harness. It ranks Python functions with a tweaked Vector
Space Model (tVSM) over CVE text and function source.

## Active Layout

```text
src/pyshare/evaluation/methods/vfdetector/
  vfdetector/      core ranker, preprocessing helpers, and native runner
  README.md
  requirements.txt
```

`vfdetector.runner` is the native execution path used by the adapter. Cross-method
checks, metrics, stats, and smoke tests live under the repository-level
`evaluation/` package.

## Reproduce Command

Run from the repository root:

```powershell
pyshare eval run --methods vfdetector
pyshare eval validate --pred-dir results/evaluation/predictions
pyshare eval metrics --pred-dir results/evaluation/predictions
```

Pilot:

```powershell
pyshare eval run --methods vfdetector --sample-size 2
```

## Native Debug Command

The adapter converts the benchmark into native JSONL and calls:

```powershell
cd C:\Capstone\pyshare
python -m pyshare.evaluation.methods.vfdetector.runner --samples results\evaluation\adapters\vfdetector\from_master.jsonl
```

Adapter inputs live under `results/evaluation/adapters/vfdetector`. Native
`workspaces/`, `output/`, CSV/JSON summaries, and failures are runtime artifacts
and are ignored by git.

## 9. Fidelity And Adaptations

Faithful VFDetector components:

- The runner reads every `.py` source blob at the vulnerable state, defined as
  the parent of the canonical fix commit.
- `FunctionExtractor` extracts every Python function it can see with AST:
  top-level functions, async functions, class methods, nested functions/classes,
  and functions defined under blocks such as `if`/`try`.
- Source-code corpora use NLTK tokenization, stopword removal, Python keyword
  removal, snake_case/camelCase splitting, WordNet synonym expansion by default,
  and POS-aware WordNet lemmatization.
- Vulnerability-report corpora use stopword removal and POS-aware lemmatization
  only; source-code-only steps stay disabled for reports.
- Ranking is the paper's tVSM: `1 + log(count)` TF, IFF over function corpora
  only, cosine similarity, length normalization, `score = x * cosine`, and
  stable top-k ordering.

Adaptations:

- The original VFDetector target was C/C++; this reimplementation targets Python
  and uses Python AST plus `keyword.kwlist` for language-specific preprocessing.
- The runner reads source from the git object store without checking out a
  working tree. This avoids Windows-invalid paths while preserving the same
  vulnerable-state source content.
- `VFDET_EXPAND=0` is an evaluation ablation knob. The default run keeps WordNet
  synonym expansion enabled.

Data/artifact status:

- Current checked-in prediction artifacts are smoke/sample outputs only. After
  the nested-function extraction fix, rerun the full VFDetector benchmark before
  using metrics for research conclusions.
