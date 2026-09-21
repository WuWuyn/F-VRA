# Evaluation Design

Keep the empirical study simple:

```text
src/pyshare/evaluation/
|-- cli.py                  # canonical reproduce/check command
|-- run_methods.py          # run full method pipelines through adapters
|-- run_ablation.py         # run variant sweeps through the same adapters
|-- adapters/               # boundary between the study and each method
|-- methods/
|   |-- vfdetector/
|   |-- vffinder/
|   `-- vfarche/
|-- metrics/                # reads prediction JSONL only
`-- scripts/                # shared preprocessing utilities

configs/evaluation/         # manifest and dependency lists
results/evaluation/         # generated predictions, metrics and stats
```

## Rules

1. `pyshare.evaluation` owns the empirical study.
   Dataset choice, variants, metrics, and statistical tests belong here.

2. `pyshare.evaluation.methods.<name>` owns method implementation.
   A method may use scripts or a CLI internally. The study should not care.

3. `pyshare.evaluation.adapters` is the only boundary.
   Each adapter converts the master dataset, runs the native method pipeline,
   and writes normalized predictions.

4. Metrics do not run methods.
   `pyshare.evaluation.metrics` only consumes prediction JSONL.

5. Ablation variants are labels/configs, not separate methods.
   Use `group = main | paper_ablation | diagnostic` to avoid mixing paper
   ablations with extra sensitivity checks.

## CLI Policy

Method-level CLI files are optional debug surfaces. The common interface for
the empirical study is `pyshare eval ...`; adapters translate that
shared command into each method's native package modules.

## Verification Policy

Use plain Python commands for empirical-study smoke checks:

```powershell
pyshare eval smoke
```

The integrated evaluation workflow uses plain Python checks.
