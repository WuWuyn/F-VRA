# CVE-to-VF evaluation

The former `cve-to-vf` project is integrated into this repository as a research
harness. Its canonical input is the finalized benchmark and severity metadata
under `data/final/`.

## Layout

```text
pyshare/
|-- src/pyshare/
|   `-- evaluation/                 # CLI, adapters, metrics and methods
|       |-- adapters/
|       |-- methods/
|       |   |-- vfdetector/         # tVSM baseline
|       |   |-- vffinder/           # ICL + semantic retrieval baseline
|       |   `-- vfarche/            # BM25/LLM/Tracker method
|       |-- metrics/
|       `-- scripts/
|-- data/
|   |-- final/
|   |   |-- vf_benchmark_finalized.jsonl  # CVE/VF ground truth
|   |   `-- severity_sources.jsonl        # CVSS, CWE and EPSS evidence
|   `-- processed/                  # generated evaluation master
|-- configs/evaluation/             # manifest and dependency lists
`-- results/evaluation/             # generated research outputs
```

Generated evaluation outputs live in `results/evaluation/` and method clone
caches live in ignored runtime directories. They are deliberately separate from
the canonical `data/` layers.

## Setup on Windows PowerShell

```powershell
cd C:\Capstone\pyshare
uv venv .venv --python 3.11
.\.venv\Scripts\Activate.ps1
uv pip install --python .\.venv\Scripts\python.exe -e ".[dev]"
uv pip install --python .\.venv\Scripts\python.exe -r requirements-evaluation.txt
```

If `uv` is unavailable, use a normal Python 3.11 installation with
`python -m venv .venv` and `python -m pip install ...` instead.

VFFinder also needs its NLP models:

```powershell
python -c "import nltk; [nltk.download(x) for x in ('punkt','punkt_tab','stopwords','wordnet','omw-1.4','averaged_perceptron_tagger','averaged_perceptron_tagger_eng')]"
python -m spacy download en_core_web_sm
python -c "import benepar; benepar.download('benepar_en3')"
```

Create the single shared environment file at the repository root, then fill in
the keys for the methods you use:

```powershell
Copy-Item .env.example .env
```

PyShare, VFFinder, VFArCHE, and `pyshare eval doctor` all read this root
`.env`. VFDetector does not need an API key. VFFinder needs an
OpenRouter-compatible key. VFArCHE needs MongoDB; its default BM25-only mode
does not need an LLM key.

## Build data and run

Always rebuild the generated master after changing either finalized input file:

```powershell
pyshare eval prepare-data
pyshare eval smoke
pyshare eval list
```

Start MongoDB only when running VFArCHE:

```powershell
docker compose -f configs\evaluation\vfarche\docker-compose.yml up -d mongo
```

Run a small sample before a full experiment:

```powershell
pyshare eval doctor --methods vfdetector
pyshare eval run --methods vfdetector --sample-size 2
pyshare eval validate
pyshare eval metrics
```

The same command shape works for `vffinder` and `vfarche`. A full run omits
`--sample-size`:

```powershell
pyshare eval run --methods vfdetector vffinder vfarche
pyshare eval validate
pyshare eval metrics
pyshare eval stats --metric rr
```

See [`../evaluation/README.md`](../evaluation/README.md) for adapter details,
ablation commands, output contracts, and method-specific limitations.
