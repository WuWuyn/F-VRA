# Localization

This module maps a CVE description and an optional patch to likely vulnerable
Python functions.

## Pipeline

1. `metadata.py` fetches CVE metadata from OSV or NVD.
2. `patch.py` downloads and parses unified diffs.
3. `function_parser.py` extracts Python functions, methods, calls, and names.
4. `tracker.py` expands patch hits through calls and changed configuration.
5. `candidates.py` combines BM25 and OpenRouter embeddings with Reciprocal Rank
   Fusion.
6. `ranking.py` combines retrieval relevance, patch evidence, and optional
   OpenRouter reranking.
7. `service.py` returns the final JSON-ready report.

## Configuration

```env
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openai/gpt-oss-120b:free
OPENROUTER_EMBEDDING_MODEL=nvidia/llama-nemotron-embed-vl-1b-v2:free
OPENROUTER_RERANK_MODEL=nvidia/llama-nemotron-rerank-vl-1b-v2:free
GITHUB_TOKEN=
NVD_API_KEY=
```

`OPENROUTER_API_KEY` enables semantic retrieval and optional pairwise chat
comparisons. Without it, candidate retrieval falls back to BM25 and reports that
fallback in `metadata.retrieval`.

## Run The Full Pipeline

Patch-present mode:

```powershell
pyshare-server localize CVE-2023-32681 `
  --auto-resolve-patch `
  --top-k 20 `
  --output .\report.json
```

PyShare infers a GitHub repository from OSV/NVD references and clones it into
`repo_cache_dir` automatically.

Patch-absent mode:

```powershell
pyshare-server localize CVE-2023-32681 `
  --top-k 20
```

Use `--no-embeddings` to test lexical retrieval in isolation.

Run the VFarche-style CVE-to-VF method with explicit ranking parameters:

```powershell
pyshare-server localize CVE-2023-32681 `
  --candidate-pool-size 100 `
  --tracker-depth 2 `
  --cve-repeat 5 `
  --swiss-rounds 8 `
  --finalists 20 `
  --output .\cve-to-vf-report.json
```

The command follows the paper's three-stage shape: CWE description expansion,
dual patch-present / patch-absent candidate selection, then Swiss-system plus
exhaustive finalist pairwise ranking. By default the pairwise stage uses a
deterministic offline fallback over retrieval and patch evidence. Pass
`--pairwise --pairwise-model <openrouter-chat-model>` to use OpenRouter chat
comparisons for the pairwise judgments.

To use an LLM as a lightweight replacement for fine-tuned patch-absent
classifiers, enable CVE entity extraction:

```powershell
pyshare-server localize CVE-2023-32681 `
  --extract-entities `
  --entity-model openai/gpt-4o-mini `
  --pairwise `
  --pairwise-model openai/gpt-4o-mini `
  --output .\llm-cve-to-vf-report.json
```

The extractor appends concise search entities such as attack vector, root cause,
affected component, and vulnerability type to the expanded CVE query before
candidate retrieval.

## Test Each Stage

Metadata:

```powershell
pyshare-server localization metadata CVE-2023-32681 --provider osv
pyshare-server localization metadata CVE-2023-32681 --provider nvd --raw
```

Patch discovery and parsing:

```powershell
pyshare-server localization patch CVE-2023-32681 --output .\patch.diff
pyshare-server localization patch --patch .\patch.diff
pyshare-server localization patch --url https://github.com/OWNER/REPO/commit/SHA
```

AST extraction:

```powershell
pyshare-server localization parse --repository .\requests --limit 30
```

Patch tracking:

```powershell
pyshare-server localization track `
  --repository .\requests `
  --patch .\patch.diff `
  --max-depth 2
```

Candidate retrieval:

```powershell
pyshare-server localization retrieve `
  --repository .\requests `
  --description "Proxy credentials leak during HTTPS redirect" `
  --top-k 20
```

The retrieval output exposes `bm25_score`, `embedding_score`, and
`fused_score`. Check `embedding_status` before interpreting the fused ranking.

Full diagnostic run:

```powershell
pyshare-server localization run `
  CVE-2023-32681 `
  --patch .\patch.diff `
  --top-k 20
```

## Ingest Package Summaries

Store a package call graph report as a server-side package summary artefact:

```powershell
pyshare-server summaries ingest `
  --package-report .\requests-callgraph-package.json `
  --package requests `
  --version 2.31.0
```

## Python API

```python
from pathlib import Path

from pyshare_server.localization import LocalizationRequest
from pyshare_server.localization.service import localize_vulnerable_functions

report = localize_vulnerable_functions(
    LocalizationRequest(
        cve_id="CVE-2023-32681",
        repository_path=Path("./requests"),
        auto_resolve_patch=True,
        top_k=20,
    )
)

print(report.mode)
print(report.to_dict()["candidates"])
```

## Tests

```powershell
pytest tests/unit/test_localization.py
```

Network calls are mocked in unit tests. Manual metadata and patch commands are
the end-to-end checks for OSV, NVD, GitHub, and OpenRouter connectivity.
