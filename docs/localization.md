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
   OpenRouter LLM reranking.
7. `service.py` returns the final JSON-compatible report.

## Configuration

```env
OPENROUTER_API_KEY=
OPENROUTER_EMBEDDING_MODEL=qwen/qwen3-embedding-0.6b
OPENROUTER_MODEL=openai/gpt-4o-mini
GITHUB_TOKEN=
NVD_API_KEY=
```

`OPENROUTER_API_KEY` enables semantic retrieval and `--use-llm`. Without it,
candidate retrieval falls back to BM25 and reports that fallback in
`metadata.retrieval`.

## Run The Full Pipeline

Patch-present mode:

```powershell
pyshare localize CVE-2023-32681 `
  --repository .\requests `
  --auto-resolve-patch `
  --top-k 20 `
  --output .\report.json
```

Manual patch:

```powershell
pyshare localize `
  --repository .\requests `
  --description "Proxy credentials may leak during HTTPS redirects" `
  --patch .\fix.patch `
  --top-k 20
```

Patch-absent mode:

```powershell
pyshare localize CVE-2023-32681 `
  --repository .\requests `
  --top-k 20
```

Add `--use-llm` to rerank the shortlist through the OpenRouter chat API. Use
`--no-embeddings` to test lexical retrieval in isolation.

## Test Each Stage

Metadata:

```powershell
pyshare localization metadata CVE-2023-32681 --provider osv
pyshare localization metadata CVE-2023-32681 --provider nvd --raw
```

Patch discovery and parsing:

```powershell
pyshare localization patch CVE-2023-32681 --output .\patch.diff
pyshare localization patch --patch .\patch.diff
pyshare localization patch --url https://github.com/OWNER/REPO/commit/SHA
```

AST extraction:

```powershell
pyshare localization parse --repository .\requests --limit 30
```

Patch tracking:

```powershell
pyshare localization track `
  --repository .\requests `
  --patch .\patch.diff `
  --max-depth 2
```

Candidate retrieval:

```powershell
pyshare localization retrieve `
  --repository .\requests `
  --description "Proxy credentials leak during HTTPS redirect" `
  --top-k 20
```

The retrieval output exposes `bm25_score`, `embedding_score`, and
`fused_score`. Check `embedding_status` before interpreting the fused ranking.

Full diagnostic run:

```powershell
pyshare localization run `
  --repository .\requests `
  --cve CVE-2023-32681 `
  --patch .\patch.diff `
  --top-k 20
```

## Python API

```python
from pathlib import Path

from pyshare.localization import LocalizationRequest
from pyshare.localization.service import localize_vulnerable_functions

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
