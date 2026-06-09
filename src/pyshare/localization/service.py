from __future__ import annotations

import json
from pathlib import Path

from pyshare.core.config import settings
from pyshare.core.models import LocalizeResult
from pyshare.localization.candidates import select_patch_absent, select_patch_present
from pyshare.localization.expansion import expand_description
from pyshare.localization.function_parser import parse_repository
from pyshare.localization.metadata import ResolvedMetadata, download_patch, resolve_metadata
from pyshare.localization.models import LocalizationReport, LocalizationRequest
from pyshare.localization.patch import load_patch, parse_patch_text
from pyshare.localization.ranking import rank_candidates
from pyshare.localization.tracker import track_patch_candidates


def _resolve_request_metadata(request: LocalizationRequest) -> ResolvedMetadata:
    if request.cve_description:
        return ResolvedMetadata(
            cve_id=request.cve_id,
            description=request.cve_description,
            cwe_id=request.cwe_id,
            source="manual",
        )
    if not request.cve_id:
        raise ValueError("Either cve_id or cve_description is required")
    resolved = resolve_metadata(request.cve_id)
    if not resolved.description:
        raise ValueError(
            f"Could not resolve a description for {request.cve_id}; "
            "provide cve_description explicitly"
        )
    if request.cwe_id:
        resolved.cwe_id = request.cwe_id
    return resolved


def localize_vulnerable_functions(request: LocalizationRequest) -> LocalizationReport:
    repository = request.repository_path.resolve()
    if not repository.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {repository}")
    if request.top_k < 1:
        raise ValueError("top_k must be at least 1")

    metadata = _resolve_request_metadata(request)
    description = expand_description(metadata.description, metadata.cwe_id)
    functions = parse_repository(repository)
    if not functions:
        raise ValueError(f"No Python functions found under {repository}")

    patch_analysis = None
    patch_source = None
    if request.patch_path:
        patch_analysis, patch_source = load_patch(request.patch_path)
    elif request.auto_resolve_patch:
        if metadata.source == "manual" and request.cve_id:
            metadata = resolve_metadata(request.cve_id)
            if request.cve_description:
                metadata.description = request.cve_description
            if request.cwe_id:
                metadata.cwe_id = request.cwe_id
            description = expand_description(metadata.description, metadata.cwe_id)
        for url in metadata.patch_urls:
            downloaded = download_patch(url)
            if downloaded:
                patch_text, patch_source = downloaded
                patch_analysis = parse_patch_text(patch_text)
                break

    if patch_analysis is not None and patch_analysis.files:
        mode = "PATCH_PRESENT"
        tracker_evidence = track_patch_candidates(functions, patch_analysis)
        selection = select_patch_present(
            description,
            functions,
            tracker_evidence,
            use_embeddings=request.use_embeddings,
        )
    else:
        mode = "PATCH_ABSENT"
        selection = select_patch_absent(
            description,
            functions,
            use_embeddings=request.use_embeddings,
        )

    candidates = rank_candidates(
        description,
        selection.candidates,
        selection.relevance_scores,
        selection.evidence,
        top_k=request.top_k,
        use_llm=request.use_llm,
    )
    return LocalizationReport(
        cve_id=request.cve_id or metadata.cve_id,
        cve_description=metadata.description,
        cwe_id=metadata.cwe_id,
        repository_path=str(repository),
        mode=mode,
        patch_source=patch_source,
        metadata_source=metadata.source,
        candidates=candidates,
        metadata={
            "functions_scanned": len(functions),
            "candidate_pool_size": len(selection.candidates),
            "references": metadata.references,
            "llm_used": bool(request.use_llm and settings.llm_api_key and candidates),
            "retrieval": {
                "strategy": (
                    "hybrid_bm25_embeddings"
                    if selection.embedding_scores
                    else "bm25_fallback"
                ),
                "embedding_status": selection.embedding_status,
                "embedding_model": selection.embedding_model,
            },
        },
    )


def write_report(report: LocalizationReport, output: str | Path) -> None:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def localize(
    cve_id: str,
    *,
    description: str = "",
    repo_path: str | Path | None = None,
    top_k: int = 20,
) -> LocalizeResult:
    """Backward-compatible compact result used by older callers."""
    if repo_path is None:
        return LocalizeResult(cve_id=cve_id, package="", mode="needs_context")
    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id=cve_id,
            cve_description=description or None,
            repository_path=Path(repo_path),
            top_k=top_k,
        )
    )
    names = [candidate.qualname for candidate in report.candidates]
    top = report.candidates[0] if report.candidates else None
    return LocalizeResult(
        cve_id=cve_id,
        package=Path(repo_path).name,
        vf=top.qualname if top else "",
        score=top.score if top else 0.0,
        mode=report.mode,
        candidates=names,
    )
