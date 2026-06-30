from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from pyshare_core.models import Evidence, VulnerabilityRecord, VulnerableEntity
from pyshare_server.localization.models import LocalizationRequest
from pyshare_server.localization.service import localize_vulnerable_functions, write_report
from pyshare_server.storage import ServerFileDb, default_server_filedb

console = Console(legacy_windows=False)


def _record_from_report(report) -> VulnerabilityRecord:
    package = Path(report.repository_path).name if report.repository_path else "unknown"
    entities = [
        VulnerableEntity(
            package=package,
            name=candidate.qualname or candidate.function_name,
            confidence=candidate.confidence,
            evidence=[
                Evidence(
                    source="localization",
                    detail=candidate.why_this_may_be_vulnerable,
                    confidence=candidate.confidence,
                    metadata={
                        "rank": candidate.rank,
                        "score": candidate.score,
                        "file_path": candidate.file_path,
                        "start_line": candidate.start_line,
                        "end_line": candidate.end_line,
                    },
                )
            ],
        )
        for candidate in report.candidates
    ]
    return VulnerabilityRecord(
        cve_id=report.cve_id or "unknown",
        package=package,
        entities=entities,
    )


def localize(
    cve_id: str = typer.Argument(..., help="CVE ID, e.g. CVE-2024-35195"),
    cwe_id: Optional[str] = typer.Option(None, "--cwe", help="CWE ID, e.g. CWE-918"),
    patch: Optional[Path] = typer.Option(None, "--patch", help="Local unified diff/patch"),
    auto_resolve_patch: bool = typer.Option(
        True,
        "--auto-resolve-patch/--no-auto-resolve-patch",
        help="Resolve metadata and patch references via OSV/NVD/GitHub",
    ),
    top_k: int = typer.Option(20, "--top-k", min=1, help="Number of results"),
    use_embeddings: bool = typer.Option(
        True,
        "--embeddings/--no-embeddings",
        help="Use OpenRouter embeddings during candidate retrieval",
    ),
    candidate_pool_size: int = typer.Option(
        100,
        "--candidate-pool-size",
        min=1,
        help="Candidate pool size before final ranking",
    ),
    tracker_max_depth: int = typer.Option(
        2,
        "--tracker-depth",
        min=0,
        help="Patch-present call graph expansion depth",
    ),
    cve_repeat: int = typer.Option(
        5,
        "--cve-repeat",
        min=1,
        help="Repeat original CVE text before CWE expansion",
    ),
    swiss_rounds: int = typer.Option(
        8,
        "--swiss-rounds",
        min=0,
        help="Swiss-system pairwise rounds",
    ),
    finalists: int = typer.Option(
        20,
        "--finalists",
        min=1,
        help="Finalist count for exhaustive pairwise ranking",
    ),
    pairwise: bool = typer.Option(
        False,
        "--pairwise/--no-pairwise",
        help="Use OpenRouter chat pairwise comparisons",
    ),
    pairwise_model: Optional[str] = typer.Option(
        None,
        "--pairwise-model",
        help="OpenRouter chat model for pairwise comparisons",
    ),
    extract_entities: bool = typer.Option(
        False,
        "--extract-entities/--no-extract-entities",
        help="Use LLM to extract attack/root-cause entities from the CVE text",
    ),
    entity_model: Optional[str] = typer.Option(
        None,
        "--entity-model",
        help="OpenRouter chat model for CVE entity extraction",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report"),
    store: Optional[Path] = typer.Option(None, "--store", help="Server file DB root"),
    persist: bool = typer.Option(True, "--persist/--no-persist", help="Store VulnerabilityRecord in file DB"),
) -> None:
    def progress(message: str) -> None:
        console.print(f"[cyan]{message}[/cyan]")

    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id=cve_id,
            cwe_id=cwe_id,
            patch_path=patch,
            auto_resolve_patch=auto_resolve_patch,
            top_k=top_k,
            use_embeddings=use_embeddings,
            candidate_pool_size=candidate_pool_size,
            tracker_max_depth=tracker_max_depth,
            cve_repeat=cve_repeat,
            swiss_rounds=swiss_rounds,
            finalists=finalists,
            pairwise=pairwise,
            pairwise_model=pairwise_model,
            extract_entities=extract_entities,
            entity_model=entity_model,
            progress_callback=progress,
        )
    )
    if output:
        write_report(report, output)
        console.print(f"Report written to {output}")
    else:
        console.print_json(json.dumps(report.to_dict(), ensure_ascii=False))
    if persist:
        db: ServerFileDb = ServerFileDb(store) if store else default_server_filedb()
        record = _record_from_report(report)
        db.put_vulnerability(record)
        console.print(f"[green]Vulnerability record stored:[/green] {record.cve_id}")
