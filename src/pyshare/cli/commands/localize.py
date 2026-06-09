from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from pyshare.cli.output.display import console
from pyshare.localization.models import LocalizationRequest
from pyshare.localization.service import localize_vulnerable_functions, write_report


def localize(
    cve_id: Optional[str] = typer.Argument(None, help="CVE ID, e.g. CVE-2024-35195"),
    repository: Path = typer.Option(..., "--repository", "-r", help="Local Python repository"),
    description: Optional[str] = typer.Option(None, "--description", help="CVE description"),
    cwe_id: Optional[str] = typer.Option(None, "--cwe", help="CWE ID, e.g. CWE-918"),
    patch: Optional[Path] = typer.Option(None, "--patch", help="Local unified diff/patch"),
    auto_resolve_patch: bool = typer.Option(
        False,
        "--auto-resolve-patch",
        help="Resolve metadata and patch references via OSV/NVD/GitHub",
    ),
    top_k: int = typer.Option(20, "--top-k", min=1, help="Number of results"),
    use_embeddings: bool = typer.Option(
        True,
        "--embeddings/--no-embeddings",
        help="Use OpenRouter embeddings during candidate retrieval",
    ),
    use_llm: bool = typer.Option(
        False,
        "--use-llm",
        help="Rerank shortlist with the OpenRouter chat API",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report"),
) -> None:
    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id=cve_id,
            cve_description=description,
            cwe_id=cwe_id,
            repository_path=repository,
            patch_path=patch,
            auto_resolve_patch=auto_resolve_patch,
            top_k=top_k,
            use_llm=use_llm,
            use_embeddings=use_embeddings,
        )
    )
    if output:
        write_report(report, output)
        console.print(f"Report written to {output}")
    else:
        console.print_json(json.dumps(report.to_dict(), ensure_ascii=False))
