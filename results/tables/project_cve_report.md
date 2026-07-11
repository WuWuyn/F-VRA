# Project CVE Report

Generated from local GitHub snapshots and local scan artifacts in `data/_scans`.

- Projects: 34
- Source finding rows: 5482
- Deduplicated project/CVE rows: 2003
- Total unique CVEs across all projects: 729

## Top Projects By Deduplicated CVEs

| project | pinned pkgs | pip-audit | osv | semgrep | snyk | dedup total |
|---|---:|---:|---:|---:|---:|---:|
| eosphoros-ai__DB-GPT | 218 | 125 (fallback:vulns) | 125 (vulns) | 355 (findings) | 104 (vulns) | 377 |
| Cinnamon__kotaemon | 369 | 208 (fallback:partial-vulns) | 227 (vulns) | 207 (findings) | 246 (vulns) | 282 |
| Chainlit__chainlit | 295 | 133 (vulns) | 133 (vulns) | 65 (findings) | 154 (vulns) | 221 |
| ATH-MaaS__Pixelle-MCP | 180 | 103 (vulns) | 103 (vulns) | 101 (findings) | 127 (vulns) | 128 |
| sparckles__Robyn | 18 | 0 (clean) | 0 (clean) | 121 (findings) | 0 (clean) | 121 |
| milesmcc__shynet | 59 | 60 (fallback:partial-vulns) | 68 (vulns) | 68 (findings) | 93 (vulns) | 102 |
| Open-LLM-VTuber__Open-LLM-VTuber | 301 | 54 (fallback:vulns) | 71 (vulns) | 0 (clean) | 57 (vulns) | 76 |
| djangostarter__web | 88 | 59 (vulns) | 59 (vulns) | 0 (clean) | 70 (vulns) | 71 |
| tropicoo__yt-dlp-bot | 72 | 61 (vulns) | 0 (clean) | 57 (findings) | 71 (vulns) | 71 |
| sunscrapers__djoser | 85 | 50 (vulns) | 0 (clean) | 0 (clean) | 61 (vulns) | 62 |

## Methodology Notes

- `size_kb` is the GitHub repository `size` field from `data/projects.json`.
- `pinned_pkgs`, `installed_pkgs`, and `install_fail` come from the Snyk pip-docker pipeline summary.
- CVE counts include only identifiers matching `CVE-YYYY-N...`; GHSA/PYSEC/SNYK IDs without a CVE alias are not counted in CVE columns.
- Each source count is paired with a source status in `project_cve_overview.csv`; `0 (clean)` is different from `0 (error)` or `0 (timeout)`.
- If one-shot pip-audit errors or times out, `pip_audit_cves` includes `pip-audit-fallback` batched Python 3.12 results when available.
- `total_unique_cves` deduplicates by `(project, CVE)` across pip-audit, pip-audit-fallback, osv-scanner, Semgrep Supply Chain, and Snyk.
- Empty or malformed JSON artifacts are skipped for that source only; other sources for the same project remain included.

## Outputs

- `project_cve_overview.csv`: project/link/size/package counts/CVE counts by source/dedup total.
- `project_cve_details.csv`: one row per project and CVE after cross-source deduplication.
- `project_cve_source_findings.csv`: source-level trace rows before project/CVE aggregation.
