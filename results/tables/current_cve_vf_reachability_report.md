# Current CVE-VF Reachability Report

## Scope

- Accepted CVE-VF records: 247
- Project-CVE query rows: 811
- Projects requested: 28
- VF targets queried: 366

## Pipeline Coverage

- Projects completed: 28
- Projects failed: 0
- Jarvis attempts: {'docker:success': 28}
- Package summary statuses: {'built': 175, 'failed_timeout': 6, 'missing_source': 1453}

## Reachability Outcomes

- Verdict counts: {'not_reachable': 198, 'potentially_reachable': 458, 'reachable': 155}
- Rows with witness paths: 155
- Total witness paths: 5974
- Median path length: 8.0
- Max path length: 19

## Cost

- Total elapsed seconds: 2639.551
- Jarvis elapsed seconds: 548.518
- Package summary elapsed seconds: 705.065
- Query latency p50/p95 ms: 130.711 / 5371.082

## Accuracy And Safe Demotion

Not computable from the current CVE-to-VF annotation alone. The current dataset supplies oracle VF anchors and evidence, but does not include adjudicated project-to-VF reachability labels. The CSV is denominator-ready for later gold-label adjudication.

## Artifacts

- Query table: `results\tables\current_cve_vf_reachability_results.csv`
- Per-project run directories: `artifacts/pipeline_runs/current_cve_vf_full_reachability/<project>/`
- Target source: `vf_annotations`
