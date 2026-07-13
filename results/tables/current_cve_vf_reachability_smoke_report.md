# Current CVE-VF Reachability Report

## Scope

- Accepted CVE-VF records: 247
- Project-CVE query rows: 9
- Projects requested: 28
- VF targets queried: 366

## Pipeline Coverage

- Projects completed: 1
- Projects failed: 0
- Jarvis attempts: {'docker:success': 1}
- Package summary statuses: {'built': 4, 'missing_source': 16}

## Reachability Outcomes

- Verdict counts: {'not_reachable': 3, 'reachable': 6}
- Rows with witness paths: 6
- Total witness paths: 978
- Median path length: 12.0
- Max path length: 17

## Cost

- Total elapsed seconds: 50.378
- Jarvis elapsed seconds: 17.739
- Package summary elapsed seconds: 27.77
- Query latency p50/p95 ms: 189.584 / 225.558

## Accuracy And Safe Demotion

Not computable from the current CVE-to-VF annotation alone. The current dataset supplies oracle VF anchors and evidence, but does not include adjudicated project-to-VF reachability labels. The CSV is denominator-ready for later gold-label adjudication.

## Artifacts

- Query table: `results\tables\current_cve_vf_reachability_smoke_results.csv`
- Per-project run directories: `artifacts/pipeline_runs/current_cve_vf_full_reachability/<project>/`
- Target source: `vf_annotations`
