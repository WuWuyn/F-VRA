# Current CVE-VF Reachability Report

## Scope

- Accepted CVE-VF records: 247
- Project-CVE query rows: 11
- Projects requested: 28
- VF targets queried: 366

## Pipeline Coverage

- Projects completed: 1
- Projects failed: 0
- Jarvis attempts: {'docker:success': 1}
- Package summary statuses: {'built': 6, 'failed': 1, 'missing_source': 53}

## Reachability Outcomes

- Verdict counts: {'potentially_reachable': 9, 'reachable': 2}
- Rows with witness paths: 2
- Total witness paths: 24
- Median path length: 6.0
- Max path length: 7

## Cost

- Total elapsed seconds: 21310.868
- Jarvis elapsed seconds: 23.324
- Package summary elapsed seconds: 21068.267
- Query latency p50/p95 ms: 134.643 / 142.69

## Accuracy And Safe Demotion

Not computable from the current CVE-to-VF annotation alone. The current dataset supplies oracle VF anchors and evidence, but does not include adjudicated project-to-VF reachability labels. The CSV is denominator-ready for later gold-label adjudication.

## Artifacts

- Query table: `results\tables\debug_benavlabs.csv`
- Per-project run directories: `artifacts/pipeline_runs/current_cve_vf_full_reachability/<project>/`
- Target source: `vf_annotations`
