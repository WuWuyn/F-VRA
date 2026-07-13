# Current CVE-VF Reachability Report

## Scope

- Accepted CVE-VF records: 247
- Project-CVE query rows: 26
- Projects requested: 28
- VF targets queried: 366

## Pipeline Coverage

- Projects completed: 0
- Projects failed: 1
- Jarvis attempts: {'docker:failed': 1, 'local:failed': 1}
- Package summary statuses: {}

## Reachability Outcomes

- Verdict counts: {'unknown': 26}
- Rows with witness paths: 0
- Total witness paths: 0
- Median path length: 0
- Max path length: 0

## Cost

- Total elapsed seconds: 23.374
- Jarvis elapsed seconds: 23.358
- Package summary elapsed seconds: 0
- Query latency p50/p95 ms: 0.0 / 0.0

## Accuracy And Safe Demotion

Not computable from the current CVE-to-VF annotation alone. The current dataset supplies oracle VF anchors and evidence, but does not include adjudicated project-to-VF reachability labels. The CSV is denominator-ready for later gold-label adjudication.

## Artifacts

- Query table: `results\tables\openllm_retry_results.csv`
- Per-project run directories: `artifacts/pipeline_runs/current_cve_vf_full_reachability/<project>/`
- Target source: `vf_annotations`
