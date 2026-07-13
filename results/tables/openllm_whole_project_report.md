# Current CVE-VF Reachability Report

## Scope

- Accepted CVE-VF records: 247
- Project-CVE query rows: 26
- Projects requested: 28
- VF targets queried: 366

## Pipeline Coverage

- Projects completed: 1
- Projects failed: 0
- Jarvis attempts: {'docker:success': 1}
- Package summary statuses: {'built': 9, 'failed_timeout': 3, 'missing_source': 48}

## Reachability Outcomes

- Verdict counts: {'not_reachable': 2, 'potentially_reachable': 17, 'reachable': 7}
- Rows with witness paths: 7
- Total witness paths: 117
- Median path length: 9
- Max path length: 14

## Cost

- Total elapsed seconds: 323.221
- Jarvis elapsed seconds: 93.751
- Package summary elapsed seconds: 152.855
- Query latency p50/p95 ms: 202.889 / 283.099

## Accuracy And Safe Demotion

Not computable from the current CVE-to-VF annotation alone. The current dataset supplies oracle VF anchors and evidence, but does not include adjudicated project-to-VF reachability labels. The CSV is denominator-ready for later gold-label adjudication.

## Artifacts

- Query table: `results\tables\openllm_whole_project_results.csv`
- Per-project run directories: `artifacts/pipeline_runs/current_cve_vf_full_reachability/<project>/`
- Target source: `vf_annotations`
