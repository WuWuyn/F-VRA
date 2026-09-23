"""Research experiment lifecycle. Each command has an explicit input snapshot."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import typer

from pyshare.evaluation.dataset import freeze_dataset
from pyshare.evaluation.environment import EnvironmentResolver, build_environments
from pyshare.evaluation.io import read_parquet, write_json, write_parquet
from pyshare.evaluation.metrics import vf_input_quality
from pyshare.evaluation.oracle import adjudicate_oracle, import_oracle
from pyshare.evaluation.reports import generate_report
from pyshare.evaluation.runner import ExperimentRunner
from pyshare.evaluation.vf import build_vf_variants


app = typer.Typer(help="Freeze, run and report PyShare research experiments", no_args_is_help=True)
REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATASET = REPO_ROOT / "experiments" / "dataset" / "v13-lock-universe"
DEFAULT_RUNS = REPO_ROOT / "experiments" / "runs"
DEFAULT_JARVIS = REPO_ROOT / "vendor" / "pythonJaRvis" / "Jarvis"


@app.command("freeze")
def freeze(
    output_dir: Path = typer.Option(DEFAULT_DATASET),
    projects: Path = typer.Option(REPO_ROOT / "configs" / "local_projects.json"),
    benchmark: Path = typer.Option(REPO_ROOT / "data" / "final" / "cve_vf_benchmark_accepted.jsonl"),
    protocol: Path = typer.Option(REPO_ROOT / "experiments" / "protocol" / "protocol-v13.yaml"),
    resolved_packages: Path = typer.Option(REPO_ROOT / "data" / "interim" / "resolved_versions" / "resolved_packages.csv"),
) -> None:
    typer.echo(json.dumps(freeze_dataset(
        REPO_ROOT, output_dir, manifest=projects, benchmark=benchmark,
        protocol=protocol, resolved_packages=resolved_packages,
    ), indent=2))


@app.command("build-env")
def build_env(
    dataset: Path = typer.Option(DEFAULT_DATASET), jarvis_root: Path = typer.Option(DEFAULT_JARVIS),
    project_id: list[str] = typer.Option([], "--project-id"), limit: int = typer.Option(0),
    force: bool = typer.Option(False, help="Rebuild even when the frozen environment is resumable."),
) -> None:
    typer.echo(json.dumps(build_environments(EnvironmentResolver(REPO_ROOT, dataset, jarvis_root), project_ids=set(project_id) or None, limit=limit, force_rebuild=force), indent=2))


@app.command("audit")
def audit(dataset: Path = typer.Option(DEFAULT_DATASET)) -> None:
    from collections import Counter, defaultdict

    result = {}
    for name in ("snapshot_audit", "environment_audit", "package_source_audit", "query_eligibility", "oracle_import_audit"):
        path = dataset / f"{name}.parquet"
        if path.exists():
            result[name] = dict(Counter(str(row.get("status") or "") for row in read_parquet(path)))
    eligibility_path = dataset / "query_eligibility.parquet"
    if eligibility_path.exists():
        rows = read_parquet(eligibility_path)
        candidates = {
            str(row["candidate_id"]): row
            for row in read_parquet(dataset / "query_candidates.parquet")
        }
        queries = {
            str(row["query_id"]): row
            for row in read_parquet(dataset / "queries.parquet")
        } if (dataset / "queries.parquet").exists() else {}
        stages = (
            ("candidate", None),
            ("affected_package_installed", "package_installed"),
            ("affected_version_installed", "affected_version"),
            ("source_available", "source_available"),
            ("vf_bound", "vf_bound"),
            ("query_eligible", "query_eligible"),
        )
        funnel = [
            {"stage": stage, "count": len(rows) if field is None else sum(bool(row.get(field)) for row in rows)}
            for stage, field in stages
        ]
        eligible_rows = [row for row in rows if bool(row.get("query_eligible"))]
        dependency_types = Counter(
            str(queries.get(str(row.get("query_id") or ""), {}).get("dependency_type") or "unknown")
            for row in eligible_rows
        )
        vf_multiplicity = Counter(
            str(len(candidates.get(str(row.get("candidate_id") or ""), {}).get("target_vfs") or []))
            for row in eligible_rows
        )
        eligibility_summary = {
            "candidate_count": len(rows),
            "status_counts": dict(Counter(str(row.get("status") or "") for row in rows)),
            "funnel": funnel,
            "eligible_strata": {
                "project_count": len({str(row.get("project_id")) for row in eligible_rows}),
                "package_count": len({
                    str(candidates.get(str(row.get("candidate_id") or ""), {}).get("affected_distribution") or "")
                    for row in eligible_rows
                }),
                "dependency_type_counts": dict(dependency_types),
                "vf_multiplicity_counts": dict(vf_multiplicity),
            },
        }
        write_json(dataset / "eligibility_summary.json", eligibility_summary)
        with (dataset / "eligibility_funnel.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["stage", "count"])
            writer.writeheader()
            writer.writerows(funnel)
        result["eligibility"] = eligibility_summary
        issues = []
        for row in rows:
            if row.get("query_eligible"):
                continue
            candidate = candidates.get(str(row.get("candidate_id") or ""), {})
            issues.append({
                "project_id": row.get("project_id"), "cve_id": row.get("cve_id"),
                "candidate_id": row.get("candidate_id"),
                "affected_distribution": candidate.get("affected_distribution"),
                "status": row.get("status"),
            })
        write_parquet(dataset / "eligibility_issues.parquet", issues)
    packages_path = dataset / "packages.parquet"
    if packages_path.exists():
        providers: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for package in read_parquet(packages_path):
            for root in package.get("import_roots") or []:
                providers[(str(package["env_id"]), str(root))].append(package)
        root_audit = []
        for (env_id, root), rows in sorted(providers.items()):
            unique = {str(row["package_id"]): row for row in rows}
            distributions = sorted(str(row["distribution"]) for row in unique.values())
            analyzable = sorted(
                str(row["distribution"]) for row in unique.values()
                if row.get("source_status") == "SOURCE_AVAILABLE"
            )
            if len(unique) == 1:
                status = "UNIQUE"
            elif analyzable:
                status = "RESOLVED_MULTI_PROVIDER_EXPANSION"
            else:
                status = "UNRESOLVED_NO_SOURCE_PROVIDER"
            root_audit.append({
                "env_id": env_id, "import_root": root, "provider_count": len(unique),
                "distributions": distributions, "analyzable_distributions": analyzable,
                "status": status,
            })
        write_parquet(dataset / "import_root_audit.parquet", root_audit)
        counts = Counter(row["status"] for row in root_audit)
        result["import_root_audit"] = {
            "root_count": len(root_audit),
            "collision_count": sum(row["provider_count"] > 1 for row in root_audit),
            "unresolved_collision_count": counts["UNRESOLVED_NO_SOURCE_PROVIDER"],
            "status_counts": dict(counts),
            "resolution": "expand every source-available provider for a shared namespace root",
        }
    write_json(dataset / "audit_summary.json", result)
    typer.echo(json.dumps(result, indent=2))


@app.command("repro-check")
def repro_check(
    dataset: Path = typer.Option(DEFAULT_DATASET),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS),
    project_id: list[str] = typer.Option([], "--project-id"),
) -> None:
    """Rebuild one environment per lockfile type twice and compare stable identities."""
    environments = read_parquet(dataset / "environments.parquet")
    if not environments:
        raise typer.BadParameter("build environments before running reproducibility checks")
    by_project = {str(row["project_id"]): row for row in environments}
    if project_id:
        selected = list(dict.fromkeys(project_id))
    else:
        by_lock = {}
        for row in sorted(environments, key=lambda item: str(item["project_id"])):
            by_lock.setdefault(str(row["lockfile_type"]), str(row["project_id"]))
        selected = [by_lock[key] for key in sorted(by_lock)]
    unknown = sorted(set(selected) - by_project.keys())
    if unknown:
        raise typer.BadParameter(f"unknown or unbuilt project ids: {unknown}")

    def identity(project: str) -> dict:
        current_env = next(row for row in read_parquet(dataset / "environments.parquet") if row["project_id"] == project)
        package_ids = sorted(
            str(row["package_id"]) for row in read_parquet(dataset / "packages.parquet")
            if row["project_id"] == project
        )
        return {
            "project_id": project,
            "lockfile_type": current_env["lockfile_type"],
            "installed_distribution_manifest_hash": current_env["installed_distribution_manifest_hash"],
            "package_ids": package_ids,
        }

    resolver = EnvironmentResolver(REPO_ROOT, dataset, jarvis_root)
    records = []
    for project in selected:
        baseline = identity(project)
        previous = baseline
        for repeat in (1, 2):
            build_result = build_environments(resolver, project_ids={project}, force_rebuild=True)
            current = identity(project)
            build_ok = build_result["environment_count"] == 1
            manifest_match = build_ok and current["installed_distribution_manifest_hash"] == baseline["installed_distribution_manifest_hash"]
            package_ids_match = build_ok and current["package_ids"] == baseline["package_ids"]
            records.append({
                "project_id": project, "lockfile_type": baseline["lockfile_type"], "repeat": repeat,
                "build_ok": build_ok,
                "manifest_match": manifest_match, "package_ids_match": package_ids_match,
                "manifest_hash": current["installed_distribution_manifest_hash"],
                "package_id_count": len(current["package_ids"]),
                "same_as_previous_repeat": current == previous,
            })
            previous = current
    payload = {
        "status": "PASS" if all(row["manifest_match"] and row["package_ids_match"] for row in records) else "FAIL",
        "selected_projects": selected, "records": records,
    }
    write_json(dataset / "reproducibility_summary.json", payload)
    typer.echo(json.dumps(payload, indent=2))
    if payload["status"] != "PASS":
        raise typer.Exit(2)


@app.command("oracle-import")
def oracle_import(workbook: Path = typer.Argument(..., exists=True), dataset: Path = typer.Option(DEFAULT_DATASET)) -> None:
    typer.echo(json.dumps(import_oracle(workbook, dataset), indent=2))


@app.command("oracle-review")
def oracle_review(decisions: Path = typer.Argument(..., exists=True), dataset: Path = typer.Option(DEFAULT_DATASET)) -> None:
    typer.echo(json.dumps(adjudicate_oracle(dataset, decisions), indent=2))


def _runner(dataset: Path, jarvis_root: Path) -> ExperimentRunner:
    if not jarvis_root.is_dir():
        raise typer.BadParameter(f"JARVIS root missing: {jarvis_root}")
    return ExperimentRunner(dataset, jarvis_root)


@app.command("fresh")
def fresh(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS), limit: int = typer.Option(0),
) -> None:
    typer.echo(json.dumps(_runner(dataset, jarvis_root).run(output_root, strategy="fresh", order="PROJECT_MAJOR", limit=limit), indent=2))


@app.command("baselines")
def baselines(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS), limit: int = typer.Option(0),
) -> None:
    """Run RQ1 package-exposure and project-usage baselines."""
    runner = _runner(dataset, jarvis_root)
    summaries = [
        runner.run(output_root, strategy=strategy, order="PROJECT_MAJOR", limit=limit)
        for strategy in ("package_exposure", "usage_filter")
    ]
    typer.echo(json.dumps(summaries, indent=2))


@app.command("determinism")
def determinism(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS), seed: int = typer.Option(17),
    fraction: float = typer.Option(0.1, min=0.0, max=1.0),
) -> None:
    """Run a deterministic 10% sample three times and compare semantic/work counters."""
    runner = _runner(dataset, jarvis_root)
    import random

    sample = list(runner.queries)
    random.Random(seed).shuffle(sample)
    runner.queries = sample[: max(1, round(len(sample) * fraction))]
    summaries, result_sets = [], []
    for repeat in range(1, 4):
        summary = runner.run(
            output_root, strategy="fresh", order="PROJECT_MAJOR",
            run_label=f"determinism-seed-{seed}-repeat-{repeat}",
        )
        summaries.append(summary)
        result_sets.append({row["query_id"]: row for row in read_parquet(output_root / summary["run_id"] / "query_results.parquet")})
    reference = result_sets[0]
    mismatches = []
    for repeat, results in enumerate(result_sets[1:], 2):
        for query_id, first in reference.items():
            second = results.get(query_id)
            fields = ("decision", "witnesses", "functions_analyzed", "unique_functions_analyzed", "call_edges_materialized")
            if second is None or any(first[field] != second[field] for field in fields):
                mismatches.append({"repeat": repeat, "query_id": query_id})
    payload = {"sample_size": len(reference), "runs": summaries, "mismatch_count": len(mismatches), "mismatches": mismatches}
    write_json(output_root / f"determinism-{seed}.json", payload)
    typer.echo(json.dumps(payload, indent=2))
    if mismatches:
        raise typer.Exit(2)


@app.command("compare")
def compare(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS),
    strategy: list[str] = typer.Option(["fresh", "project_local", "eager_shared", "progressive_shared"], "--strategy"),
    order: list[str] = typer.Option(["PROJECT_MAJOR", "CVE_MAJOR", "RANDOM"], "--order"),
    seed: int = typer.Option(1), seeds: str = typer.Option("1:30"), limit: int = typer.Option(0),
) -> None:
    runner = _runner(dataset, jarvis_root)
    if ":" in seeds:
        low, high = (int(part) for part in seeds.split(":", 1))
        random_seeds = range(low, high + 1)
    else:
        random_seeds = [int(part) for part in seeds.split(",") if part.strip()]
    summaries = []
    for ordering in order:
        for current_seed in (random_seeds if ordering == "RANDOM" else [seed]):
            for current_strategy in strategy:
                summaries.append(runner.run(output_root, strategy=current_strategy, order=ordering, seed=current_seed, limit=limit))
    typer.echo(json.dumps(summaries, indent=2))


@app.command("ablate")
def ablate(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS), limit: int = typer.Option(0),
) -> None:
    runner = _runner(dataset, jarvis_root)
    summaries = []
    for strategy in ("fresh", "project_local", "eager_shared", "progressive_shared"):
        summaries.append(runner.run(output_root, strategy=strategy, order="PROJECT_MAJOR", limit=limit))
    for budget in (20, 40, 60, 100, None):
        summaries.append(runner.run(output_root, strategy="progressive_shared", order="PROJECT_MAJOR", root_budget=budget, limit=limit))
    for depth in (1, 2, 3, 4, None):
        summaries.append(runner.run(output_root, strategy="progressive_shared", order="PROJECT_MAJOR", max_depth=depth, limit=limit))
    summaries.append(runner.run(output_root, strategy="progressive_shared", order="PROJECT_MAJOR", root_budget=60, max_depth=2, fallback_expansion=False, limit=limit))
    summaries.append(runner.run(output_root, strategy="progressive_shared", order="PROJECT_MAJOR", root_budget=60, max_depth=2, fallback_expansion=True, limit=limit))
    typer.echo(json.dumps(summaries, indent=2))


@app.command("vf")
def vf(
    variants: Path = typer.Argument(..., exists=True), dataset: Path = typer.Option(DEFAULT_DATASET),
    output_root: Path = typer.Option(DEFAULT_RUNS), jarvis_root: Path = typer.Option(DEFAULT_JARVIS),
    limit: int = typer.Option(0),
) -> None:
    """Run frozen V0/V1/V2 VF manifests; each row has query_id, variant, vf_set."""
    runner = _runner(dataset, jarvis_root)
    source = read_parquet(variants) if variants.suffix == ".parquet" else [json.loads(line) for line in variants.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_variant: dict[str, dict[str, list[dict]]] = {}
    for row in source:
        by_variant.setdefault(str(row["variant"]), {})[str(row["query_id"])] = row["vf_set"]
    baseline_name = "V0_ORACLE" if "V0_ORACLE" in by_variant else ("V0" if "V0" in by_variant else "oracle")
    baseline = by_variant.get(baseline_name, {})
    original = runner.queries
    summaries = []
    for variant, anchors in sorted(by_variant.items()):
        runner.queries = []
        for query in original:
            if query["query_id"] not in anchors:
                continue
            selected = anchors[query["query_id"]]
            valid = bool(selected) and all(item.get("package_id") == query["affected_package_id"] and item.get("function_hash") and item.get("file") for item in selected)
            runner.queries.append(query | {"vf_set": selected, "eligibility_reason": "eligible" if valid else "UNKNOWN_VF_MISMATCH"})
        summary = runner.run(output_root, strategy="fresh", order="PROJECT_MAJOR", limit=limit, run_label=variant)
        input_metrics = {
            "variant": variant, "baseline": baseline_name,
            **vf_input_quality(baseline, anchors),
        }
        write_json(output_root / summary["run_id"] / "vf_input_metrics.json", input_metrics)
        summaries.append({"variant": variant, "vf_input_metrics": input_metrics, **summary})
    runner.queries = original
    typer.echo(json.dumps(summaries, indent=2))


@app.command("vf-build")
def vf_build(
    workbook: Path = typer.Argument(..., exists=True),
    dataset: Path = typer.Option(DEFAULT_DATASET),
    patch_source: Path = typer.Option(REPO_ROOT / "data" / "interim" / "current_cve_vf" / "current_candidate_functions.jsonl"),
    output: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "vf_variants.parquet"),
) -> None:
    typer.echo(json.dumps(build_vf_variants(dataset, workbook, patch_source, output), indent=2))


@app.command("report")
def report(dataset: Path = typer.Option(DEFAULT_DATASET), output_dir: Path = typer.Option(REPO_ROOT / "results" / "experiment_report"), run: list[Path] = typer.Option([], "--run")) -> None:
    runs = run or sorted(path for path in DEFAULT_RUNS.iterdir() if path.is_dir() and (path / "summary.json").is_file())
    typer.echo(json.dumps(generate_report(dataset, runs, output_dir), indent=2))
