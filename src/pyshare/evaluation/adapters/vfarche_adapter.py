"""VFArche adapter for the normalized evaluation harness.

Native pipeline: `python -m pyshare.evaluation.methods.vfarche.cli run --dataset <jsonl>` clones the repo,
AST-parses functions, ranks by BM25, optionally reranks, and saves the top-k to
MongoDB (`topk_results`). The adapter exports those saved top-k rows and writes
the common prediction contract.

Outputs use the canonical method name `vfarche`.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .base import (
    MethodAdapter,
    REPO_ROOT,
    RunContext,
    iter_master,
    load_master_index,
    pred_record,
    run_step,
    write_jsonl,
)
from pyshare.evaluation.paths import ADAPTER_RESULTS_ROOT, METHODS_ROOT

VFARCHE = METHODS_ROOT / "vfarche"
ADAPTER_DATA_DIR = ADAPTER_RESULTS_ROOT / "vfarche"
INPUT_JSONL = ADAPTER_DATA_DIR / "from_master.jsonl"

# Tiny exporter run inside VFArche's interpreter: dump the saved top-k for the
# given CVE ids from MongoDB to a JSON file. This keeps pymongo out of the
# evaluation harness environment.
_EXPORT_CODE = (
    "import json,sys,os\n"
    "sys.path.insert(0, os.getcwd())\n"
    "from pyshare.evaluation.methods.vfarche.storage.mongo import load_topk\n"
    "ids=json.load(open(sys.argv[1],encoding='utf-8'))\n"
    "out={}\n"
    "for c in ids:\n"
    "    d=load_topk(c)\n"
    "    if d: out[c]={'topk':d.get('topk',[]),'telemetry':d.get('telemetry',{})}\n"
    "json.dump(out, open(sys.argv[2],'w',encoding='utf-8'))\n"
)


def to_vfarche(rec: dict) -> dict | None:
    """master record -> VFArCHE input record.

    VFArCHE checks out the commit it is given directly, so this adapter must use
    `vulnerable_ref` rather than the fix commit SHA used by VFDetector.
    """
    rcf = rec.get("root_cause_functions") or []
    if not rcf:
        return None
    funcs = [f["function_name"] for f in rcf if f.get("function_name")]
    if not (funcs and rec.get("repo_url") and rec.get("description")):
        return None
    ref = rec.get("vulnerable_ref")
    fix = None
    if not ref:
        patch = next(
            (p for p in rec.get("patches", []) if p.get("role") == "canonical_fix"),
            None,
        )
        ref = (patch or {}).get("parent_sha")
        fix = (patch or {}).get("sha")
    else:
        patch = next(
            (p for p in rec.get("patches", []) if p.get("role") == "canonical_fix"),
            None,
        )
        fix = (patch or {}).get("sha")
    if not ref:
        return None
    return {
        "cve_id": rec.get("advisory_id"),
        "repo_url": rec["repo_url"],
        "commit_sha": ref,
        "vulnerable_ref": ref,
        "fix_commit": fix,
        "vf_file": rcf[0].get("file_path", ""),
        "all_functions": funcs,
        "description": rec["description"],
        "cwes": rec.get("cwes") or [],
    }


class VFArcheAdapter(MethodAdapter):
    name = "vfarche"
    enabled = True

    def run(
        self,
        ctx: RunContext,
    ) -> list[Path]:
        # 1) Convert master -> VFArCHE input. Unlike VFDetector, VFArCHE
        # checks out the provided commit directly, so use vulnerable_ref.
        recs = [r for r in (to_vfarche(x) for x in iter_master(ctx.master_path)) if r]
        if ctx.limit:
            recs = recs[:ctx.limit]
        write_jsonl(INPUT_JSONL, recs)
        print(f"    [vfarche] {len(recs)} records -> {INPUT_JSONL}")
        cve_ids = [r["cve_id"] for r in recs]

        # 2) Run native pipeline. Env knobs are also used by ablation sweeps:
        #    VFARCHE_RERANK = chat|embedding|pairwise (default: BM25 only),
        #    VFARCHE_EXPAND = 1 to add description expansion.
        rerank = os.environ.get("VFARCHE_RERANK", "").strip()
        expand = os.environ.get("VFARCHE_EXPAND", "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        resume = os.environ.get("VFARCHE_RESUME", "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        continue_on_error = os.environ.get(
            "VFARCHE_CONTINUE_ON_ERROR", ""
        ).strip().lower() in ("1", "true", "yes")
        variant = ctx.variant or (rerank if rerank else "skip-llm")
        cli = ["python", "-m", "pyshare.evaluation.methods.vfarche.cli", "run", "--dataset", str(INPUT_JSONL)]
        cli += (["--rerank", rerank] if rerank else ["--skip-llm"])
        if expand:
            cli += ["--expand-description"]
        if resume:
            cli += ["--resume"]
        if continue_on_error:
            failure_log = ctx.out_dir / "logs" / "vfarche_failures.jsonl"
            cli += ["--continue-on-error", "--failure-log", str(failure_log)]
        run_step(cli, cwd=REPO_ROOT, python_bin=ctx.python_bin, timeout=24 * 3600)

        # 3) Export saved top-k from MongoDB -> common prediction contract.
        records = self._export_and_normalize(
            recs, cve_ids, variant, ctx
        )
        out_path = ctx.out_dir / f"{self.name}.jsonl"
        write_jsonl(out_path, records)
        print(f"    [vfarche] {len(records)} predictions -> {out_path}")
        return [out_path]

    def _export_and_normalize(
        self,
        recs: list[dict],
        cve_ids: list[str],
        variant: str,
        ctx: RunContext,
    ) -> list[dict]:
        gt_by_cve = {r["cve_id"]: r.get("all_functions", []) for r in recs}
        meta = load_master_index(ctx.master_path)
        with tempfile.TemporaryDirectory() as td:
            ids_path = Path(td) / "ids.json"
            out_path = Path(td) / "topk.json"
            script = Path(td) / "_export.py"
            ids_path.write_text(json.dumps(cve_ids), encoding="utf-8")
            script.write_text(_EXPORT_CODE, encoding="utf-8")
            try:
                run_step(
                    ["python", str(script), str(ids_path), str(out_path)],
                    cwd=REPO_ROOT,
                    python_bin=ctx.python_bin,
                    timeout=600,
                )
            except RuntimeError as exc:
                raise RuntimeError(
                    "could not export VFArCHE top-k from MongoDB. "
                    "Start MongoDB (`docker compose up -d mongo` in "
                    "configs/evaluation/vfarche) or set MONGO_URI to a reachable server."
                ) from exc
            topk_by_cve = json.loads(out_path.read_text(encoding="utf-8"))

        sources = {r.get('advisory_id'): r for r in iter_master(ctx.master_path)}
        records = []
        for cid in cve_ids:
            doc = topk_by_cve.get(cid, {})
            items = doc.get('topk', [])
            telemetry = doc.get('telemetry', {})
            ranked = [
                {
                    "func_id": (
                        f"{it.get('file')}::{it.get('qualname') or it.get('name')}"
                        if it.get("file") and it.get("name")
                        else it.get("qualname") or it.get("name", "")
                    ),
                    "qualified_name": it.get("qualname"),
                    "file_path": it.get("file"),
                    "function_name": it.get("name"),
                    "score": (
                        it.get("llm_score")
                        if it.get("llm_score") is not None
                        else it.get("embedding_score")
                        if it.get("embedding_score") is not None
                        else it.get("pairwise_score")
                        if it.get("pairwise_score") is not None
                        else it.get("swiss_score")
                        if it.get("swiss_score") is not None
                        else it.get("bm25_score")
                    ),
                }
                for it in items
            ]
            m = meta.get(cid, {})
            records.append(
                pred_record(
                    cid,
                    self.name,
                    variant,
                    ranked,
                    m.get("ground_truth") or gt_by_cve.get(cid, []),
                    group_id=m.get("group_id"),
                    experiment_group=ctx.experiment_group,
                    axis=ctx.axis,
                    runtime_secs=telemetry.get('runtime_secs'),
                    tokens=telemetry.get('tokens'),
                )
            )
            records[-1]['usage'] = telemetry
            records[-1]['match_policy'] = 'exact'
            source = sources.get(cid, {})
            truth = []
            for fn in source.get('root_cause_functions', []):
                path = fn.get('file_path', '').replace('\\', '/')
                qualified = fn.get('qualified_name') or fn.get('function_name', '')
                module = path.removesuffix('.py').replace('/', '.')
                if qualified.startswith(module + '.'):
                    qualified = qualified[len(module) + 1:]
                truth.append(f'{path}::{qualified}')
            records[-1]['ground_truth'] = truth
        return records
