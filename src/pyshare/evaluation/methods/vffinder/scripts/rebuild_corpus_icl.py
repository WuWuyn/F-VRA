"""Rebuild description_corpus from S-ICL or P-ICL Phase 1 outputs.

Mirrors rebuild_corpus_direct.py: only eval CVEs (role == "eval" in
cve_descriptions.json) are included, so the retrieval-stage corpus stays
aligned across direct / s-icl / p-icl levels.
"""
import json, sys, argparse
from pathlib import Path

import spacy
from pyshare.evaluation.methods.vffinder.corpus.description_corpus import build_cve_description_corpus
from pyshare.evaluation.methods.vffinder.extraction import phase1_store
from pyshare.evaluation.methods.vffinder import config

parser = argparse.ArgumentParser()
parser.add_argument("--level", choices=["s-icl", "p-icl"], required=True)
args = parser.parse_args()

# Load eval CVEs from cve_descriptions.json — only those are scored.
desc_path = config.DATA_DIR / "cve_descriptions.json"
if desc_path.exists():
    with open(desc_path, encoding="utf-8") as f:
        _raw = json.load(f)
    EVAL_CVES = {
        k for k, v in _raw.items()
        if not k.startswith("_") and isinstance(v, dict) and v.get("role") == "eval"
    }
    VPV_BY_CVE = {
        k: v.get("vendor_product_version", [])
        for k, v in _raw.items()
        if not k.startswith("_") and isinstance(v, dict)
    }
    print(f"Loaded {len(EVAL_CVES)} eval CVEs from {desc_path}")
else:
    print(f"WARNING: {desc_path} not found — processing all Phase 1 outputs",
          file=sys.stderr)
    EVAL_CVES = None  # sentinel: do not filter
    VPV_BY_CVE = {}

nlp = spacy.load(config.SPACY_MODEL)
corpus = {}
component_stats = {
    "component": "description_preprocessing",
    "variant": args.level,
    "spacy_model": config.SPACY_MODEL,
    "cves_seen": 0,
    "raw_tokens": 0,
    "refined_tokens": 0,
    "filtered_tokens": 0,
    "output_tokens": 0,
    "vpv_terms_removed": 0,
    "by_cve": {},
}

for cve_id, rec in sorted(phase1_store.load_phase1(args.level).items()):
    if EVAL_CVES is not None and cve_id not in EVAL_CVES:
        continue
    av = rec.get("attack_vector") or []
    rc = rec.get("root_cause") or []
    processed = build_cve_description_corpus(
        cve_id,
        av,
        rc,
        nlp,
        vendor_product_version=VPV_BY_CVE.get(cve_id, []),
        stats=component_stats,
    )
    component_stats["cves_seen"] += 1
    corpus[cve_id] = {
        "av": processed["av"],
        "rc": processed["rc"],
        "av_raw": " ".join(av),
        "rc_raw": " ".join(rc),
    }
    print(f"  {cve_id}: av={len(processed['av'])} rc={len(processed['rc'])}")

out = config.OUTPUT_DIR / f"description_corpus_{args.level.replace('-','_')}.json"
out.parent.mkdir(parents=True, exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(corpus, f, indent=2, ensure_ascii=False)
print(f"\nBuilt {len(corpus)} entries -> {out}")

component_stats["cves_with_vpv_terms"] = sum(
    1 for row in component_stats["by_cve"].values()
    if row.get("vpv_terms_configured", 0) > 0
)
component_stats["cves_with_vpv_terms_removed"] = sum(
    1 for row in component_stats["by_cve"].values()
    if row.get("removed_terms")
)
counter_out = out.with_name(out.stem + "_counters.json")
with open(counter_out, "w", encoding="utf-8") as f:
    json.dump(component_stats, f, indent=2, ensure_ascii=False)
print(f"Description counters -> {counter_out}")
