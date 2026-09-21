"""Rebuild case_pool.json from Phase 1 direct outputs + ground truth.

The case pool contains *demonstrations* only — CVEs whose `role` is
"casepool" in cve_descriptions.json. Eval CVEs are excluded unless
`--include-all` is used for leave-one-out; the S-ICL/P-ICL retrievers then
exclude the query CVE by id so it cannot demonstrate itself.

Reads from:
  - results/evaluation/adapters/vffinder/cve_descriptions.json
                                                (role labels: eval | casepool)
  - results/evaluation/adapters/vffinder/native_output/direct_phase1.json
                                                (Phase 1 direct-level outputs)
  - results/evaluation/adapters/vffinder/ground_truth_sample.json
  - results/evaluation/adapters/vffinder/native_output/description_corpus.json
                                                (for stemmed AV/RC tokens)
  - results/evaluation/adapters/vffinder/cve_library_map.json

Writes:
  - results/evaluation/adapters/vffinder/native_output/case_pool.json
"""
import argparse
import json
import sys
from pathlib import Path

_parser = argparse.ArgumentParser(description=__doc__)
_parser.add_argument(
    "--include-all", action="store_true",
    help="Include every CVE with a direct Phase 1 output in the pool, not just "
         "role=='casepool' CVEs. Use for a full leave-one-out run where all "
         "CVEs are eval: the s-icl/p-icl retriever excludes the query CVE by "
         "id, so a CVE never picks itself as a demonstration.")
_args = _parser.parse_args()

from pyshare.evaluation.methods.vffinder import config
from pyshare.evaluation.methods.vffinder.extraction.case_pool import (
    CaseEntry, save_case_pool, extract_dep_triplets)
from pyshare.evaluation.methods.vffinder.extraction.icl_extractor import load_nlp
from pyshare.evaluation.methods.vffinder.extraction import phase1_store
from pyshare.evaluation.methods.vffinder.corpus.description_corpus import build_cve_description_corpus

CVE_DESC_PATH = config.DATA_DIR / "cve_descriptions.json"
GT_PATH = config.DATA_DIR / "ground_truth_sample.json"
LIB_MAP_PATH = config.DATA_DIR / "cve_library_map.json"
DESC_CORPUS_PATH = config.OUTPUT_DIR / "description_corpus.json"
OUT_PATH = config.OUTPUT_DIR / "case_pool.json"

# Load role labels — only casepool CVEs are eligible as demonstrations.
if not CVE_DESC_PATH.exists():
    print(f"ERROR: {CVE_DESC_PATH} not found. Run prepare_webapp_data.py first.",
          file=sys.stderr)
    sys.exit(1)
with open(CVE_DESC_PATH) as f:
    _desc_raw = json.load(f)
CASEPOOL_CVES = {
    k for k, v in _desc_raw.items()
    if not k.startswith("_") and isinstance(v, dict) and v.get("role") == "casepool"
}
VPV_BY_CVE = {
    k: v.get("vendor_product_version", [])
    for k, v in _desc_raw.items()
    if not k.startswith("_") and isinstance(v, dict)
}
print(f"Casepool CVEs from {CVE_DESC_PATH.name}: {len(CASEPOOL_CVES)}")

with open(GT_PATH) as f:
    ground_truth = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
with open(LIB_MAP_PATH) as f:
    library_map = {k: v for k, v in json.load(f).items() if not k.startswith("_")}

# Load existing description corpus (eval CVEs only — won't have casepool tokens
# here unless someone built it separately; fall back to building from Phase 1).
desc_corpus: dict = {}
if DESC_CORPUS_PATH.exists():
    with open(DESC_CORPUS_PATH) as f:
        desc_corpus = json.load(f)

# Load Phase 1 direct outputs from the single direct_phase1.json file.
phase1: dict[str, dict] = phase1_store.load_phase1("direct")

print(f"Phase 1 outputs found: {len(phase1)} CVEs")

print("Loading spaCy ...")
nlp = load_nlp()

entries: list[CaseEntry] = []
skipped_role = 0
skipped_phase1 = 0

for cve_id, gt_funcs in ground_truth.items():
    if not _args.include_all and cve_id not in CASEPOOL_CVES:
        skipped_role += 1
        continue
    if cve_id not in phase1:
        skipped_phase1 += 1
        continue

    rec = phase1[cve_id]
    description = rec.get("description", "")

    # AV/RC stemmed tokens: prefer existing description corpus, else build from Phase 1
    if cve_id in desc_corpus and isinstance(desc_corpus[cve_id], dict):
        av_tokens = desc_corpus[cve_id].get("av", [])
        rc_tokens = desc_corpus[cve_id].get("rc", [])
    else:
        av_phrases = rec.get("attack_vector", [])
        rc_phrases = rec.get("root_cause", [])
        built = build_cve_description_corpus(
            cve_id,
            av_phrases,
            rc_phrases,
            nlp,
            vendor_product_version=VPV_BY_CVE.get(cve_id, []),
        )
        av_tokens = built.get("av", [])
        rc_tokens = built.get("rc", [])

    dep_triplets = extract_dep_triplets(nlp, description)

    entry = CaseEntry(
        cve_id=cve_id,
        description=description,
        attack_vector=rec.get("attack_vector", []),
        root_cause=rec.get("root_cause", []),
        av_tokens=av_tokens,
        rc_tokens=rc_tokens,
        vulnerable_functions=gt_funcs,
        library=library_map.get(cve_id, ""),
        dep_triplets=dep_triplets,
    )
    entries.append(entry)
    print(f"  {cve_id}: av={len(av_tokens)} rc={len(rc_tokens)} triplets={len(dep_triplets)}")

save_case_pool(entries, OUT_PATH)
print(f"\nSaved {len(entries)} entries -> {OUT_PATH}")
print(f"  skipped (role != casepool): {skipped_role}")
print(f"  skipped (no Phase 1 output): {skipped_phase1}")
