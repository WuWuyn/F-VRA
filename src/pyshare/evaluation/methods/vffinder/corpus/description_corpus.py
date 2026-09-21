"""Phase 2 — Description Corpus Generator.

Turns the raw Attack Vector / Root Cause phrases produced by Phase 1 into the
cleaned, stemmed token bags the retriever consumes.

Follows the original VFFinder (ASE'24) pipeline:
  1. Tokenise AV/RC text with spaCy
  2. POS-filter to nouns / verbs / adjectives
  3. Split identifiers (camelCase + snake_case)
  4. Lowercase and deduplicate with WordNet path_similarity
  5. Remove vendor/product/version tokens
  6. Porter-stem the result

The reusable text helpers (steps 2-4, 6) live in `vffinder/common/text_utils.py`.
"""

from ..common.text_utils import (
    refine_entities,
    filter_meaningless,
    deduplicate_wordnet,
    _STOPWORDS,
    _STEMMER,
)


def _process_phrases(
    phrases: list[str],
    nlp,
    vpv,
    stem: bool,
    *,
    stats: dict | None = None,
    cve_id: str | None = None,
    field: str | None = None,
) -> list[str]:
    """Tokenise, refine, filter and optionally stem a list of phrases."""
    raw_tokens: list[str] = []
    for phrase in (phrases or []):
        doc = nlp(phrase)
        raw_tokens.extend(tok.text for tok in doc
                          if not tok.is_space and not tok.is_punct)
    refined = refine_entities(raw_tokens)
    refined = [e for e in refined if e not in _STOPWORDS]
    filtered = filter_meaningless(refined)
    deduped_before_vpv = deduplicate_wordnet(filtered)
    vpv_terms = {str(e).lower() for e in (vpv or [])}
    removed = sorted({e for e in deduped_before_vpv if e.lower() in vpv_terms})
    deduped = [e for e in deduped_before_vpv if e.lower() not in vpv_terms]
    if stem:
        deduped = list({_STEMMER.stem(e) for e in deduped})
    if stats is not None:
        stats["raw_tokens"] = stats.get("raw_tokens", 0) + len(raw_tokens)
        stats["refined_tokens"] = stats.get("refined_tokens", 0) + len(refined)
        stats["filtered_tokens"] = stats.get("filtered_tokens", 0) + len(filtered)
        stats["output_tokens"] = stats.get("output_tokens", 0) + len(deduped)
        stats["vpv_terms_removed"] = stats.get("vpv_terms_removed", 0) + len(removed)
        by_cve = stats.setdefault("by_cve", {})
        row = by_cve.setdefault(
            cve_id or "",
            {"vpv_terms_configured": len(vpv_terms), "removed_terms": []},
        )
        row["vpv_terms_configured"] = len(vpv_terms)
        row["removed_terms"] = sorted(set(row.get("removed_terms", []) + removed))
        if field:
            row[f"{field}_tokens"] = len(deduped)
    return deduped


def build_cve_description_corpus(
    cve_id: str,
    attack_vector: list[str],
    root_cause: list[str],
    nlp,
    vendor_product_version: list[str] | None = None,
    stem: bool = True,
    stats: dict | None = None,
) -> dict[str, list[str]]:
    """Build the description-side entity corpus for one CVE.

    Returns {"av": [...], "rc": [...]} kept separate for inspection/ablation.
    The retriever (Algorithm 1) merges AV ∪ RC into one bag and weights each
    entity by TF-IDF (paper §4.2 iii / §4.4) — there is NO fixed AV/RC split.
    """
    vpv = vendor_product_version
    return {
        "av": _process_phrases(
            attack_vector, nlp, vpv, stem,
            stats=stats, cve_id=cve_id, field="av",
        ),
        "rc": _process_phrases(
            root_cause, nlp, vpv, stem,
            stats=stats, cve_id=cve_id, field="rc",
        ),
    }
