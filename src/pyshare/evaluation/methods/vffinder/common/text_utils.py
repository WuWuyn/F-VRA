"""Shared NLP text helpers used across the pipeline.

These utilities are used by both Phase 2 (description corpus) and Phase 3
(function corpus). They mirror the original VFFinder (ASE'24) Java helpers in
`CommonUtils/textUtils.py` and `APIEntityExtraction/cleanEntity.py`:

  - identifier splitting (camelCase + snake_case)
  - POS filtering to nouns / verbs / adjectives
  - meaningless-token removal
  - WordNet-based deduplication
  - Porter stemming

Python adaptation vs the Java original:
  - split_identifier() adds underscore splitting before the camelCase regex
    (Python uses snake_case; Java uses camelCase exclusively).
"""

import re

import nltk
from nltk.corpus import wordnet
from nltk.stem import PorterStemmer


# ---------------------------------------------------------------------------
# NLTK data — download silently if missing
# ---------------------------------------------------------------------------

def _ensure_nltk():
    needed = [
        ("tokenizers/punkt_tab", "punkt_tab"),
        ("taggers/averaged_perceptron_tagger_eng", "averaged_perceptron_tagger_eng"),
        ("corpora/wordnet", "wordnet"),
        ("corpora/stopwords", "stopwords"),
    ]
    for resource_path, pkg in needed:
        try:
            nltk.data.find(resource_path)
        except LookupError:
            nltk.download(pkg, quiet=True)

_ensure_nltk()

from nltk.corpus import stopwords as _sw_corpus
_STOPWORDS = set(_sw_corpus.words("english"))
_STEMMER = PorterStemmer()


# ---------------------------------------------------------------------------
# Identifier splitting  (Python adaptation of split_camel_words)
# ---------------------------------------------------------------------------

def split_identifier(token: str) -> list[str]:
    """Split a snake_case and/or camelCase identifier into lowercase words.

    Examples
    --------
    >>> split_identifier("yaml_load")
    ['yaml', 'load']
    >>> split_identifier("ImageMath")
    ['image', 'math']
    >>> split_identifier("PIL.ImageMath.eval")
    ['pil', 'image', 'math', 'eval']
    >>> split_identifier("deserialization")
    ['deserialization']
    """
    # strip leading dots/underscores, split on dot first
    parts: list[str] = []
    for segment in re.split(r"[./]", token):
        # snake_case: split on underscores
        for snake_part in segment.split("_"):
            if not snake_part:
                continue
            # camelCase + acronyms + digits. The original author's regex
            # (`[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)`) truncated an ALL-CAPS acronym
            # when a digit followed it (SHA256 -> 'sh', HTTP2 -> 'htt') and
            # dropped digit runs entirely. This splits an acronym before a
            # CamelCase word (HTMLParser -> HTML, Parser), keeps trailing
            # acronyms (parseXML -> parse, XML) and emits digit runs (SHA256 ->
            # sha, 256). Pure-digit tokens are later dropped by the POS filter.
            camel_parts = re.findall(
                r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", snake_part)
            if camel_parts:
                parts.extend(camel_parts)
            else:
                parts.append(snake_part)
    return [p.lower() for p in parts if p]


# ---------------------------------------------------------------------------
# POS filtering  (identical to author's extract_noun_verb_wordnet)
# ---------------------------------------------------------------------------

# Per-word caches. The original pipeline tags/looks-up each word in isolation,
# so the result for a given word is deterministic and reused across every
# function in the corpus. Memoising collapses millions of repeated NLTK calls
# (full-project corpus) to one per unique word — identical output, ~100x faster.
_POS_CACHE: dict[str, str] = {}


def _cached_pos(word: str) -> str:
    tag = _POS_CACHE.get(word)
    if tag is None:
        tag = nltk.pos_tag([word])[0][1]
        _POS_CACHE[word] = tag
    return tag


def filter_noun_verb(token_list: list[str]) -> list[str]:
    """Keep only nouns (NN*), verbs (VB*), adjectives (JJ*) — NLTK POS tags."""
    kept = []
    for word in token_list:
        tag = _cached_pos(word)
        if tag.startswith("NN") or tag.startswith("VB") or tag.startswith("JJ"):
            kept.append(word)
    return kept


# ---------------------------------------------------------------------------
# Meaningless-word filter  (identical to author's filter_meaningless_words)
# ---------------------------------------------------------------------------

def filter_meaningless(entity_list: list[str]) -> list[str]:
    """Remove single chars, bracket tokens, underscore tokens, then POS-filter."""
    pre = [
        e for e in entity_list
        if len(e) > 1
        and "_" not in e
        and "[" not in e
        and "]" not in e
    ]
    return filter_noun_verb(pre)


# ---------------------------------------------------------------------------
# Entity refinement  (identical to author's refine_entity)
# ---------------------------------------------------------------------------

def refine_entities(entity_list: list[str]) -> list[str]:
    """Split on '/' and '.', then apply identifier splitting."""
    after: list[str] = []
    for entity in entity_list:
        if "/" in entity or "." in entity:
            # take the last component then split further
            last = re.split(r"[./]", entity)[-1]
            after.extend(split_identifier(last))
        else:
            after.extend(split_identifier(entity))
    return list(set(after))


# ---------------------------------------------------------------------------
# WordNet deduplication  (identical to author's remove_duplicate_entity)
# ---------------------------------------------------------------------------

_SYNSET_CACHE: dict[str, object] = {}


def _cached_first_synset(word: str):
    """First WordNet synset for `word` (or None), memoised per unique word."""
    if word not in _SYNSET_CACHE:
        syns = wordnet.synsets(word)
        _SYNSET_CACHE[word] = syns[0] if syns else None
    return _SYNSET_CACHE[word]


def deduplicate_wordnet(entity_list: list[str],
                        exclude: list[str] | None = None) -> list[str]:
    """Remove semantically identical words using WordNet synset equality."""
    entity_list = list(set(e.lower() for e in entity_list))
    seen_synsets = set()
    result = []
    for w in entity_list:
        syn = _cached_first_synset(w)
        if syn is None:
            result.append(w)
        elif syn not in seen_synsets:
            seen_synsets.add(syn)
            result.append(w)

    if exclude:
        exclude_lower = {e.lower() for e in exclude}
        result = [e for e in result if e not in exclude_lower]
    return result
