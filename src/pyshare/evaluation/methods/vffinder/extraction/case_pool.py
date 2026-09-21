"""Case pool for S-ICL and P-ICL.

Stores labeled (CVE, vulnerable_functions) pairs used as few-shot
demonstrations in Phase 1 (ICL-Enhanced Extractor).

S-ICL retrieves cases by semantic cosine over UAE sentence embeddings.
P-ICL retrieves cases by grammatical PATTERN (constituency-parse + autoencoder,
see extraction/pattern_embed.py).

The case pool itself is built by `vffinder/scripts/rebuild_case_pool.py`.
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np


# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------

@dataclass
class CaseEntry:
    cve_id: str
    description: str
    attack_vector: list[str]        # raw AV phrases from Phase 1
    root_cause: list[str]           # raw RC phrases from Phase 1
    av_tokens: list[str]            # stemmed AV tokens (Phase 2)
    rc_tokens: list[str]            # stemmed RC tokens (Phase 2)
    vulnerable_functions: list[str] # func_ids from ground truth
    library: str                    # target library name
    dep_triplets: list[tuple[str, str, str]] = field(default_factory=list)
    # (subject, relation, object) from spaCy dep-parse of description


# ---------------------------------------------------------------------------
# Dependency parse triplet extraction  (legacy metadata)
# ---------------------------------------------------------------------------

def extract_dep_triplets(nlp, text: str) -> list[tuple[str, str, str]]:
    """Extract (subject, dep_relation, head) triplets from text.

    These capture syntactic structure for inspection/back-compat. Current
    P-ICL retrieval uses constituency-pattern autoencoder embeddings instead.
    """
    doc = nlp(text)
    triplets: list[tuple[str, str, str]] = []
    for token in doc:
        if token.dep_ in ("nsubj", "nsubjpass", "dobj", "pobj", "attr",
                           "appos", "nmod", "compound"):
            subj = token.lemma_.lower()
            rel = token.dep_
            head = token.head.lemma_.lower()
            if subj and head and subj != head:
                triplets.append((subj, rel, head))
    return triplets


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_case_pool(entries: list[CaseEntry], out_path: Path) -> None:
    records = [
        {
            "cve_id": e.cve_id,
            "description": e.description,
            "attack_vector": e.attack_vector,
            "root_cause": e.root_cause,
            "av_tokens": e.av_tokens,
            "rc_tokens": e.rc_tokens,
            "vulnerable_functions": e.vulnerable_functions,
            "library": e.library,
            "dep_triplets": e.dep_triplets,
        }
        for e in entries
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def load_case_pool(path: Path) -> list[CaseEntry]:
    with open(path, encoding="utf-8") as f:
        records = json.load(f)
    return [
        CaseEntry(
            cve_id=r["cve_id"],
            description=r["description"],
            attack_vector=r["attack_vector"],
            root_cause=r["root_cause"],
            av_tokens=r["av_tokens"],
            rc_tokens=r["rc_tokens"],
            vulnerable_functions=r["vulnerable_functions"],
            library=r["library"],
            dep_triplets=[tuple(t) for t in r["dep_triplets"]],
        )
        for r in records
    ]


# ---------------------------------------------------------------------------
# Anchor abstraction (paper §4.1.2) — replace the four anchor entities (VPV,
# vulnerability-type, component, attacker) with abstract tokens so two CVEs with
# DIFFERENT vocabulary but the SAME structure look alike. P-ICL selects demos on
# this abstracted form; that abstraction is the core of pattern-based selection.
# Paper recognises anchors "by LLM or regex"; this is the regex path.
# ---------------------------------------------------------------------------

_VTYPE_RE = re.compile(
    r"\b(cross[- ]site scripting|xss|sql injection|command injection|"
    r"remote code execution|rce|denial of service|dos|buffer overflow|"
    r"path traversal|directory traversal|csrf|cross[- ]site request forgery|"
    r"ssrf|server[- ]side request forgery|open redirect|deserializ\w*|"
    r"arbitrary (?:file |code )?(?:read|write|upload|execution)|"
    r"information (?:disclosure|leak)|privilege escalation|use[- ]after[- ]free|"
    r"integer overflow|race condition|improper (?:authentication|authorization|"
    r"validation|access control)|cwe-\d+)\b", re.I)
_ATTACKER_RE = re.compile(
    r"\b(?:remote |local |authenticated |unauthenticated |anonymous |malicious )*"
    r"(?:attackers?|adversar\w+)\b|\b(?:authenticated|unauthenticated|anonymous|"
    r"malicious) users?\b", re.I)
_COMPONENT_RE = re.compile(r"\b[\w/]+\.py\b|\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\b")
_VER_PHRASE_RE = re.compile(
    r"\b(?:before|after|through|prior to|up to|earlier than|and earlier|"
    r"and prior|versions?)\b", re.I)
_VERSION_RE = re.compile(r"\b\d+(?:\.\d+)+[a-z0-9.\-]*\b")
_LLM_ANCHOR_CACHE: dict[tuple[str, str], dict[str, list[str]]] = {}


def _anchor_mode() -> str:
    return (
        os.environ.get("VFFINDER_ANCHOR_MODE")
        or os.environ.get("VFF_ANCHOR_MODE")
        or "regex"
    ).lower().replace("-", "_").replace("+", "_")


def _regex_anchor_matches(text: str, product: Optional[str] = None) -> dict[str, list[str]]:
    s = text or ""
    return {
        "product": re.findall(re.escape(product), s, flags=re.I) if product else [],
        "component": _COMPONENT_RE.findall(s),
        "vulnerability_type": _VTYPE_RE.findall(s),
        "attacker": _ATTACKER_RE.findall(s),
        "version_phrase": _VER_PHRASE_RE.findall(s),
        "version": _VERSION_RE.findall(s),
    }


def _ner_anchor_matches(text: str) -> dict[str, list[str]]:
    """spaCy NER-style VPV/component recognizer; regex still handles vuln type."""
    try:
        import spacy
    except ImportError:
        return {}
    if not hasattr(_ner_anchor_matches, "_nlp"):
        try:
            _ner_anchor_matches._nlp = spacy.load("en_core_web_sm")
        except OSError:
            return {}
    doc = _ner_anchor_matches._nlp(text or "")
    out: dict[str, list[str]] = {"product": [], "component": [], "version": []}
    for ent in doc.ents:
        value = ent.text.strip()
        if not value:
            continue
        if ent.label_ in {"PRODUCT", "ORG"}:
            out["product"].append(value)
            out["component"].append(value)
        elif ent.label_ in {"VERSION", "CARDINAL"} and _VERSION_RE.fullmatch(value):
            out["version"].append(value)
    return out


def _llm_anchor_matches(text: str) -> dict[str, list[str]]:
    """Optional source-style recognizer using the configured LLM, with cache."""
    key = (text or "", os.environ.get("VFFINDER_MODEL", ""))
    if key in _LLM_ANCHOR_CACHE:
        return _LLM_ANCHOR_CACHE[key]
    try:
        from ..common.llm_client import query_llm
    except Exception:
        return {}
    prompt = (
        "Extract vulnerability anchor entities from this CVE description. "
        "Return strict JSON with keys product, component, vulnerability_type, "
        "attacker, version. Each value must be a list of exact text spans from "
        "the input. Do not invent spans.\n\nDescription:\n"
        f"{(text or '').strip()[:4000]}"
    )
    try:
        raw = query_llm(prompt, temperature=0.0)
        start = raw.find("{")
        end = raw.rfind("}") + 1
        parsed = json.loads(raw[start:end])
    except Exception:
        return {}
    out: dict[str, list[str]] = {}
    for field in ("product", "component", "vulnerability_type", "attacker", "version"):
        vals = parsed.get(field) or []
        if isinstance(vals, str):
            vals = [vals]
        out[field] = [
            str(v).strip() for v in vals
            if str(v).strip() and str(v).strip() in (text or "")
        ]
    _LLM_ANCHOR_CACHE[key] = out
    return out


def recognize_anchors(
    text: str,
    product: Optional[str] = None,
    mode: Optional[str] = None,
) -> dict[str, list[str]]:
    """Recognize paper §4.1.2 anchors with regex fallback.

    Modes:
      regex      - regex-only baseline.
      ner_regex  - spaCy NER for product/component/version + regex fallback.
      llm_regex  - configured LLM span extractor + regex fallback.
    """
    mode = (mode or _anchor_mode()).lower().replace("-", "_").replace("+", "_")
    out = _regex_anchor_matches(text, product)
    extra = {}
    if mode in {"ner", "ner_regex"}:
        extra = _ner_anchor_matches(text)
    elif mode in {"llm", "llm_regex", "llm_ner_regex"}:
        extra = _llm_anchor_matches(text)
        if mode == "llm_ner_regex":
            ner = _ner_anchor_matches(text)
            for key, values in ner.items():
                extra.setdefault(key, []).extend(values)
    for key, values in extra.items():
        merged = out.setdefault(key, [])
        for value in values:
            if value and value not in merged:
                merged.append(value)
    return {key: list(dict.fromkeys(values)) for key, values in out.items()}


def _replace_literals(text: str, values: list[str], repl: str) -> str:
    out = text
    for value in sorted(set(values), key=len, reverse=True):
        if value:
            out = re.sub(re.escape(value), repl, out, flags=re.I)
    return out


def anchor_fire_counts(text: str, product: Optional[str] = None) -> dict[str, int]:
    """Count regex anchor recognizer hits without changing anchor_abstract output."""
    return {key: len(values) for key, values in recognize_anchors(text, product).items()}


def anchor_abstract(text: str, product: Optional[str] = None) -> str:
    """Replace VPV / vuln-type / component / attacker spans with anchor tokens.

    Order matters: product → component → vuln-type → attacker → version, so a
    more specific span is consumed before a generic one overlaps it.
    """
    s = text or ""
    anchors = recognize_anchors(s, product)
    if _anchor_mode() != "regex":
        s = _replace_literals(s, anchors.get("product", []), " PRODUCT ")
        s = _replace_literals(s, anchors.get("component", []), " COMPONENT ")
        s = _replace_literals(s, anchors.get("vulnerability_type", []), " VTYPE ")
        s = _replace_literals(s, anchors.get("attacker", []), " ATTACKER ")
        s = _replace_literals(s, anchors.get("version", []), " VERSION ")
    if product:
        s = re.sub(re.escape(product), " PRODUCT ", s, flags=re.I)
    s = _COMPONENT_RE.sub(" COMPONENT ", s)
    s = _VTYPE_RE.sub(" VTYPE ", s)
    s = _ATTACKER_RE.sub(" ATTACKER ", s)
    s = _VER_PHRASE_RE.sub(" ", s)
    s = _VERSION_RE.sub(" VERSION ", s)
    return re.sub(r"\s+", " ", s).strip()


# ---------------------------------------------------------------------------
# Demonstration retrievers. S-ICL ranks pool cases by COSINE of a sentence-
# transformer (UAE-Large) embedding of the RAW description — the Python stand-in
# for the paper's angle-llama semantic baseline. P-ICL (below, separate class)
# ranks by GRAMMATICAL PATTERN via constituency parse + autoencoder, faithful to
# paper §4.1.2 — see extraction/pattern_embed.py.
# ---------------------------------------------------------------------------

class _EmbedRetriever:
    """Base: precompute one embedding per case, retrieve by cosine to the query."""

    def __init__(self, pool: list[CaseEntry], embedder):
        self.pool = pool
        self.embedder = embedder
        texts = [self._case_text(e) for e in pool]
        self._mat = (embedder.embed_batch(texts) if texts
                     else np.zeros((0, 1), dtype="float32"))

    def _case_text(self, e: CaseEntry) -> str:        # overridden per variant
        raise NotImplementedError

    def _abstract_query(self, query_text: str) -> str:  # S-ICL: identity
        return query_text

    def retrieve(self, query_cve_id: str, query_text: str,
                 top_k: int = 3, exclude_id: Optional[str] = None) -> list[CaseEntry]:
        """Top_k cases by cosine similarity, excluding the query CVE itself."""
        if self._mat.shape[0] == 0:
            return []
        q = np.asarray(self.embedder.embed([self._abstract_query(query_text)])).reshape(-1)
        sims = self._mat @ q                    # cosine (vectors are L2-normalised)
        results = []
        for i in np.argsort(sims)[::-1]:
            e = self.pool[i]
            if e.cve_id == (exclude_id or query_cve_id):
                continue
            results.append(e)
            if len(results) >= top_k:
                break
        return results


class SICLRetriever(_EmbedRetriever):
    """Paper S-ICL: demos by SEMANTIC embedding cosine over the raw description."""

    def _case_text(self, e: CaseEntry) -> str:
        return e.description


class PICLRetriever:
    """Paper P-ICL (§4.1.2): demos by grammatical PATTERN, not vocabulary.

    For each case: anchor-abstract the description (STEP 1), constituency-parse +
    prune to a leaf-token pattern sequence (STEP 2), then rank by cosine over an
    autoencoder embedding of those sequences (STEP 3). Self-contained — builds its
    own parser + pattern embedder fitted on the pool (does not use the UAE
    sentence embedder that S-ICL/ranking use).
    """

    def __init__(self, pool: list[CaseEntry], parser=None, n_components: int = 128):
        from .pattern_embed import ConstituencyParser, PatternEmbedder
        self.pool = pool
        self.parser = parser or ConstituencyParser()
        self.anchor_counts = {
            "mode": _anchor_mode(),
            "pool_texts": len(pool),
            "texts_with_any_anchor": 0,
            "matches": {
                "product": 0,
                "component": 0,
                "vulnerability_type": 0,
                "attacker": 0,
                "version_phrase": 0,
                "version": 0,
            },
            "by_cve": {},
        }
        seqs = []
        for e in pool:
            counts = anchor_fire_counts(e.description, e.library)
            self.anchor_counts["by_cve"][e.cve_id] = counts
            if any(counts.values()):
                self.anchor_counts["texts_with_any_anchor"] += 1
            for key, value in counts.items():
                self.anchor_counts["matches"][key] += value
            seqs.append(self.parser.pattern(anchor_abstract(e.description, e.library)))
        self.embedder = PatternEmbedder(n_components=n_components).fit(seqs)
        self._mat = (self.embedder.embed(seqs) if pool
                     else np.zeros((0, 1), dtype="float32"))
        self.pattern_lengths = [len(seq) for seq in seqs]

    def retrieve(self, query_cve_id: str, query_text: str,
                 top_k: int = 3, exclude_id: Optional[str] = None) -> list[CaseEntry]:
        if self._mat.shape[0] == 0:
            return []
        q_seq = self.parser.pattern(anchor_abstract(query_text))
        q = self.embedder.embed([q_seq])[0]
        sims = self._mat @ q
        results: list[CaseEntry] = []
        for i in np.argsort(sims)[::-1]:
            e = self.pool[i]
            if e.cve_id == (exclude_id or query_cve_id):
                continue
            results.append(e)
            if len(results) >= top_k:
                break
        return results

    def fire_counters(self) -> dict:
        lengths = self.pattern_lengths
        return {
            "case_pool_size": len(self.pool),
            "anchor_recognition": self.anchor_counts,
            "parser": dict(getattr(self.parser, "stats", {})),
            "pattern_embedder": dict(getattr(self.embedder, "stats", {})),
            "pattern_sequences": {
                "count": len(lengths),
                "empty": sum(1 for n in lengths if n == 0),
                "min_len": min(lengths) if lengths else 0,
                "max_len": max(lengths) if lengths else 0,
                "avg_len": (sum(lengths) / len(lengths)) if lengths else 0.0,
            },
        }
