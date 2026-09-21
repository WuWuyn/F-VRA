"""ICL-Enhanced Extractor — Step 1 of VFFinder.

Extracts the Attack Vector (AV) and Root Cause (RC) from a CVE description.
The paper defines three variants of increasing accuracy (Table 1):

  * direct  — instruction + description only, no examples        (JSI 0.35)
  * s-icl   — + 3 demonstration cases chosen by semantic similarity (JSI 0.54)
  * p-icl   — + 3 demonstration cases chosen by pattern embedding   (JSI 0.58)

This module implements `direct` fully. `s-icl` / `p-icl` accept a `retriever`
object (added in a later phase) that returns demonstration cases.

The extractor runs at the sentence level: each sentence of the description is
queried separately and the results are merged, as described in paper 4.1.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict

import spacy

from .. import config
from ..common.llm_client import query_llm

# --------------------------------------------------------------------------
# Prompt construction
# --------------------------------------------------------------------------

# Instruction block — adapted verbatim from the paper (Figure 5).
INSTRUCTION = (
    "I want you to act like an expert in vulnerability report analysis. "
    "I will give you a description. Your task is to extract the attack vector "
    "and the root cause from it. The attack vector is the method of triggering "
    "the vulnerability. The root cause is the program error or software "
    "weakness that leads to the vulnerability. If you cannot find the "
    "corresponding answer, just answer None.\n"
    "Respond with ONLY a JSON object in exactly this format:\n"
    '{"attack vector": "...", "root cause": "..."}'
)


@dataclass
class Demonstration:
    """One in-context-learning example: a description with labelled AV/RC."""
    description: str
    attack_vector: str
    root_cause: str

    def render(self) -> str:
        answer = json.dumps(
            {"attack vector": self.attack_vector or "None",
             "root cause": self.root_cause or "None"}
        )
        return f"INPUT: {self.description}\nOUTPUT: {answer}"


def build_prompt(text: str, demonstrations: list[Demonstration] | None = None) -> str:
    """Assemble the LLM prompt: instruction [+ examples] + the queried text.

    Per the paper, demonstrations are ordered by ascending similarity so the
    most similar example sits closest to the query.
    """
    parts = [INSTRUCTION]
    if demonstrations:
        parts.append("Here are some examples you can follow:")
        parts.extend(d.render() for d in demonstrations)
    parts.append(f"INPUT: {text}\nOUTPUT:")
    return "\n\n".join(parts)


# --------------------------------------------------------------------------
# LLM answer parsing
# --------------------------------------------------------------------------

_NULLISH = {"none", "n/a", "na", "null", "", "unknown"}


def _normalize(value) -> str | None:
    """Turn a raw field value into a clean string, or None if it is empty."""
    if value is None:
        return None
    text = str(value).strip().strip('"').strip()
    if text.lower() in _NULLISH:
        return None
    return text


def parse_llm_answer(answer: str) -> tuple[str | None, str | None]:
    """Extract (attack_vector, root_cause) from an LLM response.

    Tolerates markdown code fences, surrounding prose, and key-casing
    variants. Falls back to line-based parsing if JSON decoding fails.
    """
    text = (answer or "").strip()

    # Strip ```json ... ``` fences if present.
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()

    av = rc = None

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            lowered = {str(k).lower().strip(): v for k, v in data.items()}
            av = lowered.get("attack vector") or lowered.get("attackvector")
            rc = lowered.get("root cause") or lowered.get("rootcause")
        except (json.JSONDecodeError, AttributeError):
            pass

    # Fallback: "Attack Vector: ..." / "Root Cause: ..." lines.
    if av is None and rc is None:
        av_line = re.search(r"attack vector[\"']?\s*[:=]\s*(.+)", text, re.I)
        rc_line = re.search(r"root cause[\"']?\s*[:=]\s*(.+)", text, re.I)
        if av_line:
            av = av_line.group(1).strip().rstrip(",")
        if rc_line:
            rc = rc_line.group(1).strip().rstrip(",")

    return _normalize(av), _normalize(rc)


# --------------------------------------------------------------------------
# Lightweight text analysis (spaCy)
# --------------------------------------------------------------------------

def load_nlp(model: str = config.SPACY_MODEL):
    """Load the spaCy pipeline used for sentence splitting and POS tagging."""
    return spacy.load(model)


def split_sentences(nlp, description: str) -> list[str]:
    """Split a CVE description into sentences (spaCy replaces the paper's NLTK)."""
    doc = nlp(description)
    return [s.text.strip() for s in doc.sents if s.text.strip()]


# Code-like tokens worth keeping for the class-matching step (paper 4.4).
# Python descriptions mention modules/functions/classes, e.g. "PIL.ImageMath.eval".
_PASCAL_CASE = re.compile(r"\b[A-Z][a-zA-Z0-9]*[a-z][a-zA-Z0-9]*\b")
_DOTTED_PATH = re.compile(r"\b[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+\b")
_PY_FILE = re.compile(r"\b([A-Za-z_][\w]*)\.py\b")


def extract_class_names(description: str) -> list[str]:
    """Identify class / module / function names mentioned in the description.

    Adapted for Python: collects PascalCase identifiers, dotted qualified
    names (and their components), and `*.py` file stems.
    """
    found: list[str] = []
    found += _PASCAL_CASE.findall(description)
    for dotted in _DOTTED_PATH.findall(description):
        found.append(dotted)
        found += dotted.split(".")
    found += _PY_FILE.findall(description)
    # Deduplicate, keep order.
    seen, result = set(), []
    for token in found:
        if token and token not in seen:
            seen.add(token)
            result.append(token)
    return result


def extract_key_entities(nlp, phrases: list[str]) -> list[str]:
    """Tokenize AV/RC phrases into content-word lemmas (noun/verb/propn/adj).

    A light bridge toward the Description Corpus (paper 4.2); full stop-word
    removal, camelCase splitting and stemming belong to that later step.
    """
    keep_pos = {"NOUN", "PROPN", "VERB", "ADJ"}
    seen, result = set(), []
    for phrase in phrases:
        for token in nlp(phrase):
            if token.pos_ in keep_pos and not token.is_stop:
                lemma = token.lemma_.lower().strip()
                if len(lemma) > 1 and lemma not in seen:
                    seen.add(lemma)
                    result.append(lemma)
    return result


# --------------------------------------------------------------------------
# CVE entity
# --------------------------------------------------------------------------

@dataclass
class CVEEntity:
    """The structured output of the extractor for one CVE."""
    cve_id: str
    description: str
    attack_vector: list[str] = field(default_factory=list)
    root_cause: list[str] = field(default_factory=list)
    class_names: list[str] = field(default_factory=list)
    key_entities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Main extraction routine
# --------------------------------------------------------------------------

def _cases_to_demos(cases) -> list[Demonstration]:
    """Convert CaseEntry objects to Demonstration objects for the prompt.

    The retrievers return cases in DESCENDING similarity (most similar first),
    but the paper (§4.1) and build_prompt's contract require ASCENDING order so
    the most similar example sits CLOSEST to the query. Reverse here.
    """
    demos = []
    for c in reversed(cases):
        av_text = "; ".join(c.attack_vector) if c.attack_vector else "None"
        rc_text = "; ".join(c.root_cause) if c.root_cause else "None"
        demos.append(Demonstration(
            description=c.description,
            attack_vector=av_text,
            root_cause=rc_text,
        ))
    return demos


def extract_cve(cve_id: str, description: str, nlp,
                level: str = "direct", retriever=None) -> CVEEntity:
    """Run the ICL-Enhanced Extractor on a single CVE.

    Args:
        cve_id:      e.g. "CVE-2022-22817".
        description: the raw CVE description text.
        nlp:         a loaded spaCy pipeline (see `load_nlp`).
        level:       "direct" | "s-icl" | "p-icl".
        retriever:   SICLRetriever or PICLRetriever from case_pool module.
    """
    description = description.strip()
    sentences = split_sentences(nlp, description)

    attack_vectors: list[str] = []
    root_causes: list[str] = []

    for sentence in sentences:
        if level == "direct":
            demos = None
        elif level == "s-icl":
            if retriever is None:
                raise ValueError("level='s-icl' requires a SICLRetriever.")
            # S-ICL: select demos by semantic embedding cosine of the sentence.
            cases = retriever.retrieve(cve_id, sentence, exclude_id=cve_id)
            demos = _cases_to_demos(cases)
        elif level == "p-icl":
            if retriever is None:
                raise ValueError("level='p-icl' requires a PICLRetriever.")
            # P-ICL: demos by grammatical pattern (constituency parse + AE).
            cases = retriever.retrieve(cve_id, sentence, exclude_id=cve_id)
            demos = _cases_to_demos(cases)
        else:
            raise ValueError(f"Unknown level: {level!r}")

        prompt = build_prompt(sentence, demos)
        answer = query_llm(prompt)
        av, rc = parse_llm_answer(answer)
        if av:
            attack_vectors.append(av)
        if rc:
            root_causes.append(rc)

    # Deduplicate while preserving order.
    attack_vectors = list(dict.fromkeys(attack_vectors))
    root_causes = list(dict.fromkeys(root_causes))

    return CVEEntity(
        cve_id=cve_id,
        description=description,
        attack_vector=attack_vectors,
        root_cause=root_causes,
        class_names=extract_class_names(description),
        key_entities=extract_key_entities(nlp, attack_vectors + root_causes),
    )
