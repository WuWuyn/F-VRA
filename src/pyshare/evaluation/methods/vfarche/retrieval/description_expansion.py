from __future__ import annotations

from collections import Counter
import re
from rank_bm25 import BM25Okapi


_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_-]+")


_CWE_MINI_CORPUS = {
    "CWE-20": "Improper input validation. The product receives input but does not validate or incorrectly validates that input.",
    "CWE-22": "Path traversal. External input controls a pathname used to access files or directories.",
    "CWE-78": "OS command injection. Untrusted input is used to construct operating system commands.",
    "CWE-79": "Cross-site scripting. Untrusted input is included in web output without neutralization.",
    "CWE-89": "SQL injection. Untrusted input is used in a SQL command without proper neutralization.",
    "CWE-94": "Code injection. The product constructs code from externally influenced input.",
    "CWE-200": "Exposure of sensitive information to an unauthorized actor.",
    "CWE-287": "Improper authentication. The product does not prove or incorrectly proves user identity.",
    "CWE-352": "Cross-site request forgery. Unauthorized commands are transmitted from a trusted user.",
    "CWE-502": "Deserialization of untrusted data can result in code execution or object injection.",
    "CWE-601": "Open redirect. User-controlled input can redirect users to untrusted locations.",
    "CWE-863": "Incorrect authorization. The product performs an authorization check incorrectly or not at all.",
}


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN.findall(text or "")]


def _top_prf_cwe(description: str) -> str | None:
    ids = list(_CWE_MINI_CORPUS)
    corpus = [_tokenize(_CWE_MINI_CORPUS[cwe]) for cwe in ids]
    if not corpus:
        return None
    scores = BM25Okapi(corpus).get_scores(_tokenize(description))
    best_idx = max(range(len(ids)), key=lambda i: scores[i])
    return ids[best_idx] if scores[best_idx] > 0 else None


def _top_terms_fallback(description: str, corpus_texts: list[str], top_n: int) -> list[str]:
    query = set(_tokenize(description))
    counts: Counter[str] = Counter()
    for text in corpus_texts[:50]:
        counts.update(t for t in _tokenize(text) if len(t) > 3 and t not in query)
    return [term for term, _ in counts.most_common(top_n)]


def _top_terms_lsa(description: str, corpus_texts: list[str], top_n: int) -> list[str]:
    try:
        import numpy as np
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer
    except ImportError:
        return _top_terms_fallback(description, corpus_texts, top_n)

    docs = [description, *corpus_texts]
    if len(docs) < 3:
        return _top_terms_fallback(description, corpus_texts, top_n)
    vectorizer = TfidfVectorizer(
        token_pattern=r"(?u)\b[A-Za-z][A-Za-z0-9_]{2,}\b",
        stop_words="english",
        max_features=5000,
    )
    tfidf = vectorizer.fit_transform(docs)
    if tfidf.shape[1] < 2:
        return []
    n_components = min(64, tfidf.shape[0] - 1, tfidf.shape[1] - 1)
    if n_components < 1:
        return _top_terms_fallback(description, corpus_texts, top_n)

    projected = TruncatedSVD(n_components=n_components, random_state=13).fit_transform(tfidf)
    q = projected[0]
    denom = np.linalg.norm(projected[1:], axis=1) * np.linalg.norm(q)
    scores = np.divide(projected[1:] @ q, denom, out=np.zeros(len(corpus_texts)), where=denom > 0)
    top_docs = [corpus_texts[i] for i in np.argsort(scores)[-min(10, len(corpus_texts)):][::-1]]
    return _top_terms_fallback(description, top_docs, top_n)


def expand_description(
    cve: dict,
    *,
    corpus_texts: list[str] | None = None,
    alpha: float = 0.35,
    top_terms: int = 12,
) -> str:
    """Expand a CVE description with CWE concepts and pseudo relevance feedback.

    This follows the paper's shape offline: sanitize/query expansion from CWE
    text, pseudo relevance feedback from candidate code, and repeated original
    query terms so the expansion does not drown out the CVE description.
    """
    description = cve.get("description") or ""
    cwes = cve.get("cwes") or []
    chosen: list[str] = []
    for cwe in cwes:
        key = str(cwe).strip().upper()
        if key in _CWE_MINI_CORPUS:
            chosen.append(_CWE_MINI_CORPUS[key])

    if not chosen:
        prf = _top_prf_cwe(description)
        if prf:
            chosen.append(_CWE_MINI_CORPUS[prf])

    feedback_terms: list[str] = []
    if corpus_texts:
        feedback_terms = _top_terms_lsa(description, corpus_texts, top_terms)

    ingredients = []
    if chosen:
        ingredients.append(" ".join(chosen))
    if feedback_terms:
        weighted = " ".join(term for term in feedback_terms for _ in range(max(1, int(alpha * 3))))
        ingredients.append(weighted)

    if not ingredients:
        return description

    repeated_query = " ".join([description] * 5)
    return f"{repeated_query}\n\nExpansion ingredients: {' '.join(ingredients)}"
