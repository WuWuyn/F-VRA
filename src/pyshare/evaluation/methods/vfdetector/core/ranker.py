"""
tVSM (tweaked Vector Space Model) ranker.

Follows the paper exactly:
  Score = cos(r, f) * x(terms)

  x(terms) = 1 - exp(-normalized(#terms))          [Eq. 6 & 7]
  normalized(z) = (z - z_min) / (z_max - z_min)    [Eq. 7]

  tf(t, f)  = 1 + log(count(t in f))  if count > 0, else 0  [Eq. 2]
  iff(t)    = log(#functions / df(t))                         [Eq. 3]

IFF is computed over function corpora only — the CVE corpus is
excluded from the denominator, per the paper.

Implementation notes:
  - The ranking is vectorized: every function's TF-IFF vector is a row of a
    single scipy.sparse CSR matrix F, and the report vector is a dense q. All
    cosine numerators are F @ q (one sparse matvec) and all row norms come from
    a single sum-of-squares pass. This replaces the per-function Python loop
    while computing the EXACT same tVSM scores (same tf/iff/x equations); only
    the runtime drops (from O(N * V) Python-level work to a sparse matmul).
  - The vocabulary is the set of terms that appear in >=1 function. Report-only
    terms are dropped because their iff = log(N/df) with df = 0 is treated as 0,
    so they contribute nothing to any dot product or norm — excluding them is
    numerically exact, not an approximation.
  - The standalone helpers (_term_frequency, _inverse_function_frequency,
    _length_normalizer) are kept as the reference definitions of Eq. 2/3/6-7
    and are exercised directly by the unit tests.
"""

from collections import Counter

import numpy as np
from scipy import sparse


def _term_frequency(term: str, corpus: list[str]) -> float:
    """tf(t, f) = 1 + log(count(t in f)) if count > 0 else 0   [Eq. 2]"""
    count = corpus.count(term)
    return 1.0 + np.log(count) if count > 0 else 0.0


def _inverse_function_frequency(
    term: str,
    function_corpora: list[list[str]],
) -> float:
    """iff(t) = log(#functions / df(t))                          [Eq. 3]"""
    n = len(function_corpora)
    df = sum(1 for corpus in function_corpora if term in corpus)
    if df == 0:
        return 0.0
    return np.log(n / df)


def _length_normalizer(terms: int, min_terms: int, max_terms: int) -> float:
    if max_terms == min_terms:
        return 0.0
    z = (terms - min_terms) / (max_terms - min_terms)
    return 1.0 - np.exp(-z)


def rank_functions(
    cve_corpus: list[str],
    list_of_function_corpora: list[list[str]],
    top_k: int = 10,
) -> list[tuple[int, float]]:
    """
    Rank functions by tVSM score (paper Eq. 8): score = x(terms) * cos(r, f).

    Vectorized with a sparse TF-IFF matrix; numerically identical to the naive
    per-function form. Returns a sorted list of (function_index, tvsm_score),
    descending, length <= top_k.
    """
    if not list_of_function_corpora:
        return []

    function_counts: list[Counter] = [Counter(c) for c in list_of_function_corpora]
    n = len(function_counts)

    # df(t) over function corpora only; vocabulary = terms with df >= 1.
    df: Counter = Counter()
    for counts in function_counts:
        df.update(counts.keys())
    vocabulary: list[str] = sorted(df.keys())
    if not vocabulary:
        return []
    term_to_idx = {t: i for i, t in enumerate(vocabulary)}

    # iff(t) = log(#functions / df(t))                                  [Eq. 3]
    iff = np.array([np.log(n / df[t]) for t in vocabulary], dtype=float)

    # Sparse function matrix F (n x V): F[i, t] = (1 + log f_tf) * iff(t).
    rows: list[int] = []
    cols: list[int] = []
    data: list[float] = []
    for i, counts in enumerate(function_counts):
        for term, c in counts.items():
            j = term_to_idx[term]
            rows.append(i)
            cols.append(j)
            data.append((1.0 + np.log(c)) * iff[j])  # tf * iff           [Eq. 2/4]
    f_matrix = sparse.csr_matrix(
        (data, (rows, cols)), shape=(n, len(vocabulary)), dtype=float
    )

    # Report (query) vector q (V,): q[t] = (1 + log f_tr) * iff(t).
    q = np.zeros(len(vocabulary), dtype=float)
    for term, c in Counter(cve_corpus).items():
        j = term_to_idx.get(term)
        if j is not None:
            q[j] = (1.0 + np.log(c)) * iff[j]
    q_norm = float(np.linalg.norm(q))

    # cos(r, f) = (F @ q) / (||f|| * ||q||) for every function at once.   [Eq. 1/5]
    dots = f_matrix.dot(q)
    row_norms = np.sqrt(np.asarray(f_matrix.multiply(f_matrix).sum(axis=1)).ravel())
    denom = row_norms * q_norm
    cosine = np.zeros(n, dtype=float)
    nz = denom > 0
    cosine[nz] = dots[nz] / denom[nz]

    # Length weight x(terms) = 1 - exp(-normalize(#terms)).            [Eq. 6/7]
    lengths = np.array([len(c) for c in list_of_function_corpora], dtype=float)
    min_len, max_len = float(lengths.min()), float(lengths.max())
    if max_len == min_len:
        x = np.zeros(n, dtype=float)
    else:
        x = 1.0 - np.exp(-(lengths - min_len) / (max_len - min_len))

    scores = x * cosine                                              # tVSM [Eq. 8]
    # Stable sort keeps original index order on ties (matches the naive form).
    order = np.argsort(-scores, kind="stable")[:top_k]
    return [(int(i), float(scores[i])) for i in order]
