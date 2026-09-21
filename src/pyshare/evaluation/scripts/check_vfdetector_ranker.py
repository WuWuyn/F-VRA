import math

from pyshare.evaluation.methods.vfdetector.core.ranker import (
    _term_frequency,
    _inverse_function_frequency,
    _length_normalizer,
    rank_functions,
)


def _close(left: float, right: float, tol: float = 1e-9) -> bool:
    return math.isclose(left, right, rel_tol=tol, abs_tol=tol)


# ---------------------------------------------------------------------------
# _term_frequency
# ---------------------------------------------------------------------------

def test_tf_absent_term():
    assert _term_frequency("x", ["a", "b"]) == 0.0

def test_tf_present_once():
    result = _term_frequency("a", ["a", "b", "c"])
    assert _close(result, 1.0 + math.log(1))

def test_tf_present_multiple():
    result = _term_frequency("a", ["a", "a", "a"])
    assert _close(result, 1.0 + math.log(3))


# ---------------------------------------------------------------------------
# _inverse_function_frequency
# ---------------------------------------------------------------------------

def test_iff_term_in_all_functions():
    corpora = [["a", "b"], ["a", "c"], ["a", "d"]]
    result = _inverse_function_frequency("a", corpora)
    assert _close(result, math.log(3 / 3))  # log(1) = 0

def test_iff_term_in_one_function():
    corpora = [["a", "b"], ["c", "d"], ["e", "f"]]
    result = _inverse_function_frequency("a", corpora)
    assert _close(result, math.log(3 / 1))

def test_iff_term_absent():
    corpora = [["a"], ["b"], ["c"]]
    assert _inverse_function_frequency("z", corpora) == 0.0


# ---------------------------------------------------------------------------
# _length_normalizer
# ---------------------------------------------------------------------------

def test_length_normalizer_min_returns_zero():
    assert _close(_length_normalizer(10, min_terms=10, max_terms=100), 0.0)

def test_length_normalizer_max_returns_expected():
    result = _length_normalizer(100, min_terms=10, max_terms=100)
    assert _close(result, 1.0 - math.exp(-1.0))

def test_length_normalizer_monotonically_increasing():
    vals = [_length_normalizer(t, 0, 100) for t in range(0, 101, 10)]
    assert all(vals[i] <= vals[i + 1] for i in range(len(vals) - 1))

def test_length_normalizer_equal_min_max():
    assert _length_normalizer(50, min_terms=50, max_terms=50) == 0.0


# ---------------------------------------------------------------------------
# rank_functions
# ---------------------------------------------------------------------------

def test_rank_returns_empty_on_no_functions():
    assert rank_functions(["vuln", "overflow"], []) == []

def test_rank_returns_empty_on_empty_corpora():
    assert rank_functions([], [[], []]) == []

def test_rank_top_k_respected():
    cve = ["buffer", "overflow"]
    funcs = [["buffer", "overflow"]] * 20
    result = rank_functions(cve, funcs, top_k=5)
    assert len(result) <= 5

def test_rank_sorted_descending():
    cve = ["unsafe", "load", "deserializ"]
    funcs = [
        ["unsafe", "load", "deserializ", "object"],   # high overlap
        ["parse", "node", "yaml"],                     # low overlap
        ["unsafe", "load"],                            # medium overlap
    ]
    result = rank_functions(cve, funcs, top_k=3)
    scores = [score for _, score in result]
    assert scores == sorted(scores, reverse=True)

def test_rank_relevant_function_in_top_results():
    cve = ["unsafe", "load", "deserializ", "python", "object"]
    # func 0: directly related — many matching tokens, longer body
    func_related = ["unsafe", "load", "deserializ", "python", "object",
                    "arbitrary", "code", "execution", "instantiate", "class"] * 3
    # func 1: unrelated
    func_unrelated = ["parse", "node", "tree", "walk", "visit",
                      "token", "stream", "read", "write", "file"] * 2
    result = rank_functions(cve, [func_related, func_unrelated], top_k=2)
    top_index = result[0][0]
    assert top_index == 0

def test_rank_returns_index_and_score():
    cve = ["overflow"]
    funcs = [["overflow"], ["unrelated"]]
    result = rank_functions(cve, funcs, top_k=2)
    assert all(isinstance(idx, int) and isinstance(score, float)
               for idx, score in result)

def test_rank_all_zero_vectors_returns_zero_scores():
    cve = ["zzz"]
    funcs = [["aaa"], ["bbb"]]
    result = rank_functions(cve, funcs, top_k=2)
    assert all(score == 0.0 for _, score in result)


def _run_all():
    checks = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    for check in checks:
        check()
        print(f"  PASS {check.__name__.replace('test_', 'check_', 1)}")
    print(f"\n{len(checks)} ranker checks passed.")


if __name__ == "__main__":
    _run_all()
