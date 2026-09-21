"""Standalone correctness test for the Algorithm 1 rewrite (fake embedder).

One-hot embedder: cos(word, same word)=1, cos(different words)=0. So
bestMatch(desc_entity, func) = 1 iff the entity word is in the function's bag,
and a function's score = sum of TF-IDF weights of description entities it
contains (above threshold). Lets us assert ranking/threshold/class-priority
exactly. Run: python -m pyshare.evaluation.methods.vffinder.retrieval._test_algo1
"""
import numpy as np

from pyshare.evaluation.methods.vffinder.corpus.function_corpus import (
    FunctionEntity, build_call_graph, inline_expand,
)
from pyshare.evaluation.methods.vffinder.retrieval.metrics import evaluate
from pyshare.evaluation.methods.vffinder.retrieval.retrieval import (
    PrioritySemanticRetriever, compute_tfidf_weights, extract_class_hints,
)

VOCAB = ["ldap", "auth", "bind", "render", "html", "escape", "parse"]
_IDX = {w: i for i, w in enumerate(VOCAB)}


class OneHotEmbedder:
    def embed_batch(self, texts):
        out = np.zeros((len(texts), len(VOCAB)), dtype=float)
        for r, t in enumerate(texts):
            if t in _IDX:
                out[r, _IDX[t]] = 1.0
        return out


def approx(a, b, eps=1e-6):
    return abs(a - b) < eps


def test_scoring_and_ranking():
    funcs = [
        FunctionEntity("f.py::a", "a", "f.py", "", entities=["ldap", "auth", "bind"]),
        FunctionEntity("f.py::b", "b", "f.py", "", entities=["render", "html", "escape"]),
        FunctionEntity("f.py::c", "c", "f.py", "Renderer", entities=["render"]),
    ]
    r = PrioritySemanticRetriever(funcs, OneHotEmbedder(), threshold=0.5,
                                  bm25_top_k=10, cache=None)
    weights = {"ldap": 3.0, "auth": 1.0, "render": 0.5}

    # No class hint: a (3+1=4) > b (0.5) > c (0.5). a first.
    ranked = r.rank(weights, class_hints=[], top_k=3)
    ids = [fid for fid, _ in ranked]
    scores = {fid: s for fid, s in ranked}
    assert approx(scores["f.py::a"], 4.0), scores
    assert approx(scores["f.py::b"], 0.5), scores
    assert ids[0] == "f.py::a", ids

    # Class hint "Renderer": c jumps to the priority list -> ranks FIRST even
    # though its score (0.5) is far below a's (4.0).
    ranked2 = r.rank(weights, class_hints=["Renderer"], top_k=3)
    ids2 = [fid for fid, _ in ranked2]
    assert ids2[0] == "f.py::c", ids2
    assert ids2[1] == "f.py::a", ids2
    print("OK scoring + class priority")


def test_threshold_blocks_zero_matches():
    funcs = [FunctionEntity("f.py::x", "x", "f.py", "", entities=["parse"])]
    r = PrioritySemanticRetriever(funcs, OneHotEmbedder(), threshold=0.5,
                                  bm25_top_k=10, cache=None)
    # desc entity "ldap" not in func -> bestMatch 0 -> below θ -> score 0
    ranked = r.rank({"ldap": 5.0}, class_hints=[], top_k=1)
    assert approx(ranked[0][1], 0.0), ranked
    print("OK threshold")


def test_python_module_hint_priority():
    funcs = [
        FunctionEntity("auth.py::strong", "strong", "auth.py", "",
                       entities=["ldap", "auth"]),
        FunctionEntity("views.py::render_login", "render_login", "views.py", "",
                       entities=["render"]),
    ]
    r = PrioritySemanticRetriever(funcs, OneHotEmbedder(), threshold=0.5,
                                  bm25_top_k=10, cache=None)
    ranked = r.rank({"ldap": 4.0, "render": 0.5}, class_hints=["views"], top_k=2)
    ids = [fid for fid, _ in ranked]
    assert ids[0] == "views.py::render_login", ids
    print("OK Python module hint priority")


def test_tfidf_weights():
    desc = {
        "CVE-1": {"av": ["ldap", "ldap"], "rc": ["common"]},
        "CVE-2": {"av": ["common"], "rc": ["other"]},
    }
    w = compute_tfidf_weights(desc)
    # "ldap" appears in 1/2 docs (rare) twice in CVE-1 -> higher than "common"
    # which appears in both docs (df=2).
    assert w["CVE-1"]["ldap"] > w["CVE-1"]["common"], w["CVE-1"]
    print("OK tfidf")


def test_class_extraction():
    assert "FederationServer" in extract_class_hints(
        "A flaw in the FederationServer class allows ...")
    assert "RoomMember" in extract_class_hints("RoomMember.update() mishandles ...")
    assert "views" in extract_class_hints("A flaw in views.py allows ...")
    assert extract_class_hints("no classes named here") == []
    print("OK class extraction")


def test_pairwise_rerank():
    """Pairwise (Copeland) re-rank promotes the function that wins its pairs."""
    import pyshare.evaluation.methods.vffinder.retrieval.retrieval as R
    funcs = [
        FunctionEntity("f.py::x", "x", "f.py", "", entities=["ldap"]),
        FunctionEntity("f.py::y", "y", "f.py", "", entities=["html"]),
        FunctionEntity("f.py::z", "z", "f.py", "", entities=["parse"]),
    ]
    r = PrioritySemanticRetriever(funcs, OneHotEmbedder(), threshold=0.5,
                                  bm25_top_k=10, cache=None)
    ranked = [("f.py::x", 3.0), ("f.py::y", 2.0), ("f.py::z", 1.0)]
    # stub the LLM judge: z always wins, no network call
    orig = R._pairwise_compare
    R._pairwise_compare = lambda desc, fa, fb, model=None: (
        "A" if fa.func_id == "f.py::z" else "B" if fb.func_id == "f.py::z" else "A")
    try:
        out = r.rerank_pairwise(ranked, "desc", top_m=3, model=None)
    finally:
        R._pairwise_compare = orig
    ids = [i for i, _ in out]
    assert ids[0] == "f.py::z", ids                 # z won both pairs -> rank 1
    assert ids[1:] == ["f.py::x", "f.py::y"], ids   # tie broken by pointwise order
    print("OK pairwise rerank")


def test_native_metrics_aliases():
    metrics = evaluate(
        {"CVE": [("a.py::Cls.f", 1.0), ("b.py::g", 0.5)]},
        {"CVE": ["a.py::f", "b.py::g"]},
    )
    assert metrics["MRR"] == 1.0, metrics
    assert metrics["Recall@1"] == 0.5, metrics
    assert metrics["Recall@5"] == 1.0, metrics
    print("OK native metrics")


def test_inline_expand_uses_statement_count():
    funcs = [
        FunctionEntity(
            "f.py::helper", "helper", "f.py", "",
            source="def helper():\n    return 1\n",
            entities=["help"],
        ),
        FunctionEntity(
            "f.py::five", "five", "f.py", "",
            source=(
                "def five():\n"
                "    a=1\n    b=2\n    c=3\n    d=4\n"
                "    return helper()\n"
            ),
            entities=["five"],
        ),
        FunctionEntity(
            "f.py::six", "six", "f.py", "",
            source=(
                "def six():\n"
                "    a=1\n    b=2\n    c=3\n    d=4\n    e=5\n"
                "    return helper()\n"
            ),
            entities=["six"],
        ),
    ]
    inline_expand(funcs, build_call_graph(funcs))
    by_id = {f.func_id: set(f.entities) for f in funcs}
    assert "help" in by_id["f.py::five"], by_id
    assert "help" not in by_id["f.py::six"], by_id
    print("OK inline statement count")


if __name__ == "__main__":
    test_scoring_and_ranking()
    test_threshold_blocks_zero_matches()
    test_python_module_hint_priority()
    test_tfidf_weights()
    test_class_extraction()
    test_pairwise_rerank()
    test_native_metrics_aliases()
    test_inline_expand_uses_statement_count()
    print("\nALL ALGO-1 TESTS PASSED")
