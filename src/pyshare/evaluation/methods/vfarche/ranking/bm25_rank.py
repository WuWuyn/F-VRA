import re
from rank_bm25 import BM25Okapi

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _tokenize(text: str) -> list[str]:
    # split CamelCase and snake_case into subtokens
    raw = _TOKEN.findall(text or "")
    out: list[str] = []
    for tok in raw:
        out.append(tok.lower())
        for sub in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", tok):
            s = sub.lower()
            if s and s != tok.lower():
                out.append(s)
        for sub in tok.split("_"):
            if sub:
                out.append(sub.lower())
    return out


def rank_bm25(description: str, funcs: list[dict], top_k: int) -> list[dict]:
    if not funcs:
        return []
    corpus = [_tokenize(f["body"] + " " + f["qualname"] + " " + f.get("docstring", "")) for f in funcs]
    bm25 = BM25Okapi(corpus)
    scores = bm25.get_scores(_tokenize(description))

    scored = [
        {**f, "bm25_score": float(scores[i])}
        for i, f in enumerate(funcs)
    ]
    scored.sort(key=lambda x: x["bm25_score"], reverse=True)
    return scored[:top_k]
