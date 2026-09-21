"""Component 4: Priority Semantic Retrieval.

Matches CVE description corpus (Component 2) with function corpus (Component 3)
to produce a ranked list of candidate vulnerable functions.

Pipeline (follows paper Section 4.4 / Algorithm 1):
  1. Semantic Embedding  — WhereIsAI/UAE-Large-V1 (AnglE-trained, same
                           training objective as paper's angle-llama-7b)
  2. Per-entity scoring  — best semantic match per description entity, gated
                           by threshold theta and weighted by TF-IDF
  3. Class priority      — class-matched functions sorted before non-priority
                           functions, as Algorithm 1 specifies
  4. Evaluation          — MRR, Recall@K against ground truth

Optional extensions are available but OFF by default:
  - BM25 shortlist (`--bm25-top-k > 0`) to bound work on very large pools.
  - Pairwise LLM tournament (`--rank-strategy pairwise`) for diagnostics.

Code reused from original VFFinder:
  - cos_similarity()  ← CommonUtils/vecUtils.py  (typo fixed)
  - K-hop traversal   ← CommonUtils/CGUtils.py   (Java imports removed)
"""

import hashlib
import json
import math
import os
import pickle
import re
from pathlib import Path
from typing import Optional

import numpy as np
from rank_bm25 import BM25Okapi
from tqdm import tqdm

from .. import config
from ..common.text_utils import split_identifier
from ..corpus.function_corpus import FunctionEntity
from .metrics import evaluate


# ---------------------------------------------------------------------------
# cos_similarity — copied from VFFinder/CommonUtils/vecUtils.py (typo fixed)
# ---------------------------------------------------------------------------

def cos_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two numpy vectors.

    Source: CommonUtils/vecUtils.cos_simialrity() — typo in original fixed.
    """
    norm = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / norm) if norm > 0 else 0.0


# ---------------------------------------------------------------------------
# K-hop call graph traversal — copied from VFFinder/CommonUtils/CGUtils.py
# Java-specific imports (javalang, transfer_cg_mtd_name) removed.
# ---------------------------------------------------------------------------

def get_k_hop_callees(call_edges: dict[str, list[str]],
                      node: str, k: int) -> list[str]:
    """Return all functions reachable from `node` within k hops (downstream).

    Source: CGUtils.get_K_hop_next_neibor() — adapted for Python dict graph.
    """
    if k == 0:
        return [node]
    frontier = call_edges.get(node, [])
    for _ in range(k - 1):
        next_frontier = []
        for n in frontier:
            next_frontier.extend(call_edges.get(n, []))
        frontier = list(set(next_frontier))
    return frontier


def get_k_hop_callers(reverse_edges: dict[str, list[str]],
                      node: str, k: int) -> list[str]:
    """Return all functions that can reach `node` within k hops (upstream).

    Source: CGUtils.get_K_hop_prev_neibor() — adapted for Python dict graph.
    """
    if k == 0:
        return []
    frontier = reverse_edges.get(node, [])
    for _ in range(k - 1):
        next_frontier = []
        for n in frontier:
            next_frontier.extend(reverse_edges.get(n, []))
        frontier = list(set(next_frontier))
    return frontier


# ---------------------------------------------------------------------------
# Optional extension — BM25 Index
# ---------------------------------------------------------------------------

class BM25Index:
    """Optional BM25 shortlist over function entity lists.

    This is not part of the paper's Algorithm 1 ranking path. It stays off by
    default (`--bm25-top-k 0`) and exists only as a controlled scalability knob.
    """

    def __init__(self, func_entities: list[FunctionEntity]):
        self.func_entities = func_entities
        corpus = [fe.entities if fe.entities else [""] for fe in func_entities]
        self.bm25 = BM25Okapi(corpus)

    def query(self, cve_entities: list[str],
              top_k: int = 100) -> list[tuple[FunctionEntity, float]]:
        """Return top_k (FunctionEntity, bm25_score) pairs."""
        scores = self.bm25.get_scores(cve_entities)
        top_idx = scores.argsort()[::-1][:top_k]
        return [(self.func_entities[i], float(scores[i])) for i in top_idx]


# ---------------------------------------------------------------------------
# Step 2 — Semantic Embedding
# ---------------------------------------------------------------------------

class SemanticEmbedder:
    """Sentence embedder using WhereIsAI/UAE-Large-V1.

    UAE-Large-V1 is trained with AnglE loss — same training objective as the
    paper's angle-llama-7b but 335M params vs 7B, runs on CPU.

    Replaces angle-llama-7b from the original paper.
    """

    def __init__(self, model_name: str = "WhereIsAI/UAE-Large-V1"):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "VFFinder semantic retrieval requires sentence-transformers. "
                "Install configs/evaluation/requirements/vffinder.txt in the VFFinder env."
            ) from exc
        print(f"Loading embedding model: {model_name} (first run downloads ~1.3 GB)")
        self.model = SentenceTransformer(model_name)

    def embed(self, entity_list: list[str]) -> np.ndarray:
        """Embed a list of entities as a single normalised vector."""
        text = " ".join(entity_list) if entity_list else "unknown"
        return self.model.encode(text, normalize_embeddings=True)

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        """Embed multiple texts in one batch (faster for large corpora)."""
        return self.model.encode(texts, normalize_embeddings=True,
                                 show_progress_bar=False)


# ---------------------------------------------------------------------------
# Crash-safety helpers — atomic JSON write + on-disk embedding cache
# ---------------------------------------------------------------------------

def _atomic_write_json(path: str | Path, obj) -> None:
    """Write JSON atomically (write to temp file, then os.replace).

    Guarantees the target file is never left half-written if the process is
    killed mid-write — the reader sees either the old file or the new one.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class EmbeddingCache:
    """On-disk cache mapping (model, text) → embedding vector.

    The most expensive part of retrieval is embedding every function in the
    corpus. This cache persists those vectors so a re-run (after a crash, or a
    new run that shares functions) skips already-computed embeddings.

    Cache key = sha1(model_name + "\\n" + text). Because the embedding text
    encodes both the function content and `max_embed_entities`, any change to
    those naturally produces a new key — stale vectors are never reused.
    """

    def __init__(self, path: str | Path, model_name: str):
        self.path = Path(path)
        self.model_name = model_name
        self._store: dict[str, np.ndarray] = {}
        self._dirty = False
        if self.path.is_file():
            try:
                with open(self.path, "rb") as f:
                    self._store = pickle.load(f)
                print(f"Embedding cache loaded: {len(self._store)} vectors "
                      f"from {self.path}")
            except Exception as exc:  # corrupt/partial cache → start fresh
                print(f"  WARNING: could not read embedding cache "
                      f"({exc}); starting empty")
                self._store = {}

    def _key(self, text: str) -> str:
        h = hashlib.sha1()
        h.update(self.model_name.encode("utf-8"))
        h.update(b"\n")
        h.update(text.encode("utf-8"))
        return h.hexdigest()

    def embed_texts(self, texts: list[str],
                    embedder: "SemanticEmbedder") -> list[np.ndarray]:
        """Return one vector per text, embedding only cache misses."""
        keys = [self._key(t) for t in texts]
        miss_idx = [i for i, k in enumerate(keys) if k not in self._store]
        if miss_idx:
            miss_texts = [texts[i] for i in miss_idx]
            print(f"  embedding {len(miss_texts)} new texts "
                  f"({len(texts) - len(miss_texts)} cache hits) ...")
            vecs = embedder.embed_batch(miss_texts)
            for j, i in enumerate(miss_idx):
                self._store[keys[i]] = vecs[j]
            self._dirty = True
            self.save()  # persist immediately so a later crash can't lose them
        else:
            print(f"  all {len(texts)} embeddings served from cache")
        return [self._store[k] for k in keys]

    def save(self) -> None:
        if not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "wb") as f:
            pickle.dump(self._store, f, protocol=pickle.HIGHEST_PROTOCOL)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        self._dirty = False


# ---------------------------------------------------------------------------
# Optional extension — pairwise (tournament) LLM re-ranking
# ---------------------------------------------------------------------------

def _fn_summary(fe, max_terms: int = 20) -> str:
    if fe is None:
        return "(unknown function)"
    cls = f"{fe.class_name}." if fe.class_name else ""
    terms = ", ".join(fe.entities[:max_terms])
    return f"{fe.module}::{cls}{fe.name}\n  key terms: {terms}"


_PAIRWISE_PROMPT = """You are triaging a software vulnerability (CVE). Given the CVE \
description and two candidate functions from the affected project, decide which \
function is MORE LIKELY to be the vulnerable function (where the root cause of the \
vulnerability resides).

CVE description:
{desc}

Function A:
{a}

Function B:
{b}

Reply with exactly one character: A or B."""


def _pairwise_compare(description: str, fe_a, fe_b, model=None) -> str:
    """Ask the LLM which of two functions is the likelier VF. Returns 'A' or 'B'."""
    from ..common.llm_client import query_llm  # lazy: no LLM import for pointwise
    prompt = _PAIRWISE_PROMPT.format(
        desc=(description or "").strip()[:4000],
        a=_fn_summary(fe_a), b=_fn_summary(fe_b))
    try:
        resp = query_llm(prompt, model=model, temperature=0.0).strip().upper()
    except Exception:
        return "A"                      # on LLM failure, keep the pointwise order
    for ch in resp:
        if ch in ("A", "B"):
            return ch
    return "A"


# ---------------------------------------------------------------------------
# Step 3 — Priority Semantic Retriever (paper Algorithm 1)
# ---------------------------------------------------------------------------

class PrioritySemanticRetriever:
    """Priority Semantic Retrieval — VFFinder Component 4, paper Algorithm 1.

    Scores each function by per-ENTITY best match (not whole-bag cosine):

        for each description entity e (TF-IDF weight w):
            best = max_j cos(emb(e), emb(func_entity_j))
            if best > theta:  f.score += best * w        # Algorithm 1 lines 3-6

    then class matching splits functions into a priority list (class named in the
    description) and a non-priority list; each is sorted by score and the
    non-priority list is appended after the priority list (lines 7-11).

    A BM25 pre-filter can be enabled with `bm25_top_k`, but it is off by default:
    paper Algorithm 1 ranks the full function set.
    """

    def __init__(self,
                 func_entities: list[FunctionEntity],
                 embedder: SemanticEmbedder,
                 threshold: float = 0.5,
                 bm25_top_k: Optional[int] = None,
                 cache: Optional["EmbeddingCache"] = None):
        self.embedder = embedder
        self.func_entities = func_entities
        self.threshold = threshold
        self.bm25_top_k = bm25_top_k
        self.bm25 = BM25Index(func_entities)
        self._cache = cache

        # Embed every UNIQUE entity word in the corpus once (cached on disk),
        # so per-entity best-match is a couple of matrix products at rank time.
        words = sorted({w for fe in func_entities for w in fe.entities})
        print(f"Embedding {len(words)} unique corpus entities "
              f"for {len(func_entities)} functions ...")
        if words:
            vecs = (cache.embed_texts(words, embedder) if cache is not None
                    else embedder.embed_batch(words))
        else:
            vecs = []
        self.word_vec: dict[str, np.ndarray] = {w: vecs[i] for i, w in enumerate(words)}
        self.fe_by_id: dict[str, FunctionEntity] = {fe.func_id: fe for fe in func_entities}
        self.last_stats: dict = {}
        # Pre-stack each function's entity-word vectors (n_entities x dim).
        self._func_mat: dict[str, np.ndarray] = {}
        for fe in func_entities:
            rows = [self.word_vec[w] for w in fe.entities if w in self.word_vec]
            if rows:
                self._func_mat[fe.func_id] = np.vstack(rows)

    def _embed_desc_words(self, words: list[str]) -> None:
        """Ensure every description entity word has a (cached) embedding."""
        miss = sorted({w for w in words if w and w not in self.word_vec})
        if not miss:
            return
        vecs = (self._cache.embed_texts(miss, self.embedder)
                if self._cache is not None else self.embedder.embed_batch(miss))
        for i, w in enumerate(miss):
            self.word_vec[w] = vecs[i]

    def rank(self,
             desc_weights: dict[str, float],
             class_hints: Optional[list[str]] = None,
             top_k: int = 10) -> list[tuple[str, float]]:
        """Rank candidate functions for one CVE (Algorithm 1).

        Parameters
        ----------
        desc_weights : {description_entity: tfidf_weight}
        class_hints  : class names mentioned in the description (priority list)
        top_k        : number of results to return
        """
        d_words = [w for w in desc_weights if w]
        if not d_words:
            self.last_stats = {
                "desc_entity_count": 0,
                "candidate_count": 0,
                "priority_count": 0,
                "nonpriority_count": 0,
                "nonzero_score_count": 0,
                "class_hints_count": len(class_hints or []),
                "bm25_enabled": bool(self.bm25_top_k),
            }
            return []

        # Paper Algorithm 1 ranks the ENTIRE function set (fSet). The BM25
        # shortlist is an optional optimisation, OFF by default (bm25_top_k
        # falsy) so we stay faithful — measured, top-200 was silently dropping
        # ~20% of ground-truth functions before scoring (recall ceiling 80%→96%
        # once removed). Set bm25_top_k to an int only to bound work on a very
        # large pool, accepting the recall hit.
        if self.bm25_top_k:
            candidates = self.bm25.query(d_words, top_k=self.bm25_top_k)
        else:
            candidates = [(fe, 0.0) for fe in self.func_entities]
        candidate_count = len(candidates)

        self._embed_desc_words(d_words)
        d_words = [w for w in d_words if w in self.word_vec]
        if not d_words:
            return []
        D = np.vstack([self.word_vec[w] for w in d_words])      # n_d x dim
        w_arr = np.array([desc_weights[w] for w in d_words])    # n_d

        pri: list[tuple[str, float]] = []
        nonpri: list[tuple[str, float]] = []
        for fe, _ in candidates:
            F = self._func_mat.get(fe.func_id)
            if F is None:
                score = 0.0
            else:
                sims = D @ F.T                  # n_d x n_f cosine (vecs normalized)
                best = sims.max(axis=1)         # best match per description entity
                mask = best > self.threshold    # Algorithm 1 line 5 (threshold θ)
                score = float(np.dot(best[mask], w_arr[mask])) if mask.any() else 0.0
            entry = (fe.func_id, score)
            if _class_matches(fe, class_hints or []):
                pri.append(entry)
            else:
                nonpri.append(entry)

        pri.sort(key=lambda x: x[1], reverse=True)
        nonpri.sort(key=lambda x: x[1], reverse=True)
        self.last_stats = {
            "desc_entity_count": len(d_words),
            "candidate_count": candidate_count,
            "priority_count": len(pri),
            "nonpriority_count": len(nonpri),
            "nonzero_score_count": sum(1 for _fid, score in pri + nonpri if score > 0),
            "class_hints_count": len(class_hints or []),
            "bm25_enabled": bool(self.bm25_top_k),
        }
        return (pri + nonpri)[:top_k]

    def rerank_pairwise(self, ranked: list[tuple[str, float]], description: str,
                        top_m: int = 5, model=None) -> list[tuple[str, float]]:
        """LLM pairwise (Copeland) re-rank of the top-`top_m` pointwise results.

        Each unordered pair among the top-m candidates is judged by the LLM
        ("which function is the likelier VF?"); they are reordered by win count
        (ties broken by the original pointwise order). The tail below top-m is
        left untouched. m*(m-1)/2 LLM calls per CVE (m=5 -> 10).
        """
        head = ranked[:top_m]
        tail = ranked[top_m:]
        ids = [fid for fid, _ in head]
        if len(ids) < 2:
            return ranked
        wins = {fid: 0 for fid in ids}
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = ids[i], ids[j]
                winner = _pairwise_compare(
                    description, self.fe_by_id.get(a), self.fe_by_id.get(b), model)
                wins[a if winner == "A" else b] += 1
        order = {fid: k for k, fid in enumerate(ids)}      # pointwise order = tiebreak
        head_sorted = sorted(head, key=lambda p: (-wins[p[0]], order[p[0]]))
        return head_sorted + tail


# ---------------------------------------------------------------------------
# Full pipeline runner
# ---------------------------------------------------------------------------

def _parse_entities(entities) -> tuple[list[str], list[str]]:
    """Parse AV/RC entities from various description corpus formats."""
    if isinstance(entities, dict):
        return entities.get("av") or [], entities.get("rc") or []
    all_entities = list(entities)
    mid = len(all_entities) // 2
    return all_entities[:mid] or all_entities, all_entities[mid:] or all_entities


# ---------------------------------------------------------------------------
# Paper §4.2 (iii) Weight Calculation — TF-IDF over the description corpora.
# Each CVE's description corpus (AV ∪ RC entities) is one document; an entity's
# weight = TF (count in this CVE) × IDF (rarity across all CVEs). Rare, highly
# specific entities (e.g. "ldap") get a high weight; ubiquitous ones get a low
# one. Used as `entity.weight` in Algorithm 1 line 6.
# ---------------------------------------------------------------------------

def compute_tfidf_weights(desc_corpus: dict) -> dict[str, dict[str, float]]:
    """Return {cve_id: {entity: tfidf_weight}} over all description corpora."""
    from collections import Counter

    docs: dict[str, list[str]] = {}
    df: Counter = Counter()
    for cve_id, d in desc_corpus.items():
        if str(cve_id).startswith("_"):
            continue
        av, rc = _parse_entities(d)
        toks = list(av) + list(rc)
        docs[cve_id] = toks
        for t in set(toks):
            df[t] += 1

    n_docs = len(docs) or 1
    weights: dict[str, dict[str, float]] = {}
    for cve_id, toks in docs.items():
        tf = Counter(toks)
        # smoothed idf so a term present in every doc still keeps a small weight
        weights[cve_id] = {
            t: c * (math.log((n_docs + 1) / (df[t] + 1)) + 1.0)
            for t, c in tf.items()
        }
    return weights


# ---------------------------------------------------------------------------
# Paper §4.1 / §4.4 class matching — the description may name the class the VF
# lives in. We extract candidate class names from the raw CVE description with
# regexes; a function whose class_name matches goes to the priority list.
# ---------------------------------------------------------------------------

_CLASS_PATTERNS = [
    re.compile(r"\bclass\s+([A-Z][A-Za-z0-9_]+)"),          # "class FooBar"
    re.compile(r"\b([A-Z][A-Za-z0-9_]+)\s+class\b"),         # "the FooBar class"
    re.compile(r"\b([A-Z][A-Za-z0-9_]+)\.[A-Za-z_][A-Za-z0-9_]*\s*\("),  # "FooBar.method("
]
_PASCAL_CASE = re.compile(r"\b[A-Z][a-zA-Z0-9]*[a-z][a-zA-Z0-9]*\b")
_DOTTED_PATH = re.compile(r"\b[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+\b")
_PY_FILE = re.compile(r"\b([A-Za-z_][\w]*)\.py\b")


def extract_class_hints(description: str) -> list[str]:
    """Best-effort class names mentioned in a CVE description (may be empty)."""
    if not description:
        return []
    hits: list[str] = []

    def add(token: str) -> None:
        token = (token or "").strip()
        if len(token) >= 3 and token not in hits:
            hits.append(token)

    for pat in _CLASS_PATTERNS:
        for m in pat.findall(description):
            add(m)
    for m in _PASCAL_CASE.findall(description):
        add(m)
    for dotted in _DOTTED_PATH.findall(description):
        add(dotted)
        for part in dotted.split("."):
            add(part)
    for m in _PY_FILE.findall(description):
        add(m)
    return hits


def _class_matches(func: FunctionEntity, class_hints: list[str]) -> bool:
    """True if a class/module/function hint points at this function."""
    if not class_hints:
        return False
    hint_set = {h.lower() for h in class_hints if h}
    module = (func.module or "").replace("\\", "/")
    module_no_ext = module[:-3] if module.endswith(".py") else module
    module_dot = module_no_ext.replace("/", ".")
    candidates = {
        (func.class_name or "").lower(),
        (func.name or "").lower(),
        Path(module_no_ext).stem.lower(),
        module_no_ext.lower(),
        module_dot.lower(),
    }
    candidates.discard("")
    for hint in hint_set:
        parts = [p for p in re.split(r"[./]", hint) if p]
        if hint in candidates or any(p in candidates for p in parts):
            return True
    return False


def run_retrieval(description_corpus_path: str | Path,
                  function_corpus_path: str | Path,
                  ground_truth_path: Optional[str | Path] = None,
                  output_path: Optional[str | Path] = None,
                  top_k: int = 10,
                  threshold: float = 0.5,
                  model_name: str = "WhereIsAI/UAE-Large-V1",
                  bm25_top_k: Optional[int] = None,
                  library_map: Optional[dict[str, str]] = None,
                  class_hints: Optional[dict[str, list[str]]] = None,
                  rank_strategy: str = "pointwise",
                  pairwise_top_m: int = 5,
                  llm_model: Optional[str] = None,
                  descriptions: Optional[dict[str, str]] = None,
                  checkpoint_path: Optional[str | Path] = None,
                  cache_dir: Optional[str | Path] = None,
                  checkpoint_every: int = 10,
                  error_log_path: Optional[str | Path] = None) -> dict:
    """Run the full Component 4 pipeline end-to-end.

    Parameters
    ----------
    library_map : optional {cve_id: library_prefix} mapping.
        When provided, each CVE is ranked only against functions whose
        func_id starts with the given prefix (e.g. "yaml/", "PIL/").
        This mirrors the paper's per-software retrieval strategy and
        eliminates cross-library noise. CVEs not in the map use the
        full corpus.
    checkpoint_path : optional path to a JSON checkpoint file.
        Ranked results are flushed here every `checkpoint_every` CVEs and on
        completion. On startup, an existing checkpoint with matching run
        parameters is loaded and its CVEs are skipped, so a crashed run
        resumes instead of restarting. Mismatched parameters are ignored.
    cache_dir : optional directory for the on-disk embedding cache.
        Function embeddings are persisted here so a re-run skips the
        expensive re-embedding step. Pass None to disable caching.
    checkpoint_every : flush the checkpoint after this many newly-ranked CVEs.
    error_log_path : optional path to a JSON error log.
        Any CVE (or whole library) that raises during ranking is recorded here
        — {cve_id, library, error, traceback} — and skipped, so a single bad
        entry never aborts the whole run. Review this file afterwards to find
        and re-run the failures. CVEs already done from a checkpoint are not
        re-attempted.

    Returns
    -------
    {
      "ranked": {cve_id: [(func_id, score), ...]},
      "metrics": {MRR, Recall@1, Recall@5, Recall@10}  # only if ground_truth given
    }
    """
    # Load description corpus
    with open(description_corpus_path, encoding="utf-8") as f:
        desc_corpus: dict[str, dict] = json.load(f)

    # Paper §4.2(iii): TF-IDF weight per description entity (Algorithm 1 weight).
    desc_weights = compute_tfidf_weights(desc_corpus)
    class_hints = class_hints or {}
    descriptions = descriptions or {}
    pairwise = (rank_strategy == "pairwise")

    # Load function corpus
    with open(function_corpus_path, encoding="utf-8") as f:
        raw_funcs = json.load(f)
    all_func_entities = [
        FunctionEntity(
            func_id=fe["func_id"],
            name=fe["name"],
            module=fe["module"],
            class_name=fe["class_name"],
            params=fe.get("params", []),
            param_types=fe.get("param_types", []),
            entities=fe.get("entities", []),
            library=fe.get("library", ""),
        )
        for fe in raw_funcs
    ]

    # --- On-disk embedding cache (crash-safe, reused across runs) ----------
    cache: Optional[EmbeddingCache] = None
    if cache_dir is not None:
        cache_file = Path(cache_dir) / "func_embeddings.pkl"
        cache = EmbeddingCache(cache_file, model_name)

    # --- Resume from checkpoint -------------------------------------------
    # The checkpoint stores the run parameters alongside ranked results; if
    # they differ from this run, the old results are stale and ignored.
    def _file_hash(p: str | Path) -> str:
        h = hashlib.sha1()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    # Content hashes (not just paths!) so a re-built corpus / new description set
    # at the SAME path invalidates a stale checkpoint instead of being reused
    # (the bug that made re-runs silently re-emit old rankings).
    run_params = {
        "model_name": model_name,
        "top_k": top_k,
        "threshold": threshold,
        "bm25_top_k": bm25_top_k,
        "rank_strategy": rank_strategy,
        "pairwise_top_m": pairwise_top_m if pairwise else 0,
        "algo": "per_entity_tfidf_v2",
        "func_corpus_sha1": _file_hash(function_corpus_path),
        "desc_corpus_sha1": _file_hash(description_corpus_path),
        "per_library": bool(library_map),
    }
    component_counters = {
        "component": "priority_semantic_retrieval",
        "run_params": dict(run_params),
        "description_cves": len([k for k in desc_corpus if not str(k).startswith("_")]),
        "function_count": len(all_func_entities),
        "unique_libraries": len({fe.library for fe in all_func_entities if fe.library}),
        "bm25_enabled": bool(bm25_top_k),
        "bm25_top_k": bm25_top_k or 0,
        "pairwise_enabled": pairwise,
        "rank_strategy": rank_strategy,
        "class_priority": {
            "cves_with_hints": sum(1 for v in class_hints.values() if v),
            "ranked_cves_with_nonempty_prilist": 0,
            "ranked_functions_entering_prilist": 0,
            "total_class_hints_used": 0,
        },
        "candidate_pools": {
            "libraries_seen": 0,
            "full_pool_cves": 0,
            "empty_library_skips": 0,
            "pool_sizes": {},
        },
        "ranking": {
            "cves_ranked_this_run": 0,
            "cves_ranked_output": 0,
            "total_candidates_scored": 0,
            "total_nonzero_scores": 0,
            "empty_rankings": 0,
        },
    }
    ranked: dict[str, list] = {}
    if checkpoint_path and Path(checkpoint_path).is_file():
        try:
            with open(checkpoint_path, encoding="utf-8") as f:
                ckpt = json.load(f)
            if ckpt.get("_params") == run_params:
                ranked = {k: v for k, v in ckpt.get("ranked", {}).items()}
                print(f"Resuming from checkpoint: {len(ranked)} CVEs already "
                      f"ranked, {len(desc_corpus) - len(ranked)} remaining")
            else:
                print("Checkpoint found but run parameters changed — "
                      "ignoring it and starting fresh")
        except Exception as exc:
            print(f"  WARNING: could not read checkpoint ({exc}); "
                  f"starting fresh")

    def _flush_checkpoint() -> None:
        if checkpoint_path:
            _atomic_write_json(
                checkpoint_path,
                {"_params": run_params,
                 "ranked": {c: list(p) for c, p in ranked.items()}},
            )

    # --- Error collection -------------------------------------------------
    # Failures are recorded and skipped rather than aborting the run. The log
    # is flushed alongside the checkpoint so it survives a later crash too.
    import traceback as _traceback
    errors: list[dict] = []

    def _flush_errors() -> None:
        if error_log_path and errors:
            # Error logging must never be the thing that crashes the run — e.g.
            # under memory exhaustion even open() can fail (OSError 22 on
            # Windows). Swallow write failures so the run continues.
            try:
                _atomic_write_json(error_log_path, errors)
            except Exception as exc:  # noqa: BLE001 — best-effort logging
                print(f"  WARNING: could not write error log "
                      f"({type(exc).__name__}: {exc})")

    def _record_error(scope: str, ids, label: str, exc: Exception) -> None:
        errors.append({
            "scope": scope,          # "cve" or "library"
            "cve_id": ids if isinstance(ids, str) else None,
            "cve_ids": ids if isinstance(ids, list) else None,
            "library": label,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": _traceback.format_exc(),
        })
        _flush_errors()

    def _rank_cve(cve_id: str, retriever, label: str) -> bool:
        """Rank one CVE; on failure log + skip. Returns True on success."""
        try:
            weights = desc_weights.get(cve_id) or {}
            hints = class_hints.get(cve_id) or []
            result = retriever.rank(weights, hints, top_k=top_k)
            if pairwise and len(result) >= 2:
                desc_text = descriptions.get(cve_id) or " ".join(
                    sum(_parse_entities(desc_corpus[cve_id]), []))
                result = retriever.rerank_pairwise(
                    result, desc_text, top_m=pairwise_top_m, model=llm_model)
            ranked[cve_id] = result
            stats = getattr(retriever, "last_stats", {}) or {}
            component_counters["ranking"]["cves_ranked_this_run"] += 1
            component_counters["ranking"]["total_candidates_scored"] += int(
                stats.get("candidate_count", 0)
            )
            component_counters["ranking"]["total_nonzero_scores"] += int(
                stats.get("nonzero_score_count", 0)
            )
            if not result:
                component_counters["ranking"]["empty_rankings"] += 1
            if stats.get("priority_count", 0):
                component_counters["class_priority"]["ranked_cves_with_nonempty_prilist"] += 1
                component_counters["class_priority"]["ranked_functions_entering_prilist"] += int(
                    stats.get("priority_count", 0)
                )
            component_counters["class_priority"]["total_class_hints_used"] += int(
                stats.get("class_hints_count", 0)
            )
            return True
        except Exception as exc:  # noqa: BLE001 — deliberately broad: skip & log
            print(f"  ERROR ranking {cve_id} [{label}]: "
                  f"{type(exc).__name__}: {exc} — skipped")
            _record_error("cve", cve_id, label, exc)
            return False

    # Skip the (expensive) model load entirely when every CVE is already
    # present from a resumed checkpoint; otherwise load the embedder now.
    if all(cve_id in ranked for cve_id in desc_corpus):
        embedder = None
        print("All CVEs already present in checkpoint — skipping embedding.")
    else:
        embedder = SemanticEmbedder(model_name=model_name)

    if library_map:
        # Per-library retrieval: group CVEs by their target library prefix,
        # build one retriever per library, rank within that library only.
        # CVEs without a mapping fall into the "full corpus" group (key=None).
        from collections import defaultdict
        lib_to_cves: dict = defaultdict(list)
        for cve_id in desc_corpus:
            prefix = library_map.get(cve_id)  # None → full corpus
            # lists are unhashable; normalise to tuple for use as dict key
            key = tuple(prefix) if isinstance(prefix, list) else prefix
            lib_to_cves[key].append(cve_id)

        new_since_flush = 0
        for lib_key, cve_ids in lib_to_cves.items():
            # Skip CVEs already present from a resumed checkpoint.
            pending = [c for c in cve_ids if c not in ranked]
            if not pending:
                continue
            if lib_key:
                # Try library tag first (exact match), then fall back to prefix matching.
                # lib_key may be a str or a tuple of prefix strings.
                lib_names = list(lib_key) if isinstance(lib_key, tuple) else [lib_key]
                label = lib_names[0].rstrip("/")
                # 1) filter by fe.library attribute if present
                subset = [fe for fe in all_func_entities
                          if getattr(fe, "library", None) in lib_names]
                # 2) fallback: prefix match on func_id
                if not subset:
                    subset = [fe for fe in all_func_entities
                              if any(fe.func_id.startswith(p) for p in lib_names)]
                # No functions matched this library: the ground truth cannot be
                # in an empty pool, so ranking against the FULL corpus (637k
                # funcs) is both meaningless and a guaranteed memory blow-up
                # (materialising one entity matrix per function OOMs). Record
                # the CVEs as failures and skip rather than aborting the run.
                if not subset:
                    msg = f"no functions in corpus matched library '{label}'"
                    print(f"  WARNING: {msg} — skipping {len(pending)} CVEs "
                          f"{pending}")
                    _record_error("library", pending, label, RuntimeError(msg))
                    component_counters["candidate_pools"]["empty_library_skips"] += len(pending)
                    continue
            else:
                subset = all_func_entities
                label = "full"
                component_counters["candidate_pools"]["full_pool_cves"] += len(pending)

            component_counters["candidate_pools"]["libraries_seen"] += 1
            component_counters["candidate_pools"]["pool_sizes"][label] = len(subset)

            print(f"\nBuilding retriever for library '{label}' "
                  f"({len(subset)} functions, {len(pending)}/{len(cve_ids)} "
                  f"CVEs pending) ...")
            try:
                retriever = PrioritySemanticRetriever(
                    subset, embedder,
                    threshold=threshold, bm25_top_k=bm25_top_k,
                    cache=cache,
                )
            except Exception as exc:  # noqa: BLE001 — skip whole library, log
                print(f"  ERROR building retriever for '{label}': "
                      f"{type(exc).__name__}: {exc} — skipping {len(pending)} CVEs")
                _record_error("library", pending, label, exc)
                continue
            for cve_id in tqdm(pending, desc=f"ranking [{label}]"):
                if _rank_cve(cve_id, retriever, label):
                    new_since_flush += 1
                    if new_since_flush >= checkpoint_every:
                        _flush_checkpoint()
                        new_since_flush = 0
        _flush_checkpoint()
    else:
        # Original behaviour: single retriever over the full corpus
        pending = [c for c in desc_corpus if c not in ranked]
        if pending:
            retriever = PrioritySemanticRetriever(
                all_func_entities, embedder,
                threshold=threshold, bm25_top_k=bm25_top_k,
                cache=cache,
            )
            new_since_flush = 0
            for cve_id in tqdm(pending, desc="ranking"):
                if _rank_cve(cve_id, retriever, "full"):
                    new_since_flush += 1
                    if new_since_flush >= checkpoint_every:
                        _flush_checkpoint()
                        new_since_flush = 0
        _flush_checkpoint()

    _flush_errors()
    if errors:
        print(f"\n{len(errors)} item(s) failed and were skipped — "
              f"see {error_log_path}")

    component_counters["ranking"]["cves_ranked_output"] = len(ranked)
    result = {
        "_component_counters": component_counters,
        "ranked": {cve_id: list(pairs) for cve_id, pairs in ranked.items()},
    }

    # Evaluate if ground truth provided
    if ground_truth_path:
        with open(ground_truth_path, encoding="utf-8") as f:
            gt = json.load(f)
        gt = {k: v for k, v in gt.items() if not k.startswith("_")}
        result["metrics"] = evaluate(ranked, gt)
        print("\nEvaluation:")
        for metric, val in result["metrics"].items():
            print(f"  {metric}: {val}")

    # Save output
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\nOutput saved to: {output_path}")
        counter_path = Path(output_path).with_suffix(
            Path(output_path).suffix + ".component_counters.json"
        )
        with open(counter_path, "w", encoding="utf-8") as f:
            json.dump(component_counters, f, indent=2, ensure_ascii=False)
        print(f"Component counters saved to: {counter_path}")

    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Component 4: Priority Semantic Retrieval"
    )
    parser.add_argument("--desc-corpus",
                        default=str(config.OUTPUT_DIR / "description_corpus.json"),
                        help="Phase 2 description corpus JSON")
    parser.add_argument("--func-corpus",
                        default=str(config.OUTPUT_DIR / "function_corpus_all.json"),
                        help="Phase 3 function corpus JSON")
    parser.add_argument("--ground-truth",
                        default=str(config.DATA_DIR / "ground_truth_sample.json"),
                        help="ground truth JSON for evaluation (optional)")
    parser.add_argument("--output",
                        default=str(config.OUTPUT_DIR / "retrieval_results.json"),
                        help="path to write ranked results")
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Algorithm 1 similarity threshold for an entity to count")
    parser.add_argument(
        "--model",
        default=os.environ.get("VFF_EMBED_MODEL")
        or os.environ.get("VFFINDER_EMBED_MODEL")
        or "WhereIsAI/UAE-Large-V1",
    )
    parser.add_argument("--bm25-top-k", type=int, default=0,
                        help="BM25 shortlist size (0 = OFF, rank the full pool like "
                             "paper Algorithm 1; set >0 only to bound work on huge pools)")
    parser.add_argument("--class-hints",
                        default=str(config.DATA_DIR / "class_hints.json"),
                        help="JSON {cve_id: [class names]} for class-priority matching (optional)")
    parser.add_argument("--rank-strategy", choices=["pointwise", "pairwise"],
                        default="pointwise",
                        help="pointwise = Algorithm 1 only; pairwise = LLM tournament "
                             "re-rank extension of the top results")
    parser.add_argument("--pairwise-top-m", type=int, default=5,
                        help="how many top pointwise results the pairwise pass reorders")
    parser.add_argument("--llm-model", default=None,
                        help="LLM model for pairwise ranking (default: config.MODEL)")
    parser.add_argument("--descriptions",
                        default=str(config.DATA_DIR / "cve_descriptions.json"),
                        help="JSON {cve_id: {description}} — raw text for the pairwise judge")
    parser.add_argument("--library-map",
                        default=str(config.DATA_DIR / "cve_library_map.json"),
                        help="JSON file mapping cve_id to library prefix for per-library retrieval")
    parser.add_argument("--checkpoint", default=None,
                        help="checkpoint JSON for crash-safe resume "
                             "(default: <output>.checkpoint.json)")
    parser.add_argument("--no-checkpoint", action="store_true",
                        help="disable checkpoint/resume entirely")
    parser.add_argument("--checkpoint-every", type=int, default=10,
                        help="flush checkpoint after this many ranked CVEs")
    parser.add_argument("--cache-dir", default=None,
                        help="directory for the on-disk embedding cache "
                             "(default: <output-dir>/.emb_cache)")
    parser.add_argument("--no-cache", action="store_true",
                        help="disable the on-disk embedding cache")
    parser.add_argument("--error-log", default=None,
                        help="JSON error log for skipped CVEs/libraries "
                             "(default: <output>.errors.json)")
    parser.add_argument("--no-error-log", action="store_true",
                        help="do not write an error log file")
    args = parser.parse_args(argv)

    for path, name in [(args.desc_corpus, "description corpus"),
                       (args.func_corpus, "function corpus")]:
        if not Path(path).exists():
            print(f"{name} not found: {path}", file=sys.stderr)
            return 1

    library_map = None
    if args.library_map and Path(args.library_map).exists():
        with open(args.library_map, encoding="utf-8") as f:
            raw_map = json.load(f)
        library_map = {k: v for k, v in raw_map.items() if not k.startswith("_")}
        print(f"Per-library retrieval enabled ({len(library_map)} CVE mappings)")

    # Class-priority matching (paper §4.2 ii + §4.4 — the single highest-impact
    # component in the paper's RQ4 ablation). A pre-built file overrides; otherwise
    # we DERIVE hints from each CVE description with the same regex the paper uses,
    # so class matching is never silently OFF and needs no hand-curated file.
    class_hints = None
    if args.class_hints and Path(args.class_hints).exists():
        with open(args.class_hints, encoding="utf-8") as f:
            raw_hints = json.load(f)
        class_hints = {k: v for k, v in raw_hints.items() if not k.startswith("_")}
        print(f"Class-priority matching: {len(class_hints)} CVE hints from "
              f"{args.class_hints}")
    else:
        desc_path = config.DATA_DIR / "cve_descriptions.json"
        if desc_path.exists():
            with open(desc_path, encoding="utf-8") as f:
                raw_desc = json.load(f)
            class_hints = {}
            for cid, v in raw_desc.items():
                if cid.startswith("_"):
                    continue
                text = v.get("description") if isinstance(v, dict) else v
                hints = extract_class_hints(text or "")
                if hints:
                    class_hints[cid] = hints
            print(f"Class-priority matching: derived hints for "
                  f"{len(class_hints)} CVE(s) from descriptions (§4.2 ii)")

    descriptions = None
    if args.rank_strategy == "pairwise" and args.descriptions and Path(args.descriptions).exists():
        with open(args.descriptions, encoding="utf-8") as f:
            raw_desc = json.load(f)
        descriptions = {k: (v.get("description") if isinstance(v, dict) else v)
                        for k, v in raw_desc.items() if not k.startswith("_")}
        print(f"Pairwise ranking enabled (raw descriptions for {len(descriptions)} CVEs)")

    # Resolve checkpoint / cache locations (default next to the output file).
    if args.no_checkpoint:
        checkpoint_path = None
    elif args.checkpoint:
        checkpoint_path = args.checkpoint
    else:
        checkpoint_path = str(Path(args.output).with_suffix(
            Path(args.output).suffix + ".checkpoint.json"))

    if args.no_cache:
        cache_dir = None
    elif args.cache_dir:
        cache_dir = args.cache_dir
    else:
        cache_dir = str(Path(args.output).parent / ".emb_cache")

    if args.no_error_log:
        error_log_path = None
    elif args.error_log:
        error_log_path = args.error_log
    else:
        error_log_path = str(Path(args.output).with_suffix(
            Path(args.output).suffix + ".errors.json"))

    run_retrieval(
        description_corpus_path=args.desc_corpus,
        function_corpus_path=args.func_corpus,
        ground_truth_path=args.ground_truth if Path(args.ground_truth).exists() else None,
        output_path=args.output,
        top_k=args.top_k,
        threshold=args.threshold,
        model_name=args.model,
        bm25_top_k=args.bm25_top_k,
        library_map=library_map,
        class_hints=class_hints,
        rank_strategy=args.rank_strategy,
        pairwise_top_m=args.pairwise_top_m,
        llm_model=args.llm_model,
        descriptions=descriptions,
        checkpoint_path=checkpoint_path,
        cache_dir=cache_dir,
        checkpoint_every=args.checkpoint_every,
        error_log_path=error_log_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
