import logging
from typing import Optional, List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from models import CVERecord, FunctionRecord

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
# MODULE 2b: PATCH-ABSENT (TF-IDF thay the CodeBERT)
# ══════════════════════════════════════════════════════════════════

class PatchAbsentClassifier:
    """
    Patch-Absent Learning-based Candidate Selection.

    Theo paper: CodeBERT fine-tuned tao cap (description o+ function),
    tinh similarity qua CLS vector + Sigmoid.

    Implementation nay: TF-IDF Cosine Similarity thay CodeBERT
    (khong yeu cau GPU). Co che tuong tu:
      - Concatenation   : query = Final_Query + function_source
      - Bimodal         : cosine similarity (thay self-attention)
      - Feature Extract : TF-IDF vector (thay CLS vector)
      - Probability     : cosine score in [0,1] (thay Sigmoid output)

    De dung CodeBERT that: thay _tfidf_score() bang CodeBERT forward pass.
    """
    def __init__(self):
        self._vec: Optional[TfidfVectorizer] = None
        self._mat = None
        self._fns: List[FunctionRecord] = []

    def fit(self, functions: List[FunctionRecord]):
        """Build TF-IDF model tu toan bo functions."""
        self._fns = functions
        logger.info(f"[PatchAbsent] Fit TF-IDF: {len(functions)} functions...")
        corpus = [f"{fr.docstring}\n{fr.source_code}" for fr in functions]
        self._vec = TfidfVectorizer(
            max_features=15000, ngram_range=(1, 3),
            sublinear_tf=True,
            token_pattern=r"(?u)\b[a-zA-Z_][a-zA-Z0-9_]{1,}\b"
        )
        self._mat = self._vec.fit_transform(corpus)
        logger.info(f"  TF-IDF matrix: {self._mat.shape}")

    def select(self, cve: CVERecord, top_k: int = 100) -> List[FunctionRecord]:
        """
        Buoc 1-5 Patch-Absent:
          1. Tat ca functions la candidates ban dau
          2. Concatenation: query = Final_Query o+ function
          3. Bimodal: cosine similarity
          4. Feature: TF-IDF vector
          5. Score p in [0,1]
        -> top_k candidates xep hang.
        """
        if self._vec is None:
            raise RuntimeError("Goi fit() truoc select()")
        query  = cve.expanded_description or cve.description
        qvec   = self._vec.transform([query])
        sims   = cosine_similarity(qvec, self._mat)[0]
        for i, fr in enumerate(self._fns):
            fr.similarity_score = float(sims[i])
        ranked = sorted(self._fns, key=lambda x: x.similarity_score, reverse=True)
        top    = ranked[:top_k]
        logger.info(f"[PatchAbsent] Top-{top_k}: "
                    f"max={top[0].similarity_score:.4f}, min={top[-1].similarity_score:.4f}")
        return top