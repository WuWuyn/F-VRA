import os, hashlib, logging
from typing import List, Dict, Tuple, Set
from .models import CVERecord, FunctionRecord

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
# MODULE 3: SWISS-SYSTEM LLM RANKER
# ══════════════════════════════════════════════════════════════════

class LLMJudge:
    """
    Goi LLM (GPT-4 hoac tuong thich) de so sanh cap ham.
    Ky thuat: In-Context Learning (ICL) voi 2 vi du minh hoa.
    """

    SYSTEM_PROMPT = """\
You are a senior security researcher specializing in Python vulnerability analysis.
Given two Python functions and a CVE description, determine which is MORE LIKELY
to contain the described security vulnerability.

--- EXAMPLE 1 ---
CVE: "Unsafe deserialization of user-supplied pickle data allows RCE"
FUNCTION_A (save_config): def save_config(data): return json.dumps(data)
FUNCTION_B (load_session): def load_session(raw): return pickle.loads(raw)
Answer: FUNCTION_B
Reason: pickle.loads() with untrusted input enables RCE; json.dumps() is safe.

--- EXAMPLE 2 ---
CVE: "URL parsing does not strip whitespace allowing blocklist bypass"
FUNCTION_A (validate_url):
    def validate_url(url):
        parsed = urlparse(url)
        if parsed.netloc in BLOCKLIST: return False
        return True
FUNCTION_B (normalize): def normalize(url): return url.strip().lower()
Answer: FUNCTION_A
Reason: urlparse called without stripping whitespace first.
--- END EXAMPLES ---

Respond: Line 1 = "FUNCTION_A" or "FUNCTION_B". Line 2 = reason (max 25 words)."""

    def __init__(self, api_key: str = "", model: str = "gpt-4o-mini"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model   = model
        self._cache: Dict[str, Tuple[str, str]] = {}
        self.total_calls = 0

    def compare(self, fa: FunctionRecord, fb: FunctionRecord,
                cve: CVERecord) -> Tuple[FunctionRecord, FunctionRecord, float]:
        """
        So sanh 2 ham.
        Returns: (winner, loser, score)  score=1.0 (thang) hoac 0.5 (hoa)
        """
        key = hashlib.md5(
            f"{fa.full_name}|{fb.full_name}|{cve.cve_id}".encode()
        ).hexdigest()
        if key not in self._cache:
            if HAS_OPENAI and self.api_key:
                label, reason = self._api(fa, fb, cve)
            else:
                label, reason = self._heuristic(fa, fb)
            self._cache[key] = (label, reason)
        label, _ = self._cache[key]
        self.total_calls += 1
        if label == "A":
            return fa, fb, 1.0
        elif label == "B":
            return fb, fa, 1.0
        return fa, fb, 0.5

    def _api(self, fa: FunctionRecord, fb: FunctionRecord,
             cve: CVERecord) -> Tuple[str, str]:
        """Goi OpenAI API."""
        prompt = (
            f"CVE: {cve.cve_id}\nDescription: {cve.description[:400]}\n\n"
            f"FUNCTION_A [{fa.full_name}]:\n```python\n{fa.source_code[:600]}\n```\n\n"
            f"FUNCTION_B [{fb.full_name}]:\n```python\n{fb.source_code[:600]}\n```"
        )
        try:
            client = openai.OpenAI(api_key=self.api_key)
            resp   = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": self.SYSTEM_PROMPT},
                          {"role": "user",   "content": prompt}],
                max_tokens=80, temperature=0.1
            )
            text  = resp.choices[0].message.content.strip()
            lines = text.splitlines()
            label = ("A" if "FUNCTION_A" in lines[0].upper() else
                     "B" if "FUNCTION_B" in lines[0].upper() else "DRAW")
            reason = lines[1].strip() if len(lines) > 1 else ""
            return label, reason
        except Exception as e:
            logger.warning(f"  LLM API error: {e}")
            return self._heuristic(fa, fb)

    def _heuristic(self, fa: FunctionRecord,
                   fb: FunctionRecord) -> Tuple[str, str]:
        """Heuristic khi khong co API key: dung TF-IDF score."""
        if fa.similarity_score >= fb.similarity_score:
            return "A", f"Heuristic: score_A={fa.similarity_score:.4f}"
        return "B", f"Heuristic: score_B={fb.similarity_score:.4f}"


class SwissSystemRanker:
    """
    Module 3: Swiss-System + Exhaustive Pairwise Ranking.

    Buoc 1 - Swiss-System Tournament (8 vong, ~400 LLM queries):
      - Moi vong: xep cap ham co so wins tuong duong
      - Thang: +1, Thua: +0, Hoa: +0.5
      - Tranh cung cap 2 lan
      - Output: Top-20 candidates tot nhat

    Buoc 2 - Exhaustive Pairwise (Top-20, C(20,2)=190 queries):
      - So sanh toan dien moi cap trong Top-20
      - Tinh tong Wi cho tung ham
      - Xep hang giam dan theo Wi
      -> Final ranking
    """
    def __init__(self, judge: LLMJudge, num_rounds: int = 8, top_n: int = 20):
        self.judge      = judge
        self.num_rounds = num_rounds
        self.top_n      = top_n

    def rank(self, candidates: List[FunctionRecord],
             cve: CVERecord) -> List[FunctionRecord]:
        """
        Chay toan bo Swiss-System + Exhaustive Pairwise.
        Input : toi da 100 candidates
        Output: danh sach xep hang (index 0 = Top-1 VF)
        """
        if not candidates:
            return []

        # Reset
        for fr in candidates:
            fr.swiss_wins = fr.swiss_losses = 0
            fr.swiss_draws = fr.swiss_score = 0.0

        # ── Buoc 1: Swiss-System (8 vong) ───────────────────────────
        logger.info(f"\n[M3] Swiss-System: {len(candidates)} candidates, {self.num_rounds} rounds")
        played: Set[frozenset] = set()

        for rnd in range(1, self.num_rounds + 1):
            ordered = sorted(candidates,
                             key=lambda x: (x.swiss_wins + x.swiss_draws * 0.5, x.similarity_score),
                             reverse=True)
            pairs = self._swiss_pairs(ordered, played)
            if not pairs:
                logger.info(f"  Round {rnd}: khong con cap moi, dung som")
                break
            for fa, fb in pairs:
                w, l, sc = self.judge.compare(fa, fb, cve)
                if sc == 1.0:
                    w.swiss_wins  += 1
                    l.swiss_losses += 1
                else:
                    w.swiss_draws += 0.5
                    l.swiss_draws += 0.5
                played.add(frozenset([fa.full_name, fb.full_name]))
            logger.info(f"  Round {rnd}: {len(pairs)} matches | LLM calls: {self.judge.total_calls}")

        # Top-20 sau Swiss
        top20 = sorted(candidates,
                       key=lambda x: (x.swiss_wins + x.swiss_draws * 0.5, x.similarity_score),
                       reverse=True)[:self.top_n]
        logger.info(f"  Swiss done -> Top-{self.top_n} chon")

        # ── Buoc 2: Exhaustive Pairwise Ranking (Top-20) ────────────
        n_pairs = len(top20) * (len(top20) - 1) // 2
        logger.info(f"[M3] Exhaustive Pairwise: {n_pairs} matches tren Top-{len(top20)}")

        # Reset Wi cho Top-20
        for fr in top20:
            fr.swiss_wins = fr.swiss_losses = 0
            fr.swiss_draws = 0.0

        for i in range(len(top20)):
            for j in range(i + 1, len(top20)):
                w, l, sc = self.judge.compare(top20[i], top20[j], cve)
                if sc == 1.0:
                    w.swiss_wins  += 1
                    l.swiss_losses += 1
                else:
                    w.swiss_draws += 0.5
                    l.swiss_draws += 0.5

        logger.info(f"  Exhaustive done. Total LLM calls: {self.judge.total_calls}")

        # Xep hang cuoi cung theo tong Wi
        final = sorted(top20,
                       key=lambda x: (x.swiss_wins + x.swiss_draws * 0.5, x.similarity_score),
                       reverse=True)

        # Chuan hoa swiss_score [0,1]
        max_w = max((fr.swiss_wins + fr.swiss_draws * 0.5 for fr in final), default=1) or 1
        for fr in final:
            fr.swiss_score = (fr.swiss_wins + fr.swiss_draws * 0.5) / max_w

        logger.info(f"  Top-1: {final[0].full_name} "
                    f"(Wi={final[0].swiss_wins}, score={final[0].swiss_score:.3f})")
        return final

    def _swiss_pairs(self, ordered: List[FunctionRecord],
                     played: Set[frozenset]) -> List[Tuple[FunctionRecord, FunctionRecord]]:
        """Tao cap dau Swiss: wins tuong duong, tranh cap da gap."""
        pairs, unpaired = [], list(ordered)
        i = 0
        while i < len(unpaired) - 1:
            fa = unpaired[i]
            for j in range(i + 1, min(i + 6, len(unpaired))):
                fb  = unpaired[j]
                key = frozenset([fa.full_name, fb.full_name])
                if key not in played:
                    pairs.append((fa, fb))
                    unpaired.pop(j)
                    unpaired.pop(i)
                    break
            else:
                i += 1
        return pairs

