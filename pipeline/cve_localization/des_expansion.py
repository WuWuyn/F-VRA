import os
import re
import math
import logging
import json

from typing import Optional, List, Dict, Set
import requests, numpy as np, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.pipeline import Pipeline
from models import CVERecord

try:
    import nltk
    from nltk.stem import PorterStemmer
    from nltk.corpus import stopwords as _nltk_sw
    nltk.download("stopwords", quiet=True)
    nltk.download("punkt", quiet=True)
    HAS_NLTK = True
    _STEMMER = PorterStemmer()
    _STOPWORDS = set(_nltk_sw.words("english"))
except Exception:
    HAS_NLTK = False
    _STEMMER = None
    _STOPWORDS = set()

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
# MODULE 1 — QUERY EXPANSION & REFORMULATION
#
# Step 1 — Kiem tra CWE:
#   TH1: Co CWE  -> Query Expansion (QE) truc tiep tu CWE da cung cap
#   TH2: Khong CWE -> PRF + BM25 tim CWE tu CWE-1000
#
# Step 2 — Reformulation:
#   NLP preprocessing -> TF-IDF + LSA -> Cosine Similarity -> Emphasis x5
# ══════════════════════════════════════════════════════════════════

class _BM25:
    """
    BM25 (Okapi BM25) thuan Python — khong can thu vien ngoai.
    Dung trong TH2 de tim CWE lien quan nhat tu CWE-1000.
    Tham so: k1=1.5, b=0.75 (Robertson & Zaragoza 2009).
    """
    def __init__(self, corpus: List[str], k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b  = b
        self.tok = [self._t(d) for d in corpus]
        self.N   = len(self.tok)
        self.avgdl = sum(len(d) for d in self.tok) / max(self.N, 1)
        self._idf: Dict[str, float] = {}
        self._build_idf()

    def _t(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{1,}", text.lower())

    def _build_idf(self):
        df: Dict[str, int] = {}
        for doc in self.tok:
            for t in set(doc):
                df[t] = df.get(t, 0) + 1
        self._idf = {
            t: math.log((self.N - f + 0.5) / (f + 0.5) + 1.0)
            for t, f in df.items()
        }

    def scores(self, query: str) -> np.ndarray:
        q = self._t(query)
        out = np.zeros(self.N)
        for qi in q:
            idf = self._idf.get(qi, 0.0)
            if idf == 0.0:
                continue
            for i, doc in enumerate(self.tok):
                f  = doc.count(qi)
                dl = len(doc)
                num = f * (self.k1 + 1.0)
                den = f + self.k1 * (1.0 - self.b + self.b * dl / self.avgdl)
                out[i] += idf * (num / den if den > 0 else 0.0)
        return out


class CWE1000Database:
    """
    Co so du lieu CWE-1000 — dung cho TH2 (khong co CWE).

    Nguon du lieu (theo thu tu uu tien):
      1. CSV local (neu nguoi dung cung cap: cwe_database.csv)
      2. Fetch tu MITRE CAPEC GitHub JSON:
         https://raw.githubusercontent.com/CWE-CAPEC/REST-API-wg/main/json/cwe.json
      3. Fallback: 30 CWE quan trong nhat (hardcoded)

    Link tra cuu truc tiep tung CWE:
      https://cwe.mitre.org/data/definitions/{num}.html
    """

    CAPEC_JSON_URL = (
        "https://raw.githubusercontent.com/CWE-CAPEC/REST-API-wg/main/json/cwe.json"
    )
    CWE_DETAIL_URL = "https://cwe.mitre.org/data/definitions/{num}.html"

    def __init__(self, csv_path: str = "cwe_database.csv"):
        self.csv_path = csv_path
        self.df: Optional[pd.DataFrame] = None
        self._bm25: Optional[_BM25] = None
        self._corpus: List[str] = []
        self._load()

    def _load(self):
        if os.path.exists(self.csv_path):
            logger.info(f"[CWE-1000] Load CSV: {self.csv_path}")
            self.df = pd.read_csv(self.csv_path)
        else:
            logger.info(f"[CWE-1000] Fetch tu MITRE GitHub...")
            self.df = self._fetch_remote()
            if self.df is None:
                logger.warning("[CWE-1000] Fetch that bai -> dung 30 CWE hardcoded")
                self.df = self._hardcoded_30()
        self._build_bm25()
        logger.info(f"[CWE-1000] San sang: {len(self.df)} entries")

    def _fetch_remote(self) -> Optional[pd.DataFrame]:
        """Fetch CWE tu MITRE CAPEC GitHub JSON."""
        try:
            resp = requests.get(self.CAPEC_JSON_URL, timeout=15)
            resp.raise_for_status()
            raw = resp.json()
            entries = raw if isinstance(raw, list) else raw.get("weaknesses", raw.get("Weaknesses", []))
            rows = []
            for e in entries[:300]:
                rows.append({
                    "CWE_ID": f"CWE-{e.get('id', e.get('ID', ''))}",
                    "Name":   e.get("name", e.get("Name", "")),
                    "Description": e.get("description", e.get("Description", "")),
                    "ExtendedDescription": e.get("extended_description", e.get("ExtendedDescription", ""))
                })
            logger.info(f"[CWE-1000] Fetch OK: {len(rows)} CWE")
            return pd.DataFrame(rows) if rows else None
        except Exception as ex:
            logger.debug(f"[CWE-1000] Fetch error: {ex}")
            return None

    def _build_bm25(self):
        ext = "ExtendedDescription"
        self._corpus = (
            self.df["Name"].fillna("") + " " +
            self.df["Description"].fillna("") + " " +
            (self.df[ext].fillna("") if ext in self.df.columns else pd.Series([""] * len(self.df)))
        ).tolist()
        self._bm25 = _BM25(self._corpus)

    def find_top_k(self, query: str, k: int = 3) -> List[Dict]:
        """BM25 tim top-k CWE lien quan nhat."""
        if self._bm25 is None:
            return []
        sc  = self._bm25.scores(query)
        idx = np.argsort(sc)[::-1][:k]
        out = []
        for i in idx:
            row = self.df.iloc[i]
            cid = str(row.get("CWE_ID", ""))
            out.append({
                "cwe_id": cid,
                "name":   str(row.get("Name", "")),
                "description": str(row.get("Description", "")),
                "ext":    str(row.get("ExtendedDescription", "")) if "ExtendedDescription" in self.df.columns else "",
                "score":  float(sc[i]),
                "url":    self.CWE_DETAIL_URL.format(num=cid.replace("CWE-", ""))
            })
        return out

    def get_detail(self, cwe_id: str) -> Optional[Dict]:
        """Lay chi tiet mot CWE cu the."""
        num  = cwe_id.replace("CWE-", "")
        mask = self.df["CWE_ID"].astype(str).str.replace("CWE-", "") == num
        rows = self.df[mask]
        if not rows.empty:
            row = rows.iloc[0]
            return {
                "cwe_id": cwe_id,
                "name":   str(row.get("Name", "")),
                "description": str(row.get("Description", "")),
                "ext":    str(row.get("ExtendedDescription", "")) if "ExtendedDescription" in self.df.columns else "",
                "url":    self.CWE_DETAIL_URL.format(num=num)
            }
        # Fallback: fetch truc tiep tu MITRE
        return self._fetch_single(cwe_id)

    def _fetch_single(self, cwe_id: str) -> Optional[Dict]:
        """Fetch mot CWE tu MITRE website."""
        num = cwe_id.replace("CWE-", "")
        url = self.CWE_DETAIL_URL.format(num=num)
        try:
            resp  = requests.get(url, timeout=8)
            text  = resp.text
            match = re.search(
                r'<div[^>]*id="Description"[^>]*>.*?<p[^>]*>(.*?)</p>',
                text, re.DOTALL | re.IGNORECASE
            )
            desc = re.sub(r"<[^>]+>", "", match.group(1)).strip() if match else ""
            return {"cwe_id": cwe_id, "name": cwe_id, "description": desc, "ext": "", "url": url}
        except Exception:
            return None

    def _hardcoded_30(self) -> pd.DataFrame:
        """30 CWE quan trong nhat trong Python ecosystem (offline fallback)."""
        rows = [
            ("CWE-20",   "Improper Input Validation",
             "Product receives input that it does not validate or incorrectly validates.",
             "Allows crafted inputs bypassing security controls via injection, overflow, or logic bypass."),
            ("CWE-22",   "Path Traversal",
             "Software uses external input to construct pathnames without neutralizing .. sequences.",
             "Attackers escape directories using ../ sequences. Python open() without sanitization is a common sink."),
            ("CWE-78",   "OS Command Injection",
             "Software constructs OS commands using external input without neutralizing special elements.",
             "Python subprocess, os.system, os.popen with shell=True and user input enable command injection."),
            ("CWE-79",   "Cross-site Scripting",
             "Software does not neutralize user input placed in HTML output.",
             "Flask render_template, Django template without escaping enable XSS."),
            ("CWE-89",   "SQL Injection",
             "Software constructs SQL commands using external input without neutralization.",
             "Python sqlite3.execute, psycopg2 with string formatting instead of parameterized queries."),
            ("CWE-94",   "Code Injection",
             "Software constructs code segments using external input without neutralization.",
             "Python eval(), exec(), compile(), importlib with user-controlled input enable arbitrary code execution."),
            ("CWE-200",  "Exposure of Sensitive Information",
             "Product exposes sensitive information to unauthorized actors.",
             "Python logging with secrets, error messages revealing stack traces, unprotected config files."),
            ("CWE-269",  "Improper Privilege Management",
             "Software does not properly assign, modify, track, or check privileges.",
             "Python os.setuid(), multiprocessing forkserver, privilege escalation via insecure temp files."),
            ("CWE-284",  "Improper Access Control",
             "Software does not restrict access to resources from unauthorized actors.",
             "Missing authentication decorators in Flask/Django, improper permission checks."),
            ("CWE-295",  "Improper Certificate Validation",
             "Software does not validate SSL/TLS certificates enabling MITM attacks.",
             "Python requests with verify=False, ssl.CERT_NONE, urllib without cert verification."),
            ("CWE-326",  "Inadequate Encryption Strength",
             "Software uses encryption scheme with insufficient strength.",
             "Short RSA keys, weak DH parameters, or small AES key sizes in Python crypto libraries."),
            ("CWE-327",  "Use of Broken Cryptographic Algorithm",
             "Use of broken or risky cryptographic algorithm exposes sensitive information.",
             "Python hashlib.md5(), hashlib.sha1(), DES, RC4 are broken. Use SHA-256+ and AES-GCM."),
            ("CWE-400",  "Uncontrolled Resource Consumption",
             "Software does not control resource allocation enabling resource exhaustion.",
             "ReDoS via catastrophic regex backtracking in Python re module, unlimited memory allocation."),
            ("CWE-416",  "Use After Free",
             "Referencing memory after it has been freed causes crashes or code execution.",
             "Python C extensions using PyObject after Py_DECREF cause use-after-free conditions."),
            ("CWE-476",  "NULL Pointer Dereference",
             "Application dereferences a NULL pointer causing crash or exit.",
             "Python C extension NULL pointer dereferences cause segfaults."),
            ("CWE-502",  "Deserialization of Untrusted Data",
             "Application deserializes untrusted data without sufficient verification.",
             "Python pickle.loads(), marshal.loads(), yaml.load() with untrusted data enable RCE."),
            ("CWE-601",  "URL Redirection to Untrusted Site",
             "Web application uses user-controlled input for redirect URLs without validation.",
             "Flask redirect(), Django HttpResponseRedirect() with unvalidated input allow open redirect."),
            ("CWE-611",  "Improper Restriction of XML External Entity",
             "Software processes XML with entities resolving to external documents.",
             "Python xml.etree, lxml with resolve_entities=True enable XXE file read and SSRF."),
            ("CWE-693",  "Protection Mechanism Failure",
             "Product does not use or incorrectly uses a protection mechanism.",
             "Disabled CSRF protection, missing CSP, or bypassed authentication in Flask/Django."),
            ("CWE-703",  "Improper Check of Exceptional Conditions",
             "Software does not properly handle exceptional conditions.",
             "Uncaught exceptions revealing sensitive information or causing undefined behavior."),
            ("CWE-706",  "Use of Incorrectly-Resolved Name or Reference",
             "Software uses a name resolving to a resource outside intended control sphere.",
             "Python os.path.realpath() missing before file ops, tempfile.mktemp() TOCTOU, symlink following."),
            ("CWE-732",  "Incorrect Permission Assignment for Critical Resource",
             "Software assigns permissions allowing unintended read or modify access.",
             "Python os.chmod() setting world-writable permissions on config files."),
            ("CWE-770",  "Allocation of Resources Without Limits",
             "Software allocates resources without restrictions enabling resource exhaustion.",
             "Unlimited socket connections, unbounded list growth in Python web frameworks."),
            ("CWE-787",  "Out-of-bounds Write",
             "Software writes data past the end or before the beginning of a buffer.",
             "Python ctypes buffer overwrite, struct.pack_into beyond buffer size."),
            ("CWE-835",  "Loop with Unreachable Exit Condition",
             "Program contains a loop whose exit condition cannot be reached.",
             "Python tarfile processing crafted archives with circular entries causes infinite CPU consumption."),
            ("CWE-918",  "Server-Side Request Forgery SSRF",
             "Web server retrieves content from URLs without ensuring expected destination.",
             "Python urllib.request.urlopen(), requests.get() with user URLs allow SSRF to internal services."),
            ("CWE-1333", "Inefficient Regular Expression Complexity",
             "Product uses a regular expression with exponential worst-case complexity.",
             "Nested quantifiers like (a+)+ in Python re cause catastrophic backtracking (ReDoS)."),
            ("CWE-1321", "Improperly Controlled Object Prototype Modification",
             "Software does not control modifications of object prototype attributes.",
             "Prototype pollution in Python dicts via recursive merge with __proto__ keys."),
            ("CWE-190",  "Integer Overflow or Wraparound",
             "Software performs calculation producing integer overflow causing unexpected behavior.",
             "In Python C extensions, struct.pack, ctypes, integer overflow leads to buffer overflows."),
            ("CWE-116",  "Improper Encoding or Escaping of Output",
             "Software prepares structured output without proper encoding causing injection.",
             "Missing HTML escaping in Jinja2, missing SQL parameterization, improper shell escaping."),
        ]
        return pd.DataFrame(rows, columns=["CWE_ID", "Name", "Description", "ExtendedDescription"])


class QueryExpander:
    """
    Module 1 - Step 1: Query Expansion.

    TH1 (co CWE): Query Expansion (QE)
      - Lay chi tiet CWE da duoc nguoi dung cung cap
      - Trich xuat Name + Description + ExtendedDescription
      - Tao Expansion_Context

    TH2 (khong co CWE): PRF + BM25
      - BM25 tim top-3 CWE tu CWE-1000
      - Pseudo Relevance Feedback: top-3 lam context mo rong
      - Bo sung CWE IDs vao cve.cwe_ids
    """
    def __init__(self, cwe_db: CWE1000Database):
        self.cwe_db = cwe_db

    def expand(self, cve: CVERecord) -> str:
        if cve.cwe_ids:
            logger.info(f"[M1/Step1] TH1: QE tu {len(cve.cwe_ids)} CWE da cung cap")
            return self._qe(cve)
        else:
            logger.info("[M1/Step1] TH2: PRF + BM25 tim CWE tu CWE-1000")
            return self._prf_bm25(cve)

    def _qe(self, cve: CVERecord) -> str:
        """TH1 - Query Expansion truc tiep tu CWE da biet."""
        parts = ["=== EXPANSION CONTEXT (QE - CWE duoc cung cap) ==="]
        for cwe_id in cve.cwe_ids:
            detail = self.cwe_db.get_detail(cwe_id)
            if detail:
                parts.append(
                    f"\n[{detail['cwe_id']}] {detail['name']}"
                    f"\n  URL : {detail['url']}"
                    f"\n  Desc: {detail['description'][:400]}"
                    f"\n  Ext : {detail['ext'][:300]}"
                )
            else:
                num = cwe_id.replace("CWE-", "")
                url = self.cwe_db.CWE_DETAIL_URL.format(num=num)
                logger.warning(f"  Khong tim thay {cwe_id} trong DB. URL: {url}")
                parts.append(f"\n[{cwe_id}] (Khong co trong DB — xem: {url})")
        return "\n".join(parts)

    def _prf_bm25(self, cve: CVERecord) -> str:
        """TH2 - PRF + BM25: tim top-3 CWE tu CWE-1000."""
        top3 = self.cwe_db.find_top_k(cve.description, k=3)
        parts = ["=== EXPANSION CONTEXT (PRF + BM25 - CWE-1000) ==="]
        for rank, item in enumerate(top3, 1):
            if item["cwe_id"] and item["cwe_id"] not in cve.cwe_ids:
                cve.cwe_ids.append(item["cwe_id"])
            parts.append(
                f"\n[Rank {rank}] {item['cwe_id']} - {item['name']} (BM25={item['score']:.3f})"
                f"\n  URL : {item['url']}"
                f"\n  Desc: {item['description'][:400]}"
                f"\n  Ext : {item['ext'][:300]}"
            )
        logger.info(f"  PRF phat hien CWE: {[i['cwe_id'] for i in top3]}")
        return "\n".join(parts)


class DescriptionReformulator:
    """
    Module 1 - Step 2: Reformulation.

    Buoc a) NLP Preprocessing: xoa stopwords, stemming (running->run)
    Buoc b) TF-IDF + LSA (SVD): vector hoa, giam chieu 100D
    Buoc c) Cosine Similarity: do khoang cach ngu nghia orig vs expansion
    Buoc d) Emphasis x5: lap lai description goc 5 lan

    Output: Final_Query (plain text) san sang cho Module 2.
    """

    SECURITY_NEUTRAL: Set[str] = {
        "product", "affected", "version", "versions", "before", "through",
        "attacker", "attackers", "allow", "allows", "allowed", "issue",
        "vulnerability", "vulnerabilities", "cve", "nvd", "nist",
        "software", "application", "system", "component", "module",
        "vendor", "advisory", "reference", "reported", "discovered",
        "exist", "exists", "via", "using", "used", "use", "also",
        "note", "however", "therefore", "thus", "hence", "could",
    }

    def __init__(self, n_components: int = 100):
        self.n_components = n_components

    def _preprocess(self, text: str) -> str:
        """
        NLP co ban:
        - Lowercase + xoa ky tu dac biet
        - Xoa stopwords (NLTK + security-neutral)
        - Stemming neu co NLTK
        """
        text  = text.lower()
        text  = re.sub(r"[^a-zA-Z0-9_\s]", " ", text)
        words = text.split()
        all_stop = _STOPWORDS | self.SECURITY_NEUTRAL
        result = []
        for w in words:
            if w in all_stop or len(w) < 2:
                continue
            w = _STEMMER.stem(w) if (HAS_NLTK and _STEMMER) else w
            result.append(w)
        return " ".join(result)

    def reformulate(self, cve: CVERecord) -> str:
        """
        Step 2 hoan chinh.
        Input : cve.description + cve.expansion_context
        Output: Final_Query = (orig x5) + refined_context
        """
        orig_clean = self._preprocess(cve.description)
        ctx_clean  = self._preprocess(cve.expansion_context)

        corpus = [orig_clean]
        if ctx_clean.strip():
            corpus.append(ctx_clean)

        # TF-IDF + LSA (SVD)
        n_comp = min(self.n_components, max(len(corpus) - 1, 1))
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=8000,
                ngram_range=(1, 2),
                sublinear_tf=True,
                token_pattern=r"(?u)\b[a-zA-Z_][a-zA-Z0-9_]{1,}\b"
            )),
            ("svd", TruncatedSVD(n_components=n_comp, random_state=42))
        ])
        matrix = pipe.fit_transform(corpus)

        # Cosine Similarity giua orig va context
        if len(corpus) >= 2:
            sim = float(cosine_similarity(matrix[0:1], matrix[1:2])[0][0])
            logger.info(f"  [M1/Step2] Cosine(orig, context) = {sim:.4f}")
        else:
            sim = 1.0

        # Chi them context neu co lien quan ngu nghia (sim > nguong)
        refined_ctx = ctx_clean if sim > 0.05 else ""

        # Emphasis x5: lap lai description goc 5 lan
        # Dam bao khong bi "lac de" boi expansion context
        emphasized = " ".join([orig_clean] * 5)

        final_query = emphasized
        if refined_ctx.strip():
            final_query += "\n\n" + refined_ctx

        logger.info(f"  [M1/Step2] Final_Query: {len(final_query)} chars")
        return final_query


class Module1:
    """Dieu phoi Module 1: Step 1 + Step 2."""

    def __init__(self, cwe_db_path: str = "cwe_database.csv"):
        self.cwe_db       = CWE1000Database(csv_path=cwe_db_path)
        self.expander     = QueryExpander(self.cwe_db)
        self.reformulator = DescriptionReformulator(n_components=100)

    def run(self, cve: CVERecord) -> CVERecord:
        """Chay toan bo Module 1, dien ket qua vao CVERecord."""
        logger.info(f"\n{'='*60}")
        logger.info(f"[Module1] CVE: {cve.cve_id}")
        logger.info(f"  Desc: {cve.description[:80]}...")

        # Step 1: Query Expansion
        cve.expansion_context = self.expander.expand(cve)

        # Step 2: Reformulation
        cve.expanded_description = self.reformulator.reformulate(cve)

        logger.info("[Module1] Hoan thanh - Final_Query san sang")
        return cve
