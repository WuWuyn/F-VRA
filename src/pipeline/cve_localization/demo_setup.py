import json, textwrap, logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
# DEMO SETUP
# ══════════════════════════════════════════════════════════════════

class DemoSetup:
    """
    Tao folder demo day du de chay thu ngay ma khong can chuan bi thu cong.
    Gom 2 CVE:
      - CVE-2023-24329: co CWE (TH1 - QE mode)
      - CVE-2022-42919: khong co CWE (TH2 - PRF+BM25 mode)
    """

    @staticmethod
    def create(base: str = "/tmp/vfarche_demo") -> str:
        folder = Path(base)
        folder.mkdir(parents=True, exist_ok=True)

        # CVE-2023-24329 JSON (co CWE -> TH1)
        (folder / "CVE-2023-24329.json").write_text(json.dumps({
            "cve_id": "CVE-2023-24329",
            "description": (
                "An issue exists in the CPython urllib.parse component before 3.11.4. "
                "URL parsing functions fail to sanitize URLs that begin with blank "
                "characters. This allows attackers to bypass blocklist validation "
                "by prepending whitespace to malicious URLs. The urlparse and urlsplit "
                "functions do not strip leading whitespace, leading to URL validation "
                "bypass vulnerabilities in security-sensitive URL filtering."
            ),
            "cwe_ids":   ["CWE-20"],
            "patch_urls": ["https://github.com/python/cpython/issues/102153"]
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        # CVE-2022-42919 JSON (khong co CWE -> TH2)
        (folder / "CVE-2022-42919.json").write_text(json.dumps({
            "cve_id": "CVE-2022-42919",
            "description": (
                "Python multiprocessing forkserver mode on Linux allows pickled data "
                "to be deserialized from an arbitrary address. A local attacker executes "
                "arbitrary code via a crafted pickle payload, exploiting insecure "
                "deserialization in the multiprocessing module."
            ),
            "cwe_ids":   [],
            "patch_urls": ["https://github.com/python/cpython/issues/97514"]
        }, indent=2, ensure_ascii=False), encoding="utf-8")

        # url_utils.py - thu vien cho CVE-2023-24329
        (folder / "url_utils.py").write_text(textwrap.dedent('''\
            """URL utilities - contains CVE-2023-24329 style vulnerability."""
            from urllib.parse import urlparse, urlsplit

            BLOCKED_DOMAINS = ["evil.com", "malware.org", "phishing.net"]

            class URLValidator:
                """Validates URLs from user input."""

                def validate_url(self, url: str) -> bool:
                    """
                    VULNERABILITY: Does not strip leading whitespace.
                    Attacker can prepend \\n to bypass blocklist.
                    """
                    parsed = urlparse(url)          # BUG: no url.strip() first
                    return parsed.netloc.lower() not in BLOCKED_DOMAINS

                def safe_validate_url(self, url: str) -> bool:
                    """Fixed version: strips whitespace before parsing."""
                    url = url.strip()
                    parsed = urlparse(url)
                    return parsed.netloc.lower() not in BLOCKED_DOMAINS

                def parse_redirect(self, param: str) -> str:
                    """Returns redirect URL without scheme validation."""
                    return param

                def normalize(self, url: str) -> str:
                    """Normalize URL - safe."""
                    return urlsplit(url.strip())._replace(fragment="").geturl()

            def fetch_url(url: str) -> bytes:
                """Fetches URL content - no SSRF protection."""
                import urllib.request
                return urllib.request.urlopen(url).read()

            def get_scheme(url: str) -> str:
                """Returns URL scheme."""
                return urlparse(url).scheme
        '''), encoding="utf-8")

        # data_loader.py - thu vien cho CVE-2022-42919
        (folder / "data_loader.py").write_text(textwrap.dedent('''\
            """Data loading utilities - contains CVE-2022-42919 style vulnerability."""
            import json, pickle, base64, os

            class DataLoader:
                """Loads data from various formats."""

                def load_from_pickle(self, data: bytes):
                    """VULNERABILITY: pickle.loads with untrusted data = RCE."""
                    return pickle.loads(data)

                def load_from_json(self, data: str) -> dict:
                    """Safe: json.loads does not execute code."""
                    return json.loads(data)

                def load_session(self, encoded: str):
                    """VULNERABILITY: base64 decode then pickle.loads."""
                    raw = base64.b64decode(encoded)
                    return pickle.loads(raw)

                def save_session(self, obj) -> str:
                    """Serialize session to base64 string."""
                    return base64.b64encode(pickle.dumps(obj)).decode()

            class CacheManager:
                """In-memory cache with persistence."""

                def __init__(self):
                    self._store: dict = {}

                def get(self, key: str):
                    return self._store.get(key)

                def set(self, key: str, value) -> None:
                    self._store[key] = value

                def load_persistent(self, path: str):
                    """VULNERABILITY: loads pickle from file path."""
                    if os.path.exists(path):
                        with open(path, "rb") as f:
                            self._store = pickle.load(f)
        '''), encoding="utf-8")

        logger.info(f"[DemoSetup] Folder demo: {folder}")
        return str(folder)