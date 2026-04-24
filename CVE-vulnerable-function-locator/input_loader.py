import json, logging
from pathlib import Path
from typing import Optional, List
from models import CVERecord

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
# INPUT LOADER
# ══════════════════════════════════════════════════════════════════

class InputLoader:
    """
    Doc du lieu dau vao tu folder nguoi dung chuan bi.

    Cau truc folder:
        input_folder/
            CVE-2023-24329.json    <- JSON, ten = CVE-ID
            urllib_parse.py        <- source .py cua thu vien bi anh huong
            requests_utils.py      <- co the nhieu file .py
            fix.patch              <- tuy chon

    Schema JSON:
        {
          "cve_id":      "CVE-2023-24329",
          "description": "...",
          "cwe_ids":     ["CWE-20"],      <- optional
          "patch_urls":  ["https://..."]  <- optional
        }

    NOTE: Code CO THE ket noi internet de bo sung them thong tin CWE
    tu MITRE/NVD (qua link), nhung du lieu goc LUON do nguoi dung cung cap.
    KHONG co mock CVE, KHONG auto-crawl CVE.
    """

    def __init__(self, input_folder: str):
        self.folder = Path(input_folder).resolve()
        if not self.folder.exists():
            raise FileNotFoundError(f"Folder khong ton tai: {self.folder}")

    def load_cve(self, cve_id: str) -> CVERecord:
        """
        Doc CVE tu file JSON.
        File phai ten: <cve_id>.json  (vd: CVE-2023-24329.json)
        """
        json_path = self.folder / f"{cve_id}.json"
        if not json_path.exists():
            raise FileNotFoundError(
                f"Khong tim thay file: {json_path}\n"
                f"Hay tao file {cve_id}.json trong {self.folder}"
            )
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        if "cve_id" not in data or "description" not in data:
            raise ValueError(f"JSON thieu truong bat buoc 'cve_id' hoac 'description': {json_path}")

        cve = CVERecord(
            cve_id=data["cve_id"],
            description=data["description"].strip(),
            cwe_ids=data.get("cwe_ids", []),
            patch_urls=data.get("patch_urls", [])
        )
        logger.info(f"[InputLoader] Load CVE: {cve.cve_id}")
        logger.info(f"  CWE IDs   : {cve.cwe_ids or '(khong co)'}")
        logger.info(f"  Patch URLs: {len(cve.patch_urls)} link(s)")
        return cve

    def get_py_files(self) -> List[Path]:
        """Lay tat ca file .py trong folder."""
        files = sorted(self.folder.glob("*.py"))
        if not files:
            files = sorted(self.folder.rglob("*.py"))
        logger.info(f"[InputLoader] Tim thay {len(files)} file .py")
        return files

    def get_patch_file(self) -> Optional[Path]:
        """Tim file .patch/.diff trong folder (neu co)."""
        for ext in ("*.patch", "*.diff"):
            found = list(self.folder.glob(ext))
            if found:
                return found[0]
        return None