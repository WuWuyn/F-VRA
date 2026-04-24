from dataclasses import dataclass, field
from typing import List, Optional

# ══════════════════════════════════════════════════════════════════
# DATACLASSES
# ══════════════════════════════════════════════════════════════════

@dataclass
class CVERecord:
    """
    Dữ liệu CVE do NGUOI DUNG cung cap qua file JSON.
    Khong tu dong crawl — user la chu the.
    """
    cve_id: str
    description: str
    cwe_ids: List[str]       = field(default_factory=list)
    patch_urls: List[str]    = field(default_factory=list)
    # Duoc dien boi Module 1:
    expanded_description: str = ""
    expansion_context: str    = ""


@dataclass
class FunctionRecord:
    """Mot ham/method duoc trich xuat tu .py file."""
    full_name: str       # package.module.Class.method
    package: str
    module: str
    class_name: str
    function_name: str
    source_code: str
    docstring: str
    file_path: str
    start_line: int
    end_line: int
    callers: List[str]    = field(default_factory=list)
    similarity_score: float = 0.0
    swiss_score: float      = 0.0
    swiss_wins: int         = 0
    swiss_losses: int       = 0
    swiss_draws: float      = 0.0


@dataclass
class MatchResult:
    """Ket qua cuoi cung cua VFArCHE."""
    cve_id: str
    mode_used: str
    ranked_functions: List[FunctionRecord]
    top_function: Optional[FunctionRecord]
    confidence: float