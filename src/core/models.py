from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Verdict(str, Enum):
    AFFECTED     = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN      = "UNKNOWN"


class OutputFormat(str, Enum):
    table = "table"
    json  = "json"
    sarif = "sarif"


@dataclass
class IndexResult:
    package:       str
    version:       str
    functions:     int = 0
    api_count:     int = 0
    elapsed_s:     float = 0.0
    cached:        bool = False


@dataclass
class LocalizeResult:
    cve_id:        str
    package:       str
    vf:            str = ""
    score:         float = 0.0
    mode:          str = "unknown"
    candidates:    list[str] = field(default_factory=list)
    cached:        bool = False


@dataclass
class ScanResult:
    cve_id:        str
    project:       Path
    verdict:       Verdict = Verdict.UNKNOWN
    vf:            str = ""
    entry_points:  list[str] = field(default_factory=list)
    hit_set:       list[str] = field(default_factory=list)
    call_chain:    list[str] = field(default_factory=list)
    query_time_ms: float = 0.0
    llm_invoked:   bool = False
