from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Verdict(str, Enum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    UNKNOWN = "unknown"

    # Backward-compatible aliases used by the old CLI display layer.
    AFFECTED = "reachable"
    NOT_AFFECTED = "not_reachable"


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    sarif = "sarif"


class EntryPointType(str, Enum):
    MAIN = "main"
    CLI = "cli"
    WEB = "web"
    TEST = "test"
    UNKNOWN = "unknown"


@dataclass(eq=False)
class FunctionNode:
    file_path: str
    function_name: str
    qualified_name: str = ""
    line_number: int = 0
    entry_type: EntryPointType = EntryPointType.UNKNOWN
    is_external: bool = False

    def __hash__(self) -> int:
        return hash((str(Path(self.file_path)).replace("\\", "/"), self.function_name, self.is_external))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FunctionNode):
            return False
        return (
            str(Path(self.file_path)).replace("\\", "/"),
            self.function_name,
            self.is_external,
        ) == (
            str(Path(other.file_path)).replace("\\", "/"),
            other.function_name,
            other.is_external,
        )


@dataclass(eq=False)
class ExternalNode(FunctionNode):
    target_module: str = ""
    target_name: str = ""
    is_external: bool = True

    @property
    def identity_string(self) -> str:
        return ".".join(part for part in (self.target_module, self.target_name) if part)

    def __hash__(self) -> int:
        return hash((self.target_module, self.target_name, True))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, ExternalNode)
            and self.target_module == other.target_module
            and self.target_name == other.target_name
        )


@dataclass
class CallEdge:
    caller: FunctionNode
    callee: FunctionNode


@dataclass
class CallGraph:
    nodes: set[FunctionNode] = field(default_factory=set)
    edges: list[CallEdge] = field(default_factory=list)

    def add_node(self, node: FunctionNode) -> bool:
        before = len(self.nodes)
        self.nodes.add(node)
        return len(self.nodes) != before


@dataclass
class LibrarySummary:
    inner_summary: dict[str, set[str]] = field(default_factory=dict)
    outer_summary: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class ReachabilityPath:
    project_api: str
    tpl_chain: list[str]
    vulnerable_target: str


@dataclass
class QueryReport:
    is_vulnerable: bool
    paths: list[ReachabilityPath] = field(default_factory=list)


@dataclass
class Evidence:
    source: str
    detail: str
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerableEntity:
    package: str
    name: str
    entity_type: str = "function"
    role: str = "sink"
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class VulnerabilityRecord:
    cve_id: str
    package: str
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    entities: list[VulnerableEntity] = field(default_factory=list)


@dataclass
class IndexResult:
    package: str
    version: str
    functions: int = 0
    api_count: int = 0
    elapsed_s: float = 0.0
    cached: bool = False


@dataclass
class LocalizeResult:
    cve_id: str
    package: str
    vf: str = ""
    score: float = 0.0
    mode: str = "unknown"
    candidates: list[str] = field(default_factory=list)
    cached: bool = False


@dataclass
class ScanResult:
    cve_id: str
    project: Path
    verdict: Verdict = Verdict.UNKNOWN
    vf: str = ""
    entry_points: list[str] = field(default_factory=list)
    hit_set: list[str] = field(default_factory=list)
    call_chain: list[str] = field(default_factory=list)
    query_time_ms: float = 0.0
    llm_invoked: bool = False
