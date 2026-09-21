"""Shared data models for VFFinder method components."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FunctionEntity:
    func_id: str
    name: str
    module: str
    class_name: str
    params: list[str] = field(default_factory=list)
    param_types: list[str] = field(default_factory=list)
    source: str = ""
    entities: list[str] = field(default_factory=list)
    library: str = ""

    def to_dict(self) -> dict:
        return {
            "func_id": self.func_id,
            "name": self.name,
            "module": self.module,
            "class_name": self.class_name,
            "params": self.params,
            "param_types": self.param_types,
            "entities": self.entities,
            "library": self.library,
        }
