from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class IdentifierKind(str, Enum):
    MODULE = "module"
    EXTERNAL_MODULE = "external_module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    ATTRIBUTE = "attribute"


class TypeGraphRelationKind(str, Enum):
    ASSIGNS_TO = "assigns_to"
    POINTS_TO = "points_to"
    PARAMETER_FLOW = "parameter_flow"
    RETURN_FLOW = "return_flow"
    ATTRIBUTE_FLOW = "attribute_flow"
    IMPORT_ALIAS = "import_alias"
    INHERITS = "inherits"


@dataclass(frozen=True)
class TypeGraphNode:
    kind: IdentifierKind
    name: str
    namespace: str = ""

    @property
    def identity(self) -> str:
        return "::".join(part for part in (self.kind.value, self.namespace, self.name) if part)


@dataclass(frozen=True)
class TypeGraphRelation:
    source: TypeGraphNode
    target: TypeGraphNode
    kind: TypeGraphRelationKind
    location: str = ""
    reason: str = ""


@dataclass
class TypeGraphState:
    """Function-local type facts used by the callgraph engine.

    Missing variables mean top/unknown, so callers should keep candidates rather
    than pruning when a lookup returns ``None``.
    """

    bindings: dict[str, set[str]] = field(default_factory=dict)
    relations: list[TypeGraphRelation] = field(default_factory=list)

    def get(self, name: str) -> set[str] | None:
        values = self.bindings.get(name)
        return set(values) if values is not None else None

    def strong_update(self, name: str, types: Iterable[str], *, reason: str = "", location: str = "") -> None:
        values = {item for item in types if item}
        if not values:
            self.bindings.pop(name, None)
            return
        self.bindings[name] = values
        source = TypeGraphNode(IdentifierKind.VARIABLE, name)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=TypeGraphNode(IdentifierKind.CLASS, value),
                    kind=TypeGraphRelationKind.POINTS_TO,
                    location=location,
                    reason=reason,
                )
            )

    def weak_update(self, name: str, types: Iterable[str], *, reason: str = "", location: str = "") -> None:
        current = self.bindings.get(name)
        values = {item for item in types if item}
        if current is None or not values:
            self.bindings.pop(name, None)
            return
        self.strong_update(name, current | values, reason=reason, location=location)

    def set_top(self, name: str) -> None:
        self.bindings.pop(name, None)

    def copy(self) -> "TypeGraphState":
        return TypeGraphState({name: set(values) for name, values in self.bindings.items()}, list(self.relations))

    @staticmethod
    def join(left: "TypeGraphState", right: "TypeGraphState") -> "TypeGraphState":
        joined = TypeGraphState()
        for name in left.bindings.keys() & right.bindings.keys():
            joined.bindings[name] = set(left.bindings[name]) | set(right.bindings[name])
        joined.relations = list(left.relations) + list(right.relations)
        return joined


@dataclass
class FunctionTypeGraph:
    function: str
    entry_types: dict[str, set[str]] = field(default_factory=dict)
    return_types: set[str] = field(default_factory=set)
    relations: list[TypeGraphRelation] = field(default_factory=list)

    def record_parameter_flow(self, parameter: str, types: Iterable[str], *, caller: str = "") -> None:
        values = {item for item in types if item}
        if not values:
            return
        self.entry_types.setdefault(parameter, set()).update(values)
        source = TypeGraphNode(IdentifierKind.VARIABLE, parameter, namespace=self.function)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=TypeGraphNode(IdentifierKind.CLASS, value),
                    kind=TypeGraphRelationKind.PARAMETER_FLOW,
                    reason=f"argument propagated from {caller}" if caller else "argument propagated from callsite",
                )
            )

    def record_return_flow(self, types: Iterable[str], *, reason: str = "") -> None:
        values = {item for item in types if item}
        self.return_types.update(values)
        source = TypeGraphNode(IdentifierKind.FUNCTION, self.function)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=TypeGraphNode(IdentifierKind.CLASS, value),
                    kind=TypeGraphRelationKind.RETURN_FLOW,
                    reason=reason,
                )
            )
