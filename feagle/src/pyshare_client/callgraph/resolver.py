"""Resolver primitives shared by package and project call graph builders."""

from pyshare_client.callgraph.engine import ClassInfo, LibraryIndex, ModuleScope, _dotted_name

__all__ = ["ClassInfo", "LibraryIndex", "ModuleScope", "_dotted_name"]
