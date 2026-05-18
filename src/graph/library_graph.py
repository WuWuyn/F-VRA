from pyshare.core.config import settings


class LibraryGraph:
    """Neo4j-backed call graph for a library version (GL)."""

    def __init__(self, package: str, version: str):
        self.package = package
        self.version = version

    def add_function(self, name: str, module: str) -> None:
        # TODO: implement
        raise NotImplementedError

    def add_call_edge(self, caller: str, callee: str) -> None:
        # TODO: implement
        raise NotImplementedError

    def close(self) -> None:
        pass
