from pyshare.core.models import ScanResult


class PathExplainer:
    """Retrieves and formats call chains from the Neo4j graph for --explain output."""

    def explain(self, result: ScanResult) -> list[str]:
        # TODO: implement — query shortest path in Neo4j
        raise NotImplementedError
