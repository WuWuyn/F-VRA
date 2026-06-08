from pathlib import Path
from pyshare.core.config import settings


class ProjectGraph:
    """Incremental Neo4j call graph for a user project, updated per git commit."""

    def __init__(self, project: Path):
        self.project = project

    def update(self, commit_sha: str) -> None:
        # TODO: implement incremental graph update
        raise NotImplementedError

    def close(self) -> None:
        pass
