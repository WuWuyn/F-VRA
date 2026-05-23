"""Neo4j driver provider — singleton + module-level re-exports.

The package layout maps ``src/`` to the importable package ``pyshare``,
so ``pyshare.core.config`` resolves to ``src/core/config.py`` (NOT
``pyshare.src.core.config`` — that path was incorrect in the original
commit). ``db_provider`` stays as the single source of truth for the
Neo4j driver, with ``get_driver()`` exposed as a convenience for
modules that prefer the function-style API.
"""
from __future__ import annotations

import atexit
from typing import Optional

import neo4j
from neo4j import GraphDatabase

from pyshare.core.config import settings


class Neo4jDriverProvider:
    """Lazy-connecting singleton holder for the Neo4j driver.

    Instantiated once at module load time as ``db_provider``. Code
    typically calls ``db_provider.get_session()`` to run Cypher; the
    underlying driver is created on first use and reused thereafter.
    """

    def __init__(self) -> None:
        self._uri = settings.neo4j_uri
        self._user = settings.neo4j_user
        self._password = settings.neo4j_password
        self._driver: Optional[neo4j.Driver] = None

    def connect(self) -> neo4j.Driver:
        """Return the shared driver, creating it on first call.

        Verifies connectivity immediately so failures surface here
        rather than at first query.
        """
        if self._driver is None:
            self._driver = GraphDatabase.driver(
                self._uri,
                auth=(self._user, self._password),
            )
            self._driver.verify_connectivity()
        return self._driver

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def get_session(self):
        """Return a fresh Neo4j session for running Cypher."""
        return self.connect().session()


db_provider = Neo4jDriverProvider()
atexit.register(db_provider.close)


def get_driver() -> neo4j.Driver:
    """Function-style accessor for modules that want the raw driver
    rather than going through ``db_provider``."""
    return db_provider.connect()


def close_driver() -> None:
    """Close the shared driver (called automatically at process exit)."""
    db_provider.close()


# Sub-module re-exports — populated lazily to avoid heavy imports when
# the graph layer isn't needed (e.g. just importing pyshare.cli).
def __getattr__(name):
    if name in ("project_graph", "reachability", "path_explainer",
                "init_schema"):
        from importlib import import_module
        if name == "init_schema":
            mod = import_module("pyshare.graph._schema")
            return mod.init_schema
        return import_module(f"pyshare.graph.{name}")
    raise AttributeError(f"module 'pyshare.graph' has no attribute {name!r}")


__all__ = [
    "Neo4jDriverProvider",
    "close_driver",
    "db_provider",
    "get_driver",
    "init_schema",
    "path_explainer",
    "project_graph",
    "reachability",
]
