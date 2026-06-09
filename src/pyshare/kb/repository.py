from __future__ import annotations

from typing import Protocol

from pyshare.core.models import VulnerabilityRecord


class VulnerabilityRepository(Protocol):
    def get(self, cve_id: str) -> VulnerabilityRecord | None:
        ...

    def put(self, record: VulnerabilityRecord) -> None:
        ...
