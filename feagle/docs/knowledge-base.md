# Vulnerable-Function Knowledge Base

This module defines the storage boundary for CVE-to-vulnerable-function
records.

The core entities live in `pyshare_core.models`:

- `VulnerabilityRecord`
- `VulnerableEntity`
- `Evidence`

Storage implementations must satisfy `VulnerabilityRepository`:

```python
from pyshare_core.models import VulnerabilityRecord


class VulnerabilityRepository:
    def get(self, cve_id: str) -> VulnerabilityRecord | None:
        ...

    def put(self, record: VulnerabilityRecord) -> None:
        ...
```

## Current Status

The protocols and models exist in `pyshare_core`. The server file DB adapter
stores vulnerable-function records and package summaries as SQLite metadata plus
JSON payloads.

The next storage implementation should preserve:

- CVE and package identity
- affected and fixed version ranges
- vulnerable function or entity
- evidence and source
- role and confidence
- patch and metadata provenance

Repository contract tests cover the current SQLite + JSON file DB adapter.
