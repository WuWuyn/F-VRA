from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PatchFileChange:
    file_path: str
    old_lines: set[int] = field(default_factory=set)
    new_lines: set[int] = field(default_factory=set)
    added: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)


@dataclass
class PatchAnalysis:
    files: list[PatchFileChange]
    called_names: set[str] = field(default_factory=set)
    changed_names: set[str] = field(default_factory=set)
    changed_globals: set[str] = field(default_factory=set)


_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_\.]*)\s*\(")
_NAME = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=")
_HUNK = re.compile(r"@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?")


def _normalise_path(raw: str) -> str:
    value = raw.strip().split("\t", 1)[0]
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return value.replace("\\", "/")


def parse_patch_text(text: str) -> PatchAnalysis:
    files: list[PatchFileChange] = []
    current: PatchFileChange | None = None
    old_line = new_line = 0

    for line in text.splitlines():
        if line.startswith("+++ "):
            path = _normalise_path(line[4:])
            if path != "/dev/null":
                current = PatchFileChange(file_path=path)
                files.append(current)
            continue
        match = _HUNK.match(line)
        if match:
            old_line, new_line = int(match.group(1)), int(match.group(2))
            continue
        if current is None or line.startswith(("diff ", "index ", "--- ")):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current.new_lines.add(new_line)
            current.added.append(line[1:])
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            current.old_lines.add(old_line)
            current.deleted.append(line[1:])
            old_line += 1
        else:
            current.context.append(line[1:] if line.startswith(" ") else line)
            old_line += 1
            new_line += 1

    changed_text = "\n".join(
        line for change in files for line in [*change.added, *change.deleted]
    )
    called_names = {match.group(1).split(".")[-1] for match in _CALL.finditer(changed_text)}
    changed_names = set(_NAME.findall(changed_text))
    changed_globals = {
        match.group(1)
        for line in changed_text.splitlines()
        if (match := _ASSIGN.match(line))
        and (match.group(1).isupper() or "_" in match.group(1))
    }
    return PatchAnalysis(
        files=files,
        called_names=called_names,
        changed_names=changed_names,
        changed_globals=changed_globals,
    )


def load_patch(path: str | Path) -> tuple[PatchAnalysis, str]:
    patch_path = Path(path).resolve()
    return parse_patch_text(patch_path.read_text(encoding="utf-8", errors="ignore")), str(patch_path)
