from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


_HUNK = re.compile(r"@@ -(?P<old>\d+)(?:,(?P<old_n>\d+))? \+(?P<new>\d+)(?:,(?P<new_n>\d+))? @@")


@dataclass
class DiffLine:
    kind: str
    text: str
    old_lineno: int | None = None
    new_lineno: int | None = None


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[DiffLine] = field(default_factory=list)


@dataclass
class FilePatch:
    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path if self.new_path != "/dev/null" else self.old_path


def _git(repo: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.stdout


def load_patch(repo: str | Path, vulnerable_ref: str, fix_commit: str) -> list[FilePatch]:
    """Return parsed Python file hunks for vulnerable_ref..fix_commit."""
    repo = Path(repo)
    raw = _git(
        repo,
        [
            "diff",
            "--find-renames",
            "--unified=0",
            vulnerable_ref,
            fix_commit,
            "--",
            "*.py",
        ],
    )
    return parse_unified_diff(raw)


def parse_unified_diff(raw: str) -> list[FilePatch]:
    patches: list[FilePatch] = []
    current: FilePatch | None = None
    hunk: Hunk | None = None
    old_line = new_line = 0

    for line in raw.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            old_path = parts[2][2:] if len(parts) > 2 and parts[2].startswith("a/") else ""
            new_path = parts[3][2:] if len(parts) > 3 and parts[3].startswith("b/") else old_path
            current = FilePatch(old_path=old_path, new_path=new_path)
            patches.append(current)
            hunk = None
            continue
        if current is None:
            continue
        if line.startswith("--- "):
            path = line[4:].strip()
            current.old_path = "/dev/null" if path == "/dev/null" else path.removeprefix("a/")
            continue
        if line.startswith("+++ "):
            path = line[4:].strip()
            current.new_path = "/dev/null" if path == "/dev/null" else path.removeprefix("b/")
            continue
        m = _HUNK.match(line)
        if m:
            old_line = int(m.group("old"))
            new_line = int(m.group("new"))
            hunk = Hunk(
                old_start=old_line,
                old_count=int(m.group("old_n") or "1"),
                new_start=new_line,
                new_count=int(m.group("new_n") or "1"),
            )
            current.hunks.append(hunk)
            continue
        if hunk is None or not line:
            continue
        prefix, text = line[0], line[1:]
        if prefix == "-":
            hunk.lines.append(DiffLine("-", text, old_lineno=old_line))
            old_line += 1
        elif prefix == "+":
            hunk.lines.append(DiffLine("+", text, new_lineno=new_line))
            new_line += 1
        elif prefix == " ":
            hunk.lines.append(DiffLine(" ", text, old_lineno=old_line, new_lineno=new_line))
            old_line += 1
            new_line += 1

    return [p for p in patches if p.path.endswith(".py") and p.hunks]
