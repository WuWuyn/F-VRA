from __future__ import annotations

from pyshare.evaluation.methods.vfarche.retrieval.patch_diff import DiffLine, FilePatch, Hunk, parse_unified_diff
import pyshare.evaluation.methods.vfarche.retrieval.tracker as tracker


def test_parse_unified_diff() -> None:
    raw = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -2 +2,2 @@
-    return open(path).read()
+    safe = sanitize(path)
+    return open(safe).read()
"""
    patches = parse_unified_diff(raw)
    assert len(patches) == 1
    assert patches[0].old_path == "app.py"
    assert patches[0].hunks[0].lines[0].kind == "-"
    assert patches[0].hunks[0].lines[1].new_lineno == 2


def test_tracker_static_expansion() -> None:
    funcs = [
        {
            "name": "sanitize",
            "qualname": "sanitize",
            "file": "app.py",
            "start_line": 1,
            "end_line": 2,
            "body": "def sanitize(x):\n    return x",
            "docstring": "",
        },
        {
            "name": "vulnerable",
            "qualname": "vulnerable",
            "file": "app.py",
            "start_line": 4,
            "end_line": 5,
            "body": "def vulnerable(path):\n    return open(path).read()",
            "docstring": "",
        },
        {
            "name": "caller",
            "qualname": "caller",
            "file": "app.py",
            "start_line": 7,
            "end_line": 8,
            "body": "def caller(p):\n    return vulnerable(p)",
            "docstring": "",
        },
    ]
    patch = FilePatch(
        old_path="app.py",
        new_path="app.py",
        hunks=[
            Hunk(
                old_start=5,
                old_count=1,
                new_start=7,
                new_count=2,
                lines=[
                    DiffLine("-", "    return open(path).read()", old_lineno=5),
                    DiffLine("+", "    safe = sanitize(path)", new_lineno=7),
                    DiffLine("+", "    return open(safe).read()", new_lineno=8),
                ],
            )
        ],
    )
    original = tracker.load_patch
    tracker.load_patch = lambda repo, vuln, fix: [patch]
    try:
        selected = tracker.select_with_tracker(
            ".",
            {"cve_id": "CVE-X", "description": "path traversal", "vulnerable_ref": "v", "fix_commit": "f"},
            funcs,
            top_k=10,
        )
    finally:
        tracker.load_patch = original
    names = [item["name"] for item in selected]
    assert names[0] == "vulnerable"
    assert "sanitize" in names
    assert "caller" in names


def main() -> int:
    test_parse_unified_diff()
    test_tracker_static_expansion()
    print("PASS vfarche tracker checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
