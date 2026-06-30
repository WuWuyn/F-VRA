from __future__ import annotations

import ast
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"

CLIENT_SAFE_DIRS = [
    SRC_ROOT / "pyshare_client",
]

CLIENT_FORBIDDEN_PREFIXES = (
    "pyshare_server",
)

SERVER_FORBIDDEN_DIRS = [
    SRC_ROOT / "pyshare_server",
]


def _python_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
        else:
            files.extend(sorted(path.rglob("*.py")))
    return files


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def _violations(files: list[Path], forbidden_prefixes: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for path in files:
        for module in sorted(_imports(path)):
            if module in forbidden_prefixes or module.startswith(forbidden_prefixes):
                out.append(f"{path.relative_to(REPO_ROOT)} imports {module}")
    return out


def test_client_boundary_does_not_import_server_side_code():
    files = _python_files(CLIENT_SAFE_DIRS)

    assert _violations(files, CLIENT_FORBIDDEN_PREFIXES) == []


def test_server_boundary_does_not_import_client_package():
    files = _python_files(SERVER_FORBIDDEN_DIRS)

    assert _violations(files, ("pyshare_client",)) == []


def test_core_boundary_does_not_import_client_or_server():
    files = _python_files([SRC_ROOT / "pyshare_core"])

    assert _violations(files, ("pyshare_client", "pyshare_server")) == []


def test_legacy_pyshare_namespace_is_removed():
    assert not (SRC_ROOT / "pyshare").exists()


def test_source_and_tests_do_not_import_legacy_pyshare_namespace():
    files = _python_files(
        [
            SRC_ROOT / "pyshare_core",
            SRC_ROOT / "pyshare_client",
            SRC_ROOT / "pyshare_server",
            REPO_ROOT / "tests",
        ]
    )

    violations = []
    for path in files:
        for module in sorted(_imports(path)):
            if module == "pyshare" or module.startswith("pyshare."):
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {module}")

    assert violations == []
