import os


def collect_python_files(repo_path: str) -> list[str]:
    """Recursively collect all .py file paths under repo_path."""
    py_files: list[str] = []
    for dirpath, _, filenames in os.walk(repo_path):
        for fname in filenames:
            if fname.endswith(".py"):
                py_files.append(os.path.join(dirpath, fname))
    return py_files


def read_source(file_path: str) -> str | None:
    """Read a source file, returning None on any IO error."""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None
