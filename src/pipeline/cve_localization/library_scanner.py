import ast, logging
from pathlib import Path
from typing import List, Dict, Optional
from .models import FunctionRecord

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
# LIBRARY SCANNER
# ══════════════════════════════════════════════════════════════════

class LibraryScanner:
    """
    Quet tat ca .py files nguoi dung cung cap.
    Trich xuat moi function/method.
    Dinh dang: package.module.Class.method
    """
    def __init__(self, py_files: List[Path], package_name: str = "lib"):
        self.py_files     = py_files
        self.package_name = package_name
        self.functions: List[FunctionRecord] = []

    def scan(self) -> List[FunctionRecord]:
        self.functions = []
        for f in self.py_files:
            self._scan_file(f)
        logger.info(f"[Scanner] {len(self.functions)} functions tu {len(self.py_files)} files")
        return self.functions

    def _scan_file(self, py_file: Path):
        try:
            src  = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(py_file))
        except SyntaxError as e:
            logger.warning(f"  SyntaxError {py_file.name}: {e}")
            return
        lines  = src.splitlines()
        module = f"{self.package_name}.{py_file.stem}"
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._extract(node, module, "", lines, py_file)
            elif isinstance(node, ast.ClassDef):
                self._scan_class(node, module, lines, py_file)

    def _scan_class(self, cls: ast.ClassDef, module: str,
                    lines: list, py_file: Path, parent: str = ""):
        cls_full = f"{parent}.{cls.name}" if parent else cls.name
        for node in cls.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._extract(node, module, cls_full, lines, py_file)
            elif isinstance(node, ast.ClassDef):
                self._scan_class(node, module, lines, py_file, cls_full)

    def _extract(self, fn: ast.FunctionDef, module: str, cls: str,
                 lines: list, py_file: Path):
        start = fn.lineno
        end   = getattr(fn, "end_lineno", start)
        src   = "\n".join(lines[start - 1:end])
        doc   = ast.get_docstring(fn) or ""
        # Xay dung full_name: package.module.Class.method
        parts = [module] + ([cls] if cls else []) + [fn.name]
        full  = ".".join(parts)
        mp    = module.split(".")
        self.functions.append(FunctionRecord(
            full_name=full, package=mp[0], module=".".join(mp[1:]),
            class_name=cls, function_name=fn.name,
            source_code=src, docstring=doc, file_path=str(py_file),
            start_line=start, end_line=end
        ))

    def build_call_graph(self) -> Dict[str, List[str]]:
        """Xay dung call graph: callee -> [callers]."""
        logger.info("[Scanner] Xay dung call graph...")
        name_map = {fr.function_name: fr.full_name for fr in self.functions}
        name_map.update({fr.full_name: fr.full_name for fr in self.functions})
        graph: Dict[str, List[str]] = {fr.full_name: [] for fr in self.functions}
        for caller in self.functions:
            try:
                for node in ast.walk(ast.parse(caller.source_code)):
                    if isinstance(node, ast.Call):
                        name = self._resolve(node)
                        if name and name in name_map:
                            cf = name_map[name]
                            if cf != caller.full_name and caller.full_name not in graph[cf]:
                                graph[cf].append(caller.full_name)
            except Exception:
                pass
        for fr in self.functions:
            fr.callers = graph.get(fr.full_name, [])
        edges = sum(len(v) for v in graph.values())
        logger.info(f"  Call graph: {edges} edges")
        return graph

    @staticmethod
    def _resolve(call: ast.Call) -> Optional[str]:
        f = call.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f.attr
        return None
