import re, logging
from pathlib import Path
from typing import List, Dict, Tuple, Set
from models import FunctionRecord
from library_scanner import LibraryScanner

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
# MODULE 2a: PATCH-PRESENT (Pattern-Based Tracker)
# ══════════════════════════════════════════════════════════════════

class PatchAnalyzer:
    """
    Phan tich .patch de xac dinh VF candidates.

    5 Pattern theo VFArCHE paper:
      1. Replaced Methods  : xoa ham A, them ham B -> A la VF
      2. Replaced Classes  : doi class -> toan bo class cu la VF
      3. Additional Args   : them tham so -> ham goc la VF
      4. Config Changes    : doi bien global -> moi ham dung bien do
      5. No Pattern Match  : sua if/else -> chinh ham chua dong do
    """
    def __init__(self, scanner: LibraryScanner):
        self.scanner = scanner
        # Bang tra: (file_path, line) -> FunctionRecord
        self._line_map: Dict[Tuple[str, int], FunctionRecord] = {}
        for fr in scanner.functions:
            for ln in range(fr.start_line, fr.end_line + 1):
                self._line_map[(fr.file_path, ln)] = fr

    def analyze(self, patch_path: str) -> List[FunctionRecord]:
        """Phan tich .patch -> danh sach VF candidates."""
        logger.info(f"[PatchAnalyzer] Phan tich: {patch_path}")
        content = Path(patch_path).read_text(encoding="utf-8", errors="ignore")
        hunks   = self._parse_hunks(content)
        logger.info(f"  Tim thay {len(hunks)} hunks")
        candidates: Dict[str, FunctionRecord] = {}
        for h in hunks:
            for fr in self._map_hunk(h):
                candidates[fr.full_name] = fr
        logger.info(f"  Patch-Present: {len(candidates)} candidates")
        return list(candidates.values())

    def _parse_hunks(self, text: str) -> List[Dict]:
        """Chia patch thanh cac Hunk."""
        hunks, cur_file, cur = [], "", None
        for line in text.splitlines():
            if line.startswith("+++ b/"):
                cur_file = line[6:].strip()
            elif line.startswith("@@"):
                if cur:
                    hunks.append(cur)
                m = re.search(r"-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?", line)
                if m:
                    cur = {
                        "file": cur_file,
                        "old_start": int(m.group(1)), "new_start": int(m.group(2)),
                        "removed": [], "added": [],
                        "_oln": int(m.group(1)), "_nln": int(m.group(2))
                    }
            elif cur is not None:
                if line.startswith("-"):
                    cur["removed"].append((cur["_oln"], line[1:]))
                    cur["_oln"] += 1
                elif line.startswith("+"):
                    cur["added"].append((cur["_nln"], line[1:]))
                    cur["_nln"] += 1
                else:
                    cur["_oln"] += 1
                    cur["_nln"] += 1
        if cur:
            hunks.append(cur)
        return hunks

    def _map_hunk(self, h: Dict) -> List[FunctionRecord]:
        """Apply 5 patterns len mot hunk."""
        results: List[FunctionRecord] = []
        rtexts = [t for _, t in h["removed"]]
        atexts = [t for _, t in h["added"]]
        fns    = self._fns_in_file(h["file"], h["old_start"])

        rdefs = [l.strip() for l in rtexts if l.strip().startswith("def ")]
        adefs = [l.strip() for l in atexts if l.strip().startswith("def ")]

        # Pattern 1: Replaced Methods
        if rdefs and adefs:
            logger.info(f"  [P1] Replaced Method")
            for fr in fns:
                for rdef in rdefs:
                    m = re.search(r"def\s+(\w+)", rdef)
                    if m and fr.function_name == m.group(1):
                        results.append(fr)

        # Pattern 2: Replaced Classes
        rcls = [l for l in rtexts if re.search(r"class\s+\w+", l)]
        acls = [l for l in atexts if re.search(r"class\s+\w+", l)]
        if rcls and acls:
            logger.info(f"  [P2] Replaced Class")
            for fr in self.scanner.functions:
                for rc in rcls:
                    m = re.search(r"class\s+(\w+)", rc)
                    if m and fr.class_name == m.group(1):
                        results.append(fr)

        # Pattern 3: Additional Arguments
        for rd in rdefs:
            for ad in adefs:
                rm = re.search(r"def\s+(\w+)\s*\(([^)]*)\)", rd)
                am = re.search(r"def\s+(\w+)\s*\(([^)]*)\)", ad)
                if rm and am and rm.group(1) == am.group(1):
                    rp = [p.strip() for p in rm.group(2).split(",") if p.strip()]
                    ap = [p.strip() for p in am.group(2).split(",") if p.strip()]
                    if len(ap) > len(rp):
                        logger.info(f"  [P3] Additional Args: {rm.group(1)}")
                        for fr in fns:
                            if fr.function_name == rm.group(1):
                                results.append(fr)

        # Pattern 4: Config Changes (UPPER_CASE = value)
        for rl, al in zip(rtexts[:5], atexts[:5]):
            rm = re.match(r"\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+)", rl)
            am = re.match(r"\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+)", al)
            if rm and am and rm.group(1) == am.group(1):
                var = rm.group(1)
                logger.info(f"  [P4] Config Change: {var}")
                for fr in self.scanner.functions:
                    if var in fr.source_code:
                        results.append(fr)

        # Pattern 5: No match -> ham chua dong sua
        if not results:
            logger.info(f"  [P5] No pattern match -> ham chua dong")
            results.extend(fns)

        return results

    def _fns_in_file(self, rel_path: str, start: int) -> List[FunctionRecord]:
        """Tim functions trong file tai dung do."""
        out = []
        for fr in self.scanner.functions:
            if not str(fr.file_path).endswith(rel_path.lstrip("/")):
                continue
            if fr.start_line <= start <= fr.end_line:
                out.append(fr)
        if not out:  # Fallback: tat ca functions trong file
            for fr in self.scanner.functions:
                if str(fr.file_path).endswith(rel_path.lstrip("/")):
                    out.append(fr)
        return out

    def track_callers(self, seeds: List[FunctionRecord], max_depth: int = 3) -> List[FunctionRecord]:
        """
        Tracker: tu seed functions (bi sua truc tiep),
        truy nguoc call graph tim callers trong max_depth buoc.
        Dam bao tim VF khong chi nam trong vung bi sua truc tiep.
        """
        if not any(fr.callers for fr in self.scanner.functions):
            self.scanner.build_call_graph()
        fn_map  = {fr.full_name: fr for fr in self.scanner.functions}
        visited: Set[str] = {fr.full_name for fr in seeds}
        result  = list(seeds)
        queue   = list(seeds)
        for _ in range(max_depth):
            nxt = []
            for fn in queue:
                for cn in fn.callers:
                    if cn not in visited and cn in fn_map:
                        visited.add(cn)
                        result.append(fn_map[cn])
                        nxt.append(fn_map[cn])
            queue = nxt
        logger.info(f"  Tracker: {len(seeds)} seeds -> {len(result)} "
                    f"(+{len(result)-len(seeds)} callers)")
        return result


