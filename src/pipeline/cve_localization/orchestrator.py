import json, logging
from pathlib import Path
from typing import Optional, List
from .models import CVERecord, FunctionRecord, MatchResult
from .input_loader import InputLoader
from .des_expansion import Module1
from .library_scanner import LibraryScanner
from .patch_present import PatchAnalyzer
from .patch_absent import PatchAbsentClassifier
from .swiss_ranker import LLMJudge, SwissSystemRanker

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════

class VFArCHE:
    """
    Orchestrator chinh cua VFArCHE v2.0.

    Pipeline:
      InputLoader   -> doc CVE JSON + .py files
      Module1       -> Query Expansion + Reformulation
      LibraryScanner -> trich xuat functions
      Module2       -> PATCH-PRESENT hoac PATCH-ABSENT
      Module3       -> Swiss-System + Exhaustive Pairwise ranking
      Output        -> vfarche_results.json
    """
    def __init__(self,
                 input_folder: str,
                 cwe_db_path: str = "cwe_database.csv",
                 llm_api_key: str = "",
                 llm_model: str = "gpt-4o-mini",
                 package_name: str = "lib"):

        self.input_folder = input_folder
        self.package_name = package_name
        self.loader       = InputLoader(input_folder)
        self.module1      = Module1(cwe_db_path)
        self.judge        = LLMJudge(api_key=llm_api_key, model=llm_model)
        self.ranker       = SwissSystemRanker(self.judge, num_rounds=8, top_n=20)
        self._scanner:    Optional[LibraryScanner]        = None
        self._patch_an:   Optional[PatchAnalyzer]         = None
        self._classifier: Optional[PatchAbsentClassifier] = None

    def _init_scanner(self):
        if self._scanner is not None:
            return
        py_files = self.loader.get_py_files()
        if not py_files:
            raise FileNotFoundError(
                f"Khong tim thay .py file trong: {self.input_folder}\n"
                f"Hay them file .py cua thu vien bi anh huong vao folder do."
            )
        self._scanner    = LibraryScanner(py_files, package_name=self.package_name)
        self._scanner.scan()
        self._patch_an   = PatchAnalyzer(self._scanner)
        self._classifier = PatchAbsentClassifier()
        self._classifier.fit(self._scanner.functions)

    def analyze(self,
                cve_id: str,
                top_k_candidates: int = 100,
                top_k_output: int = 10) -> MatchResult:
        """
        Phan tich chinh: tim VF cho mot CVE.

        Args:
            cve_id           : "CVE-2023-24329"
            top_k_candidates : so candidates dua vao Swiss ranking (mac dinh 100)
            top_k_output     : so ket qua tra ve cuoi cung

        Returns:
            MatchResult (luu ra vfarche_results.json trong input folder)
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"VFArCHE Analysis: {cve_id}")
        logger.info(f"{'='*60}")

        # Load CVE tu JSON nguoi dung cung cap
        cve = self.loader.load_cve(cve_id)

        # Init scanner
        self._init_scanner()
        if not self._scanner.functions:
            raise RuntimeError("Khong trich xuat duoc function nao tu .py files!")

        # Module 1: Query Expansion + Reformulation
        cve = self.module1.run(cve)

        # Module 2: Candidate Selection
        patch_file = self.loader.get_patch_file()
        mode       = "PATCH_ABSENT"
        candidates: List[FunctionRecord] = []

        if patch_file:
            # PATCH-PRESENT
            logger.info(f"\n[M2] Che do: PATCH-PRESENT ({patch_file.name})")
            mode      = "PATCH_PRESENT"
            seeds     = self._patch_an.analyze(str(patch_file))
            candidates = self._patch_an.track_callers(seeds, max_depth=3)
            # Bo sung neu khong du candidates
            if len(candidates) < top_k_candidates:
                extra = self._classifier.select(cve, top_k=top_k_candidates * 2)
                ex_set = {fr.full_name for fr in candidates}
                for fr in extra:
                    if fr.full_name not in ex_set:
                        candidates.append(fr)
                        ex_set.add(fr.full_name)
                        if len(candidates) >= top_k_candidates:
                            break
        else:
            # PATCH-ABSENT
            logger.info("\n[M2] Che do: PATCH-ABSENT (TF-IDF Classifier)")
            candidates = self._classifier.select(cve, top_k=top_k_candidates)

        candidates = candidates[:100]
        logger.info(f"  Candidates dua vao ranking: {len(candidates)}")

        # Module 3: Swiss-System + Exhaustive Pairwise
        ranked = self.ranker.rank(candidates, cve)

        # Tinh confidence
        if len(ranked) >= 2:
            w1 = ranked[0].swiss_wins + ranked[0].swiss_draws * 0.5
            w2 = ranked[1].swiss_wins + ranked[1].swiss_draws * 0.5
            mw = len(ranked) - 1
            confidence = min(1.0, (w1 - w2 + 1) / (mw + 1)) if mw > 0 else 1.0
        else:
            confidence = 1.0

        result = MatchResult(
            cve_id=cve_id, mode_used=mode,
            ranked_functions=ranked[:top_k_output],
            top_function=ranked[0] if ranked else None,
            confidence=confidence
        )

        self._print_report(result, cve)
        self._save_json(result, cve)
        return result

    def _print_report(self, result: MatchResult, cve: CVERecord):
        print(f"\n{'='*65}")
        print(f"  VFArCHE RESULTS — {result.cve_id}")
        print(f"{'='*65}")
        print(f"  Mode       : {result.mode_used}")
        print(f"  Confidence : {result.confidence:.2%}")
        print(f"  CWE IDs    : {', '.join(cve.cwe_ids) or '(auto-detected)'}")
        print(f"  Patch URLs : {cve.patch_urls or '(none)'}")
        print(f"{'─'*65}")
        print(f"  RANKED VULNERABLE FUNCTIONS (package.module.Class.method):")
        print(f"{'─'*65}")
        for i, fr in enumerate(result.ranked_functions, 1):
            tag = ">>> [TOP-1]" if i == 1 else f"    [{i:>2}]   "
            print(f"  {tag} {fr.full_name}")
            print(f"           Wi={fr.swiss_wins} | "
                  f"Score={fr.swiss_score:.3f} | "
                  f"TF-IDF={fr.similarity_score:.4f} | "
                  f"{Path(fr.file_path).name}:{fr.start_line}")
        print(f"{'='*65}")

    def _save_json(self, result: MatchResult, cve: CVERecord):
        """Luu ket qua ra vfarche_results.json trong input folder."""
        out_path = Path(self.input_folder) / "vfarche_results.json"
        data = {
            "cve_id":      result.cve_id,
            "mode_used":   result.mode_used,
            "confidence":  round(result.confidence, 4),
            "cwe_ids":     cve.cwe_ids,
            "patch_urls":  cve.patch_urls,
            "top_function": (result.top_function.full_name
                             if result.top_function else None),
            "ranked_functions": [
                {
                    "rank":        i + 1,
                    "full_name":   fr.full_name,
                    "file":        Path(fr.file_path).name,
                    "start_line":  fr.start_line,
                    "end_line":    fr.end_line,
                    "swiss_wins":  fr.swiss_wins,
                    "swiss_draws": fr.swiss_draws,
                    "tfidf_score": round(fr.similarity_score, 6),
                    "swiss_score": round(fr.swiss_score, 4),
                }
                for i, fr in enumerate(result.ranked_functions)
            ],
            "module1_context": {
                "expansion_context_preview": cve.expansion_context[:400],
                "final_query_length":        len(cve.expanded_description),
            }
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"\n[Output] Ket qua luu tai: {out_path}")
        print(f"\n  Ket qua JSON: {out_path}")