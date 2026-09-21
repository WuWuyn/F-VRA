"""Lightweight checks for VFFinder fidelity-sensitive wiring."""
from __future__ import annotations

from pyshare.evaluation.paths import METHODS_ROOT, PROJECT_ROOT, RESULTS_ROOT

REPO_ROOT = PROJECT_ROOT

from pyshare.evaluation.adapters.vffinder_adapter import DATA_DIR as ADAPTER_DATA_DIR
from pyshare.evaluation.adapters.vffinder_adapter import OUT as ADAPTER_OUTPUT_DIR
from pyshare.evaluation.adapters.vffinder_adapter import class_hints_for
from pyshare.evaluation.scripts.extract_functions import extract_file
from pyshare.evaluation.methods.vffinder import config as vffinder_config
from pyshare.evaluation.methods.vffinder.retrieval.retrieval import extract_class_hints
from pyshare.evaluation.methods.vffinder.scripts import build_function_corpus_from_jsonl as corpus_builder


def test_adapter_class_hints_include_python_file_and_dotted_parts() -> None:
    hints = class_hints_for("A flaw in pkg.views.LoginView.dispatch and views.py")
    assert "LoginView" in hints, hints
    assert "views" in hints, hints
    assert "dispatch" in hints, hints


def test_retrieval_class_hints_match_adapter_coverage() -> None:
    hints = extract_class_hints("RoomMember.update() in membership.py mishandles input")
    assert "RoomMember" in hints, hints
    assert "membership" in hints, hints


def test_shared_extractor_falls_back_on_python2_syntax() -> None:
    src = """\
class Legacy:
    def render(self, req):
        print 'py2 syntax'
"""
    qnames = [r["qualified_name"] for r in extract_file(src, "pkg/views.py")]
    assert "pkg.views.Legacy.render" in qnames, qnames


def test_entity_filter_defaults_are_less_lossy() -> None:
    assert corpus_builder.MIN_IDENTIFIER_LEN <= 2
    assert corpus_builder.MIN_STRING_LEN <= 2
    assert corpus_builder.MIN_COMMENT_ALPHA <= 1


def test_result_dirs_default_outside_method_tree() -> None:
    method_root = METHODS_ROOT / "vffinder"
    for path in (vffinder_config.DATA_DIR, vffinder_config.OUTPUT_DIR):
        try:
            path.relative_to(method_root)
        except ValueError:
            pass
        else:
            raise AssertionError(path)
        path.relative_to(RESULTS_ROOT)
    assert ADAPTER_DATA_DIR == vffinder_config.DATA_DIR
    assert ADAPTER_OUTPUT_DIR == vffinder_config.OUTPUT_DIR


def _run_all() -> None:
    checks = [
        v for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]
    for check in checks:
        check()
        print(f"  PASS {check.__name__.replace('test_', 'check_', 1)}")
    print(f"\n{len(checks)} vffinder-fidelity checks passed.")


if __name__ == "__main__":
    _run_all()
