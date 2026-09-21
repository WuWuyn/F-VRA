from pyshare.evaluation.methods.vfdetector.core.code_processor import FunctionExtractor, clean_text, _split_multiword
from pyshare.evaluation.methods.vfdetector.core.report_processor import process_cve
from pyshare.evaluation.methods.vfdetector.runner import choose_vuln_ref, find_rank


# ---------------------------------------------------------------------------
# _split_multiword
# ---------------------------------------------------------------------------

def test_split_snake_case():
    assert _split_multiword("get_user_id") == ["get", "user", "id"]

def test_split_camel_case():
    assert _split_multiword("getUserId") == ["get", "User", "Id"]

def test_no_split_single_word():
    assert _split_multiword("load") == ["load"]

def test_split_mixed():
    assert _split_multiword("parse_NodeValue") == ["parse", "Node", "Value"]

def test_split_acronym_and_digits():
    assert _split_multiword("HTTPServerSHA256") == ["HTTP", "Server", "SHA", "256"]


# ---------------------------------------------------------------------------
# clean_text
# ---------------------------------------------------------------------------

def test_clean_text_removes_stopwords():
    tokens = clean_text("the function is vulnerable")
    assert "the" not in tokens
    assert "is" not in tokens

def test_clean_text_removes_python_keywords():
    tokens = clean_text("if return while import class")
    assert "if" not in tokens
    assert "return" not in tokens
    assert "while" not in tokens

def test_clean_text_removes_non_alpha():
    tokens = clean_text("func(arg1, arg2) = 123")
    for t in tokens:
        assert t.isalpha()

def test_clean_text_lemmatizes():
    tokens = clean_text("running buffers classes")
    assert "run" in tokens
    assert "buffer" in tokens
    assert "class" not in tokens  # "class" is a Python keyword

def test_clean_text_splits_snake_case():
    tokens = clean_text("buffer_overflow")
    assert "buffer" in tokens
    assert "overflow" in tokens

def test_clean_text_empty_string():
    assert clean_text("") == []

def test_clean_text_only_stopwords():
    assert clean_text("the and is a an") == []


# ---------------------------------------------------------------------------
# process_cve
# ---------------------------------------------------------------------------

def test_process_cve_keeps_language_keywords_as_report_terms():
    assert "class" in process_cve("class pollution vulnerability")

def test_process_cve_does_not_apply_source_identifier_splitting():
    tokens = process_cve("buffer_overflow")
    assert "buffer" not in tokens
    assert "overflow" not in tokens


# ---------------------------------------------------------------------------
# FunctionExtractor
# ---------------------------------------------------------------------------

SIMPLE_SOURCE = """\
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
"""

ASYNC_SOURCE = """\
async def fetch(url):
    pass
"""

CLASS_SOURCE = """\
class MyClass:
    def method(self):
        pass

    def another(self):
        pass
"""

NESTED_SOURCE = """\
def outer():
    def inner():
        pass
    return inner
"""

SYNTAX_ERROR_SOURCE = "def broken(:"


def test_extracts_top_level_functions():
    funcs = FunctionExtractor(SIMPLE_SOURCE).extract()
    assert set(funcs.keys()) == {"add", "subtract"}

def test_extracts_async_function():
    funcs = FunctionExtractor(ASYNC_SOURCE).extract()
    assert "fetch" in funcs

def test_extracts_class_methods():
    funcs = FunctionExtractor(CLASS_SOURCE).extract()
    assert "MyClass.method" in funcs
    assert "MyClass.another" in funcs

def test_keeps_same_method_name_in_different_classes():
    source = """\
class First:
    def save(self):
        return 1

class Second:
    def save(self):
        return 2
"""
    funcs = FunctionExtractor(source).extract()
    assert set(funcs) == {"First.save", "Second.save"}

def test_extracts_nested_function_with_parent_qualified_name():
    funcs = FunctionExtractor(NESTED_SOURCE).extract()
    assert "outer" in funcs
    assert "outer.inner" in funcs
    assert "inner" not in funcs

def test_function_source_content():
    funcs = FunctionExtractor(SIMPLE_SOURCE).extract()
    assert "return a + b" in funcs["add"]

def test_syntax_error_falls_back_to_regex_extraction():
    source = """\
class Legacy:
    def render(self, req):
        print 'py2 syntax'
"""
    funcs = FunctionExtractor(source).extract()
    assert "Legacy.render" in funcs

def test_empty_source():
    funcs = FunctionExtractor("").extract()
    assert funcs == {}


# ---------------------------------------------------------------------------
# Native result matching
# ---------------------------------------------------------------------------

def test_find_rank_matches_benchmark_qualified_name_alias():
    top = [("pkg/mod.py::Service.buggy", "pkg/mod.py", 0.42)]
    assert find_rank(top, {"pkg.mod.Service.buggy"}) == 1


def test_choose_vuln_ref_prefers_benchmark_ref():
    ref, note = choose_vuln_ref(
        {"commit_sha": "fix-sha", "vulnerable_ref": "vuln-sha"},
        Path("."),
    )
    assert ref == "vuln-sha"
    assert note == ""


def _run_all():
    checks = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    for check in checks:
        check()
        print(f"  PASS {check.__name__.replace('test_', 'check_', 1)}")
    print(f"\n{len(checks)} code-processor checks passed.")


if __name__ == "__main__":
    _run_all()
