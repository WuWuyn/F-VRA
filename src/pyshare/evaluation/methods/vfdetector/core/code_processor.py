import ast
import io
import keyword
import re
import textwrap
import tokenize

from functools import lru_cache

import nltk
from nltk import pos_tag
from nltk.corpus import stopwords
from nltk.corpus import wordnet as wn
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize

nltk.download("punkt", quiet=True)
nltk.download("punkt_tab", quiet=True)
nltk.download("stopwords", quiet=True)
nltk.download("wordnet", quiet=True)
nltk.download("omw-1.4", quiet=True)
nltk.download("averaged_perceptron_tagger", quiet=True)
nltk.download("averaged_perceptron_tagger_eng", quiet=True)  # newer NLTK split

_STOPWORDS = set(stopwords.words("english"))
_PY_KEYWORDS = set(keyword.kwlist)
_lemmatizer = WordNetLemmatizer()


def _wordnet_pos(treebank_tag: str):
    """Map a Penn-Treebank POS tag to the WordNet POS the lemmatizer expects."""
    if treebank_tag.startswith("J"):
        return wn.ADJ
    if treebank_tag.startswith("V"):
        return wn.VERB
    if treebank_tag.startswith("R"):
        return wn.ADV
    return wn.NOUN  # nouns are the WordNetLemmatizer default


def _lemmatize_pos(tokens: list[str], drop: set[str]) -> list[str]:
    """POS-aware WordNet lemmatization (paper 3.2): POS-tag the tokens, map each
    tag to a WordNet POS, then lemmatize with it. This is what produces the
    paper's context-aware reductions ('running'->'run' as a verb, 'better'->'good'
    as an adjective) instead of the noun-only default. `drop` is re-applied after
    lemmatization (a lemma can collapse onto a stopword/keyword).
    ponytail: pos_tag runs once per function corpus — the slow step; that's the
    price of paper-faithful lemmatization. Batch-tag if runtime ever matters."""
    result: list[str] = []
    for token, tag in pos_tag(tokens):
        lemma = _lemmatizer.lemmatize(token, _wordnet_pos(tag))
        if lemma in drop:
            continue
        result.append(lemma)
    return result


def _split_multiword(token: str) -> list[str]:
    """Split snake_case, dotted paths, camelCase, acronyms, and digit runs."""
    result: list[str] = []
    for segment in re.split(r"[./]", token):
        for part in segment.split("_"):
            if not part:
                continue
            words = re.findall(
                r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+",
                part,
            )
            result.extend(words or [part])
    return result or [token]


def _source_lex_tokens(text: str) -> list[str]:
    """Tokenize Python source with the stdlib lexer instead of an NL tokenizer.

    VFDetector is still a lexical bag-of-words method, but source code should be
    split by Python's token stream first. This keeps identifiers/comments/string
    content available without relying on punctuation behavior in NLTK's prose
    tokenizer.
    """
    out: list[str] = []
    try:
        stream = tokenize.generate_tokens(io.StringIO(text).readline)
        for tok in stream:
            tok_type, tok_text = tok.type, tok.string
            if tok_type == tokenize.NAME:
                out.append(tok_text)
            elif tok_type == tokenize.COMMENT:
                out.extend(word_tokenize(tok_text.lstrip("#")))
            elif tok_type == tokenize.STRING:
                try:
                    value = ast.literal_eval(tok_text)
                except Exception:
                    value = tok_text
                if isinstance(value, str):
                    out.extend(word_tokenize(value))
                else:
                    out.append(tok_text)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return word_tokenize(text)
    return out


@lru_cache(maxsize=None)
def _wordnet_synonyms(word: str) -> tuple[str, ...]:
    """Semantic-meaning extraction (paper Section 3.2).

    Return the WordNet synonym lemmas of `word` so that synonymous-but-
    differently-spelled terms (the paper's 'finalize' vs 'conclude'/'complete'
    example) can still match between the report and the code. Multiword synset
    lemmas (e.g. 'sum_up') are split into individual alphabetic words; the word
    itself is excluded. Cached because the same tokens recur across functions.
    """
    synonyms: set[str] = set()
    for synset in wn.synsets(word):
        for lemma in synset.lemmas():
            for part in lemma.name().lower().split("_"):
                if part.isalpha() and part != word:
                    synonyms.add(part)
    return tuple(sorted(synonyms))


def clean_text(
    text: str,
    expand_synonyms: bool = False,
    remove_keywords: bool = True,
    split_multiword: bool = True,
) -> list[str]:
    """Produce the corpus token list for a piece of text (paper Section 3.2/3.3).

    Pipeline: tokenize -> [multiword split] -> lowercase -> drop non-alphabetic,
    stopword [and (Python) language-keyword] tokens -> [optional WordNet synonym
    expansion] -> POS-aware WordNet lemmatization.

    The bracketed steps are SOURCE-CODE-corpus only (paper Section 3.2):
      * `split_multiword`  - "addRequest" -> "add","Request" (a source-code phenomenon)
      * `remove_keywords`  - language-specific keyword removal ("...for generating
                             code corpora", Section 3.2)
      * `expand_synonyms`  - WordNet semantic-meaning extraction
    Vulnerability-report corpora are stopword-removal + lemmatize only (Section
    3.3), so `process_cve` turns the bracketed steps off.
    """
    # Tokenize WITHOUT lowercasing first: _split_multiword needs the original
    # case to split camelCase (paper's "addRequest" -> "add","Request"). Lowercase
    # AFTER the split. (Lowercasing first silently disabled camelCase splitting.)
    if remove_keywords or split_multiword:
        tokens = _source_lex_tokens(text)
    else:
        tokens = word_tokenize(text)

    expanded: list[str] = []
    for token in tokens:
        parts = _split_multiword(token) if split_multiword else [token]
        expanded.extend(p.lower() for p in parts)

    # Which tokens to discard: stopwords always; language keywords for code only.
    drop = _STOPWORDS | _PY_KEYWORDS if remove_keywords else _STOPWORDS

    # Keep only meaningful alphabetic tokens.
    kept: list[str] = []
    for token in expanded:
        if not token.isalpha():
            continue
        if token in drop:
            continue
        kept.append(token)

    # Semantic-meaning extraction: enrich code tokens with WordNet synonyms
    # (paper 3.2). Done before lemmatization, matching the paper's stage order.
    if expand_synonyms:
        enriched: list[str] = list(kept)
        for token in kept:
            for syn in _wordnet_synonyms(token):
                if syn in drop:
                    continue
                enriched.append(syn)
        kept = enriched

    # Final stage: POS-aware WordNet lemmatization to base forms (paper 3.2 / 3.3).
    return _lemmatize_pos(kept, drop)


class FunctionExtractor(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self._source = source
        self._source_lines = source.splitlines(keepends=True)
        self._functions: dict[str, str] = {}
        self._stack: list[str] = []  # enclosing class / function names

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._collect(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._collect(node)

    def _collect(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        func_lines = self._source_lines[node.lineno - 1 : node.end_lineno]
        func_source = textwrap.dedent("".join(func_lines))
        qual_name = ".".join([*self._stack, node.name])
        key = qual_name if qual_name not in self._functions else f"{qual_name}@L{node.lineno}"
        self._functions[key] = func_source
        # Recurse so nested functions/classes are extracted too. The paper's
        # "every function of each source file" means every function; in Python
        # that includes nested defs. This matches the shared extract_functions
        # corpus that VFFinder ranks over, so both methods see the same candidates.
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def extract(self) -> dict[str, str]:
        try:
            tree = ast.parse(self._source)
        except SyntaxError:
            return _regex_fallback_functions(self._source)
        self.visit(tree)
        return self._functions


_DEF_RE = re.compile(r"^(?P<indent>[ \t]*)(?:async[ \t]+)?def[ \t]+(?P<name>\w+)[ \t]*\(", re.MULTILINE)
_CLASS_RE = re.compile(r"^(?P<indent>[ \t]*)class[ \t]+(?P<name>\w+)\b", re.MULTILINE)


def _indent_width(line: str) -> int:
    return len(line.expandtabs(4)) - len(line.expandtabs(4).lstrip(" "))


def _block_source(lines: list[str], start_idx: int, indent: int) -> str:
    end = start_idx + 1
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        if line.strip() and _indent_width(line) <= indent:
            break
        end = i + 1
    return textwrap.dedent("".join(lines[start_idx:end]))


def _regex_fallback_functions(source: str) -> dict[str, str]:
    """Best-effort extraction for Python-2 or otherwise unparseable files."""
    lines = source.splitlines(keepends=True)
    stack: list[tuple[int, str]] = []
    functions: dict[str, str] = {}

    for idx, line in enumerate(lines):
        indent = _indent_width(line)
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()

        class_match = _CLASS_RE.match(line)
        if class_match:
            stack.append((indent, class_match.group("name")))
            continue

        def_match = _DEF_RE.match(line)
        if not def_match:
            continue
        name = def_match.group("name")
        qual_name = ".".join([*(n for _i, n in stack), name])
        key = qual_name if qual_name not in functions else f"{qual_name}@L{idx + 1}"
        functions[key] = _block_source(lines, idx, indent)
        stack.append((indent, name))

    return functions


def _selfcheck() -> None:
    """Nested functions/classes and conditionally-defined functions are all
    extracted, with parent-qualified names (paper: 'every function')."""
    src = textwrap.dedent('''
        def outer():
            def inner():
                return 1
            return inner

        class Foo:
            def method(self):
                def deep():
                    return 2
                return deep

        if True:
            def conditional():
                return 3
    ''')
    keys = set(FunctionExtractor(src).extract())
    expected = {"outer", "outer.inner", "Foo.method",
                "Foo.method.deep", "conditional"}
    assert expected <= keys, sorted(keys)
    print("code_processor self-check OK:", sorted(keys))


if __name__ == "__main__":
    _selfcheck()
