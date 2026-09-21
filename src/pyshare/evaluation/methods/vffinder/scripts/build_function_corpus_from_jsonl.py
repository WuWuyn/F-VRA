"""Build function_corpus_all.json from the JSONL dataset.

This is Phase 3 of the VFFinder pipeline (API Entity Extraction), specialised
for the case where source code arrives in the dataset rather than as a parsed
library tree. It produces one FunctionEntity per (vf_file, func_name) triple,
combining:

  * the primary vulnerable function - full 6-channel entity bag built from
    its source code (APIName, APIClz, APIVar, APIParaName, APIParaType,
    APIString) - same logic as corpus/function_corpus.py.
  * the sibling functions named in `all_functions` - name-only entity bags
    (source is not in the JSONL).

Ablation flags (mirror the paper's `extraction_opt_dict`):

    --no-stem               disable Porter stemming
    --channels CSV          which entity channels to keep
                            (default: APIName,APIClz,APIParaName,APIParaType,APIVar,APIString)
    --no-docstring          skip docstring (Python-only, not in paper)

Usage (from the directory containing vffinder/):
    python -m pyshare.evaluation.methods.vffinder.scripts.build_function_corpus_from_jsonl
    python -m pyshare.evaluation.methods.vffinder.scripts.build_function_corpus_from_jsonl --channels APIName,APIClz,APIVar
    python -m pyshare.evaluation.methods.vffinder.scripts.build_function_corpus_from_jsonl --no-stem
"""

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path


from pyshare.evaluation.methods.vffinder import config
from pyshare.evaluation.methods.vffinder.common.text_utils import (
    split_identifier,
    filter_meaningless,
    deduplicate_wordnet,
    _STOPWORDS,
    _STEMMER,
)

DEFAULT_JSONL = config.DATA_DIR / "direct_final_modified.jsonl"
DEFAULT_OUTPUT = config.OUTPUT_DIR / "function_corpus_all.json"

ALL_CHANNELS = ("APIName", "APIClz", "APIParaName", "APIParaType",
                "APIVar", "APIString")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# Noise filters for Python-specific entity extraction. They are deliberately
# configurable because short names such as "id", "io", or small string tokens can
# be vulnerability-relevant. Defaults are less aggressive than the old fixed
# thresholds while still dropping single-letter loop variables by default.
MIN_IDENTIFIER_LEN = max(1, _env_int("VFF_MIN_IDENTIFIER_LEN", 2))
MIN_STRING_LEN = max(1, _env_int("VFF_MIN_STRING_LEN", 2))
MIN_COMMENT_ALPHA = max(1, _env_int("VFF_MIN_COMMENT_ALPHA", 1))


# --- Text helpers (mirrors function_corpus.py) --------------------------------

def _clean_combined(raw: list[str], stem: bool = True) -> list[str]:
    lowered = [w.lower() for w in raw]
    no_stop = [w for w in lowered if w not in _STOPWORDS]
    filtered = filter_meaningless(no_stop)
    deduped = deduplicate_wordnet(filtered)
    if stem:
        deduped = list({_STEMMER.stem(e) for e in deduped})
    return deduped


_URL_PATTERN = re.compile(r"https?://|www\.|\.com|\.org|\.io|\.py\b")
_COMMENT_RE = re.compile(r"#.*$", re.MULTILINE)


def _dedent(source: str) -> str:
    """Remove common leading whitespace so ast.parse succeeds."""
    lines = source.splitlines()
    non_empty = [l for l in lines if l.strip()]
    if not non_empty:
        return source
    indent = len(non_empty[0]) - len(non_empty[0].lstrip())
    return "\n".join(l[indent:] if len(l) > indent else l for l in lines)


def _extract_func_name(source: str) -> str:
    m = re.search(r"(?:async\s+)?def\s+(\w+)\s*\(", source)
    return m.group(1) if m else "unknown"


def _entities_from_source(source: str,
                          func_name: str,
                          class_name: str,
                          channels: set[str],
                          include_docstring: bool,
                          stem: bool = True,
                          channel_stats: dict | None = None) -> list[str]:
    """Build entity bag from function source code, channel-gated.

    Mirrors the 6-channel extraction in corpus/function_corpus.py.
    `channels` is a set of channel names to KEEP - others are dropped.
    `stem` controls Porter stemming (the `--no-stem` ablation must reach the
    real corpus, so it has to be threaded all the way down to `_clean_combined`).
    """
    raw: list[str] = []

    def add_channel(channel: str, tokens: list[str]) -> None:
        raw.extend(tokens)
        if channel_stats is not None:
            channel_stats[channel] = channel_stats.get(channel, 0) + len(tokens)

    if "APIName" in channels:
        add_channel("APIName", split_identifier(func_name))
    if "APIClz" in channels and class_name:
        add_channel("APIClz", split_identifier(class_name))

    try:
        dedented = _dedent(source)
        tree = ast.parse(dedented)
    except SyntaxError:
        return _clean_combined(raw, stem=stem)

    func_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_node = node
            break

    if func_node is None:
        return _clean_combined(raw, stem=stem)

    args = func_node.args
    if "APIParaName" in channels:
        toks: list[str] = []
        for arg in args.args + args.posonlyargs + args.kwonlyargs:
            if arg.arg not in ("self", "cls"):
                toks += split_identifier(arg.arg)
        if args.vararg:
            toks += split_identifier(args.vararg.arg)
        if args.kwarg:
            toks += split_identifier(args.kwarg.arg)
        add_channel("APIParaName", toks)

    if "APIParaType" in channels:
        toks: list[str] = []
        all_args = list(args.args + args.posonlyargs + args.kwonlyargs)
        if args.vararg:
            all_args.append(args.vararg)
        if args.kwarg:
            all_args.append(args.kwarg)
        for arg in all_args:
            if arg.annotation:
                ann_str = ast.unparse(arg.annotation)
                for part in re.split(r"[|\[\],\s]+", ann_str):
                    toks += split_identifier(part)
        add_channel("APIParaType", toks)

    if "APIVar" in channels:
        toks: list[str] = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Load)):
                if len(node.id) >= MIN_IDENTIFIER_LEN:
                    toks += split_identifier(node.id)
            elif isinstance(node, ast.Attribute):
                if len(node.attr) >= MIN_IDENTIFIER_LEN:
                    toks += split_identifier(node.attr)
        add_channel("APIVar", toks)

    if "APIString" in channels:
        toks: list[str] = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.strip()
                if len(val) >= MIN_STRING_LEN and not _URL_PATTERN.search(val):
                    for tok in val.split():
                        toks += split_identifier(tok)
        for comment in _COMMENT_RE.findall(dedented):
            body = comment.lstrip("#").strip()
            if not body or _URL_PATTERN.search(body):
                continue
            alpha_toks = [
                t for t in body.split()
                if t.isalpha() and len(t) >= MIN_IDENTIFIER_LEN
            ]
            if len(alpha_toks) >= MIN_COMMENT_ALPHA:
                for tok in alpha_toks:
                    toks += split_identifier(tok)
        add_channel("APIString", toks)

    if include_docstring:
        toks: list[str] = []
        doc = ast.get_docstring(func_node) or ""
        for tok in doc.split():
            toks += split_identifier(re.sub(r"[^a-zA-Z0-9_]", "", tok))
        add_channel("Docstring", toks)

    return _clean_combined(raw, stem=stem)


def _library_tag_from_package(packages: list[dict]) -> str:
    if not packages:
        return ""
    name = packages[0].get("name", "").lower()
    for sep in ("-", "_"):
        parts = name.split(sep)
        if len(parts) > 1:
            name = parts[-1]
            break
    return name


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  WARNING: line {lineno} skipped ({e})", file=sys.stderr)
    return records


# --- Main build logic --------------------------------------------------------

def build(jsonl_path: Path,
          output_path: Path,
          channels: set[str],
          stem: bool,
          include_docstring: bool) -> None:
    print(f"Reading {jsonl_path} ...")
    records = load_jsonl(jsonl_path)
    print(f"  {len(records)} records loaded")
    print(f"Channels enabled: {sorted(channels)}")
    print(f"Stemming: {stem} | Docstring: {include_docstring}")

    func_seen: set[str] = set()
    func_entries: list[dict] = []
    total_records = len(records)

    for idx, rec in enumerate(records):
        vf_file = rec.get("vf_file", "unknown.py")
        vf_source = rec.get("vf_function", "")
        all_funcs = rec.get("all_functions") or []
        pkgs = rec.get("packages") or []
        lib_tag = _library_tag_from_package(pkgs)

        # Primary: vulnerable function with full source
        prim_name = (_extract_func_name(vf_source) if vf_source
                     else (all_funcs[0] if all_funcs else "unknown"))
        prim_id = f"{vf_file}::{prim_name}"

        if prim_id not in func_seen:
            func_seen.add(prim_id)
            entities = _entities_from_source(
                vf_source, prim_name, "", channels, include_docstring, stem=stem,
            )
            func_entries.append({
                "func_id": prim_id,
                "name": prim_name,
                "module": vf_file,
                "class_name": "",
                "params": [],
                "param_types": [],
                "entities": entities,
                "library": lib_tag,
            })

        # Siblings: name-only entity bags (no source available)
        for fn_name in all_funcs:
            if fn_name == prim_name:
                continue
            sib_id = f"{vf_file}::{fn_name}"
            if sib_id in func_seen:
                continue
            func_seen.add(sib_id)

            sib_raw: list[str] = []
            if "APIName" in channels:
                sib_raw += split_identifier(fn_name)
            if "APIClz" in channels and lib_tag:
                sib_raw += split_identifier(lib_tag)
            sib_entities = _clean_combined(sib_raw, stem=stem)
            func_entries.append({
                "func_id": sib_id,
                "name": fn_name,
                "module": vf_file,
                "class_name": "",
                "params": [],
                "param_types": [],
                "entities": sib_entities,
                "library": lib_tag,
            })

        if (idx + 1) % 200 == 0:
            print(f"  ... {idx + 1}/{total_records} records "
                  f"({len(func_entries)} functions so far)")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(func_entries, f, indent=2, ensure_ascii=False)
    print(f"\nWrote {len(func_entries)} functions -> {output_path}")


# --- CLI ----------------------------------------------------------------------

def _parse_channels(raw: str) -> set[str]:
    requested = {c.strip() for c in raw.split(",") if c.strip()}
    unknown = requested - set(ALL_CHANNELS)
    if unknown:
        print(f"ERROR: unknown channel(s): {sorted(unknown)}. "
              f"Valid: {ALL_CHANNELS}", file=sys.stderr)
        sys.exit(1)
    return requested


def main():
    parser = argparse.ArgumentParser(
        description="Build function_corpus_all.json from the JSONL dataset (Phase 3)."
    )
    parser.add_argument("--jsonl", default=str(DEFAULT_JSONL),
                        help=f"JSONL dataset (default: {DEFAULT_JSONL})")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT),
                        help=f"Output JSON (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--channels", default=",".join(ALL_CHANNELS),
                        help=f"Comma-separated channels to keep "
                             f"(default: all {len(ALL_CHANNELS)})")
    parser.add_argument("--no-stem", action="store_true",
                        help="disable Porter stemming")
    parser.add_argument("--no-docstring", action="store_true",
                        help="skip docstring channel (Python-only)")
    args = parser.parse_args()

    print(
        "WARNING: this legacy dataset-local corpus only builds from the JSONL "
        "functions already listed in the benchmark. It is not the repo-wide "
        "evaluation corpus; use evaluation.scripts.build_vffinder_corpus for "
        "benchmark runs.",
        file=sys.stderr,
    )
    jsonl_path = Path(args.jsonl)
    if not jsonl_path.exists():
        print(f"ERROR: JSONL file not found: {jsonl_path}", file=sys.stderr)
        sys.exit(1)

    channels = _parse_channels(args.channels)

    build(
        jsonl_path=jsonl_path,
        output_path=Path(args.output),
        channels=channels,
        stem=not args.no_stem,
        include_docstring=not args.no_docstring,
    )


if __name__ == "__main__":
    main()
