"""build_vffinder_corpus.py — full-repo function corpus in vffinder's schema.

Fixes the DEGENERATE corpus problem (D-0005): vffinder's own
build_function_corpus_from_jsonl only knows the ground-truth functions listed in
the JSONL, so it ranks each CVE against ~1-2 candidates (its own answer) →
hit@1 is guaranteed and meaningless.

Here we extract EVERY function of each repo (via extract_functions) and emit them
in vffinder's entity schema, so vffinder ranks repo-wide. The `library` tag is
derived with vffinder's OWN `_library_tag_from_package`, so it matches the
cve_library_map.json that prepare_webapp_data writes (per-library retrieval then
pairs each CVE with all functions of its repo).

CLI:
    python -m pyshare.evaluation.scripts.build_vffinder_corpus --master M.jsonl --limit 3 \
           --out results/evaluation/adapters/vffinder/native_output/function_corpus_all.json
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import textwrap
from collections import defaultdict
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:  # degrade gracefully if tqdm isn't installed
    tqdm = None

from pyshare.evaluation.paths import PROJECT_ROOT, RESULTS_ROOT

REPO_ROOT = PROJECT_ROOT

# vffinder helpers (entity builder + library tag) — reuse so output matches its schema.
from pyshare.evaluation.methods.vffinder import config as vffinder_config  # noqa: E402
from pyshare.evaluation.methods.vffinder.scripts.build_function_corpus_from_jsonl import (  # noqa: E402
    _entities_from_source, _library_tag_from_package, ALL_CHANNELS, _clean_combined,
    MIN_IDENTIFIER_LEN, MIN_STRING_LEN, MIN_COMMENT_ALPHA,
)
from pyshare.evaluation.methods.vffinder.common.text_utils import split_identifier  # noqa: E402

from .extract_functions import extract_corpus_from_sources, module_path  # noqa: E402
from .fetch_repo import ensure_repo_cloned, read_py_sources, slugify     # noqa: E402

CACHE_DIR = RESULTS_ROOT / "artifacts" / "repo_cache"


def _class_name(qualified_name: str, file_path: str, func_name: str) -> str:
    """Immediate enclosing class from a qualified_name, '' if module-level."""
    mod = module_path(file_path)
    rest = qualified_name[len(mod) + 1:] if qualified_name.startswith(mod + ".") else qualified_name
    if rest.endswith("." + func_name):
        rest = rest[: -(len(func_name) + 1)]
    elif rest == func_name:
        rest = ""
    return rest.split(".")[-1] if rest else ""


def _qualified_tail(qualified_name: str, file_path: str, func_name: str) -> str:
    """Part of qualified_name after the module path: Class.method or method."""
    mod = module_path(file_path)
    if qualified_name.startswith(mod + "."):
        return qualified_name[len(mod) + 1:]
    return func_name


def _import_aliases_for_module(source: str, rel_path: str) -> dict[str, str]:
    """Best-effort import alias map for static call resolution."""
    aliases: dict[str, str] = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return aliases
    current = module_path(rel_path)

    def resolve_relative(module: str | None, level: int) -> str:
        if level <= 0:
            return module or ""
        parts = current.split(".")[:-level]
        if module:
            parts += module.split(".")
        return ".".join(p for p in parts if p)

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = resolve_relative(node.module, node.level)
            for alias in node.names:
                if alias.name != "*":
                    bound = alias.asname or alias.name
                    aliases[bound] = f"{base}.{alias.name}" if base else alias.name
    return aliases


def _class_bases_for_module(
    source: str,
    rel_path: str,
    aliases: dict[str, str],
) -> dict[str, list[str]]:
    """Best-effort class inheritance map: qualified class -> base classes."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    module = module_path(rel_path)

    def dotted_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = dotted_name(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        if isinstance(node, ast.Subscript):
            return dotted_name(node.value)
        return None

    def resolve_base(name: str | None) -> str | None:
        if not name:
            return None
        if name in aliases:
            return aliases[name]
        if "." in name:
            first, rest = name.split(".", 1)
            if first in aliases:
                return f"{aliases[first]}.{rest}"
            return name
        return f"{module}.{name}"

    out: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            qual = f"{module}.{node.name}"
            bases = [
                base for b in node.bases
                if (base := resolve_base(dotted_name(b)))
            ]
            out[qual] = bases
    return out


def _call_arg_tokens(call: "ast.Call") -> list[str]:
    """Split-identifier tokens of every name/attribute in a call's arguments —
    the 'actual parameters passed' that paper §4.3 attributes to the callee."""
    toks: list[str] = []
    for arg in list(call.args) + [kw.value for kw in call.keywords]:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Name):
                toks += split_identifier(sub.id)
            elif isinstance(sub, ast.Attribute):
                toks += split_identifier(sub.attr)
    return toks


def _parse_function_source(source: str) -> ast.AST | None:
    try:
        return ast.parse(textwrap.dedent(source or ""))
    except SyntaxError:
        return None


def _function_statement_count(source: str) -> int | None:
    """Count AST body statements for the first function in a source snippet."""
    tree = _parse_function_source(source)
    if tree is None:
        return None
    node = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
        None,
    )
    if node is None:
        return None
    body = list(node.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(getattr(body[0], "value", None), ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    return len(body)


def _augment_invocation(funcs: list[dict], sources: dict[str, str] | None = None,
                        max_lines: int = 5, stem: bool = True) -> dict:
    """Paper §4.3 interactive corpus — both halves, in place.

    A single AST pass over each function body builds the intra-repo call graph
    (matched by callee NAME — Python has no static type resolution like the
    paper's Soot, so a method call `x.foo()` links to every repo function named
    `foo`; an inherent language adaptation). From it:

      * Callee inline  — for each SHORT function (< max_lines statements), union
        the entity bags of the functions it calls ("enriches short methods").
      * Caller params  — for EVERY function F, the actual argument tokens at F's
        call sites are added to F's bag ("enriches function input information").

    Implemented with adjacency dicts — NOT the O(n^2) matrix in
    corpus.function_corpus.Graph, which blows up on big repos (airflow ~26k fns).
    `funcs` items carry a transient "_source" key (stripped before writing).
    """
    name_to_ids: dict[str, list[str]] = defaultdict(list)
    module_name_to_ids: dict[tuple[str, str], list[str]] = defaultdict(list)
    module_tail_to_id: dict[tuple[str, str], str] = {}
    same_class_to_ids: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    full_qualified_to_id: dict[str, str] = {}
    class_method_to_ids: dict[tuple[str, str], list[str]] = defaultdict(list)
    local_class_qual: dict[tuple[str, str], str] = {}
    module_to_tails: dict[str, list[tuple[str, str]]] = defaultdict(list)

    # Optimization 1: Only parse modules that actually contain functions in funcs
    unique_modules = {f["module"] for f in funcs}
    import_aliases = {
        rel: _import_aliases_for_module(sources[rel], rel)
        for rel in unique_modules if sources and rel in sources
    }
    class_bases: dict[str, list[str]] = {}
    for rel in unique_modules:
        if sources and rel in sources:
            class_bases.update(
                _class_bases_for_module(sources[rel], rel, import_aliases.get(rel, {}))
            )

    for f in funcs:
        name_to_ids[f["name"]].append(f["func_id"])
        module_name_to_ids[(f["module"], f["name"])].append(f["func_id"])
        tail = f.get("_qual_tail") or f["name"]
        module_tail_to_id[(f["module"], tail)] = f["func_id"]

        # Pre-group tails by module to optimize resolve_imported symbol search
        module_to_tails[f["module"]].append((tail, f["func_id"]))

        if f.get("_qualified_name"):
            full_qualified_to_id[f["_qualified_name"]] = f["func_id"]
            if f.get("class_name"):
                class_qual = f["_qualified_name"].rsplit("." + f["name"], 1)[0]
                class_method_to_ids[(class_qual, f["name"])].append(f["func_id"])
                local_class_qual[(f["module"], f["class_name"])] = class_qual
        if f.get("class_name"):
            same_class_to_ids[(f["module"], f["class_name"], f["name"])].append(f["func_id"])
    by_id = {f["func_id"]: f for f in funcs}

    def resolve_imported(module_or_symbol: str) -> list[str]:
        if module_or_symbol in full_qualified_to_id:
            return [full_qualified_to_id[module_or_symbol]]
        mod, _, name = module_or_symbol.rpartition(".")
        if not mod:
            return []
        module_file = mod.replace(".", "/") + ".py"
        ids = module_name_to_ids.get((module_file, name), [])
        if ids:
            return ids
        # Optimization 2: Avoid O(N) full repository dictionary scan by looking up local module tails
        suffix = "." + name
        return [
            fid for tail, fid in module_to_tails.get(module_file, [])
            if tail.endswith(suffix)
        ]

    def method_ids_for_class_or_bases(
        class_qual: str | None,
        method: str,
        seen: set[str] | None = None,
    ) -> tuple[list[str], bool]:
        if not class_qual:
            return [], False
        seen = seen or set()
        if class_qual in seen:
            return [], False
        seen.add(class_qual)
        ids = list(class_method_to_ids.get((class_qual, method), []))
        inherited = False
        for base in class_bases.get(class_qual, []):
            base_ids, base_inherited = method_ids_for_class_or_bases(base, method, seen)
            if base_ids:
                inherited = True
                ids.extend(base_ids)
            inherited = inherited or base_inherited
        return list(dict.fromkeys(ids)), inherited

    def dotted_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = dotted_name(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        return None

    def annotation_name(node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return dotted_name(node)
        if isinstance(node, ast.Subscript):
            return annotation_name(node.value)
        return None

    def infer_local_types(f: dict, tree: ast.AST) -> dict[str, str]:
        module = f["module"]
        aliases = import_aliases.get(module, {})
        types: dict[str, str] = {}

        def class_qual(name: str | None) -> str | None:
            if not name:
                return None
            if name in aliases:
                return aliases[name]
            if "." in name:
                first, rest = name.split(".", 1)
                if first in aliases:
                    return f"{aliases[first]}.{rest}"
            return local_class_qual.get((module, name))

        for node in ast.walk(tree):
            inferred: str | None = None
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    inferred = class_qual(dotted_name(node.value.func))
                targets = [
                    name for target in node.targets
                    if (name := dotted_name(target))
                ]
            elif isinstance(node, ast.AnnAssign):
                inferred = class_qual(annotation_name(node.annotation))
                if inferred is None and isinstance(node.value, ast.Call):
                    inferred = class_qual(dotted_name(node.value.func))
                name = dotted_name(node.target)
                targets = [name] if name else []
            if inferred:
                for name in targets:
                    types[name] = inferred
        return types

    def resolve_call_ids(f: dict, call: ast.Call,
                         local_types: dict[str, str] | None = None) -> tuple[list[str], str]:
        fn = call.func
        module = f["module"]
        aliases = import_aliases.get(module, {})
        local_types = local_types or {}
        ids: list[str] = []
        strategy = "unresolved"
        if isinstance(fn, ast.Name):
            name = fn.id
            ids.extend(module_name_to_ids.get((module, name), []))
            if ids:
                strategy = "module_local"
            if name in aliases:
                ids.extend(resolve_imported(aliases[name]))
                if ids:
                    strategy = "import_alias"
        elif isinstance(fn, ast.Attribute):
            attr = fn.attr
            owner = dotted_name(fn.value)
            if owner in {"self", "cls"} and f.get("class_name"):
                ids.extend(same_class_to_ids.get((module, f["class_name"], attr), []))
                strategy = "same_class"
                if f.get("_qualified_name"):
                    class_qual = f["_qualified_name"].rsplit("." + f["name"], 1)[0]
                    base_ids, inherited = method_ids_for_class_or_bases(class_qual, attr)
                    ids.extend(base_ids)
                    if inherited and base_ids:
                        strategy = "inherited_self"
            elif owner:
                first = owner.split(".", 1)[0]
                if owner in local_types:
                    typed_ids, inherited = method_ids_for_class_or_bases(
                        local_types[owner], attr
                    )
                    ids.extend(typed_ids)
                    if typed_ids:
                        strategy = "typed_owner_inherited" if inherited else "typed_owner"
                if owner == f.get("class_name"):
                    ids.extend(same_class_to_ids.get((module, owner, attr), []))
                    if ids:
                        strategy = "same_class_name"
                if first in aliases:
                    suffix = owner.split(".", 1)[1] if "." in owner else ""
                    target = aliases[first]
                    if suffix:
                        target = f"{target}.{suffix}"
                    ids.extend(resolve_imported(f"{target}.{attr}"))
                    if ids:
                        strategy = "import_alias_attr"
        if not ids:
            callee = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
            if callee:
                # Optimization 3: Cap fallback name-only matches to <= 15 definitions to prevent dilution and O(N*M) blowup
                candidates = name_to_ids.get(callee, [])
                if len(candidates) <= 15:
                    ids.extend(candidates)
                    if ids:
                        strategy = "fallback_name_only"
        return list(dict.fromkeys(i for i in ids if i != f["func_id"])), strategy

    downstream: dict[str, set[str]] = defaultdict(set)   # caller -> callee ids
    caller_raw: dict[str, set[str]] = defaultdict(set)   # callee id -> arg tokens
    stats = {
        "functions_seen": len(funcs),
        "functions_with_parsed_source": 0,
        "call_edges_resolved": 0,
        "caller_param_tokens_added": 0,
        "functions_receiving_caller_param_tokens": 0,
        "callee_inline_tokens_added": 0,
        "functions_receiving_callee_inline_entities": 0,
        "short_functions_seen": 0,
        "call_edges_by_resolution": {},
    }
    iterator = tqdm(funcs, desc="    resolving calls", leave=False) if tqdm else funcs
    for f in iterator:
        src = f.get("_source") or ""
        if not src:
            continue
        tree = _parse_function_source(src)
        if tree is None:
            continue
        stats["functions_with_parsed_source"] += 1

        # Optimization 4: Extract statement count directly from the parsed tree to avoid parsing it again in the next loop
        node = next(
            (n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
            None,
        )
        if node is not None:
            body = list(node.body)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(getattr(body[0], "value", None), ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]
            f["_stmt_count"] = len(body)

        local_types = infer_local_types(f, tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                ids, strategy = resolve_call_ids(f, node, local_types)
                if not ids:
                    continue
                by_strategy = stats["call_edges_by_resolution"]
                by_strategy[strategy] = by_strategy.get(strategy, 0) + len(ids)
                arg_toks = _call_arg_tokens(node)
                for cid in ids:
                    downstream[f["func_id"]].add(cid)
                    caller_raw[cid].update(arg_toks)
                    stats["call_edges_resolved"] += 1

    for f in funcs:
        ents = set(f["entities"])
        # callee inline — short functions only (paper: "methods within 5 statements")
        stmt_count = f.get("_stmt_count")
        if stmt_count is not None and stmt_count <= max_lines:
            stats["short_functions_seen"] += 1
            before_inline = set(ents)
            for cid in downstream.get(f["func_id"], ()):
                ents.update(by_id[cid]["entities"])
            added_inline = ents - before_inline
            if added_inline:
                stats["functions_receiving_callee_inline_entities"] += 1
                stats["callee_inline_tokens_added"] += len(added_inline)
        # caller parameters — every function with incoming calls
        raw = caller_raw.get(f["func_id"])
        if raw:
            before_caller = set(ents)
            ents.update(_clean_combined(list(raw), stem=stem))
            added_caller = ents - before_caller
            if added_caller:
                stats["functions_receiving_caller_param_tokens"] += 1
                stats["caller_param_tokens_added"] += len(added_caller)
        f["entities"] = sorted(ents)
    return stats


def _atomic_write_json(path: Path, data) -> None:
    """Write JSON to a temp file then os.replace — a kill mid-write can only ever
    corrupt the throwaway .tmp, never the real file.

    Source read from arbitrary repos (and odd file names) can carry lone
    surrogates (U+D800–DFFF) — invalid UTF-8 that json.dumps happily keeps in the
    returned str but that utf-8 *cannot* encode (UnicodeEncodeError: surrogates
    not allowed). Encode with errors="replace" so a single bad token becomes
    U+FFFD instead of crashing the whole (multi-hundred-MB) corpus write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    text = json.dumps(data, ensure_ascii=False, indent=2)
    tmp.write_bytes(text.encode("utf-8", "replace"))
    os.replace(tmp, path)


def _progress_path(out_path: Path) -> Path:
    return out_path.with_suffix(out_path.suffix + ".progress.json")


def _counter_path(out_path: Path) -> Path:
    return out_path.with_suffix(out_path.suffix + ".component_counters.json")


def _empty_component_stats(params: dict, repos_total: int) -> dict:
    return {
        "component": "function_corpus",
        "params": params,
        "repos_total": repos_total,
        "repos_done": 0,
        "repos_processed_this_run": 0,
        "functions_total": 0,
        "functions_with_entities": 0,
        "entity_tokens_total": 0,
        "libraries": 0,
        "enabled_channels": params.get("channels", []),
        "local_channel_raw_token_counts": {},
        "augmentation": {
            "functions_seen": 0,
            "functions_with_parsed_source": 0,
            "call_edges_resolved": 0,
            "caller_param_tokens_added": 0,
            "functions_receiving_caller_param_tokens": 0,
            "callee_inline_tokens_added": 0,
            "functions_receiving_callee_inline_entities": 0,
            "short_functions_seen": 0,
            "call_edges_by_resolution": {},
        },
    }


def _add_aug_stats(total: dict, part: dict) -> None:
    for key, value in part.items():
        if isinstance(value, dict):
            dst = total.setdefault(key, {})
            for sub_key, sub_value in value.items():
                dst[sub_key] = int(dst.get(sub_key, 0)) + int(sub_value)
        else:
            total[key] = int(total.get(key, 0)) + int(value)


def _refresh_component_stats(stats: dict, entries: list[dict], done: set[str]) -> dict:
    stats["repos_done"] = len(done)
    stats["functions_total"] = len(entries)
    stats["functions_with_entities"] = sum(1 for e in entries if e.get("entities"))
    stats["entity_tokens_total"] = sum(len(e.get("entities") or []) for e in entries)
    stats["libraries"] = len({e.get("library", "") for e in entries if e.get("library")})
    return stats


def build_corpus(master_path: Path, limit: int | None, out_path: Path,
                 inline: bool = True, channels: set[str] | None = None,
                 resume: bool = True, stem: bool = True) -> dict:
    groups = [json.loads(l) for l in master_path.open(encoding="utf-8") if l.strip()]
    if limit:
        groups = groups[:limit]

    channels = channels or set(ALL_CHANNELS)
    # One corpus per (repo, vulnerable_ref): a repo shared by several CVEs is
    # built once. setdefault keeps the first library tag seen for that repo.
    by_repo: dict[str, tuple] = {}
    for g in groups:
        repo_url, ref = g.get("repo_url"), g.get("vulnerable_ref")
        if not (repo_url and ref):
            continue
        lib = _library_tag_from_package([{"name": g.get("package_name", "")}])
        dest = CACHE_DIR / slugify(repo_url.replace("https://github.com/", ""))
        by_repo.setdefault(str(dest), (repo_url, ref, dest, lib))

    # Checkpoint params: a change to channels/inline/master/limit (e.g. a
    # different ablation config) invalidates the checkpoint so we never mix a
    # `sig` corpus with a `sig+body` one.
    # `aug` versions the invocation-augmentation logic so a change to it (e.g.
    # adding caller-params) invalidates an older checkpoint instead of silently
    # resuming a corpus built by the previous algorithm.
    params = {"channels": sorted(channels), "inline": inline,
              "master": str(master_path), "limit": limit, "stem": stem,
              "entity_filters": {
                  "min_identifier_len": MIN_IDENTIFIER_LEN,
                  "min_string_len": MIN_STRING_LEN,
                  "min_comment_alpha": MIN_COMMENT_ALPHA,
              },
              "extract": "ast+regex-fallback-v1",
              "aug": "callee+caller-v5-ast-fallback-entity-filters" if inline else "off"}
    prog_path = _progress_path(out_path)
    counter_path = _counter_path(out_path)

    entries: list[dict] = []
    # Dedup is keyed on (library, func_id), NOT func_id alone: func_id is
    # "<repo-relative-path>::<func>" with no repo/library qualifier, so common
    # paths (setup.py::main, models.py::save, __init__.py funcs) collide ACROSS
    # repos. A global func_id dedup would drop repo B's function because an
    # earlier repo A (a DIFFERENT library) claimed the id first — then B's
    # per-library retrieval subset (filtered by fe.library) silently lacks it,
    # deflating recall when that function is ground truth. (Ground truth itself
    # is keyed file::func, so the func_id format must stay unqualified to remain
    # joinable; scoping the dedup by library is the correct fix.)
    seen_ids: set[tuple[str, str]] = set()
    done: set[str] = set()                        # repo dests already processed
    component_stats = _empty_component_stats(params, len(by_repo))
    if resume and out_path.is_file() and prog_path.is_file():
        try:
            prog = json.loads(prog_path.read_text(encoding="utf-8"))
            if prog.get("params") == params:
                entries = json.loads(out_path.read_text(encoding="utf-8"))
                seen_ids = {(e["library"], e["func_id"]) for e in entries}
                done = set(prog.get("done_repos", []))
                component_stats = prog.get("component_counters") or component_stats
                component_stats = _refresh_component_stats(component_stats, entries, done)
                print(f"  resume: {len(done)} repo(s) done, "
                      f"{len(entries)} functions in checkpoint")
            else:
                old = prog.get("params", {})
                diff = [f"{k}: {old.get(k)!r} -> {params[k]!r}"
                        for k in params if old.get(k) != params[k]]
                print("  checkpoint params changed — rebuilding corpus from scratch")
                print(f"    changed: {'; '.join(diff) or '(unknown)'}")
        except Exception:  # noqa: BLE001 — corrupt checkpoint -> start clean
            print("  could not read checkpoint — starting clean")

    emit = tqdm.write if tqdm else print
    todo = [v for v in by_repo.values() if str(v[2]) not in done]
    bar = tqdm(todo, desc="corpus", unit="repo") if tqdm else todo
    if done:
        emit(f"  skipping {len(done)} checkpointed repo(s); {len(todo)} to do")

    for repo_url, ref, dest, lib in bar:
        err = ensure_repo_cloned(repo_url, ref, dest)
        if err:
            emit(f"  SKIP {repo_url}: {err}")     # not marked done -> retried next run
            continue
        # Read source straight from the git object store (no working tree) so
        # repos with NTFS-illegal paths (aux/, ':' in names) don't fail on Windows.
        sources = read_py_sources(dest, ref)
        if sources is None:
            emit(f"  SKIP {repo_url}: cannot list tree at {ref}")
            continue

        funcs = extract_corpus_from_sources(sources)
        repo_funcs: list[dict] = []
        channel_stats = component_stats.setdefault("local_channel_raw_token_counts", {})
        for f in funcs:
            cls = _class_name(f["qualified_name"], f["file_path"], f["function_name"])
            qual_tail = _qualified_tail(
                f["qualified_name"], f["file_path"], f["function_name"])
            entities = _entities_from_source(
                f["source"], f["function_name"], cls, channels,
                include_docstring=True, stem=stem,
                channel_stats=channel_stats)
            repo_funcs.append({
                "func_id": f"{f['file_path']}::{qual_tail}",
                "name": f["function_name"],
                "module": f["file_path"],
                "class_name": cls,
                "params": [],
                "param_types": [],
                "entities": entities,
                "library": lib,
                "_qualified_name": f["qualified_name"],
                "_qual_tail": qual_tail,
                "_source": f["source"],          # transient — for call graph
            })

        if inline and repo_funcs:
            aug_stats = _augment_invocation(repo_funcs, sources=sources, stem=stem)
            _add_aug_stats(component_stats["augmentation"], aug_stats)

        added = 0
        for f in repo_funcs:
            f.pop("_source", None)               # don't serialize source
            f.pop("_qualified_name", None)
            f.pop("_qual_tail", None)
            key = (f["library"], f["func_id"])
            if key in seen_ids:
                continue
            seen_ids.add(key)
            entries.append(f)
            added += 1
        emit(f"  {repo_url}: {added} functions (library='{lib}', inline={inline})")
        component_stats["repos_processed_this_run"] += 1

        # Checkpoint after each repo so an interrupted build resumes here.
        done.add(str(dest))
        component_stats = _refresh_component_stats(component_stats, entries, done)
        _atomic_write_json(out_path, entries)
        _atomic_write_json(
            prog_path,
            {
                "params": params,
                "done_repos": sorted(done),
                "component_counters": component_stats,
            },
        )

    if tqdm and not isinstance(bar, list):
        bar.close()
    component_stats = _refresh_component_stats(component_stats, entries, done)
    _atomic_write_json(out_path, entries)         # final write (also covers empty/all-skip)
    _atomic_write_json(counter_path, component_stats)
    print(f"\nWrote {len(entries)} functions across {len(done)} repos -> {out_path}")
    print(f"Component counters -> {counter_path}")
    return {"total": len(entries), "n_repos": len(done)}


def _selfcheck() -> None:
    """Assert both invocation-augmentation halves propagate (paper §4.3)."""
    funcs = [
        {"func_id": "a.py::helper", "name": "helper", "entities": ["help"],
         "module": "a.py", "class_name": "", "_qual_tail": "helper",
         "_source": "def helper():\n    return 1\n"},                       # short callee
        {"func_id": "a.py::tiny", "name": "tiny", "entities": ["tiny"],
         "module": "a.py", "class_name": "", "_qual_tail": "tiny",
         "_source": "def tiny():\n    return helper()\n"},                  # short caller
        {"func_id": "a.py::big", "name": "big", "entities": ["big"],
         "module": "a.py", "class_name": "", "_qual_tail": "big",
         "_source": "def big(self):\n    " + "\n    ".join(f"x{i}=1" for i in range(8))
                     + "\n    return helper()\n"},                            # long: calls helper
        {"func_id": "a.py::caller", "name": "caller", "entities": ["call"],
         "module": "a.py", "class_name": "", "_qual_tail": "caller",
         "_source": "def caller():\n    return helper(secretToken)\n"},      # passes arg to helper
        {"func_id": "a.py::five", "name": "five", "entities": ["five"],
         "module": "a.py", "class_name": "", "_qual_tail": "five",
         "_source": "def five():\n    a=1\n    b=2\n    c=3\n    d=4\n    return helper()\n"},
        {"func_id": "a.py::six", "name": "six", "entities": ["six"],
         "module": "a.py", "class_name": "", "_qual_tail": "six",
         "_source": "def six():\n    a=1\n    b=2\n    c=3\n    d=4\n    e=5\n    return helper()\n"},
        {"func_id": "a.py::Worker.run", "name": "run", "entities": ["worker"],
         "module": "a.py", "class_name": "Worker", "_qual_tail": "Worker.run",
         "_qualified_name": "a.Worker.run",
         "_source": "    def run(self):\n        return 1\n"},
        {"func_id": "a.py::use_worker", "name": "use_worker", "entities": ["use"],
         "module": "a.py", "class_name": "", "_qual_tail": "use_worker",
         "_source": "def use_worker():\n    worker = Worker()\n    return worker.run()\n"},
    ]
    _augment_invocation(funcs, stem=False)
    by_id = {f["func_id"]: set(f["entities"]) for f in funcs}
    # caller-params: helper gains tokens from `secretToken` at its call site.
    assert {"secret", "token"} <= by_id["a.py::helper"], by_id["a.py::helper"]
    # callee-inline: short `tiny` calls helper, so helper's entity bag is unioned
    # into tiny; `big` is long so it is NOT inlined.
    assert "help" in by_id["a.py::tiny"], by_id["a.py::tiny"]
    assert "help" in by_id["a.py::five"], by_id["a.py::five"]
    assert "help" not in by_id["a.py::six"], by_id["a.py::six"]
    assert "help" not in by_id["a.py::big"], by_id["a.py::big"]
    assert "worker" in by_id["a.py::use_worker"], by_id["a.py::use_worker"]
    print("build_vffinder_corpus self-check OK:", sorted(by_id["a.py::helper"]))


def main() -> None:
    ap = argparse.ArgumentParser(description="Build full-repo vffinder corpus.")
    if "--selfcheck" in sys.argv:
        _selfcheck()
        return
    ap.add_argument("--master", type=Path,
                    default=REPO_ROOT / "data" / "processed" / "cve_to_vf_evaluation.jsonl")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", type=Path,
                    default=vffinder_config.OUTPUT_DIR / "function_corpus_all.json")
    ap.add_argument("--no-inline", action="store_true",
                    help="disable callee-inline invocation augmentation (paper §4.3)")
    ap.add_argument("--channels", default=",".join(ALL_CHANNELS),
                    help=f"entity channels to keep (default: all {len(ALL_CHANNELS)}). "
                         f"Valid: {','.join(ALL_CHANNELS)}")
    ap.add_argument("--no-resume", action="store_true",
                    help="ignore any existing checkpoint and rebuild from scratch")
    ap.add_argument("--no-stem", action="store_true",
                    help="disable Porter stemming (paper §4.2 preprocessing ablation)")
    args = ap.parse_args()
    chans = {c.strip() for c in args.channels.split(",") if c.strip()}
    unknown = chans - set(ALL_CHANNELS)
    if unknown:
        raise SystemExit(f"unknown channel(s): {sorted(unknown)}; valid: {ALL_CHANNELS}")
    build_corpus(args.master, args.limit, args.out,
                 inline=not args.no_inline, channels=chans,
                 resume=not args.no_resume, stem=not args.no_stem)


if __name__ == "__main__":
    main()
