"""Adapter base class + shared helpers for the auto-run driver.

Task framing: **function-level VF localization** — each method, given a CVE
description + repo, produces a *ranked list of functions*. The common prediction
contract is therefore one record per (CVE, variant):

    {
      "cve_id": "CVE-2020-26257",
      "method": "vffinder",
      "variant": "p-icl",                  # "default" for single-output methods
      "ranked_functions": [                 # ordered best-first
          {"func_id": "...py::fn", "score": 0.91},
          ...
      ],
      "ground_truth": ["...py::fn", ...]    # gold VF names/ids for this CVE
    }

An adapter does THREE things (see subclasses):
  1. convert the master dataset -> the method's own input format,
  2. run the method's NATIVE pipeline (subprocess; we never edit method code),
  3. parse the method's native output -> the contract above.

Metrics (MRR / Recall@K) are a SEPARATE later layer that reads the JSONL files
this driver writes. They are intentionally out of scope here.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from abc import ABC, abstractmethod
from pathlib import Path
from pyshare.evaluation.paths import PROJECT_ROOT, SHARED_ENV_FILE

# Backwards-compatible name used throughout the adapters.
REPO_ROOT = PROJECT_ROOT


def load_shared_env(path: Path = SHARED_ENV_FILE) -> None:
    """Load the repository-root .env without overriding real environment vars."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_shared_env()


@dataclass(frozen=True)
class RunContext:
    """Normalized execution context for main runs and ablation variants."""

    master_path: Path
    out_dir: Path
    python_bin: str = "python"
    limit: int | None = None
    experiment_group: str = "main"
    variant: str | None = None
    axis: str | None = None


class MethodAdapter(ABC):
    """One adapter per method. The driver only ever calls `run()`."""

    name: str = "base"
    enabled: bool = True

    @abstractmethod
    def run(self, ctx: RunContext) -> list[Path]:
        """Convert input, run the native pipeline, write normalized predictions.

        `ctx.limit` is the shared sample-size control. The evaluation CLI sets
        it once and each adapter applies it before invoking the native method.

        Returns the list of prediction files written (one per variant, or a
        single file containing all variants - adapter's choice)."""
        ...


# ─────────────────────────── shared helpers ────────────────────────────────

def iter_master(master_path: Path):
    """Yield each record (dict) of the master benchmark JSONL."""
    with open(master_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def load_master_index(master_path: Path) -> dict[str, dict]:
    """Return advisory_id/cve_id -> master metadata used by adapters/validation."""
    index: dict[str, dict] = {}
    for rec in iter_master(master_path):
        cid = rec.get("advisory_id") or rec.get("cve_id")
        if not cid:
            continue
        gts = []
        for fn in rec.get("root_cause_functions") or []:
            gts.append(
                fn.get("qualified_name")
                or (
                    f"{fn.get('file_path')}::{fn.get('function_name')}"
                    if fn.get("file_path") and fn.get("function_name")
                    else fn.get("function_name")
                )
            )
        index[cid] = {
            "group_id": rec.get("group_id") or cid,
            "ground_truth": [g for g in gts if g],
            "mapping_type": rec.get("mapping_type"),
        }
    return index


def run_step(cmd: list[str], cwd: Path, timeout: int = 3600,
             python_bin: str | None = None) -> None:
    """Run one pipeline command, raising RuntimeError on non-zero exit.

    `python_bin` (if given) replaces a leading literal "python" token so each
    adapter can target its own interpreter / conda env. UTF-8 is forced to avoid
    Windows cp1252 UnicodeDecodeErrors (see vffinder README §8).

    The child inherits this console so its logs and tqdm progress bars stream
    live; PYTHONUNBUFFERED makes its prints appear immediately."""
    if python_bin and cmd and cmd[0] == "python":
        cmd = [python_bin, *cmd[1:]]
    env = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8",
           "PYTHONUNBUFFERED": "1", **os.environ}
    print(f"    $ {' '.join(cmd)}   (cwd={cwd})", flush=True)
    proc = subprocess.run(cmd, cwd=str(cwd), env=env, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"step failed (exit {proc.returncode}) — see output above")


def _split_func_id(func_id: str) -> tuple[str | None, str]:
    if "::" in func_id:
        path, rest = func_id.split("::", 1)
        return path or None, rest.split(".")[-1]
    return None, func_id.split(".")[-1]


def _ranked_entry(item) -> dict:
    if isinstance(item, dict):
        func_id = (
            item.get("func_id")
            or item.get("qualified_name")
            or item.get("name")
            or ""
        )
        score = item.get("score")
        if score is None:
            score = item.get("llm_score")
        if score is None:
            score = item.get("bm25_score")
        file_path, function_name = _split_func_id(str(func_id))
        return {
            "func_id": str(func_id),
            "qualified_name": item.get("qualified_name"),
            "file_path": item.get("file_path") or item.get("file") or file_path,
            "function_name": item.get("function_name") or item.get("name") or function_name,
            "score": (None if score is None else float(score)),
        }
    func_id, score = item
    file_path, function_name = _split_func_id(str(func_id))
    return {
        "func_id": str(func_id),
        "qualified_name": None,
        "file_path": file_path,
        "function_name": function_name,
        "score": (None if score is None else float(score)),
    }


def pred_record(
    cve_id: str,
    method: str,
    variant: str,
    ranked: list,
    ground_truth: list[str],
    *,
    group_id: str | None = None,
    experiment_group: str = "main",
    axis: str | None = None,
    runtime_secs: float | None = None,
    tokens: int | None = None,
    cost: float | None = None,
) -> dict:
    """Build one normalized prediction record (the common contract)."""
    rec = {
        "cve_id": cve_id,
        "group_id": group_id or cve_id,
        "method": method,
        "variant": variant,
        "experiment_group": experiment_group,
        "axis": axis,
        "ranked_functions": [_ranked_entry(item) for item in ranked],
        "ground_truth": list(ground_truth),
    }
    if runtime_secs is not None:
        rec["runtime_secs"] = float(runtime_secs)
    if tokens is not None:
        rec["tokens"] = int(tokens)
    if cost is not None:
        rec["cost"] = float(cost)
    return rec
