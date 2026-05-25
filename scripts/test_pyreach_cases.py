"""Smoke-test our pipeline against PyReach's CVE dataset.

For each case:
  1. Setup .venv at the client project (if missing)
  2. Install vulnerable TPL version
  3. Run our reachability_query.query() with the known vf
  4. Capture verdict + chain
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

# Force pyshare config to use a separate Neo4j DB per case? Not needed —
# we differentiate by project_id (folder name).
from pyshare.pipeline import reachability_query
from pyshare.pipeline.project_scanner import run_jarvis

PYREACH_ROOT = Path(r"E:\2026 WorkSpace\pyreach\paper\py_cve")

# Cases: (cve_id, client_subdir, tpl_pip_spec, vf_qname, expected_paper_verdict)
# expected_paper_verdict is informational (what PyReach paper considers
# correct), used only for reporting.
CASES = [
    ("CVE-2020-14343", "factions-moxy-main",
     "pyyaml==5.3.1", "yaml.load",
     "NOT_AFFECTED",      # uses safe_load only
     "client"),
    ("CVE-2020-14343", "Hyper2374Bot-main",
     "pyyaml==5.3.1", "yaml.load",
     "?",
     "client"),
    ("CVE-2020-28493", "f5go-master",
     "Jinja2==2.11.2", "jinja2.utils.urlize",  # actual public name in 2.11
     "?",
     "client"),
    ("CVE-2019-7548", "flask_small_orm_app-master",
     "sqlalchemy==1.2.17", "sqlalchemy.orm.query.Query.order_by",
     "?",
     "client"),
    ("CVE-2018-15560", "final-project-group-4-master",
     "pycryptodome==3.6.5", "Crypto.Cipher._mode_ecb.EcbMode.encrypt",
     "?",
     "clients"),
    # Additional cases — more breadth
    ("CVE-2020-14343", "online-yaml-parser-master",
     "pyyaml==5.3.1", "yaml.load",
     "?",
     "client"),
    ("CVE-2020-14343", "op5-cli-master",
     "pyyaml==5.3.1", "yaml.load",
     "?",
     "client"),
    ("CVE-2019-7548", "emoji_bot-main",
     "sqlalchemy==1.2.17", "sqlalchemy.orm.query.Query.order_by",
     "?",
     "client"),
    ("CVE-2019-7548", "rpgpt-master",
     "sqlalchemy==1.2.17", "sqlalchemy.orm.query.Query.order_by",
     "?",
     "client"),
    ("CVE-2019-7548", "HTML-GUI-Development-main",
     "sqlalchemy==1.2.17", "sqlalchemy.orm.query.Query.order_by",
     "?",
     "client"),
]


def setup_venv(project: Path, tpl_spec: str) -> bool:
    venv = project / ".venv"
    venv_py = venv / "Scripts" / "python.exe"
    if venv_py.exists():
        # Check if TPL installed
        pkg = tpl_spec.split("==")[0].lower().replace("-", "_")
        r = subprocess.run(
            [str(venv_py), "-c", f"import {pkg}; print('OK')"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return True
    # Create venv + install
    print(f"  [setup] creating venv + installing {tpl_spec}...")
    if not venv.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)],
                       check=True, timeout=60)
    r = subprocess.run(
        [str(venv_py), "-m", "pip", "install", "--quiet", tpl_spec],
        capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        print(f"  [setup] pip install failed: {r.stderr[:300]}")
        return False
    return True


def run_case(cve, subdir, tpl, vf, expected, clients_key):
    project = PYREACH_ROOT / cve / clients_key / subdir
    if not project.is_dir():
        return {"status": "no_project", "project": str(project)}
    print(f"\n[CASE] {cve} / {subdir}")
    print(f"       vf = {vf}")

    if not setup_venv(project, tpl):
        return {"status": "venv_failed"}

    # Force a fresh JARVIS run for cleanliness on first scan; clear cache
    cache = project / ".pyshare" / "jarvis.json"
    if cache.exists():
        cache.unlink()

    t0 = time.perf_counter()
    result = reachability_query.query(
        cve_id=cve, project=project, vf=vf, explain=True,
    )
    elapsed = (time.perf_counter() - t0) * 1000

    return {
        "status": "ok",
        "cve": cve,
        "client": subdir,
        "vf": vf,
        "expected_paper": expected,
        "verdict": result.verdict.value,
        "entry_points": result.entry_points,
        "chain": result.call_chain,
        "elapsed_ms": elapsed,
    }


def main():
    results = []
    for case in CASES:
        try:
            r = run_case(*case)
        except Exception as e:
            r = {"status": "error", "case": case[:2], "error": str(e)}
        results.append(r)
        print(json.dumps({k: v for k, v in r.items() if k != "chain"},
                         indent=2, default=str))

    out = Path("scripts/pyreach_test_results.json")
    out.write_text(json.dumps(results, indent=2, default=str),
                   encoding="utf-8")
    print(f"\nFull results written to {out}")


if __name__ == "__main__":
    main()
