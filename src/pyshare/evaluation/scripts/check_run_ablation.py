"""Standalone checks for run_ablation.py orchestration.

A fake adapter exercises the full run_axis path without invoking any real method.

Run:
  python -m pyshare.evaluation.scripts.check_run_ablation
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from pyshare.evaluation import run_ablation as ra


class _FakeAdapter:
    """Stands in for a method adapter and records native env/config context."""

    def __init__(self, name: str, fail_on=()):
        self.name = name
        self.fail_on = set(fail_on)
        self.seen_env = []
        self.seen_ctx = []

    def run(self, ctx):
        variant = ctx.variant
        # capture the env the runner set, to assert plumbing + cleanup
        self.seen_env.append({k: os.environ.get(k) for k in ra.CONTROLLED})
        self.seen_ctx.append(ctx)
        if variant in self.fail_on:
            raise RuntimeError("boom")
        rec = {"cve_id": "C1", "method": self.name, "variant": variant,
               "group_id": "G1", "experiment_group": ctx.experiment_group, "axis": ctx.axis,
               "ranked_functions": [{"func_id": "foo", "score": 1.0}],
               "ground_truth": ["foo"]}
        (ctx.out_dir / f"{self.name}.jsonl").write_text(
            json.dumps(rec) + "\n", encoding="utf-8")
        return [ctx.out_dir / f"{self.name}.jsonl"]


def _inject(method, axis, variants, adapter):
    ra.REGISTRY[method] = adapter
    ra.AXES[(method, axis)] = variants


def _cleanup(method, axis):
    ra.REGISTRY.pop(method, None)
    ra.AXES.pop((method, axis), None)
    for k in ra.CONTROLLED:
        os.environ.pop(k, None)


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_apply_env_clears_then_sets():
    os.environ["VFARCHE_RERANK"] = "stale"
    ra._apply_env({"VFARCHE_EXPAND": "1"})
    assert "VFARCHE_RERANK" not in os.environ        # stale controlled var cleared
    assert os.environ["VFARCHE_EXPAND"] == "1"
    for k in ra.CONTROLLED:
        os.environ.pop(k, None)


def test_axes_integrity():
    for (m, ax), variants in ra.AXES.items():
        labels = [c["variant"] for c in variants]
        assert len(labels) == len(set(labels)), f"duplicate variant in {m}/{ax}"
        assert all("variant" in c and "env" in c for c in variants)


# ── run_axis (full glue, fake adapter) ───────────────────────────────────────

def test_run_axis_pins_relabels_and_tags():
    fake = _FakeAdapter("fake")
    _inject("fake", "ax", [{"variant": "a", "env": {}},
                           {"variant": "b", "env": {"VFARCHE_RERANK": "chat"}}], fake)
    try:
        with tempfile.TemporaryDirectory() as td:
            out = ra.run_axis("fake", "ax", Path("dummy"), "python", None, out_root=Path(td))
            files = sorted(p.name for p in out.glob("*.jsonl"))
            assert files == ["fake__a.jsonl", "fake__b.jsonl"]
            for label in ("a", "b"):
                rec = json.loads((out / f"fake__{label}.jsonl").read_text(encoding="utf-8"))
                assert rec["variant"] == label
                assert rec["experiment_group"] == "paper_ablation"
                assert rec["axis"] == "ax"
            assert fake.seen_ctx[0].variant == "a"
            assert fake.seen_ctx[1].variant == "b"
            # variant 'b' saw VFARCHE_RERANK=chat; 'a' did not (clean slate per variant)
            assert fake.seen_env[0].get("VFARCHE_RERANK") is None
            assert fake.seen_env[1].get("VFARCHE_RERANK") == "chat"
            assert not any(k in os.environ for k in ra.CONTROLLED)   # cleaned after sweep
    finally:
        _cleanup("fake", "ax")


def test_run_axis_isolates_failure():
    fake = _FakeAdapter("fake", fail_on=("a",))
    _inject("fake", "ax2", [{"variant": "a", "env": {}},
                            {"variant": "b", "env": {}}], fake)
    try:
        with tempfile.TemporaryDirectory() as td:
            out = ra.run_axis("fake", "ax2", Path("d"), "python", None, out_root=Path(td))
            files = sorted(p.name for p in out.glob("*.jsonl"))
            assert files == ["fake__b.jsonl"]           # 'a' failed, 'b' still produced
    finally:
        _cleanup("fake", "ax2")


def test_run_axis_env_cleaned_even_on_failure():
    fake = _FakeAdapter("fake", fail_on=("a", "b"))
    _inject("fake", "ax3", [{"variant": "a", "env": {"VFARCHE_EXPAND": "1"}},
                            {"variant": "b", "env": {}}], fake)
    try:
        with tempfile.TemporaryDirectory() as td:
            ra.run_axis("fake", "ax3", Path("d"), "python", None, out_root=Path(td))
            assert not any(k in os.environ for k in ra.CONTROLLED)   # finally cleaned
    finally:
        _cleanup("fake", "ax3")


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  PASS {fn.__name__.replace('test_', 'check_', 1)}")
    print(f"\n{len(fns)} checks passed.")


if __name__ == "__main__":
    _run_all()
