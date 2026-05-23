"""Sample project — uses unsafe yaml.load().

This represents a real-world bug pattern: parsing an untrusted YAML
config with ``yaml.load`` (no Loader=) instead of ``yaml.safe_load``.
PyYAML < 5.4 will deserialize arbitrary Python objects, enabling RCE.

Expected PyShare verdict for CVE-2020-14343 (vf = ``yaml.load``):
    AFFECTED via app.load_config
"""
import argparse
import yaml


def load_config(path):
    """Parse a YAML config file. VULNERABLE: uses yaml.load directly."""
    with open(path, encoding="utf-8") as f:
        return yaml.load(f)   # <-- vulnerable sink (no Loader specified)


def merge_defaults(cfg, defaults):
    out = dict(defaults)
    out.update(cfg or {})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config")
    args = ap.parse_args()
    cfg = load_config(args.config)
    cfg = merge_defaults(cfg, {"debug": False, "retries": 3})
    print(cfg)


if __name__ == "__main__":
    main()
