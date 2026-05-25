"""Sample project — uses yaml.safe_load only.

This is the correct pattern: ``yaml.safe_load`` rejects Python-object
directives, so it isn't affected by CVE-2020-14343 even on PyYAML < 5.4.

Expected PyShare verdict for CVE-2020-14343 (vf = ``yaml.load``):
    NOT_AFFECTED (no direct call to yaml.load anywhere in source)
"""
import argparse
import yaml


def read_config(path):
    """Safe YAML parse — does NOT allow arbitrary Python objects."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def read_all_documents(path):
    """Multi-document YAML, still safe."""
    with open(path, encoding="utf-8") as f:
        return list(yaml.safe_load_all(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config")
    args = ap.parse_args()
    cfg = read_config(args.config)
    print(cfg)


if __name__ == "__main__":
    main()
