# sample: safe_yaml

A tiny app that loads YAML config but **only** via `yaml.safe_load` /
`yaml.safe_load_all`. Even with PyYAML 5.3.1 installed (the vulnerable
version range), this app is **NOT** vulnerable to CVE-2020-14343 — the
unsafe ``yaml.load`` is never invoked from project code.

## Expected PyShare verdict

```
CVE        : CVE-2020-14343
vf         : yaml.load
Verdict    : NOT_AFFECTED
```

## Why PyShare gets this right

The AST direct-caller scanner only matches the *short name* `load` on
attribute / bare calls. ``yaml.safe_load`` is a different attribute
(``safe_load``), so no synthetic edge is injected to vf, and the call
graph has no path from any project entry to ``yaml.load``.
