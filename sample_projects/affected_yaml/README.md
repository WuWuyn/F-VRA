# sample: affected_yaml

A tiny app that loads a YAML config via the **unsafe** `yaml.load(f)`
call (no `Loader=` argument). Vulnerable to **CVE-2020-14343** (PyYAML
< 5.4).

## Expected PyShare verdict

```
CVE        : CVE-2020-14343
vf         : yaml.load
Verdict    : AFFECTED
Entry      : app.load_config
Chain      : load_config -> yaml.load
```

## How it triggers

`app.load_config()` calls `yaml.load(f)` directly. Any YAML payload
with a Python-object directive (e.g. `!!python/object/apply:...`) will
be deserialized when parsed, enabling arbitrary code execution.
