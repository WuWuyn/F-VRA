# sample: affected_requests

A tiny HTTP client built on `requests`. Calls
`Session.request("GET", ...)` directly — exactly the attack surface of
**CVE-2024-35195** (improper certificate-verification reset on session
reuse).

## Expected PyShare verdict

```
CVE        : CVE-2024-35195
vf         : requests.sessions.Session.request
Verdict    : AFFECTED
Entries    : client.fetch, client.post_json
Chain      : fetch -> requests.sessions.Session.request
```

## Note about `requests.get(url)`

The function `fetch_default()` calls `requests.get(url)` instead of
`Session.request(...)` directly. Internally `get()` *does* call
`Session.request`, but PyShare's static AST scan matches the short
name `request` only on direct calls. `requests.get` won't trigger the
synthetic edge by itself. This documents a known limitation — see
[GRAPH_LAYER.md](../../docs/GRAPH_LAYER.md#known-limitations).
