"""Per-CVE provider-reported usage; missing usage is unknown, never zero."""
_calls = 0
_tokens = 0
_missing = 0


def reset() -> None:
    global _calls, _tokens, _missing
    _calls = _tokens = _missing = 0


def record(usage) -> None:
    global _calls, _tokens, _missing
    _calls += 1
    if usage is not None and not isinstance(usage, dict):
        usage = usage.model_dump()
    usage = usage or {}
    total = usage.get('total_tokens')
    if total is None and usage.get('prompt_tokens') is not None:
        total = usage['prompt_tokens'] + usage.get('completion_tokens', 0)
    if total is None:
        _missing += 1
    else:
        _tokens += int(total)


def snapshot() -> dict:
    return {'tokens': None if _missing else _tokens,
            'reported_tokens': _tokens, 'api_calls': _calls,
            'usage_missing_calls': _missing}
