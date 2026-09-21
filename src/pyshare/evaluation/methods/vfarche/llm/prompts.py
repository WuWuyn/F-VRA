RELEVANCE_SYSTEM = """You are a security expert. Given a CVE description and a Python function,
decide on a scale 0-10 how likely this function is the one that contains the vulnerability.
Respond with ONLY a single integer 0-10. No explanation."""


def relevance_user_prompt(cve_description: str, func: dict) -> str:
    body = func["body"]
    if len(body) > 4000:
        body = body[:4000] + "\n# ... [truncated]"
    return f"""CVE description:
{cve_description}

Function: {func['qualname']}  (file: {func['file']}, line {func['start_line']})
```python
{body}
```

Likelihood (0-10):"""


BATCH_SYSTEM = """You are a security expert ranking Python functions for vulnerability relevance.
For each function, output ONE line: <function_index>,<score_0_to_10>
Do not output anything else. Function index is the number shown in the prompt."""


def batch_user_prompt(cve_description: str, funcs: list[dict]) -> str:
    blocks = []
    for i, f in enumerate(funcs):
        body = f["body"]
        if len(body) > 1500:
            body = body[:1500] + "\n# ... [truncated]"
        blocks.append(
            f"--- Function {i}: {f['qualname']} ({f['file']}:{f['start_line']}) ---\n"
            f"```python\n{body}\n```"
        )
    return (
        f"CVE description:\n{cve_description}\n\n"
        + "\n\n".join(blocks)
        + "\n\nOutput one line per function: index,score"
    )


PAIRWISE_SYSTEM = """You are a security expert comparing two Python functions for CVE vulnerable-function localization.
Choose which function is more likely to contain the vulnerable logic.
Use these comparison rules:
- Prefer functions that directly implement the vulnerable behavior described by the CVE.
- Prefer security boundary, parsing, authorization, path, serialization, network, or validation logic when it matches the CVE.
- Treat helpers as relevant only when they are closer to the described vulnerable behavior than the alternative.
Respond with exactly one token: A, B, or TIE."""


def pairwise_user_prompt(cve_description: str, func_a: dict, func_b: dict) -> str:
    def block(label: str, f: dict) -> str:
        body = f["body"]
        if len(body) > 1800:
            body = body[:1800] + "\n# ... [truncated]"
        return (
            f"Function {label}: {f['qualname']} ({f['file']}:{f['start_line']})\n"
            f"```python\n{body}\n```"
        )

    return (
        f"CVE description:\n{cve_description}\n\n"
        "Examples:\n"
        "- If the CVE describes path traversal and A normalizes/validates paths while B formats logging output, answer A.\n"
        "- If the CVE describes authorization bypass and B checks permissions while A only renders a template, answer B.\n"
        "- If both functions are unrelated utility code, answer TIE.\n\n"
        f"{block('A', func_a)}\n\n"
        f"{block('B', func_b)}\n\n"
        "Which function is more likely to be the vulnerable function? Answer A, B, or TIE."
    )
