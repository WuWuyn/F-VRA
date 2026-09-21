"""Thin wrapper around an OpenAI-compatible Chat Completions endpoint.

Works with OpenRouter, DeepSeek, Groq, OpenAI — anything that speaks the
OpenAI API. The endpoint and key come from config.py (environment variables).

Replaces the original repo's LLMRequest/ask_GPT.py, which used the retired
openai<1.0 SDK, hardcoded a (leaked) API key, and had a model-name typo.
"""

import time

from openai import OpenAI

from .. import config

_client = None


def get_client() -> OpenAI:
    """Lazily build a single OpenAI-compatible client from config."""
    global _client
    if _client is None:
        if not config.API_KEY:
            raise RuntimeError(
                f"{config.KEY_ENV} is not set. Run:  "
                f'setx {config.KEY_ENV} "your-key"  then open a new terminal.'
            )
        _client = OpenAI(
            api_key=config.API_KEY,
            base_url=config.BASE_URL,
            # Harmless for other providers; used by OpenRouter for attribution.
            default_headers={"X-Title": "VFFinder-extractor"},
        )
    return _client


def query_llm(prompt: str, *, model: str | None = None,
              temperature: float | None = None, max_retries: int = 4) -> str:
    """Send a single-turn prompt to the LLM and return the text response.

    Retries with exponential backoff (3s, 6s, 12s) — long enough to ride out
    the per-minute rate limits of free-tier models.
    """
    client = get_client()
    model = config.validate_llm_model(model)
    temperature = config.TEMPERATURE if temperature is None else temperature

    last_err = None
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": prompt},
                ],
            )
            if not resp.choices:
                raise RuntimeError(f"empty response from endpoint: {resp}")
            return resp.choices[0].message.content or ""
        except Exception as e:  # network / rate-limit / server errors
            last_err = e
            if attempt < max_retries - 1:
                time.sleep(3 * (2 ** attempt))
    raise RuntimeError(f"LLM query failed after {max_retries} attempts: {last_err}")
