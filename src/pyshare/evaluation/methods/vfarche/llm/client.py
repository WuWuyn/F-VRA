from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from pyshare.evaluation.methods.vfarche.config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_PROVIDER
from .usage import record

_client: OpenAI | None = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        if not LLM_API_KEY:
            raise RuntimeError(
                f"API key for provider '{LLM_PROVIDER}' is not set. "
                f"Set the matching environment variable (e.g. OPENAI_API_KEY "
                f"or OPENROUTER_API_KEY) in .env."
            )
        _client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)
    return _client


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def chat(messages: list[dict], model: str | None = None, temperature: float = 0.0) -> str:
    resp = get_client().chat.completions.create(
        model=model or LLM_MODEL,
        messages=messages,
        temperature=temperature,
    )
    record(resp.usage)
    return resp.choices[0].message.content or ""


def describe() -> str:
    return f"provider={LLM_PROVIDER}  model={LLM_MODEL}  base_url={LLM_BASE_URL}"
