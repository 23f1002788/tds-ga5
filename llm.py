import os
import json
import re
import asyncio
from openai import AsyncOpenAI

OPENROUTER_API_KEY = os.environ.get(
    "OPENROUTER_API_KEY"
)
OPENROUTER_MODEL = os.environ.get(
    "OPENROUTER_MODEL",
    "google/gemini-2.0-flash-lite-preview-02-05:free"
)

_client = AsyncOpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY or "dummy_key",
)

async def call_llm_json(prompt: str, timeout: float = 15.0) -> dict:
    """
    Calls OpenRouter LLM and parses JSON output.
    Returns parsed dict or list.
    """
    if not OPENROUTER_API_KEY:
        return {}
    try:
        response = await asyncio.wait_for(
            _client.chat.completions.create(
                model=OPENROUTER_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=2048,
            ),
            timeout=timeout,
        )
        text = (response.choices[0].message.content or "").strip()
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            text = match.group(0)
        return json.loads(text)
    except Exception as e:
        print(f"⚠️ OpenRouter LLM call failed or timed out: {e}", flush=True)
        return {}
