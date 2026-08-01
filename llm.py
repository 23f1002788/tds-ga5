import os
import json
import re
import asyncio
from openai import AsyncOpenAI

API_KEY = os.environ.get("AIPIPE_KEY", "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IjIzZjEwMDI3ODhAZHMuc3R1ZHkuaWl0bS5hYy5pbiIsImlhdCI6MTc4NTYwMTA5NywiaXNzIjoiaHR0cHM6Ly9haXBpcGUub3JnIiwiYXVkIjoiYWlwaXBlLWFwaSIsImV4cCI6MTc4NjIwNTg5N30.0yOTxXEfgNOD052tGxk6ZcTGNRJF6BI1hq3R-4zPouI")
BASE_URL = os.environ.get("AIPIPE_BASE", "https://aipipe.org/openai/v1")
MODEL = os.environ.get("AIPIPE_MODEL", "gpt-4o-mini")

_client = AsyncOpenAI(
    base_url=BASE_URL,
    api_key=API_KEY or "dummy_key",
)

async def call_llm_json(prompt: str, timeout: float = 15.0) -> dict:
    """
    Calls OpenRouter LLM and parses JSON output.
    Returns parsed dict or list.
    """
    if not API_KEY:
        return {}
    try:
        response = await asyncio.wait_for(
            _client.chat.completions.create(
                model=MODEL,
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
