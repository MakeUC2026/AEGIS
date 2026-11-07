"""Gemini REST client: structured JSON output and 768-d embeddings (PRD §3.2, D-15).

The API key travels in the `x-goog-api-key` header, never in the URL (so it never lands
in access logs). Every call is charged to the global daily budget first.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

import httpx

from app.llm.base import EMBEDDING_DIMENSIONS, LLMError, LLMTimeout

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_JSON_TIMEOUT_S = 30.0
DEFAULT_EMBED_TIMEOUT_S = 2.0


class Budget(Protocol):
    async def spend(self, provider: str) -> None: ...


class GeminiClient:
    def __init__(
        self,
        api_key: str,
        budget: Budget,
        embedding_model: str,
        transport: httpx.AsyncBaseTransport | None = None,
        base_url: str = GEMINI_BASE_URL,
    ) -> None:
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set")
        self._budget = budget
        self._embedding_model = embedding_model
        self._http = httpx.AsyncClient(
            base_url=base_url, headers={"x-goog-api-key": api_key}, transport=transport
        )

    async def _post(self, path: str, body: dict[str, Any], timeout_s: float) -> dict[str, Any]:
        await self._budget.spend("gemini")
        try:
            resp = await self._http.post(path, json=body, timeout=timeout_s)
        except httpx.TimeoutException as exc:
            raise LLMTimeout(f"gemini {path} timed out after {timeout_s}s") from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"gemini {path} transport error") from exc
        if resp.status_code != httpx.codes.OK:
            raise LLMError(f"gemini {path} returned HTTP {resp.status_code}")
        return resp.json()

    async def generate_json(
        self,
        model: str,
        prompt: str,
        schema: dict[str, Any],
        timeout_s: float = DEFAULT_JSON_TIMEOUT_S,
    ) -> dict[str, Any]:
        body = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseJsonSchema": schema,
            },
        }
        data = await self._post(f"/models/{model}:generateContent", body, timeout_s)
        try:
            raw = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(raw)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise LLMError("gemini returned no usable JSON") from exc
        if not isinstance(parsed, dict):
            raise LLMError("gemini JSON answer is not an object")
        return parsed

    async def embed(self, text: str, timeout_s: float = DEFAULT_EMBED_TIMEOUT_S) -> list[float]:
        body = {
            "content": {"parts": [{"text": text}]},
            "outputDimensionality": EMBEDDING_DIMENSIONS,
        }
        data = await self._post(f"/models/{self._embedding_model}:embedContent", body, timeout_s)
        values = data.get("embedding", {}).get("values")
        if not isinstance(values, list) or len(values) != EMBEDDING_DIMENSIONS:
            raise LLMError("gemini embedding has the wrong shape")
        return [float(v) for v in values]

    async def aclose(self) -> None:
        await self._http.aclose()
