"""Strict Sentinel layer 3: the Gemini judge (PRD §7.3, D-15, M3 A-04, B-05).

The judge only recommends. M2 takes `max(layer_1_2_score, judge.risk)`, so the judge can raise a
score, never lower it (I-1). Any failure raises; a verdict is never made up (I-2).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import pathlib
import re
import unicodedata
from typing import Any

from pydantic import ValidationError

from app.contracts.sentinel import CheckedItem, JudgeError, JudgeTimeout, JudgeVerdict
from app.llm.base import JsonModel, LLMError, LLMTimeout

JUDGE_TIMEOUT_S = 8.0
POLICY_PATH = pathlib.Path(__file__).resolve().parents[3] / "policy" / "judge-policy.md"
DATA_OPEN = "<<<UNTRUSTED_DATA>>>"
DATA_CLOSE = "<<<END_UNTRUSTED_DATA>>>"

JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "risk": {"type": "integer", "minimum": 0, "maximum": 100},
        "suggested_action": {"type": "string", "enum": ["allow", "review", "deny", "divert"]},
        "reason": {"type": "string"},
    },
    "required": ["risk", "suggested_action", "reason"],
    "additionalProperties": False,
}

# Bands from the policy's risk table; an answer outside its band is rejected (handoff note: a
# live model returned risk 9 with deny).
_ACTION_BANDS = {"allow": (0, 29), "review": (30, 59), "deny": (60, 94), "divert": (95, 100)}


# Any case, spacing or full-width variant of either delimiter (M2 hands us case-folded text).
_DELIMITER = re.compile(r"<{3}\s*(?:end_)?untrusted_data\s*>{3}", re.IGNORECASE)


def _untrusted(text: str) -> str:
    """Strip delimiters until none remain, so nested copies cannot reassemble one."""
    text = unicodedata.normalize("NFKC", text)
    while True:
        stripped = _DELIMITER.sub("", text)
        if stripped == text:
            return text
        text = stripped


def build_prompt(item: CheckedItem, policy: str) -> str:
    call = f"tool: {item.tool}\narguments: {item.canonical_args}\n" if item.tool else ""
    data = (
        f"stage: {item.stage}\n{call}"
        f"item under check:\n{_untrusted(item.text)}\n\n"
        f"recent context:\n{_untrusted(item.context_excerpt)}"
    )
    return f"{policy}\n\n{DATA_OPEN}\n{_untrusted(data)}\n{DATA_CLOSE}\n\nAnswer with the JSON now."


def parse_verdict(raw: dict[str, Any]) -> JudgeVerdict:
    try:
        verdict = JudgeVerdict.model_validate(raw, strict=True)  # no "0" -> 0 coercion
    except ValidationError as exc:
        raise JudgeError(f"judge answer fails the schema: {exc.error_count()} error(s)") from exc
    low, high = _ACTION_BANDS[verdict.suggested_action]
    if not low <= verdict.risk <= high:
        raise JudgeError(f"risk {verdict.risk} disagrees with action {verdict.suggested_action}")
    return verdict


class Judge:
    def __init__(self, llm: JsonModel, model: str, policy_path: pathlib.Path = POLICY_PATH) -> None:
        self._llm = llm
        self._model = model
        self._policy = policy_path.read_text()
        self._hash = "sha256:" + hashlib.sha256(self._policy.encode()).hexdigest()

    async def assess(self, item: CheckedItem) -> JudgeVerdict:
        prompt = build_prompt(item, self._policy)
        try:
            async with asyncio.timeout(JUDGE_TIMEOUT_S):
                raw = await self._llm.generate_json(
                    self._model, prompt, JUDGE_SCHEMA, timeout_s=JUDGE_TIMEOUT_S
                )
        except (TimeoutError, LLMTimeout) as exc:
            raise JudgeTimeout(f"judge took longer than {JUDGE_TIMEOUT_S:.0f} s") from exc
        except LLMError as exc:  # includes BudgetExhausted
            raise JudgeError(f"judge call failed: {exc}") from exc
        except Exception as exc:  # anything else the client lets through still fails closed (I-2)
            raise JudgeError(f"judge call failed: {type(exc).__name__}") from exc
        return parse_verdict(raw)

    def policy_hash(self) -> str:
        return self._hash

    def model_id(self) -> str:
        return self._model


def policy_path() -> pathlib.Path:
    """`AEGIS_POLICY_PATH` overrides the repo path (the backend image may lay files out else)."""
    override = os.environ.get("AEGIS_POLICY_PATH")
    return pathlib.Path(override) if override else POLICY_PATH


def create() -> Judge:
    """`ports.py` factory (`app.firewall.judge:create`): Flash model pinned by M1 (A-16)."""
    from app.config import get_settings
    from app.db.engine import get_engine
    from app.llm.budget import DailyBudget
    from app.llm.gemini import GeminiClient

    settings = get_settings()
    if not settings.gemini_flash_model_id:
        raise RuntimeError("AEGIS_GEMINI_FLASH_MODEL_ID is not set")
    engine = get_engine()
    client = GeminiClient(
        settings.gemini_api_key.get_secret_value(),
        DailyBudget(engine, settings.daily_llm_budget),
        settings.gemini_embedding_model_id,
    )
    return Judge(client, settings.gemini_flash_model_id, policy_path())
