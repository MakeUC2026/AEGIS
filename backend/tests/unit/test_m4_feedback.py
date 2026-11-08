"""M4 C7: feedback writer. M4-X30 (grade and key only) plus its failure fallback."""

from __future__ import annotations

from app.llm.base import BudgetExhausted, LLMError
from app.llm.scripted import ScriptedLLM
from app.quiz import rubric
from app.quiz.feedback import MAX_FEEDBACK_CHARS, write_feedback
from app.quiz.models import AnswerKey
from tests.m4_quiz_support import SECRET, feedback, grade

FLASH = "flash-model"
KEY = AnswerKey(
    attack_happened=True,
    attack_family="exfiltration_via_email",
    why_it_worked_or_failed="The Gatekeeper denied the outbound email to an unknown recipient.",
    deciding_layer="rule",
    prevention="Keep email recipients on an allowlist.",
    was_diverted=False,
)


async def _write(llm: ScriptedLLM, scores: dict[str, int] | None = None, mcq: int = 3):  # type: ignore[no-untyped-def]
    async def redact(text: str) -> str:
        return text.replace(SECRET, "[SECRET]")

    return await write_feedback(
        llm,
        model=FLASH,
        mcq_points=mcq,
        item_scores=scores or grade(3, 1, 0, 2),
        key=KEY,
        redact=redact,
    )


async def test_prompt_holds_the_grade_and_the_key() -> None:  # X30
    llm = ScriptedLLM(json_answers=[feedback("Nice work on the attack.")])
    result = await _write(llm)
    assert result.text == "Nice work on the attack." and not result.fallback
    call = llm.json_calls[0]
    assert call.model == FLASH
    for needle in ("exfiltration via email", "allowlist", "Gatekeeper", "rule"):
        assert needle in call.prompt
    for item in rubric.RUBRIC:
        assert item.title in call.prompt
    assert "attack: 3 / 3" in call.prompt and "defense_layer: 0 / 3" in call.prompt
    assert "mcq: 3 / 5" in call.prompt


async def test_writer_has_no_input_for_student_text() -> None:  # X30
    import inspect

    from app.quiz import feedback as module

    params = set(inspect.signature(module.write_feedback).parameters)
    assert params == {"llm", "model", "mcq_points", "item_scores", "key", "redact"}


async def test_feedback_text_is_redacted() -> None:
    llm = ScriptedLLM(json_answers=[feedback(f"The token was {SECRET}.")])
    assert SECRET not in (await _write(llm)).text


async def test_one_bad_reply_is_retried() -> None:
    llm = ScriptedLLM(json_answers=[{"feedback": "  "}, feedback("Second try.")])
    assert (await _write(llm)).text == "Second try." and len(llm.json_calls) == 2


async def test_failures_fall_back_to_a_grade_based_message() -> None:
    llm = ScriptedLLM(json_answers=[LLMError("x"), LLMError("y")])
    result = await _write(llm)
    assert result.fallback and "Keep email recipients on an allowlist" in result.text
    assert "Attack" in result.text and "Defense layer" in result.text


async def test_budget_exhausted_also_falls_back_without_retry() -> None:
    llm = ScriptedLLM(json_answers=[BudgetExhausted("used up")])
    result = await _write(llm)
    assert result.fallback and len(llm.json_calls) == 1


async def test_overlong_feedback_is_trimmed() -> None:
    llm = ScriptedLLM(json_answers=[feedback("x" * 5000)])
    assert len((await _write(llm)).text) <= MAX_FEEDBACK_CHARS


async def test_no_attack_key_is_described_as_such() -> None:
    llm = ScriptedLLM(json_answers=[feedback("ok")])
    await write_feedback(
        llm,
        model=FLASH,
        mcq_points=5,
        item_scores=grade(),
        key=AnswerKey.no_attack("Only ordinary messages."),
        redact=None,
    )
    assert "no attack happened" in llm.json_calls[0].prompt.lower()
