"""Contract shapes must match PRD §10.1 and §14 exactly (frozen at Gate 1).

These tests pin the shared interface all four machines build against.
"""

from __future__ import annotations

import pathlib
import typing
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.contracts import common, firewall, firewall_read, sentinel
from app.contracts.arena import ArenaSession, LevelConfigUpdate
from app.contracts.firewall import (
    HUMAN_DENIED_MESSAGE,
    NEUTRAL_REFUSAL,
    PENDING_REVIEW_MESSAGE,
    AgentDefinition,
    Facts,
    FeedItem,
    LevelConfig,
    MockStateSeed,
    PlayerView,
    RegisterSession,
    ToolDef,
    ToolEffect,
)
from app.contracts.firewall_read import DivertItem


def _literal_values(alias: object) -> set[str]:
    return set(typing.get_args(alias))


def test_enums_match_prd_10_1() -> None:
    assert _literal_values(common.Mode) == {"off", "basic", "strict"}
    assert _literal_values(common.Stage) == {
        "input_check",
        "tool_call_check",
        "tool_executed",
        "output_check",
        "review_resolved",
        "finalize",
    }
    assert _literal_values(common.Decision) == {"allow", "deny", "review", "human_deny", "divert"}
    assert _literal_values(common.ExecutionStatus) == {
        "not_executed",
        "executed",
        "held",
        "diverted",
    }
    assert _literal_values(common.TicketStatus) == {
        "pending",
        "approved",
        "human_denied",
        "expired",
    }
    assert _literal_values(common.ScoreBand) == {"low", "medium", "high"}


def test_prd_copy_constants() -> None:
    assert PENDING_REVIEW_MESSAGE == (
        "Your request is pending human review. The result will appear here once a reviewer decides."
    )
    assert HUMAN_DENIED_MESSAGE == "A reviewer denied this request."
    assert NEUTRAL_REFUSAL == "I can't help with that."


def _view(**overrides: object) -> PlayerView:
    base: dict[str, object] = {
        "status": "replied",
        "reply": "hi",
        "tool_effects": [],
        "ticket_id": None,
        "defense_feed": [],
    }
    return PlayerView.model_validate({**base, **overrides})


@pytest.mark.parametrize("status", ["replied", "blocked", "awaiting_review", "human_denied"])
def test_player_view_accepts_prd_statuses(status: str) -> None:
    assert _view(status=status).status == status


@pytest.mark.parametrize("status", ["not_sent", "redacted", "diverted", "sent"])
def test_player_view_rejects_non_aff_statuses(status: str) -> None:
    # D-09: no redaction status; not_sent belongs to the arena, not the AFF.
    with pytest.raises(ValidationError):
        _view(status=status)


def test_feed_item_never_reports_divert() -> None:
    with pytest.raises(ValidationError):
        FeedItem(stage="tool_call_check", decision="divert", rule_ids=[], score_band="high")
    item = FeedItem(stage="input_check", decision="allow", rule_ids=[], score_band="low")
    assert item.shadow_decision is None


def test_feed_item_shadow_decision_for_off_mode() -> None:
    item = FeedItem(
        stage="tool_call_check",
        decision="allow",
        rule_ids=["R-003", "B-01"],
        score_band="high",
        shadow_decision="deny",
    )
    assert item.shadow_decision == "deny"


def test_tool_effect_hides_divert() -> None:
    with pytest.raises(ValidationError):
        ToolEffect(call_id="c1", tool="send_email", state="diverted", visible_content=None)


def test_facts_defaults() -> None:
    facts = Facts(
        decision="divert",
        rule_ids=[],
        secret_attempted=True,
        secret_delivered=False,
        diverted=True,
    )
    assert facts.secret_used is None


def test_level_config_defaults_and_mode() -> None:
    cfg = LevelConfig(
        level_id="lvl-1",
        level_version=1,
        mode="off",
        rule_version=0,
        weights={},
        thresholds={"review": 30, "deny": 60, "divert": 95, "alert": 99},
        divert_enabled=False,
    )
    assert cfg.review_timeout_s == 120
    with pytest.raises(ValidationError):
        LevelConfig.model_validate({**cfg.model_dump(), "mode": "allow"})


def test_register_session_carries_mock_state_seed() -> None:
    req = RegisterSession(
        owner_ref="00000000-0000-0000-0000-000000000001",
        agent=AgentDefinition(
            system_prompt="p",
            tools=[ToolDef(name="search_docs", json_schema={"type": "object"}, high_risk=False)],
            model_id="gemini-bot-test",
        ),
        level=LevelConfig(
            level_id="lvl-1",
            level_version=1,
            mode="off",
            rule_version=0,
            weights={},
            thresholds={},
            divert_enabled=False,
        ),
        secret="DEMO_TOKEN_42",
        mock_state_seed=MockStateSeed(),
    )
    assert req.eval is False
    assert req.mock_state_seed.documents == []


def test_contract_models_are_immutable() -> None:
    view = _view()
    with pytest.raises(ValidationError):
        view.status = "blocked"  # type: ignore[misc]


def test_divert_item_has_no_network_fields() -> None:
    forbidden = {"ip", "subnet", "asn", "asn_org", "country", "user_agent", "client_fingerprint"}
    assert forbidden.isdisjoint(DivertItem.model_fields)


def test_arena_session_has_c4_columns() -> None:
    expected = {
        "id",
        "user_id",
        "level_id",
        "level_version",
        "mode",
        "fw_session_id",
        "manifest_id",
        "secret_version",
        "status",
        "secret_obtained_at",
        "started_at",
        "closed_at",
        "admin_test",
        "recap_unlocked_at",
    }
    assert expected <= set(ArenaSession.model_fields)


def test_level_config_update_validates_threshold_order() -> None:
    with pytest.raises(ValidationError):
        LevelConfigUpdate(
            level_id="lvl-2",
            thresholds={"review": 70, "deny": 40, "divert": 95, "alert": 99},
        )
    ok = LevelConfigUpdate(
        level_id="lvl-2",
        thresholds={"review": 40, "deny": 70, "divert": 95, "alert": 99},
    )
    assert ok.thresholds is not None


def test_level_config_update_rejects_bad_timeout() -> None:
    with pytest.raises(ValidationError):
        LevelConfigUpdate(level_id="lvl-2", review_timeout_s=0)


def test_ports_protocols_exist() -> None:
    for name in ("read_catalog", "register_session", "send_message", "check_ticket"):
        assert hasattr(firewall.FirewallPort, name)
    assert hasattr(firewall.FirewallPort, "close_session")
    for name in ("get_session_summaries", "get_manifest_summary", "redact_for_session"):
        assert hasattr(firewall_read.FirewallReadPort, name)
    assert hasattr(sentinel.RiskyHistoryPort, "lookup")
    assert hasattr(sentinel.JudgePort, "assess")


def test_contracts_never_import_fastapi() -> None:
    root = pathlib.Path(firewall.__file__).parent
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "import fastapi" not in text and "from fastapi" not in text, path


def test_datetimes_are_timezone_aware() -> None:
    with pytest.raises(ValidationError):
        ArenaSession(
            id="00000000-0000-0000-0000-000000000001",
            user_id="00000000-0000-0000-0000-000000000002",
            level_id="lvl-1",
            level_version=1,
            mode="off",
            fw_session_id="fws-1",
            manifest_id="man-1",
            secret_version=1,
            status="active",
            secret_obtained_at=None,
            started_at=datetime(2026, 11, 8),  # naive
            closed_at=None,
            admin_test=False,
            recap_unlocked_at=None,
        )
    aware = datetime(2026, 11, 8, tzinfo=UTC)
    assert aware.tzinfo is not None
