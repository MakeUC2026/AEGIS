"""In-memory C3 fake. Tests (or the dev FakeFirewall observer) fill it in."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from app.contracts.firewall import NotFound, TurnResult
from app.contracts.firewall_read import (
    SECRET_PLACEHOLDER,
    DecisionCount,
    DecisionItem,
    DivertItem,
    FamilyCount,
    ForensicItem,
    InsightFilters,
    ManifestSummary,
    PatternCount,
    RuleCount,
    SessionSummary,
    TicketItem,
    TranscriptItem,
)

SCORE_BY_BAND = {"low": 10, "medium": 45, "high": 80}


class FakeFirewallRead:
    def __init__(self) -> None:
        self.transcripts: dict[str, list[TranscriptItem]] = defaultdict(list)
        self.decisions: dict[str, list[DecisionItem]] = defaultdict(list)
        self.tickets: dict[str, list[TicketItem]] = defaultdict(list)
        self.diverts: dict[str, list[DivertItem]] = defaultdict(list)
        self.forensics: dict[str, list[ForensicItem]] = defaultdict(list)
        self.manifests: dict[str, ManifestSummary] = {}
        self.rule_counts: list[RuleCount] = []
        self.pattern_counts: list[PatternCount] = []
        self.decision_counts: list[DecisionCount] = []
        self.family_counts: list[FamilyCount] = []
        self._secrets: dict[str, str] = {}

    def set_secret(self, fw_session_id: str, secret: str) -> None:
        self._secrets[fw_session_id] = secret

    def _redact(self, fw_session_id: str, text: str) -> str:
        secret = self._secrets.get(fw_session_id)
        return text.replace(secret, SECRET_PLACEHOLDER) if secret else text

    def record_turn(
        self, fw_session_id: str, message_id: str, text: str, result: TurnResult
    ) -> None:
        """Observer hook: derive transcript, decisions and diverts from a fake turn."""
        now = datetime.now(UTC)
        view, facts = result.player_view, result.facts
        self.transcripts[fw_session_id].append(
            TranscriptItem(
                message_id=message_id,
                time=now,
                speaker="student",
                text=self._redact(fw_session_id, text),
            )
        )
        if view.reply is not None:
            self.transcripts[fw_session_id].append(
                TranscriptItem(
                    message_id=message_id,
                    time=now,
                    speaker="bot",
                    text=self._redact(fw_session_id, view.reply),
                    status=view.status,
                    is_decoy=facts.diverted,
                )
            )
        for n, feed in enumerate(view.defense_feed):
            decision = "divert" if facts.diverted and feed.decision == "allow" else feed.decision
            self.decisions[fw_session_id].append(
                DecisionItem(
                    event_id=f"evt-fake-{fw_session_id}-{message_id}-{n}",
                    time=now,
                    message_id=message_id,
                    stage=feed.stage,
                    decision=decision,
                    shadow_decision=feed.shadow_decision,
                    execution_status="diverted" if decision == "divert" else "not_executed",
                    sentinel_score=SCORE_BY_BAND[feed.score_band],
                    score_breakdown={},
                    thresholds_used={},
                    rule_ids=list(feed.rule_ids),
                    risky_pattern_ids=[],
                )
            )
        if facts.diverted:
            shown = next(
                (e.visible_content for e in view.tool_effects if e.visible_content),
                view.reply or "",
            )
            self.diverts[fw_session_id].append(
                DivertItem(
                    event_id=f"evt-fake-{fw_session_id}-{message_id}-divert",
                    time=now,
                    stage="tool_call_check",
                    tool=view.tool_effects[0].tool if view.tool_effects else None,
                    attempted_summary=self._redact(fw_session_id, text),
                    decoy_shown=self._redact(fw_session_id, shown),
                )
            )

    async def get_transcript(self, fw_session_id: str) -> list[TranscriptItem]:
        return list(self.transcripts.get(fw_session_id, []))

    async def get_decisions(self, fw_session_id: str) -> list[DecisionItem]:
        return list(self.decisions.get(fw_session_id, []))

    async def get_tickets(self, fw_session_id: str) -> list[TicketItem]:
        return list(self.tickets.get(fw_session_id, []))

    async def get_diverts(self, fw_session_id: str) -> list[DivertItem]:
        return list(self.diverts.get(fw_session_id, []))

    async def get_forensics(self, fw_session_id: str) -> list[ForensicItem]:
        return list(self.forensics.get(fw_session_id, []))

    async def get_rule_fire_counts(self, filters: InsightFilters) -> list[RuleCount]:
        return list(self.rule_counts)

    async def get_risky_pattern_counts(self, filters: InsightFilters) -> list[PatternCount]:
        return list(self.pattern_counts)

    async def get_decision_counts(self, filters: InsightFilters) -> list[DecisionCount]:
        return list(self.decision_counts)

    async def get_attack_family_counts(self, filters: InsightFilters) -> list[FamilyCount]:
        return list(self.family_counts)

    async def get_session_summaries(self, fw_session_ids: list[str]) -> list[SessionSummary]:
        return [
            SessionSummary(
                fw_session_id=sid,
                diverted_count=len(self.diverts.get(sid, [])),
                max_sentinel_score=max(
                    (d.sentinel_score for d in self.decisions.get(sid, [])), default=None
                ),
                secret_delivered_at=None,
                echo_excluded=False,
            )
            for sid in fw_session_ids
        ]

    async def get_manifest_summary(self, fw_session_id: str) -> ManifestSummary:
        if fw_session_id not in self.manifests:
            raise NotFound(fw_session_id)
        return self.manifests[fw_session_id]

    async def redact_for_session(self, fw_session_id: str, text: str) -> str:
        return self._redact(fw_session_id, text)
