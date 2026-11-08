"""Quiz context builder (PRD §13.2, §15.3, E-58).

Gathers the session through C3 (`FirewallReadPort`) and C4 (`ArenaServicePort`), runs every
text through `redact_for_session` (M4 never holds the secret value), derives the private answer
key, and renders the lot for a prompt with all student-derived text wrapped as untrusted data.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.contracts.arena import ArenaServicePort, ArenaSession
from app.contracts.firewall import NotFound
from app.contracts.firewall_read import (
    DecisionItem,
    DivertItem,
    FirewallReadPort,
    ForensicItem,
    ManifestSummary,
    TranscriptItem,
)
from app.quiz.answer_key import derive_answer_key
from app.quiz.models import AnswerKey
from app.quiz.wrap import UntrustedWrapper


@dataclass(frozen=True)
class QuizContext:
    session_id: str
    level_name: str
    mode: str
    secret_obtained: bool
    manifest: ManifestSummary | None
    transcript: tuple[TranscriptItem, ...]
    decisions: tuple[DecisionItem, ...]
    diverts: tuple[DivertItem, ...]
    forensics: tuple[ForensicItem, ...]
    answer_key: AnswerKey

    def render(self, wrapper: UntrustedWrapper) -> str:
        """Prompt material. Facts are ours; transcript, divert and forensic text is wrapped."""
        facts = [
            f"level: {self.level_name}",
            f"mode: {self.mode}",
            f"secret obtained: {'yes' if self.secret_obtained else 'no'}",
            f"messages: {sum(t.speaker == 'student' for t in self.transcript)}",
            f"diverted turns: {len(self.diverts)}",
        ]
        if self.manifest:
            facts.append(f"rule set version: {self.manifest.rule_version}")
            facts.append(f"thresholds: {self.manifest.thresholds}")
        sections = ["SESSION FACTS\n" + "\n".join(facts)]
        sections.append(
            "DECISIONS (stage, decision, score, rules fired, risky patterns)\n"
            + "\n".join(
                f"{d.stage} {d.decision} score={d.sentinel_score} rules={d.rule_ids} "
                f"patterns={d.risky_pattern_ids}"
                for d in self.decisions
            )
        )
        lines = "\n".join(f"[{t.speaker}] {t.text}" for t in self.transcript)
        sections.append("TRANSCRIPT\n" + wrapper.wrap("transcript", lines))
        if self.diverts:
            text = "\n".join(
                f"student attempted: {d.attempted_summary} | student believed they got: "
                f"{d.decoy_shown}"
                for d in self.diverts
            )
            sections.append("DIVERTS\n" + wrapper.wrap("diverts", text))
        if self.forensics:
            text = "\n".join(
                f"{f.attack_family}: {f.summary} | missed: {', '.join(f.missed_signals)}"
                for f in self.forensics
            )
            sections.append("FORENSICS\n" + wrapper.wrap("forensics", text))
        return "\n\n".join(sections)


async def _manifest(read: FirewallReadPort, fw_session_id: str) -> ManifestSummary | None:
    try:
        return await read.get_manifest_summary(fw_session_id)
    except NotFound:  # a missing manifest only drops the config facts
        return None


async def build_context(
    session: ArenaSession, *, arena: ArenaServicePort, read: FirewallReadPort
) -> QuizContext:
    fw = session.fw_session_id
    transcript, decisions, tickets, diverts, forensics, manifest, levels = await asyncio.gather(
        read.get_transcript(fw),
        read.get_decisions(fw),
        read.get_tickets(fw),
        read.get_diverts(fw),
        read.get_forensics(fw),
        _manifest(read, fw),
        arena.list_levels(),
    )

    async def clean(text: str) -> str:
        return await read.redact_for_session(fw, text)

    red_transcript = await asyncio.gather(*(clean(t.text) for t in transcript))
    red_attempted = await asyncio.gather(*(clean(d.attempted_summary) for d in diverts))
    red_shown = await asyncio.gather(*(clean(d.decoy_shown) for d in diverts))
    red_summary = await asyncio.gather(*(clean(f.summary) for f in forensics))
    red_signals = [await asyncio.gather(*(clean(s) for s in f.missed_signals)) for f in forensics]

    key = derive_answer_key(
        session, decisions=decisions, diverts=diverts, forensics=forensics, tickets=tickets
    )
    level = next((lv for lv in levels if lv.level_id == session.level_id), None)
    return QuizContext(
        session_id=session.id,
        level_name=level.name if level else session.level_id,
        mode=session.mode,
        secret_obtained=session.secret_obtained_at is not None,
        manifest=manifest,
        transcript=tuple(
            t.model_copy(update={"text": text})
            for t, text in zip(transcript, red_transcript, strict=True)
        ),
        decisions=tuple(decisions),
        diverts=tuple(
            d.model_copy(update={"attempted_summary": a, "decoy_shown": s})
            for d, a, s in zip(diverts, red_attempted, red_shown, strict=True)
        ),
        forensics=tuple(
            f.model_copy(update={"summary": text, "missed_signals": sig})
            for f, text, sig in zip(forensics, red_summary, red_signals, strict=True)
        ),
        answer_key=key,
    )
