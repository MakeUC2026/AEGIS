"""Gemini structured-output shapes for the forensic worker (PRD §10.2, §10.3, M3 A-05, A-06).

The Pydantic models validate the answer; `*_SCHEMA` is what we send as `responseJsonSchema`.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.contracts.common import Mode
from app.contracts.firewall_admin import RuleForm
from app.contracts.fixtures import AttackFamily
from app.firewall.risky_patterns import PatternSpec


class _Answer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


MAX_SIGNALS = 20  # bounds what the model can make us store (security review)
Signal = Annotated[str, Field(max_length=300)]

_ATLAS_ID = re.compile(r"AML\.T\d{4}(\.\d{3})?")


def _atlas_ids(ids: list[str]) -> list[str]:
    # Checked here, not in the JSON schema, so the schema Gemini sees stays simple.
    bad = [i for i in ids if not _ATLAS_ID.fullmatch(i)]
    if bad:
        raise ValueError(f"not ATLAS technique IDs: {bad}")
    return ids


class ForensicAnalysis(_Answer):
    attack_family: AttackFamily
    atlas_techniques: Annotated[list[str], AfterValidator(_atlas_ids)] = Field(default_factory=list)
    summary: str = Field(min_length=1, max_length=600)  # two plain sentences
    missed_signals: list[Signal] = Field(default_factory=list, max_length=MAX_SIGNALS)
    would_have_blocked_in: list[Mode] = Field(default_factory=list)


class RuleDraft(_Answer):
    kind: Literal["rule"]
    rule: RuleForm


class PatternDraft(_Answer):
    kind: Literal["pattern"]
    pattern: PatternSpec


class DraftAnswer(_Answer):
    """At most one improvement per event; `draft` is null when nothing sensible fits."""

    draft: RuleDraft | PatternDraft | None = Field(default=None, discriminator="kind")


class ForensicAnswer(_Answer):
    """One structured call per event (C-02, C-03): the analysis plus at most one draft."""

    analysis: ForensicAnalysis
    draft: RuleDraft | PatternDraft | None = Field(default=None, discriminator="kind")


FORENSIC_SCHEMA: dict[str, Any] = ForensicAnalysis.model_json_schema()
DRAFT_SCHEMA: dict[str, Any] = DraftAnswer.model_json_schema()
