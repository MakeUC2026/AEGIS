"""Seed fixtures (M1 A-13): every file parses, and the seed set covers what M2/M3 need."""

from __future__ import annotations

import json
import pathlib
import re
import typing

import pytest

from app.contracts.fixtures import AttackFamily, FixtureFile

ROOT = pathlib.Path(__file__).resolve().parents[3] / "fixtures"
TOOLS = {"search_docs", "read_file", "send_email", "query_db", "run_shell"}
ALLOWLIST_DOMAIN = "company.example"
SECRET_LIKE = re.compile(r"DEMO_[A-Z0-9]{16,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}")


def _load(kind: str) -> list[FixtureFile]:
    files = sorted((ROOT / ("attacks" if kind == "attack" else "benign")).glob("*.json"))
    assert files, f"no {kind} fixtures"
    return [FixtureFile.model_validate(json.loads(p.read_text())) for p in files]


def test_attack_fixtures_cover_every_family() -> None:
    families = {a.family for f in _load("attack") for a in f.attacks}
    assert families == set(typing.get_args(AttackFamily))


def test_attack_ids_are_unique_and_off_never_enforces() -> None:
    attacks = [a for f in _load("attack") for a in f.attacks]
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids))
    for attack in attacks:
        # D-02: Off computes in shadow and enforces Allow (schema-invalid calls aside).
        assert attack.expected.get("off", "allow") == "allow", attack.id


def test_benign_set_is_big_enough_and_covers_every_tool() -> None:
    benign = [b for f in _load("benign") for b in f.benign]
    messages = [m for b in benign for m in b.messages]
    calls = [c for b in benign for c in b.tool_calls]
    assert len(messages) >= 15
    assert len(calls) >= 10
    assert {c.tool for c in calls} == TOOLS
    ids = [b.id for b in benign]
    assert len(ids) == len(set(ids))


def test_benign_emails_stay_inside_the_allowlist() -> None:
    for f in _load("benign"):
        for b in f.benign:
            for call in b.tool_calls:
                if call.tool == "send_email":
                    assert call.arguments["to"].endswith("@" + ALLOWLIST_DOMAIN), b.id


@pytest.mark.parametrize("kind", ["attack", "benign"])
def test_fixtures_hold_no_secret_looking_values(kind: str) -> None:
    folder = ROOT / ("attacks" if kind == "attack" else "benign")
    for path in folder.glob("*.json"):
        assert not SECRET_LIKE.search(path.read_text()), path
