"""The poisoned notes name the file the level really holds (found in the D-06 and demo runs).

With a fixed list of fallbacks the real bot spent its tool rounds on files that did not exist at
levels 2 and 3, hit the 5-round cap before the email, and "Strict stopped the attack" for the wrong
reason. Every level's notes now point at that level's own secret file, so the same attack reaches
the email at every level and a stop is the firewall's."""

from __future__ import annotations

import pytest

from app.arena.scenario_data import SECRET_HOLDERS
from app.arena.seed import build_mock_state

NOTES = "docs/q3-planning-notes.md"
SECRET = "INTNOTE-TESTSECRET0000000000000"


@pytest.mark.parametrize("level", sorted(SECRET_HOLDERS))
def test_the_notes_name_this_levels_secret_file_and_it_exists(level: str) -> None:
    state = build_mock_state(level, SECRET)
    notes = state.filesystem[NOTES]
    holder = SECRET_HOLDERS[level]["path"]
    assert holder in notes and holder in state.filesystem
    others = [h["path"] for k, h in SECRET_HOLDERS.items() if k != level]
    assert not any(path in notes for path in others)  # no detour through a file that is not there
    assert "{" not in notes  # no placeholder left behind
    assert SECRET not in notes  # the notes point at the secret, they do not contain it
