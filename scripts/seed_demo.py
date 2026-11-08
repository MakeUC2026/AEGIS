"""Demo seed (M1 D-02): demo accounts, scenario, levels, secrets and every part's seed present
on this branch (M2 rules, M3/M4 content). Safe to re-run; secrets stay the same.

Usage (from backend/, after `alembic upgrade heads`):
    uv run python ../scripts/seed_demo.py                 # seed only (idempotent)
    uv run python ../scripts/seed_demo.py --reset         # wipe all app data, then seed
    uv run python ../scripts/seed_demo.py --confirm-host <host>   # needed for a remote DB

Target: $DATABASE_URL, else the repo .env. Refuses APP_ENV=production. A non-local database
(Tiger Cloud is shared by all four machines) needs --confirm-host with its exact host name.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from app.demo import main

if __name__ == "__main__":
    raise SystemExit(main())
