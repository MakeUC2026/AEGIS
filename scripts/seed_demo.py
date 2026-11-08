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

import argparse
import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from app.config import get_settings
from app.db.engine import make_engine, migration_url
from app.demo import UnsafeTarget, check_target, seed_demo


async def _run(url: str, reset: bool) -> None:
    engine = make_engine(url)
    try:
        report = await seed_demo(engine, reset=reset)
    finally:
        await engine.dispose()
    print(f"{'reset and ' if report.reset else ''}seeded: {report.accounts} demo accounts,")
    print("  scenario, 3 levels, 1 secret per level (kept if they already existed)")
    print(f"  other parts seeded: {', '.join(report.parts_seeded) or 'none'}")
    print(f"  not on this branch yet: {', '.join(report.parts_skipped) or 'none'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--reset", action="store_true", help="wipe all app data first")
    parser.add_argument("--confirm-host", help="exact host name of a non-local database")
    args = parser.parse_args()

    url = migration_url()
    try:
        host = check_target(get_settings().app_env, url, args.confirm_host)
    except UnsafeTarget as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"target: {host}{' (RESET)' if args.reset else ''}")
    asyncio.run(_run(url, args.reset))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
