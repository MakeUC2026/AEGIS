"""Demo seed and reset (M1 D-02): demo accounts, scenario, levels, secrets, and every other
part's seed that exists on this branch (M2 rules, M3/M4 content). Idempotent unless reset.

Run: `python -m app.demo [--reset] [--confirm-host HOST]` (the container does this on start when
AEGIS_SEED_ON_START=1, M1 D-03), or `scripts/seed_demo.py` from a checkout.

Reset truncates every app table (all of `public` except `alembic_version`), then reseeds, so
secrets are new afterwards. `check_target` refuses production and any non-local database
unless its host is confirmed by name: Tiger Cloud is shared by all four machines.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import sys
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.seed import seed as seed_arena
from app.auth.claims import primary_role
from app.contracts.common import Role

LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "db"})  # "db": the Compose service

# Other parts' seeders, "module:function", each `async def seed(engine) -> None`, idempotent.
# A module that is not on this branch yet is skipped and reported.
PART_SEEDERS: tuple[str, ...] = (
    "app.firewall.seed:seed",  # M2: starting rules (PRD §7.2)
    "app.admin.seed:seed",  # M3
    "app.classroom.seed:seed",  # M4
    "app.quiz.seed:seed",  # M4
)

_RESET = """
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables
           WHERE schemaname = 'public' AND tablename <> 'alembic_version'
  LOOP
    EXECUTE format('TRUNCATE TABLE public.%I RESTART IDENTITY CASCADE', r.tablename);
  END LOOP;
END $$;
"""

_UPSERT_USER = (
    "INSERT INTO users (auth0_sub, name, email, role) VALUES (:sub, :name, :email, :role)"
    " ON CONFLICT (auth0_sub) DO UPDATE SET name = EXCLUDED.name, email = EXCLUDED.email,"
    " role = EXCLUDED.role, updated_at = now()"
)


@dataclass(frozen=True)
class DemoUser:
    sub: str
    name: str
    email: str
    roles: frozenset[Role]


# Mirrors frontend/lib/dev-auth.ts DEV_USERS (a unit test keeps them in step). No role means
# student, exactly as roles_from_claims treats a token without roles.
DEMO_USERS: tuple[DemoUser, ...] = (
    DemoUser("dev|student-ada", "Ada (student)", "ada@students.example", frozenset({"student"})),
    DemoUser("dev|student-ben", "Ben (student)", "ben@students.example", frozenset({"student"})),
    DemoUser("dev|teacher-cho", "Cho (teacher)", "cho@staff.example", frozenset({"teacher"})),
    DemoUser(
        "dev|admin-dee", "Dee (firewall admin)", "dee@staff.example", frozenset({"firewall_admin"})
    ),
    DemoUser(
        "dev|both-eli",
        "Eli (teacher + firewall admin)",
        "eli@staff.example",
        frozenset({"teacher", "firewall_admin"}),
    ),
)


class UnsafeTarget(Exception):
    """The database is production, or remote and not confirmed by host name."""


@dataclass
class DemoReport:
    reset: bool
    accounts: int = 0
    parts_seeded: list[str] = field(default_factory=list)
    parts_skipped: list[str] = field(default_factory=list)


def check_target(app_env: str, database_url: str, confirm_host: str | None) -> str:
    """Return the target host if seeding it is allowed; raise UnsafeTarget otherwise."""
    if app_env == "production":
        raise UnsafeTarget("refusing to seed or reset with APP_ENV=production")
    host = make_url(database_url).host or ""
    if host in LOCAL_HOSTS or host == confirm_host:
        return host
    raise UnsafeTarget(
        f"{host!r} is not a local database (it may be shared by the whole team); "
        f"re-run with --confirm-host {host} if you mean it"
    )


async def reset_data(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(_RESET))


async def seed_accounts(engine: AsyncEngine) -> int:
    async with engine.begin() as conn:
        for u in DEMO_USERS:
            params = {"sub": u.sub, "name": u.name, "email": u.email, "role": primary_role(u.roles)}
            await conn.execute(text(_UPSERT_USER), params)
    return len(DEMO_USERS)


async def seed_demo(engine: AsyncEngine, reset: bool = False) -> DemoReport:
    report = DemoReport(reset=reset)
    if reset:
        await reset_data(engine)
    report.accounts = await seed_accounts(engine)
    await seed_arena(engine)
    for spec in PART_SEEDERS:
        module_name, _, attr = spec.partition(":")
        try:
            # module_name comes only from the constant PART_SEEDERS allowlist.
            module = importlib.import_module(module_name)  # nosemgrep: non-literal-import
        except ModuleNotFoundError as exc:
            # Only "this part is not on the branch" is a skip; a broken import inside an
            # existing seeder must still fail loudly.
            if exc.name is None or not module_name.startswith(exc.name):
                raise
            report.parts_skipped.append(module_name)
            continue
        await getattr(module, attr)(engine)
        report.parts_seeded.append(module_name)
    return report


async def _run(url: str, reset: bool) -> DemoReport:
    from app.db.engine import make_engine

    engine = make_engine(url)
    try:
        return await seed_demo(engine, reset=reset)
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    from app.config import get_settings
    from app.db.engine import migration_url

    parser = argparse.ArgumentParser(prog="seed_demo", description="Demo seed (M1 D-02)")
    parser.add_argument("--reset", action="store_true", help="wipe all app data first")
    parser.add_argument("--confirm-host", help="exact host name of a non-local database")
    args = parser.parse_args(argv)

    url = migration_url()
    try:
        host = check_target(get_settings().app_env, url, args.confirm_host)
    except UnsafeTarget as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"target: {host}{' (RESET)' if args.reset else ''}")
    report = asyncio.run(_run(url, args.reset))
    print(f"{'reset and ' if report.reset else ''}seeded: {report.accounts} demo accounts,")
    print("  scenario, 3 levels, 1 secret per level (kept if they already existed)")
    print(f"  other parts seeded: {', '.join(report.parts_seeded) or 'none'}")
    print(f"  not on this branch yet: {', '.join(report.parts_skipped) or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
