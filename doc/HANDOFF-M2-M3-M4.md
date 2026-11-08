# Handoff: start M2, M3 and M4

For the agents and teammates on machines M2, M3 and M4. M1 has reached the Gate 0 bootstrap
checkpoint: `master` has the contracts, fakes, auth, database layer, Gemini client, frontend
shell and CI, and CI is green. You can start now and work in parallel.

Read your progress doc first. It is your plan, edge cases and exit criteria:

| Machine | Progress doc | Branch | You build |
| --- | --- | --- | --- |
| M2 | [PROGRESS-M2-AFF-Core.md](PROGRESS-M2-AFF-Core.md) | `m2/aff-core` | AFF core: pipeline, rules, Sentinel layer 1, Gatekeeper, Review, Divert, event store |
| M3 | [PROGRESS-M3-AFF-Intel-Admin.md](PROGRESS-M3-AFF-Intel-Admin.md) | `m3/aff-intel-admin` | Risky history, judge, forensics, drafts, firewall admin console |
| M4 | [PROGRESS-M4-Classroom.md](PROGRESS-M4-Classroom.md) | `m4/classroom` | Teacher dashboard, insights, secrets screen, quiz |

The PRD is [PRD-Injection-Arena-Unified.md](PRD-Injection-Arena-Unified.md). Since Gate 0, D-15 is
revised: **Gemini is the attacked bot**. There is no Grok or xAI anywhere.

---

## 1. Prerequisites

Docker (with Compose), Git, [uv](https://docs.astral.sh/uv/) and Node.js 24. uv installs Python
3.12 for you.

## 2. Local setup

Every step says which folder to run it in. Run them in order.

| # | Folder | Command | What it does |
| --- | --- | --- | --- |
| 1 | anywhere | `git clone https://github.com/MakeUC2026/AEGIS.git && cd AEGIS` | Get the repo (or `git pull` on `master` if you already have it) |
| 2 | repo root | `git switch -c m2/aff-core` (or `m3/aff-intel-admin`, `m4/classroom`) | Your branch, from `master` |
| 3 | repo root | `cp .env.example .env` | Local settings. Git-ignored, never commit it |
| 4 | repo root | Edit `.env`: set `AEGIS_PROXY_SECRET` to the output of `openssl rand -hex 32` | The Next.js to FastAPI shared secret. The local DB password can stay as it is |
| 5 | repo root | `docker compose up -d db` | Local TimescaleDB with pgvector on `127.0.0.1:55432` |
| 6 | `backend/` | `uv sync` | Creates `backend/.venv` (Python 3.12) from `uv.lock` |
| 7 | `backend/` | `uv run python ../scripts/dev_keys.py` | Writes dev sign-in keys and dev mode into `.env` |
| 8 | `backend/` | `uv run alembic upgrade heads` | Migrates the local DB. Reads `DATABASE_URL` from `.env` |
| 9 | `backend/` | `uv run pytest` | All backend tests should pass |
| 10 | repo root | `ln -sf ../.env frontend/.env.local` | The frontend reads the same `.env`. Must be run from the repo root |
| 11 | `frontend/` | `npm ci` then `npm test` | Installs packages and runs the frontend tests |

**Run the app** (two terminals):

| Folder | Command |
| --- | --- |
| `backend/` | `uv run uvicorn --factory app.main:create_app --reload --port 8000` |
| `frontend/` | `npm run dev` |

Open <http://localhost:3000>, click **Enter the Arena**, and pick a dev user. There is one per
role: two students, a teacher, a firewall admin, and a teacher who is also a firewall admin.

**VS Code:** select the interpreter `backend/.venv/bin/python` (Python: Select Interpreter).

**Real services (optional):** everything above runs on dev sign-in and fakes. To call real Gemini
models or test real Auth0 sign-in, get `GEMINI_API_KEY` and the `AUTH0_*` web-app values from the
project owner privately and paste them into your `.env`. Model IDs are already pinned in
`.env.example`. Set `AEGIS_AUTH_MODE=auth0` for real sign-in.

## 3. Fakes and seams

Your branch starts with every seam faked (`AEGIS_USE_FAKES=firewall,read,admin,risky,judge,arena`).
Remove a seam from that list only once its real code is on your branch:

| Seam | Removed by | Real module (exposes `create()`) |
| --- | --- | --- |
| `firewall`, `read`, `admin` | M2 | `app/firewall/interface.py`, `read_api.py`, `admin_api.py` |
| `risky`, `judge` | M3 | `app/firewall/risky_history.py`, `judge.py` |
| `arena` | M1 | `app/arena/service.py` |

Get seams in code through `app.firewall.ports` (`get_firewall()`, `get_firewall_read()` and so
on). If you remove a seam too early you get a `PortUnavailable` error that names it.

`AEGIS_FAKE_SCRIPT=dev` makes the fake firewall answer by keyword, so every chat status can be
seen in the UI: `fail` gives Not sent, `administrator` gives Review, `notes` plus `email` gives a
win in Off, a block in Basic and a divert in Strict, and `characters` gives the split leak.

## 4. What is on `master` for you

| You need | Where |
| --- | --- |
| Contracts C1 to C8 (frozen at Gate 1) | `backend/app/contracts/` |
| Fakes for every seam, `fake_turn()` builder | `backend/app/contracts/fakes/` |
| Auth: `require_user`, `require_role(...)`, `client_meta` | `backend/app/auth/deps.py` |
| Test tokens: `make_keys()`, `make_token(keys, sub=..., roles=[...])` | `backend/app/auth/testing.py` |
| DB engine, `record_audit(conn, *, ...)` | `backend/app/db/` |
| Gemini: `chat_with_tools` (the bot), `generate_json`, `embed`; `ScriptedLLM` for tests; `DailyBudget` | `backend/app/llm/` |
| Your router, already mounted | `backend/app/admin/router.py` (M3), `classroom/router.py` and `quiz/router.py` (M4) |
| Your page, already in the nav | `frontend/app/admin/` (M3), `frontend/app/classroom/` and `frontend/app/quiz/` (M4) |
| Browser API helper: `apiFetch(path, options)` | `frontend/lib/api.ts` (client components) |
| Server API helper: `serverGet(segments)`, `getMe()` | `frontend/lib/server-api.ts` (server components) |
| Theme tokens and shared classes | `frontend/app/globals.css` (use the variables, not hard-coded colors) |
| Integration test fixtures (fresh DB per run) | `backend/tests/integration/conftest.py` |
| Seed attack and benign fixtures | `fixtures/attacks/`, `fixtures/benign/` (add files with your `m2_`, `m3_`, `m4_` prefix) |
| Your demo seed, picked up by `scripts/seed_demo.py` automatically | Write `async def seed(engine) -> None`, idempotent, in `backend/app/firewall/seed.py` (M2 rules), `backend/app/admin/seed.py` (M3), or `backend/app/classroom/seed.py` and `backend/app/quiz/seed.py` (M4). If the file is absent, it is skipped. Run `uv run python ../scripts/seed_demo.py` from `backend/`. Add `--reset` to wipe all app data first. A remote DB such as Tiger needs `--confirm-host <host>` |

## 5. Rules (from §0 of every progress doc)

- **Stay in your folders and tables** (§0.1, §0.2). Shared files (`main.py`, `contracts/`, `ports.py`,
  `frontend/lib/*`, `components/shell/*`, CI) belong to M1: ask for changes with a small PR.
- **Contracts freeze at Gate 1.** Review `backend/app/contracts/` now. After the freeze a change needs
  approval from all four machines.
- **Your migration:** own file, fixed revision ID, `down_revision = "0001_foundation"`, your branch
  label: `0003_firewall_core` (M2), `0004_firewall_intel` (M3), `0005_classroom` (M4). Always
  `alembic upgrade heads`. No foreign keys to other parts except `users.id`.
- **Tests first,** deterministic: stub models with `ScriptedLLM`, never call real models in tests.
- **Merging:** your branch goes to `master` only when every box in your §7 Exit criteria is ticked and
  CI is green (ruff, pytest, tsc, eslint, build, gitleaks). Merge order at Gate 3 is M1, M2, M3, M4.
  Early merges are allowed only for your migration file and seed.
- **Commits:** Conventional Commits with your machine as scope, for example `feat(m2): gatekeeper bands`.
- **Secrets:** never commit `.env` or keys. Synthetic secrets only in fixtures.
- **Keep your progress doc current** after every unit of work: tick boxes, add a Progress log row.

## 6. Notes per machine

**M2**
- The bot runner calls `GeminiClient.chat_with_tools(model, messages, tools)` with
  `AEGIS_BOT_MODEL_ID` (`gemini-2.5-flash`). Keep each returned `ToolCall` (including `signature`) and
  send it back in the next `ChatMessage(role="assistant", tool_calls=[...])`, or Gemini rejects the
  follow-up turn.
- Tool-call arguments that are not a JSON object arrive as a raw string. Deny them, don't repair them.
- Merge your `0003_firewall_core` migration and rule seed early (Gate 1), because M3 reads your tables.

**M3**
- Judge model: `AEGIS_GEMINI_FLASH_MODEL_ID` (`gemini-3.5-flash`). Forensics and grading:
  `AEGIS_GEMINI_PRO_MODEL_ID` (`gemini-3.1-pro-preview`). Embeddings: `gemini-embedding-001`, 768 dimensions.
- In a live check the Pro model returned risk 9 together with action deny. Define the 0 to 100 risk
  scale explicitly in the judge prompt and validate the answer.
- Admin routes must use `require_role("firewall_admin")`. A teacher gets 403 (E-55).

**M4**
- Read other parts only through C3 (`get_firewall_read()`) and C4/C8 (`get_arena_service()`). Never
  query their tables.
- Redact with `redact_for_session(fw_session_id, text)`; you never get the secret value itself.
- Call `unlock_recap(session_id)` when a quiz starts.

## 7. Known open items (not blocking you)

- Railway and Vercel deploys (M1 A-14). Tiger Cloud is set up and migrated.
- Bot gullibility smoke test (M1 A-15), right after M1's scenario seed (B-02).
- Team members' Auth0 roles: sign up at the app, then send your email to the project owner.
