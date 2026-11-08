# Final-Merge Prompt: Machine M3 (AFF Intelligence and Admin Console), Gate 3 to Integration

I'm working on **Injection Arena (repo: AEGIS)**, a security-education platform for MakeUC 2026.
The PRD is `doc/PRD-Injection-Arena-Unified.md` (v3.1) and is the source of truth. M3's plan is
`doc/PROGRESS-M3-AFF-Intel-Admin.md`. Read both in full first, including §0 (binding on every
machine), the Phase D Step 0 and plan-check tables, both Phase D review tables, every §10 row and
the H17 Progress log row. Phases A to D are done except the items below. This prompt is the
checklist for M3's **final merge to `master`** (plan §0.6, §6, §7, §8). It sets the process, not
the spec.

**Nothing merges or is pushed without my explicit approval**, at each step. That includes the
`integration` branch, the M3 branch on `origin` (it needs a force-push or a merge, ask which), and
the PR to `master`. Don't commit unless I ask.

## Step 1: Unblock what waits on other machines

Check `origin` first (`git fetch`; the sandbox needs `github.com` in `allowed_domains`).

- **M2 (B-07, X-1, X-2, AC-1).** When an `integration` branch and M2's C6 `admin_api.py` and C2
  `interface.py` exist: run E-50 and E-51 end to end with M2's Gatekeeper, assert M3-X18 together
  with M2, sign off C7 with M2, and rerun **D-03** (`test_d03_demo_path_*`) and the
  `FwEventSource` tests on real M2 (real C6 instead of `FakeFirewallAdmin`, M2's Basic pipeline
  instead of M3's one-turn evaluator). Confirm with M2: `RiskyBehaviorRecord.input_text` equals
  the normalized `CheckedItem.text`; `conn` is an `AsyncConnection`; how their writer stores turn
  text in `fw_conversation` (M3's reads are in plan §10); idempotent `create_rule` keyed by draft
  ID (optional). Tell M2 that M3 reads `fw_tool_calls` and `fw_sessions` read-only (owner, H14).
- **M1.** Still open: `policy/` and `fixtures/` missing from the backend image
  (`AEGIS_POLICY_PATH`, `AEGIS_FIXTURES_DIR`); `validate_weights` 0–100 vs 5–60; coverage `omit`
  lists `app/admin/*`, `app/workers/*` and lacks `concurrency = ["greenlet", "thread"]`;
  `npm audit` 8 moderate (`minimatch`). Hand M1 the DM1-1 sign-off notes (plan §4, Deferred from
  M1) to copy into its Progress log. Tell M1 about `google-re2` and `.claude-flow/` in the PR.
- **UI (`feature/frontend_ui`).** Owner decision H14: M3 does **API only**; the six P0 screens and
  the P1 screens are not built by M3. When that branch has them, run a Playwright pass against the
  real API as firewall admin, student and teacher (redirected), at 390 px, zero console errors,
  plus `tsc --noEmit`, ESLint, vitest and `next build`. Check each screen against PRD §11 and the
  plan §10 UI rows (queue order and `x-server-time` skew, 409 `reason`, operator table, history,
  audit `actor_name`, model text rendered as text). Then do **DM1-3** (live `human_denied`) with
  M1. If that branch changes M3's files (`frontend/app/admin/{layout.tsx,AdminNav.tsx,
  admin.module.css,mock.ts}` or the six screen pages), stop and ask me how to combine them. Never
  edit that branch yourself.
- **D-05** (P2 live metrics) only if M2's continuous aggregates land and every MVP test passes.

## Step 2: Exit criteria (plan §7), all must be `[x]`

For each of X-1 to X-7, show the evidence (test names and output) in the plan before ticking it.
X-6 is CI: `ruff check`, `ruff format --check`, `pytest`, `tsc --noEmit` (strict), `next build`,
`gitleaks detect`, `alembic upgrade heads` on an empty TimescaleDB with pgvector. gitleaks could
not be downloaded through this sandbox's proxy: run it in CI or ask me to run it. X-7: only the
approved non-M3 changes (plan X-7 note). In a normal shell, restore `.env.example` in the working
tree first (`git checkout -- .env.example`; the sandboxed merge could not write it).

## Step 3: Merge (plan §0.6), only with my approval

Order at G3: M1, then M2, then M3, then M4. Rebase (or merge, ask me) on the latest `master`
after M2 lands, rerun the whole suite, then open the PR from `m3/aff-intel-admin` to `master`
with Conventional Commits (`feat(m3): ...`). After merge: INT-1 to INT-4 (plan §8) with fakes off.

## Process (unchanged from Phase D)

- **Integration tests** use a real TimescaleDB with pgvector and `ScriptedLLM` (I-6). The sandbox
  cannot read `.env` or run `docker`, so ask me to start
  `docker run -d --name aegis-m3-test -p 55434:5432 -e POSTGRES_USER=aegis -e POSTGRES_PASSWORD=m3-synthetic-test -e POSTGRES_DB=aegis timescale/timescaledb-ha:pg17`
  and run with `TEST_DATABASE_URL=postgresql+asyncpg://aegis:m3-synthetic-test@127.0.0.1:55434/aegis`,
  `AEGIS_TEST_DB=aegis_test_m3`, `UV_CACHE_DIR=$TMPDIR/uvcache`. Never report a DB test as passing
  without running it. Write tests first and watch them fail.
- **harness-os**: Constitution → Specification → Test Suite → Generate Code → Code Review for any
  new code. The project has no `harness.config.json`, so the tests stage is not gate-observed:
  record that, never self-assert RED or GREEN. Run the reviewer agent `request_review` names.
- **Code review** as a QA/QC engineer: secrets (synthetic only, `[SECRET]` in reports), SAST (ruff
  `S`, semgrep with `--no-git-ignore`; run it via `uvx` with `HOME` and `UV_TOOL_DIR` under
  `$TMPDIR`), SCA (`pip-audit`, `npm audit`), Hypothesis with `hypothesis.event()` on new parsers,
  concurrency, test strength (negatives fail for the named reason, passing controls, non-empty
  parametrized lists), DAST over every `/api/admin` route.
- **Codex**: loop `codex exec --sandbox read-only` (outside the sandbox, it writes `~/.codex`; keep
  prompts and output in the session scratchpad) until Claude and Codex both find nothing.
- **Stay in your lane**: don't edit `contracts/`, `ports.py`, `main.py`, `frontend/lib/*`,
  `components/shell/*` or M2's tables. A contract change is a PR for all four machines.
- Keep `doc/PROGRESS-M3-AFF-Intel-Admin.md` current throughout; add a Progress log row at the merge.

## End

When M3 is merged and INT-1 to INT-4 pass: ask me to remove the test DB container
(`docker rm -f aegis-m3-test`), and delete this prompt.
