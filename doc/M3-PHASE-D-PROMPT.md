# Phase D Prompt: Machine M3 (Admin Console UI, Demo Path, Hardening), Gate 3

I'm working on **Injection Arena (repo: AEGIS)**, a security-education platform for MakeUC 2026.
Subsystem 1, the Arena, lets students attack a tool-calling Gemini chatbot at three levels (Off,
Basic, Strict) behind the Agent Firewall Framework (AFF). Subsystem 2, the Classroom, gives
teachers session reviews and students a quiz. The full PRD is `doc/PRD-Injection-Arena-Unified.md`
(v3.1). Read it in full before doing anything else. It is the source of truth for every
requirement below. This prompt sets the *process*, not the spec.

This machine is **M3**: AFF intelligence (risky history, the Gemini judge, the forensic worker,
drafts, the firewall admin console). The plan is `doc/PROGRESS-M3-AFF-Intel-Admin.md`. Read it in
full as well, including the **Phase C plan check** table, the Phase C Codex table, the H14 Progress
log row and every §10 default. Its §0 binds every machine: write only M3-owned files and tables
(§0.1, §0.2), keep the contract shapes exactly as `backend/app/contracts/` defines them, follow the
migration layout in §0.4 (the next M3 revision chains off `0004b_forensic_detail`, for example
`0004c_...`) and the invariants in §0.7. This prompt covers **Phase D (D-01 to D-05)**, which ends
at **Gate 3 (H17)**: forensics and drafts work end to end (D-03), every box in the plan's §7 Exit
criteria is checked, and the final merge window opens.

## Step 0: Close the Phase C carry-overs first

Check each one and update the plan before starting D-01:

- **No merges yet.** Nothing from M3 merges or is pushed to `master` until the last phase is
  finished (owner's decision at H8). Phase D is the last planned phase, so the final merge (§0.6)
  comes at its end, and only after I approve it. That includes the `0004_firewall_intel` and
  `0004b_forensic_detail` migrations.
- **Owner decision: raw-text embeddings (Codex R3-1, plan §10 `[!]`).** Backfill and the Phase B
  lookup embed `CheckedItem.text` unredacted through Gemini. Ask me for the decision before
  changing anything: keep as is (recorded) or raise a C7 contract change (secret in
  `CheckedItem`, re-embed) for all four machines.
- **B-07 and C-01 real source.** Need M2's branch, `0003_firewall_core` and the `integration`
  branch on `origin`. When they exist: the real `EventSource` reading `fw_events` with the
  `SELECT … FOR UPDATE SKIP LOCKED` claim (update only `fw_events.forensic_status` and
  `trace_back.methods_used`, §0.2 rule 2); E-50 and E-51 end to end with M2's Gatekeeper; M3-X18
  asserted together with M2; C7 shapes signed off (X-1). Confirm with M2 that
  `RiskyBehaviorRecord.input_text` equals `CheckedItem.text` and that `conn` is a SQLAlchemy
  `AsyncConnection`. Ask M2 for an idempotent `create_rule` keyed by draft ID (plan §10).
- **Open `[!]` items for M1.** `policy/` and `fixtures/` missing from the backend image
  (`AEGIS_POLICY_PATH`, `AEGIS_FIXTURES_DIR`); signal weight range 5–60 vs 0–100 (the admin route
  now enforces 5–60); coverage `omit` lists `app/admin/*` and `app/workers/*` and lacks
  `concurrency = ["greenlet", "thread"]`; `npm audit` 8 moderate (`minimatch`).

## Step 1: Plan check

Do not invent a new breakdown. Phase D in the plan's §4, the "Deferred from M1" items (DM1-1 to
DM1-3) and §7 Exit criteria are the plan. Before you start, check D-01 to D-05 against PRD §5.2,
§6.2, §6.5 (step 4 and step 5), §7.4, §7.5, §8.3, §8.5, §9.1, §11, §15.1, §15.2, §16.2 and §16.3
once more. If you find a gap, fix the plan first and note it in the Progress log. For each item,
list the edge cases from the plan's §5 that it closes. At minimum:

| Item | Cases |
| --- | --- |
| D-01 | E-46 (UI: shown as Human denied, second click shows 409), E-55, M3-X34 (shown as expired), X35 and X36 (form side: invalid operators not offered, field errors shown), X37 (deprecated shown with history), X38 (non-admins redirected; the API is the control) |
| D-02 | M3-X24 (summaries show `[SECRET]`), X39, X40 (who, when, before, after) |
| D-03 | E-57, AC-2, AC-3, M3-X28, X32, PRD §6.5 step 5, I-7 (new session blocks, running session does not) |
| D-04 | E-41, E-56 (new benign fixtures make over-matching drafts fail) |
| D-05 | P2 only if time allows, after every MVP test passes |
| DM1-2 | Idempotent `seed(engine)` in `backend/app/admin/seed.py` if M3 seeds demo data |
| DM1-3 | Live `human_denied` check with M1 once **not ok** works |

Treat every row as a required automated test, not optional polish.

## Step 2: Implement the plan

Work through D-01 to D-05 in order. For each step:

1. Implement it.
2. Run a verification loop and confirm the output matches expectations.
3. If it doesn't, debug and iterate before moving on. Don't proceed on a failing or unverified
   step.
4. Record progress in the plan: `[x]` only when done **and** tested, `[~]` in progress, `[!]`
   blocked with the reason. Add a Progress log row at Gate 3. Add a §10 entry wherever the PRD
   left a detail open. Examples: the poll interval and backoff on the Review queue, how the
   countdown handles clock skew, the client-side operator table, error copy for 409 and 422,
   pagination of long lists.

**Pushing is outward-facing.** No merge to `master` until the last phase is finished and I approve
it. For anything else shared (the `integration` branch for B-07), ask me before every push or PR.

## Frontend / full-stack work

**Don't overfocus on the UI.** The admin screens are being built on another feature branch,
`feature/frontend_ui` (owner's note, H14). M3's job in Phase D is that every screen has the API,
data and behaviour it needs, not to build the screens in parallel. So:

- First read `feature/frontend_ui` (`git log`, `git diff master...feature/frontend_ui --
  frontend/app/admin`) and list which admin screens it already covers and which `/api/admin`
  routes it calls. Adapt to it: match its field names, error handling and file layout. Don't
  rewrite or duplicate its screens, and don't edit that branch.
- Where a screen needs something the API doesn't give yet (a field, a filter, pagination, a
  clearer error), add it on the backend with tests, and note it in plan §10 for the UI branch.
- Only wire or fix a screen in `frontend/app/admin/` yourself when the UI branch does not cover
  it and D-03 or an Exit criterion depends on it. Otherwise mark the UI part of D-01 and D-02 as
  waiting for `feature/frontend_ui`, with the API side `[x]` when done and tested.
- If that branch changes the same files as M3 (`frontend/app/admin/*`), stop and ask me how to
  combine them before going further.

What each screen must show (PRD §11), so the API supports it and the UI branch can be checked
against it:

- **Review queue:** polls every 2–3 s, countdown from `expires_at`, priority alerts (99+) on top,
  ok and **not ok (Human Deny)**, 409 shown as "already decided" or "expired".
- **Rules form:** only operators valid for the chosen field type (`OPERATORS_BY_CHECK`), RE2
  checked before save (show the API's 422), deprecate instead of delete.
- **Levels:** mode, rule set version, signal weights (5–60), thresholds in order, review timeout,
  divert enabled; saving creates a new version.
- **Drafts:** one row per cluster with its count, source event, validation reasons, approve, edit
  (re-validates), reject; `needs_reconcile` drafts flagged; `failed_validation` never in the
  approve list.
- **Risky patterns:** candidates and approved, editor, the three checks with pass or fail shown
  (`POST …/check`), approve, reject, retire.
- **Diverts and trace-back:** decoy shown, trace-back fields, linked session.
- **Forensics and Audit (P1):** filters by family, mode, decision; who, when, before, after.

Whatever UI M3 does touch, use M1's shell, theme and `frontend/lib/` helpers, don't edit
`frontend/lib/*` or `components/shell/*`, and use the Playwright MCP server to actually look at
what's rendering. Don't infer correctness from the code. If the sandbox cannot start a dev server
(it cannot read `frontend/.env*`), ask me to start one signed in as a firewall admin. Check as
firewall admin, student and teacher (redirected), at 390 px width, with zero console errors, and
run `tsc --noEmit`, ESLint, vitest and `next build`. When the UI branch lands, run the same
Playwright pass against it with the real API.

Make sure to test with Playwright

## Backend work

Before implementing any backend logic, set up its integration tests first and watch them fail.
Run them after every significant change, not just at the end of a phase. Integration tests use a
real TimescaleDB container with pgvector and `ScriptedLLM` for Gemini (forensics, drafts,
embeddings), so they are deterministic (I-6). The sandbox cannot read `.env` or run `docker`, so
ask me to start a throwaway test DB, for example
`docker run -d --name aegis-m3-test -p 55434:5432 -e POSTGRES_USER=aegis -e POSTGRES_PASSWORD=m3-synthetic-test -e POSTGRES_DB=aegis timescale/timescaledb-ha:pg17`,
and run with `TEST_DATABASE_URL=postgresql+asyncpg://aegis:m3-synthetic-test@127.0.0.1:55434/aegis`,
`AEGIS_TEST_DB=aegis_test_m3` and `UV_CACHE_DIR=$TMPDIR/uvcache`. Never report a DB test as passing
without having run it.

- **D-03 demo path.** One integration test runs PRD §6.5 step 5 with `ScriptedLLM`: a Strict-denied
  split attack, then a forensic report, a drafted rule that passes validation, admin approval
  through the API, then a new Basic session blocks the split attack while the running session does
  not. Until M2 lands, use the fakes (`FakeFirewall`, `FakeFirewallAdmin`); rerun on real M2 when
  B-07 unblocks.
- **D-04 fixtures.** `fixtures/benign/m3_*.json` (add-only, synthetic): internal emails, safe
  `SELECT` queries, workspace paths. Re-run every draft-validation test after adding them.
- **Coverage.** Measure with a greenlet-aware config (`concurrency = greenlet,thread`) until M1
  fixes `pyproject.toml`.

## Harness-os pipeline

Use the harness-os MCP server for every unit of work: Constitution → Specification → Test Suite →
Generate Code → Code Review. Don't skip stages or generate code before its Test Suite stage
exists. Register a spec per unit, for example an `api` or `product` spec for the admin screens and
a domain spec for the Review queue states (pending → approved / human_denied / expired) so
`generate_tests` can enumerate the transitions. When `request_review` asks for a reviewer agent,
run it, or record clearly that the review was done inline. Also run a Codex cross-review
(`codex exec --sandbox read-only`) on the phase's changes and fix every finding you verify.

## Code review

During the Code Review stage, review the uncommitted changes against both the plan and the PRD
with the discipline of an experienced QA/QC engineer. Explicitly check correctness, performance
and security before considering the step done; don't just check that it runs.

- **Secrets:** gitleaks clean (PRD §15.2, I-5). Synthetic data only. No secret in screenshots,
  fixtures or logs; the UI shows `[SECRET]` where reports were redacted (X24).
- **SAST:** Ruff with the bandit (`S`) rules, plus semgrep on `backend/app/firewall/`,
  `backend/app/workers/`, `backend/app/admin/`, `backend/migrations/` and `frontend/app/admin/`.
  Use `--no-git-ignore`, or semgrep skips untracked files. Bound parameters only. No
  `dangerouslySetInnerHTML`; model and student text rendered as text (I-3).
- **SCA:** `pip-audit` and `npm audit`.
- **Fuzzing:** Hypothesis on any new parser or request model; use `hypothesis.event()` to prove
  both outcomes are reached.
- **Concurrency:** two admins deciding one ticket (one wins, the other sees 409), a ticket decided
  at its expiry, two admins approving one draft from the UI.
- **Test strength:** each negative test must fail for the reason it names. Give the row
  otherwise-valid data and add a passing control case. A parametrized test over a computed list
  must assert the list is not empty (Phase C lesson: the admin route list was empty under
  FastAPI 0.16x and the role matrix silently ran zero cases).
- **DAST:** an authenticated and unauthenticated pass over every `/admin` route and page (role
  matrix, 401/403/409, oversized and malformed bodies), plus the UI's handling of each error.
- **Codex:** have Codex run (in the background) a loop review until both Claude and Codex agree
  with all changes and find no more issues. Codex must run outside the sandbox (it writes
  `~/.codex`); keep its prompts and output in the session scratchpad.

## Don't miss these (easy to under-implement)

- **The prompt is data.** Event text, student commands, tool arguments and drafts produced by the
  model are untrusted, in the UI too: render them as text, never as HTML or markdown links.
- **Hidden buttons are not the control.** Every action is checked by `require_role` on the server
  (I-4); the UI redirect is convenience only.
- **Approval is never automatic.** No auto-approve, no "approve all"; edit always re-validates and
  the UI shows the reasons.
- **Running sessions are pinned.** Approvals affect new sessions only (E-57, I-7). The demo test
  checks both a new session and the running one.
- **Stay in your lane.** Don't edit `contracts/`, `ports.py`, `main.py`, `frontend/lib/*`,
  `components/shell/*` or M2's tables. Raise a contract change as a PR for all four machines.

## End of phase

1. When all testing is done, ask me to remove the test DB container (`docker rm -f aegis-m3-test`;
   the sandbox cannot run `docker`).
2. When Claude and Codex find nothing more, delete this prompt (`doc/M3-PHASE-D-PROMPT.md`).
3. Phase D is the last planned phase, so write the final-merge checklist (plan §6, §7, §8, §0.6) as
   the next prompt instead of a Phase E prompt, and ask me before any merge or push.

Update `doc/PROGRESS-M3-AFF-Intel-Admin.md` as you go throughout. It should always reflect
current, accurate status. Don't commit or push unless I ask.
