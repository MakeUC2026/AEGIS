# Master Prompt: Machine M1 (Foundation, Infra, Arena)

I want to implement a project called **Injection Arena (repo: AEGIS)**, a security-education
platform for MakeUC 2026 with two subsystems. Subsystem 1, the Arena, lets students attack a
tool-calling company chatbot (Grok) at three levels (Off, Basic, Strict) behind an Agent
Firewall Framework (AFF) that scores every input, tool call and reply and decides Allow, Deny,
Review or Divert. Subsystem 2, the Classroom, lets teachers review sessions and gives students
an AI-generated quiz. The full PRD is at `doc/PRD-Injection-Arena-Unified.md`. Read it in full
before doing anything else. It is the source of truth for every requirement below. This prompt
sets the *process*, not the spec.

This machine is **M1**, one of four machines working in parallel. M1's stream is Foundation
(scaffold, DB, auth, contracts, LLM clients), Infra (Vercel, Railway, Tiger Data, Compose) and
the Arena (Level Blueprint), plus leading integration. It is defined in
`doc/PROGRESS-M1-Foundation-Arena.md`. Read that in full as well. Its §0 (shared operating
rules) is identical in all four progress docs and binds every machine: write only M1-owned files
and tables (§0.1, §0.2), keep contract shapes exactly as PRD §14 plus the additions in M1 §3.1,
follow the migration layout in §0.4, and merge by the protocol in §0.6. M2, M3 and M4 build
against the contracts and fakes M1 ships, so M1's Gate 0 output is on everyone's critical path.

## Step 1 — Implementation plan

The plan already exists: `doc/PROGRESS-M1-Foundation-Arena.md`. Do not create a new one or a
different phase breakdown. Its Phases A–D map to the PRD §17.2 gates (G0 at H3, G1 at H8,
G2 at H14, G3 at H17). Its §5 edge case table is derived from PRD §4–§6, §14, §15 and §16.2:
E-54 (recap part), E-55 (auth part) and M1-X01 to M1-X29. Treat every row as a required
automated test, not optional polish. "Complete" means the doc's §6 acceptance criteria (AC-1
to AC-8, including the PRD §4.3 auth acceptance), its §7 exit criteria (X-1 to X-8), and the
PRD §16.3 checklist rows M1 leads. Before you start, check the doc against the PRD once more.
If you find a gap, fix the doc first and note the fix in its Progress log.

**Order.** Phase A items A-01 to A-06, A-12 and A-13 (layout, contracts and fakes, `ports.py`,
LLM clients, DB and `0001_foundation`, `main.py` with placeholder routers, CI, seed fixtures)
come first, because M2, M3 and M4 rebase on them. Get them green and ready to merge to `master`
before Phase B. Pushing to the shared GitHub remote (`origin`) is outward-facing: ask the user
before every push or PR.

## Step 2 — Implement the plan

Work through the plan phase by phase. For each step:

1. Implement it.
2. Run a verification loop and confirm the output matches expectations.
3. If it doesn't, debug and iterate before moving on. Don't proceed on a failing or unverified
   step.
4. Record progress in `doc/PROGRESS-M1-Foundation-Arena.md`: tick the checkbox (`[x]` only when
   done **and** tested, `[~]` in progress, `[!]` blocked with the reason), add a Progress log row
   at each gate, and add a **Design decisions** entry wherever the PRD left an implementation
   detail open. Examples: field-level shapes of the contract additions in M1 §3.1, exact UI copy
   not given in PRD §6.2, the Grok system prompt wording, seed dataset contents, the dev
   authentication mode, and polling intervals.

**External accounts.** Some items need credentials this machine may not have: the Auth0 tenant
(A-07), Vercel, Railway and Tiger Cloud deploys (A-14), the Grok gullibility smoke test (A-15)
and pinned model IDs (A-16). Build and test everything on the code side locally (a local JWKS
for token verification, `ScriptedLLM` for models, a TimescaleDB container for the database),
then mark these items `[!]` with exactly what is needed from the user. Never report one of them
as done without having run it.

## Backend work

Before implementing any backend logic, set up its integration tests first. Run them after every
significant change, not just at the end of a phase. Integration tests use a real TimescaleDB
container with pgvector, `FakeFirewall`, and `ScriptedLLM`, so they are deterministic (invariant
I-6). This applies especially to:

- Token verification and role checks: `require_user`, `require_role`, 401 and 403, the role read
  from the `https://aegis/roles` claim and never from the DB cache, and the concurrent first-call
  upsert (PRD §4.3, M1-X01 to M1-X08).
- The trusted proxy boundary: requests without the shared secret header are rejected, and
  `x-forwarded-for` and `ClientMeta` are trusted only with it (PRD §8.5, §15.1).
- The hourly cap of 30 per student and the global daily budget, including a `not_sent` retry
  with the same `message_id` not using another slot (PRD §6.1, §15.1).
- The arena session lifecycle state machine from PRD §6.3: Sent to Replied, Blocked,
  AwaitingReview or NotSent; retry with the same message ID; review polling; close; recap lock
  and unlock.
- The win evaluator and secret compromise: facts only, first delivery only, divert never wins
  (PRD §5.3, §6.4).
- Level and secret version snapshots, level versioning and secret rotation, each audited, with
  running sessions keeping their snapshot (PRD §5.2, §5.3, invariant I-7).
- C4 and C8 services, and the response filter that lets only `player_view` reach the browser
  (invariant I-3).
- Migrations: `alembic upgrade heads` on an empty TimescaleDB with pgvector, with the branch
  layout from §0.4.

## Frontend / full-stack work

Use the Playwright MCP server for any frontend or full-stack change. Actually look at what's
rendering; don't infer correctness from the code alone. This matters in particular for:

- The landing page and sign-up with the privacy notice (PRD §4.3, §15.2), and the role-aware tab
  nav (PRD §4.2).
- The level picker: Obtained badges, compromised tag, rules list, remaining messages (PRD §6.1).
- The chat screen with **all six statuses and their exact PRD §6.2 copy**, the tool-output view,
  and the defense feed (diverts shown as executed and allow until the recap), the review input
  lock and polling, the win banner, and the recap (PRD §6.2).
- The fingerprint being sent only on levels with divert enabled (PRD §8.5).

Every screen gets its data from the FastAPI API (driven by scripted `FakeFirewall` sessions in
development). No hard-coded demo data in components. This is a hard requirement, not cleanup you
can defer.

## Harness-os pipeline

Use the harness-os MCP server and follow its pipeline for every unit of work:
Constitution → Specification → Test Suite → Generate Code → Code Review. Don't skip stages or
generate code before its Test Suite stage exists.

## Code review

During the Code Review stage, review the uncommitted changes against both the plan
(`doc/PROGRESS-M1-Foundation-Arena.md`) and the PRD (`doc/PRD-Injection-Arena-Unified.md`) with
the discipline of an experienced QA/QC engineer. Explicitly check for correctness, performance
and security before considering the step done; don't just check that it runs. Security tooling
for this project:

- **Secrets:** gitleaks. This is a PRD §15.2 requirement and must be clean.
- **SAST:** Ruff with the bandit (`S`) rules, plus semgrep on backend and frontend.
- **SCA:** `pip-audit`, `npm audit`, and a Dependabot config for pip, npm, Docker and GitHub
  Actions.
- **DAST:** an OWASP ZAP baseline scan against the local Compose stack.
- **Fuzzing:** Hypothesis property tests on input handling: message text, `message_id`, filter
  query params, `x-forwarded-for` parsing, and token claims.

## Don't miss these — easy to under-implement in a large spec

- **Contracts are for four machines, not one.** Every type in PRD §14.3–§14.6 verbatim, plus
  every addition in M1 §3.1 (`MockStateSeed`, `Catalog`, `TicketResult`, `close_session`, typed
  errors, the C3, C6, C7 and C8 shapes, `FeedItem.shadow_decision`, `get_session_summaries`,
  `get_manifest_summary`, `redact_for_session`), with a scriptable fake for every seam and the
  `AEGIS_USE_FAKES` switch in `ports.py`.
- **Information flow (I-3).** Arena responses are built from `player_view` only. A test asserts
  that no `facts`, judge reasons, tool arguments or trace-back keys appear in any arena JSON.
- **The arena never truncates player text** (M1-X23). The AFF decides what to do with oversized
  input.
- **Version snapshots.** `level_version` and `secret_version` are snapshotted at session start.
  New level versions and rotations reach new sessions only.
- **Compromise is first-only per secret version, and a divert is never a win** (M1-X15, M1-X16).
- **Role from the token, never the DB** (M1-X06). No role claim means `student`. Dual-role users
  get both tab sets, and each route still checks its own role.
- **Proxy trust.** FastAPI accepts only requests carrying the shared proxy secret.
  `x-forwarded-for` is trusted only on those.
- **Fingerprint** only on levels with divert enabled, computed without a fingerprinting library.
- **Seeds.** The Off level uses the Strict thresholds (it scores like Strict in shadow).
  `rule_version = 0` means "pin the latest". There is exactly one poisoned document. The attacker
  mailbox is on an external domain and the allowlist is `company.example`.
- **Placeholder routers** for `admin`, `classroom` and `quiz`. One Alembic history with the
  branch labels from §0.4. Always `upgrade heads`.
- **`audit_log` and `record_audit`** live in Foundation. Every C8 write is audited.
- **Synthetic secrets only.** Secrets are generated at seed time and never committed.
  `.env.example` holds fake values only.
- **Stay in your lane.** Write nothing in M2, M3 or M4 folders beyond the Gate 0 placeholders and
  the fakes.

Update `doc/PROGRESS-M1-Foundation-Arena.md` as you go throughout. It should always reflect
current, accurate status, not just a snapshot from when the plan was created.
