# Phase C Prompt: Machine M3 (Forensic Worker, Drafts, Admin API), Gate 2

I'm working on **Injection Arena (repo: AEGIS)**, a security-education platform for MakeUC 2026.
Subsystem 1, the Arena, lets students attack a tool-calling Gemini chatbot at three levels (Off,
Basic, Strict) behind the Agent Firewall Framework (AFF). Subsystem 2, the Classroom, gives
teachers session reviews and students a quiz. The full PRD is `doc/PRD-Injection-Arena-Unified.md`
(v3.1). Read it in full before doing anything else. It is the source of truth for every
requirement below. This prompt sets the *process*, not the spec.

This machine is **M3**: AFF intelligence (risky history, the Gemini judge, the forensic worker,
drafts, the firewall admin console). The plan is `doc/PROGRESS-M3-AFF-Intel-Admin.md`. Read it in
full as well, including the **Phase B plan check** table, the H8 Progress log row and every §10
default. Its §0 binds every machine: write only M3-owned files and tables (§0.1, §0.2), keep the
contract shapes exactly as `backend/app/contracts/` defines them, follow the migration layout in
§0.4 (a later M3 revision chains off `0004_firewall_intel`, for example `0004b_...`) and the
invariants in §0.7. This prompt covers **Phase C (C-01 to C-10)**, which ends at **Gate 2 (H14)**:
Strict works with the real C7 on the shared `integration` branch, and E-50 and E-51 pass with
real M2 (X-2).

## Step 0: Close the Phase B carry-overs first

Check each one and update the plan before starting C-01:

- **No merges yet.** Nothing from M3 merges or is pushed to `master` until the last phase is
  finished (owner's decision at H8). That includes the B-01 `0004_firewall_intel` seam merge.
- **B-07 hand-off.** Needs M2's branch and the `integration` branch on `origin`. When they exist:
  E-50 and E-51 end to end with M2's Gatekeeper, M3-X18 asserted together with M2, C7 shapes
  signed off (X-1). Confirm with M2 that `RiskyBehaviorRecord.input_text` equals
  `CheckedItem.text` (the embedding cache key) and that `conn` is a SQLAlchemy `AsyncConnection`.
- **Open `[!]` items.** `policy/` and `fixtures/` are missing from the backend image (M1; the
  judge can use `AEGIS_POLICY_PATH`, the worker needs `AEGIS_FIXTURES_DIR`). Signal weight range
  5–60 vs 0–100 (M1, before D-01). Commit `8e692aa` on this branch carries the
  `eslint-config-next` downgrade, which is not M3's: keep it out of M3's PR or get M1's sign-off.

## Step 1: Plan check

Do not invent a new breakdown. Phase C in the plan's §4 is the plan. Before you start, check
C-01 to C-10 against PRD §7.5, §8.3, §8.5, §9.1, §10.2, §10.3, §11, §14.4, §15.1, §15.3 and
§16.2 once more. If you find a gap, fix the plan first and note it in the Progress log. For each
item, list the edge cases from the plan's §5 that it closes. At minimum:

| Item | Cases |
| --- | --- |
| C-01 | M3-X20, X21, X22, X26, X27 |
| C-02 | M3-X23, X24, X25, X28 (report side); `trace_back.methods_used` for diverts |
| C-03 | M3-X28 (at most one draft per event) |
| C-04 | E-56, M3-X29, X31 (validation side) |
| C-05 | M3-X30 |
| C-06 | E-57 (approval side), M3-X31, X32, X33, X40 |
| C-07 | E-39, E-40, E-41, M3-X12, X15 (retire), X40 |
| C-08 | M3-X11 (backfill side), X41 |
| C-09 | M3-X24 (summaries redacted), X39 |
| C-10 | E-46 (admin side), E-55, M3-X34, X35, X36, X37, X38, X40 |

Treat every row as a required automated test, not optional polish.

## Step 2: Implement the plan

Work through C-01 to C-10 in order. For each step:

1. Implement it.
2. Run a verification loop and confirm the output matches expectations.
3. If it doesn't, debug and iterate before moving on. Don't proceed on a failing or unverified
   step.
4. Record progress in the plan: `[x]` only when done **and** tested, `[~]` in progress, `[!]`
   blocked with the reason. Add a Progress log row at Gate 2. Add a §10 entry wherever the PRD
   left a detail open. Examples: the NOTIFY payload and channel, the claim query, retry backoff
   timings, the redaction method, the forensic and draft model IDs, the cluster query, the admin
   route paths and error codes.

**Pushing is outward-facing.** No merge to `master` until the last phase is finished. For
anything else shared (the `integration` branch for B-07), ask me before every push or PR.

## Backend work

Before implementing any backend logic, set up its integration tests first and watch them fail.
Run them after every significant change, not just at the end of a phase. Integration tests use a
real TimescaleDB container with pgvector and `ScriptedLLM` for Gemini (forensics, drafts,
embeddings), so they are deterministic (I-6). Phase B note: the session sandbox cannot read
`.env`, so the tests ran against a throwaway container on port 55433 with
`TEST_DATABASE_URL=postgresql+asyncpg://aegis:<synthetic>@127.0.0.1:55433/aegis` and
`UV_CACHE_DIR=$TMPDIR/uvcache`. Never report a DB test as passing without having run it.

- **M2 dependencies.** Until M2's `0003_firewall_core` lands, the worker reads events through a
  local `EventSource` protocol with an in-memory implementation (plan §3.2), and the admin router
  uses `FakeFirewallAdmin` (C6). Do not create or migrate M2's tables. When `0003` lands, add the
  real `EventSource` reading `fw_events` and update only `fw_events.forensic_status` and
  `trace_back.methods_used` (§0.2 rule 2).
- **C-01 worker.** `app/workers/forensics.py`: `LISTEN fw_events_forensic` plus 10 s polling,
  claim with `SELECT … FOR UPDATE SKIP LOCKED`. Pick Deny, Human Deny and Divert (or the same as
  `shadow_decision` in Off), plus Off allows that delivered the secret. Never a Basic allow with
  no secret delivered (X26).
- **C-02 analysis.** Redact the secret to `[SECRET]` before anything reaches Gemini or the
  table (X24), wrap all event text as untrusted data (X25), validate with `ForensicAnalysis`,
  write `forensic_reports`, up to 3 tries with backoff, then `forensic_status: failed` with the
  reason (X23). **Check the Gemini schema keywords here** (§10: `oneOf`, `discriminator`, `$ref`,
  `const` in the draft union). Do one live call or read the Gemini docs through context7. If
  Gemini refuses them, flatten the schema sent to Gemini and keep Pydantic as the validator.
- **C-03 to C-05 drafts.** At most one draft per event (the `drafts.source_event_id` unique
  index already enforces it). Validate against the original event (must match) and every benign
  fixture (must match none), using `risky_patterns.validate_for_approval` for patterns. Failures
  are kept as `failed_validation` with the reason and never show in the approve list. Cluster by
  embedding at cosine 0.9 or more against open drafts.
- **C-06 and C-07 approval.** Never automatic. Every pattern approval and retirement issues the
  next version through the `risky_pattern_versions` ledger (its primary key issues each version
  once, approvals and retirements alike; a Codex finding in Phase B). In one transaction: insert
  the ledger row `current + 1`, update the pattern (`approved_in_version` or
  `retired_in_version` to that version), call `record_audit` (X40). A race is a unique violation;
  map it to 409 (X33). An edited draft re-runs validation before approve is allowed (X31). A rule
  draft goes through C6 `create_rule`.
- **C-08 jobs.** Embedding backfill for `risky_behavior_events` rows with `NULL` embeddings
  (index `risky_behavior_events_backfill_idx` exists), outside any M2 transaction, with the same
  embedding validation as `lookup` (768 finite float32 values). Hourly `purge_expired_trace_back`
  through C6.
- **C-09 C3.** `get_forensics` and `get_attack_family_counts` in
  `app/firewall/forensics_read.py`, exact shapes from `contracts/firewall_read.py`. No secret, no
  trace-back fields (X39).
- **C-10 admin router.** Every route behind `require_role("firewall_admin")`: 401 without a
  token, 403 for student and teacher (X38, E-55). 409 on an already decided or expired ticket
  (E-46, X34). Levels go through C8 with the X35 checks; rules through C6 with the X36 operator
  checks; deprecation never deletes (X37).

## Frontend / full-stack work

Phase C adds no new screens (Phase D wires them to the API). If you touch `frontend/app/admin/`,
use the Playwright MCP server and actually look at what's rendering. Don't infer correctness from
the code. A dev server already signed in as a firewall admin was used in Phase B.

Make sure to test with Playwright

## Harness-os pipeline

Use the harness-os MCP server for every unit of work: Constitution → Specification → Test Suite →
Generate Code → Code Review. Don't skip stages or generate code before its Test Suite stage
exists. Register a spec per unit, for example a domain spec for the draft and pattern state
machines (pending → failed_validation / approved / rejected; candidate → approved → retired) so
`generate_tests` can enumerate the transitions. When `request_review` asks for a reviewer agent,
run it, or record clearly that the review was done inline. Also run a Codex cross-review
(`codex exec --sandbox read-only`) on the phase's changes and fix every finding you verify.

## Code review

During the Code Review stage, review the uncommitted changes against both the plan and the PRD
with the discipline of an experienced QA/QC engineer. Explicitly check correctness, performance
and security before considering the step done; don't just check that it runs.

- **Secrets:** gitleaks clean (PRD §15.2, I-5). Synthetic data only. A test asserts the real
  secret never appears in `forensic_reports`, drafts, logs or Gemini prompts (X24).
- **SAST:** Ruff with the bandit (`S`) rules, plus semgrep on `backend/app/firewall/`,
  `backend/app/workers/`, `backend/app/admin/` and `backend/migrations/`. Use
  `--no-git-ignore`, or semgrep skips untracked files (Phase B lesson). Bound parameters only.
- **SCA:** `pip-audit` and `npm audit`.
- **Fuzzing:** Hypothesis on the forensic and draft parsers (only a valid model or a raised
  error), on draft validation (a draft that matches a benign fixture never reaches `pending`), and
  on the admin request models. Use `hypothesis.event()` to prove both outcomes are reached; in
  Phase B the first fuzz version never produced a match.
- **Concurrency:** two worker instances on one backlog (X20), two admins approving one draft
  (X33), an approval racing a retirement (one ledger version), a ticket decided at its expiry.
- **Test strength:** each negative test must fail for the reason it names. In Phase B a CHECK
  test passed for the wrong reason (another constraint rejected the row first). Give the row
  otherwise-valid data and add a passing control case.
- **DAST:** now applicable. Run an authenticated and unauthenticated pass over every `/admin`
  route (role matrix, 401/403/409, oversized and malformed bodies).
- **Codex** have codex runs (background) a loop test until both Claude and Codex agree with all changes and found no more issues.
## Don't miss these (easy to under-implement)

- **The prompt is data.** Event text, student commands, tool arguments and drafts produced by the
  model are untrusted. Delimit them for Gemini, and never let them change the attack family list,
  the schema or the validation result (X25).
- **Redact before sending, not after.** The secret must not reach Gemini at all, not just be
  scrubbed from the stored report.
- **At most one draft, exactly once.** A retried event must not produce a second report or draft;
  rely on the unique indexes and handle the conflict.
- **Validation is re-run on every edit.** Approve must re-check, not trust a stored `pending`.
- **No network inside someone else's transaction.** The backfill and Gemini calls happen outside
  M2's transactions and outside the claim's row lock where possible.
- **Running sessions are pinned.** Approvals affect new sessions only (E-57, I-7). Test both a new
  session and the running one.
- **Stay in your lane.** Don't edit `contracts/`, `ports.py`, `main.py` or M2's tables. Raise a
  contract change as a PR for all four machines.

Update `doc/PROGRESS-M3-AFF-Intel-Admin.md` as you go throughout. It should always reflect
current, accurate status. Don't commit or push unless I ask.
