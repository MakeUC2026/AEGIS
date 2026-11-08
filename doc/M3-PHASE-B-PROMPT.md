# Phase B Prompt: Machine M3 (Schema, Risky History Lookup, Judge), Gate 1

I'm working on **Injection Arena (repo: AEGIS)**, a security-education platform for MakeUC 2026.
Subsystem 1, the Arena, lets students attack a tool-calling Gemini chatbot at three levels (Off,
Basic, Strict) behind the Agent Firewall Framework (AFF). Subsystem 2, the Classroom, gives
teachers session reviews and students a quiz. The full PRD is `doc/PRD-Injection-Arena-Unified.md`
(v3.1). Read it in full before doing anything else. It is the source of truth for every
requirement below. This prompt sets the *process*, not the spec.

This machine is **M3**: AFF intelligence (risky history, the Gemini judge, the forensic worker,
drafts, the firewall admin console). The plan is `doc/PROGRESS-M3-AFF-Intel-Admin.md`. Read it in
full as well, including the **Phase A recheck** section and the §10 defaults. Its §0 binds every
machine: write only M3-owned files and tables (§0.1, §0.2), keep the C7 shapes exactly as
`backend/app/contracts/sentinel.py` defines them, follow the migration layout in §0.4 and the
invariants in §0.7. Phase A is done (A-07 waits only on `next build`). This prompt covers
**Phase B (B-01 to B-07)**, which ends at **Gate 1 (H8)**: the `0004` migration merged and the C7
shapes signed off with M2.

## Step 1: Plan check

Do not invent a new breakdown. Phase B in the plan's §4 is the plan. Before you start, check
B-01 to B-07 against PRD §7.3 layer 2 and 3, §7.5, §10.1, §14.7, §15.1 and §16.2 once more. If
you find a gap, fix the plan first and note it in the Progress log. For each item, list the edge
cases from the plan's §5 that it closes. At minimum:

| Item | Cases |
| --- | --- |
| B-01 | `alembic upgrade heads` on an empty DB; the migration layout in §0.4 |
| B-02 | E-42, E-43, E-50 (lookup side), E-51, M3-X02, X03, X06, X07, X08, X09, X10, X15 |
| B-03 | M3-X11 |
| B-04 | E-43, X15 (the version a new session pins) |
| B-05 | M3-X16, X17, X18 (with M2), X19, E-09 and E-52 (M3 side) |
| B-06 | AC-7 (lookup under 50 ms p95) |
| B-07 | E-50, E-51 end to end, AC-1, X-1, X-2 |

Treat every row as a required automated test, not optional polish.

## Step 2: Implement the plan

Work through B-01 to B-07 in order. For each step:

1. Implement it.
2. Run a verification loop and confirm the output matches expectations.
3. If it doesn't, debug and iterate before moving on. Don't proceed on a failing or unverified
   step.
4. Record progress in the plan: `[x]` only when done **and** tested, `[~]` in progress, `[!]`
   blocked with the reason. Add a Progress log row at Gate 1. Add a §10 entry wherever the PRD
   left a detail open. Examples: column types and indexes, the HNSW parameters, the CTE shape,
   the embedding cache size and lifetime, how the candidate is de-duplicated, and the judge
   model ID.

**Pushing is outward-facing.** B-01 is a seam merge to `master` and B-07 uses the shared
`integration` branch. Ask me before every push or PR.

## Backend work

Before implementing any backend logic, set up its integration tests first. Run them after every
significant change, not just at the end of a phase. Integration tests use a real TimescaleDB
container with pgvector (`timescale/timescaledb-ha:pg16` from `docker-compose.yml`) and
`ScriptedLLM` for embeddings and the judge, so they are deterministic (I-6). If the sandbox
blocks Docker, say so and mark the affected items `[!]`. Never report a DB test as passing
without having run it.

- **B-01 `0004_firewall_intel` migration.** Fixed revision ID `0004_firewall_intel`,
  `down_revision = "0001_foundation"`, branch label `fw_intel`. Tables:
  - `risky_tool_patterns`: `status` in candidate, approved or rejected; `approved_in_version`;
    `retired_in_version`; source event; `conditions` JSON.
  - `risky_behavior_events`: a hypertable on `time` with the PRD §7.5 columns plus `shadow`,
    `input_text_hash`, and `input_embedding vector(768)` with an HNSW `vector_cosine_ops` index.
  - `forensic_reports`.
  - `drafts`: `status` in pending, failed_validation, approved or rejected; validation result;
    cluster ID; embedding.

  No foreign keys except to `users.id` (§0.2 rule 5). Store M2 IDs as plain `text` or `uuid`.
  Use CHECK constraints for the status enums. Add a unique index so one approval version can't be
  issued twice; C-06 and M3-X33 rely on it. Test: `alembic upgrade heads` (plural) and
  `downgrade` on an empty TimescaleDB with pgvector, alongside M1's `0002_arena`.
- **B-02 `lookup` (C7).** One SQL round trip per checked item, written as a CTE:
  - The approved patterns for this tool with `approved_in_version <= item.pattern_version` and
    (`retired_in_version` is null or `> item.pattern_version`), so the pinned version decides
    (E-43, M3-X15, I-7). Candidate and rejected rows never apply (E-42).
  - The count of this user's **non-shadow** events on the same tool in the last 7 days (M3-X02,
    X03, X07, X08).
  - Whether this user has any earlier non-shadow divert.
  - The top-3 nearest embeddings across **all** users, shadow rows included (the similarity
    corpus, plan §10).

  Match pattern conditions in Python with `risky_patterns.match`, re-validating stored
  `conditions` through `PatternSpec`. Then score with `score_signals`. The input embedding comes
  from `GeminiClient.embed` with a 2 s timeout, cached by text hash for `record_behavior`. An
  input check (no tool) skips the user-tool count (M3-X06). Any DB error, embedding error or
  timeout raises `RiskyHistoryError` (M3-X09, X10, I-2). Never return partial signals.
- **B-03 `record_behavior` and `add_candidate`.** Insert inside the caller's connection and
  transaction. Make **no** network calls (M3-X11, PRD §15.1). The embedding comes from the B-02
  cache, else `null` (the C-08 backfill fills it). Store `input_text_hash`, never extra copies of
  the raw text. `add_candidate` writes `status = candidate` and skips a duplicate (same tool and
  args hash) instead of adding a second row. Test that a rollback by the caller leaves no row.
- **B-04 `current_pattern_version()`.** The highest `approved_in_version`, or 0.
- **B-05 judge factory.** `app.firewall.judge:create` (the key `ports.py` already expects) builds
  `Judge` with M1's `GeminiClient`, the shared budget, and the Flash model ID pinned by M1 (A-16).
  Read the model ID from settings; don't hard-code it. Also add
  `app.firewall.risky_history:create`. Both must resolve through `ports.py` with `risky` and
  `judge` removed from `AEGIS_USE_FAKES`. Keep the Phase A guarantees: the judge only raises
  (I-1), every failure raises `JudgeError` or `JudgeTimeout`, and the delimiters are stripped
  without regard to case.
- **B-06 performance.** Seed 10,000 `risky_behavior_events` rows (with embeddings) and 200
  patterns, then measure the lookup over at least 200 runs without the embedding call. p95 must
  be under 50 ms (PRD §7.5). Record p50, p95 and the `EXPLAIN ANALYZE` plan in the Progress log.
  If it misses, fix the index or the query, not the target.
- **B-07 hand-off.** Give M2 the C7 implementations on the `integration` branch (ask before
  pushing). Confirm E-50 (a retry in a new session scores 15 user-tool points and gets a stricter
  decision) and E-51 (similarity ≥ 0.85 records +25 in `score_breakdown.similarity`) pass end to
  end with M2's Gatekeeper. Also assert M3-X18 with M2: an injected judge answer of risk 0 never
  lowers the final score below the rule score.

## Frontend / full-stack work

Phase B has no new screens. If you touch `frontend/app/admin/`, use the Playwright MCP server and
actually look at what's rendering; don't infer correctness from the code. Close the one Phase A
carry-over: run `next build` on a shell that can read `frontend/.env*`, then tick A-07.

## Harness-os pipeline

Use the harness-os MCP server for every unit of work: Constitution → Specification → Test Suite →
Generate Code → Code Review. Don't skip stages or generate code before its Test Suite stage
exists. When `request_review` asks for a reviewer agent, run it, or record clearly that the
review was done inline.

## Code review

During the Code Review stage, review the uncommitted changes against both the plan and the PRD
with the discipline of an experienced QA/QC engineer. Explicitly check correctness, performance
and security before considering the step done; don't just check that it runs.

- **Secrets:** gitleaks clean (PRD §15.2, I-5). Synthetic data only in seeds and tests.
- **SAST:** Ruff with the bandit (`S`) rules, plus semgrep on `backend/app/firewall/` and
  `backend/migrations/`. Bound parameters only. No f-string SQL, including in the vector query.
- **SCA:** `pip-audit` and `npm audit`.
- **Fuzzing:** Hypothesis on `lookup` inputs (any `CheckedItem` text, tool, args and pinned
  version). Properties: it either returns valid signals or raises `RiskyHistoryError`, never
  anything else. Points never drop below 0. A pattern above the pinned version never applies.
- **Concurrency:** two lookups and a `record_behavior` running together. An approval racing a
  session start, where the session must see one consistent version.
- **DAST:** still not applicable. The admin API arrives in C-10.

## Don't miss these (easy to under-implement)

- **Pinned version, both ends.** Approved at or below the pin **and** not retired at or below the
  pin. Test a pattern approved after the session started and one retired after it started.
- **Shadow rows.** Excluded from user-tool and prior-divert points, included in similarity.
- **Fail closed, no fallbacks.** No "similarity null" on embedding failure unless the team agrees
  and it is recorded (plan §10).
- **No network inside M2's transaction** (`record_behavior`, `add_candidate`).
- **`null` vs `0`.** A layer that did not run is `null` in `score_breakdown` (PRD §10.1). In
  Strict, layer 2 either runs or raises.
- **Open `[!]` items from the recheck.** `policy/` and `fixtures/` must be in the backend image
  before the judge factory goes live (ask M1). The `eslint-config-next` downgrade in
  `frontend/package.json` is not M3's. Ask M1 to add `.claude-flow/` to `.gitignore`. The signal
  weight range (5–60 in the plan, 0–100 in M1's contract) needs an answer before D-01. Check the
  status of each and update the plan.
- **Gemini schema keywords.** The draft schema uses `oneOf` and `discriminator`. That gets
  checked in C-02, not here, but don't build anything in B that depends on it.
- **Stay in your lane.** Don't edit `contracts/`, `ports.py`, `main.py` or M2's tables. Raise a
  contract change as a PR for all four machines.

Update `doc/PROGRESS-M3-AFF-Intel-Admin.md` as you go throughout. It should always reflect
current, accurate status. Don't commit or push unless I ask.
