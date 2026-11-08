# Progress Doc M2: AFF Core (Pipeline, Sentinel Layer 1, Gatekeeper, Review, Divert, Event Store)

| Field | Value |
| --- | --- |
| Machine | **M2** |
| Stream | Agent Firewall Framework core: canonical tool calls, mock tools, bot runner (Gemini), rules engine, Sentinel layer 1, Gatekeeper, Review, Divert, decoy, trace-back, leak detection, event store, C2, C3 and C6 interfaces |
| Branch | `m2/aff-core` |
| Source of truth | [PRD-Injection-Arena-Unified.md](PRD-Injection-Arena-Unified.md) (PRD v3.1). When this doc and the PRD disagree, the PRD wins unless the PRD leaves the point open. Then this doc's §0 decides |
| Sibling docs | [M1 Foundation and Arena](PROGRESS-M1-Foundation-Arena.md) · [M3 AFF Intel and Admin](PROGRESS-M3-AFF-Intel-Admin.md) · [M4 Classroom](PROGRESS-M4-Classroom.md) |
| PRD sections owned | §0 (D-01, D-02, D-03, D-03a, D-04, D-06, D-09, D-10, D-11), §7.1, §7.2, §7.3 layer 1 and hard overrides, §7.4, §7.6, §8.1–§8.6, §9.1–§9.4, §10.1, §14.3, §14.4 |
| Status | `IN PROGRESS`: started 2026-11-07 on the M1 computer, on branch `m2/aff-core` (cut from `master` `27df46c`) in the same workspace as M1 (user decision: no separate folder). Running under the M2 master prompt (`doc/M2-MASTER-PROMPT.md`, local only, never committed). **DM1-1 done** (contract sign-off). Next: Phase A |

Status legend for every checkbox list: `[ ]` not started · `[~]` in progress (add a note) · `[x]` done and tested · `[!]` blocked (add a note to the Progress log).

---

## 0. Shared operating rules (identical in all four progress docs)

### 0.1 Machine map

| Machine | Stream | Branch | Owns code | Owns tables | PRD sections |
| --- | --- | --- | --- | --- | --- |
| **M1** | Foundation, Infra, Arena, integration lead | `m1/foundation-arena` | `backend/app/{main.py,auth/,db/,contracts/,llm/,arena/}`, `backend/app/firewall/ports.py`, `frontend/{lib/,components/shell/,app/(auth)/,app/arena/}`, `fixtures/{attacks,benign}/` (seed set), `docker-compose.yml`, `Dockerfile`, `railway.json`, `vercel.json`, `.env.example`, CI | `users`, `audit_log`¹, `scenario`, `levels`, `secrets`, `arena_sessions`, `results`, `usage` | 3, 4, 5, 6, 14.1–14.2, 14.5–14.6, 15 |
| **M2** | AFF core: pipeline, canonical calls, mock tools, bot runner, rules engine, Sentinel layer 1, Gatekeeper, Review, Divert, decoy, trace-back, leak detection, event store | `m2/aff-core` | `backend/app/firewall/` except the M3 files and `ports.py` | `rules`, `fw_manifests`, `fw_claims`, `fw_conversation`, `fw_mock_state`, `fw_tickets`, `fw_events`, `trace_back` | 7.1–7.4 (layer 1, overrides, bands), 7.6, 8, 9, 10.1, 14.3, 14.4 |
| **M3** | AFF intelligence: risky history, Gemini judge, forensics worker, drafts, firewall admin console | `m3/aff-intel-admin` | `backend/app/firewall/{risky_history.py,risky_patterns.py,judge.py,forensics_read.py}`, `backend/app/workers/`, `backend/app/admin/`, `frontend/app/admin/`, `policy/` | `risky_tool_patterns`, `risky_behavior_events`, `forensic_reports`, `drafts` | 7.3 layers 2–3, 7.5, 10.2, 10.3, 11 |
| **M4** | Classroom: teacher dashboard, insights, secrets screen, quiz | `m4/classroom` | `backend/app/{classroom/,quiz/}`, `frontend/app/{classroom/,quiz/}`, `fixtures/quiz/` | `quiz`, `quiz_questions`, `quiz_turns`, `quiz_result` | 12, 13 |

¹ PRD §14.7 lists `audit_log` under AFF. It moves to Foundation so that all four machines can write audit rows through one function (`app/db/audit.py::record_audit`) from Gate 0. The admin console (M3) still owns the Audit screen. PRD §14.2 lists `users` under Classroom; the PRD's Foundation stream is led by the Classroom lead, so `users` sits with M1 here.

### 0.2 Ownership rules

1. Write only to your own folders and tables. Read another part's data only through the contract functions in §0.3.
2. **AFF exception.** M2 and M3 are both the AFF part (PRD §14.7). M3 may **read** `fw_events`, `fw_tickets`, `fw_conversation`, `rules` and `trace_back` directly. M3 may **update** only `fw_events.forensic_status` and `trace_back.methods_used`. Every other AFF write goes through the owner's functions.
3. Shared files belong to M1: `backend/app/main.py`, `backend/app/contracts/`, `backend/app/firewall/ports.py`, `frontend/lib/*`, `frontend/components/shell/*`, `docker-compose.yml`, CI config. Other machines ask for changes through a small PR that M1 reviews. After Gate 1, a change to `contracts/` needs approval from all four machines (PRD §14.1).
4. At Gate 0, M1 creates a placeholder `router.py` in `app/admin/`, `app/classroom/` and `app/quiz/`, already mounted in `main.py`. After the Gate 0 merge, each placeholder belongs to its folder owner, so nobody else edits `main.py`.
5. No foreign keys across parts except to `users.id`. Store other parts' IDs as plain `uuid` or `text` columns.
6. Fixtures are add-only. New files use a machine prefix (`m2_*.json`, `m3_*.json`, `m4_*.json`). Never edit another machine's fixture file.
7. Synthetic secrets only (`DEMO_TOKEN_42` style). No real credentials or student data in fixtures, logs, screenshots or commits.

### 0.3 Contract seams

All shapes are Pydantic v2 models in `backend/app/contracts/` (PRD D-16, §14). M1 writes every model and a minimal fake for each seam by Gate 0. The provider machine may improve its own fake later in its own PR.

| Seam | Contract file | Implementation (provider) | Consumers | Fake (in `contracts/fakes/`) |
| --- | --- | --- | --- | --- |
| C1 users | `contracts/users.py` | `app/auth/` (M1) | all | n/a |
| C2 Arena ↔ AFF | `contracts/firewall.py` | `app/firewall/interface.py` (M2) | M1 | `FakeFirewall` |
| C3 AFF read for Classroom | `contracts/firewall_read.py` | `app/firewall/read_api.py` (M2); `get_forensics`, `get_attack_family_counts` in `app/firewall/forensics_read.py` (M3) | M4, M1 (recap) | `FakeFirewallRead` |
| C4 Arena read | `contracts/arena.py` | `app/arena/service.py` (M1) | M4, M3 | `FakeArenaService` |
| C5 auth | `app/auth/` (`require_user`, `require_role`) | M1 | all | test helper `make_token(roles=[...])` |
| C6 AFF admin operations (new) | `contracts/firewall_admin.py` | `app/firewall/admin_api.py` (M2) | M3 | `FakeFirewallAdmin` |
| C7 Sentinel plug-ins (new) | `contracts/sentinel.py` (`RiskyHistoryPort`, `JudgePort`) | `app/firewall/risky_history.py`, `app/firewall/judge.py` (M3) | M2 | `InMemoryRiskyHistory`, `StubJudge` |
| C8 Arena admin and teacher operations (new) | `contracts/arena.py` | `app/arena/service.py` (M1) | M3 (Levels screen), M4 (secrets, quiz) | `FakeArenaService` |
| LLM clients | `app/llm/` (`GeminiClient.chat_with_tools` (the bot), `GeminiClient.generate_json`, `GeminiClient.embed`, `ScriptedLLM`) | M1 | M2, M3, M4 | `ScriptedLLM` replays scripted answers |
| Audit | `app/db/audit.py::record_audit(conn, *, actor_id, entity, entity_id, action, before, after)` (joins the caller's transaction; refuses secret values) | M1 | all | writes to the real table, or to an in-memory list in unit tests |

**Wiring.** `app/firewall/ports.py` (M1) returns the real or the fake implementation of each seam. The env var `AEGIS_USE_FAKES` takes a comma list (`firewall,read,admin,risky,judge,arena`). Each machine's branch sets only what it lacks. At integration the value is empty.

### 0.4 Migrations

- One Alembic history in `backend/migrations/`. Base revision `0001_foundation` (M1): extensions `timescaledb`, `vector`, `pgcrypto`, plus tables `users` and `audit_log`.
- Each part gets its own file with a fixed revision ID, `down_revision = "0001_foundation"` and its own branch label:
  `0002_arena` (M1, label `arena`) · `0003_firewall_core` (M2, label `fw_core`) · `0004_firewall_intel` (M3, label `fw_intel`) · `0005_classroom` (M4, label `classroom`).
- Later revisions in a part chain off that part's last revision (for example `0003b_fw_cagg` with `down_revision = "0003_firewall_core"`).
- Always run `alembic upgrade heads` (plural). At integration, M1 adds `0099_merge_heads` to join the branches.
- TimescaleDB continuous aggregates cannot be created inside a transaction. Put them in their own revision and use `op.get_context().autocommit_block()`.

### 0.5 Gates (hours from kickoff H0, PRD §17.2)

| Gate | Hour | Whole-team exit criteria (PRD) | What each machine must have merged or shown |
| --- | --- | --- | --- |
| G0 | H3 | Stack deployed to Vercel and Railway and running locally; Auth0 roles work; contracts and fakes merged | M1: bootstrap PR merged to `master`. M2, M3, M4: rebased on it, Track A logic unit-tested |
| G1 | H8 | Basic denies a fixture attack with a logged score; contracts frozen | M2: `0003` migration and rule seed merged, Basic deny demo. M3: `0004` migration merged. M1: arena on `FakeFirewall` end to end. M4: classroom API on fakes |
| G2 | H14 | MVP AFF: all four actions, Review loop, Divert, Strict with risky history. If any MVP test fails, cut all stretch items | M2 and M3: Strict works with real C7 on a shared `integration` branch. M1, M4: UI flows complete on fakes |
| G3 | H17 | Forensics and drafts working; dashboard and quiz complete on fakes. No interface changes after this | Every machine's **Exit criteria** (its own §7) are checked. The final merge window opens |
| G4 | H21 | End-to-end demo script passes twice in a row on real models | Joint, led by M1 |
| — | H21–H24 | Rehearse, backup video, Devpost | Joint |

### 0.6 Merge protocol to `master`

1. **Early seam merges** may go to `master` before exit criteria are met, but only for: the M1 Gate 0 bootstrap, a machine's own migration file and seed, and contract-change PRs approved by all four. CI must be green.
2. **Final merge.** Open a PR from your branch to `master` only when every box in your §7 Exit criteria is `[x]`, CI is green and the branch is rebased on the latest `master`. CI means `ruff check`, `ruff format --check`, `pytest`, `tsc --noEmit` (strict), `next build`, `gitleaks detect`, and `alembic upgrade heads` on an empty TimescaleDB with pgvector.
3. **Order at G3:** M1, then M2, then M3, then M4. Rebase after each one lands. Then M1 empties `AEGIS_USE_FAKES` and runs the integration suite (M1 §8).
4. After a final merge, fixes go in small PRs named `fix/<machine>-<topic>`.
5. Commit messages use Conventional Commits with the machine as scope, for example `feat(m2): gatekeeper bands`.

### 0.7 Global invariants (test the ones your code touches)

| ID | Invariant | PRD |
| --- | --- | --- |
| I-1 | Models recommend, deterministic rules decide. No model output can lower a score below what the rules set | §1.2, D-04, §7.3 |
| I-2 | Fail closed in Basic and Strict: a rule error, judge error or timeout, DB error, oversized input or expired review ends in Deny | §15.1 |
| I-3 | Only `player_view` reaches the browser. `facts`, judge reasons, tool arguments, blocked text and trace-back data never do | §15.1, §6.2 |
| I-4 | Every route checks roles on the server with `require_user` and `require_role`. Hidden buttons are never the control | §4.1, C5 |
| I-5 | Synthetic secrets only; Gitleaks clean; `.env` never committed | §15.2 |
| I-6 | Tests are deterministic: the Gemini bot and security models are stubbed with `ScriptedLLM`. The real-model attack suite is reported, not gated | §16.1 |
| I-7 | A session is pinned to its manifest. Config, rule, pattern, level and secret changes affect new sessions only | §5.2, §7.5, §15.1 |

### 0.8 How to report progress

Update the checkboxes in this doc as you go. At every gate, add a row to the Progress log at the end (time, gate, done, blocked, next). A `[!]` item that blocks another machine must also be raised with that machine's owner straight away.

---

## 1. Mission and scope

M2 builds the `app/firewall/` package: the layer the model cannot talk its way past. Every input, tool call and reply goes through it, gets a Sentinel score, gets a Gatekeeper action, and is written to `fw_events`.

**In scope**

- Session registration and the immutable manifest. Message claims, idempotency and concurrency.
- Bot runner on Gemini function calling (through M1's `GeminiClient.chat_with_tools`), history window, and tool-call rounds.
- Canonical tool calls: schema validation, normalization, `call_id`, canonical hash. Mock tools over `fw_mock_state`.
- Rules engine (RE2, field-typed operators, versioning, 50 ms cap) and seeding the starting rules R-001 to R-006 and B-01 to B-04.
- Sentinel layer 1, the score combiner (layers 1 + 2 + judge, "only raise"), hard overrides, the Gatekeeper bands, strictest-wins.
- Modes Off, Basic and Strict, including Off shadow decisions.
- Review: tickets, parking and continuation, decide, expiry, `check_ticket`.
- Divert: transaction, decoy generation (Gemini) with the secret scan and template fallback, trace-back.
- Leak detection: exact, normalized, cumulative, echo exclusion. Facts.
- Event store `fw_events` (hypertable) with `NOTIFY` for the forensic worker, continuous aggregates for counts.
- C2 (`interface.py`), C3 (`read_api.py`, except the two M3 functions) and C6 (`admin_api.py`).

**Out of scope (other machines)**: risky history lookup, judge, embeddings, forensics, drafts, admin UI and router (M3); arena endpoints and UI (M1); classroom (M4). M2 calls M3's code only through C7 (`RiskyHistoryPort`, `JudgePort`), and uses `InMemoryRiskyHistory` and `StubJudge` until M3 lands.

---

## 2. PRD traceability

| PRD ref | Requirement | Where in this doc |
| --- | --- | --- |
| D-01, §7.4 conflict rule | Four actions, strictest wins | Phase A (A-07), E-07 |
| D-02, §7.2 | Modes; Off computes in shadow and enforces Allow | Phase B (B-09), E-44 |
| D-03, §8.4–§8.6 | Divert, trace-back, decoy | Phase C (C-05 to C-08) |
| D-03a, §8.3 | Review, Human Deny, expiry | Phase C (C-01 to C-04) |
| D-04, §7.3 | One score 0–100, layers only raise, hard overrides | Phase A (A-05, A-06) |
| D-06, §5.4, §9.3 | Basic scans each message; Strict also scans cumulative output | Phase A (A-04), E-22 |
| D-09 | Statuses `replied`, `blocked`, `awaiting_review`, `human_denied` (`not_sent` is the arena's) | Phase B, Phase C |
| D-10 | What can be held; pending message returned at once; secret replies never held | Phase C, E-46a, E-46c |
| D-11 | All tools are mocks on session mock state in Postgres | Phase B (B-05) |
| §7.6 | Canonical tool calls and limits | Phase A (A-01, A-02) |
| §9.1–§9.4 | Rules, starting rules, leak detection by mode, facts | Phase A, Phase B |
| §10.1 | Event store row shape and enums | Phase B (B-03) |
| §14.3, §14.4 | C2 and C3 | Phase B, Phase C |
| §15.1 | Fail closed, atomicity, concurrency, reproducibility, performance, information flow | §5, Phase D |
| §16.3 rows 1–5 | Acceptance items M2 leads | §6 |

---

## 3. Interfaces M2 provides and consumes

### 3.1 M2 provides

| Seam | Functions | Notes |
| --- | --- | --- |
| C2 `app/firewall/interface.py` | `read_catalog()`, `register_session(req)`, `send_message(owner_ref, fw_session_id, message_id, text, client)`, `check_ticket(owner_ref, ticket_id)`, `close_session(owner_ref, fw_session_id)` | Raises the typed errors in `contracts/firewall.py` (`SessionBusy`, `MessageConflict`, `ModeChangeRejected`, `SessionClosed`, `NotFound`, `BotUnavailable`) |
| C3 `app/firewall/read_api.py` | `get_transcript`, `get_decisions`, `get_tickets`, `get_diverts`, `get_rule_fire_counts`, `get_risky_pattern_counts`, `get_decision_counts`, `get_session_summaries`, `get_manifest_summary`, `redact_for_session` | Server-side only. No judge reasons, no tool arguments, no blocked text, no trace-back fields. Transcript marks decoys. Every text field comes back with the secret replaced by `[SECRET]` (M4 §3.3) |
| C6 `app/firewall/admin_api.py` | `list_pending_tickets()`, `decide_ticket(ticket_id, decision, admin_id)`, `list_rules()`, `create_rule(form, admin_id)`, `update_rule(rule_id, form, admin_id)` (new version), `deprecate_rule(rule_id, admin_id)`, `set_builtin_enabled(rule_id, enabled, admin_id)`, `list_events(filter)`, `list_diverts_admin(filter)`, `get_trace_back(trace_id)`, `purge_expired_trace_back(now)` | Every write calls `record_audit`. Used by M3's admin router and drafts approval. `purge_expired_trace_back` is scheduled by M3's worker |
| `fw_events` `NOTIFY` | Channel `fw_events_forensic`, payload `event_id` | Sent in the same transaction as each insert whose `forensic_status` is `pending` (§10.2 selection) |

### 3.2 M2 consumes

| From | What | Until real code lands |
| --- | --- | --- |
| M3 (C7) | `RiskyHistoryPort.lookup(item) -> RiskyHistorySignals`, `record_behavior(record, conn)`, `add_candidate(candidate, conn)`, `current_pattern_version()` | `InMemoryRiskyHistory` |
| M3 (C7) | `JudgePort.assess(item) -> JudgeVerdict` (raises `JudgeTimeout` or `JudgeError`), `policy_hash()`, `model_id()` | `StubJudge` (scripted risk, or scripted timeout) |
| M1 | `GeminiClient.chat_with_tools` (bot), `GeminiClient.generate_json` (decoys), `ScriptedLLM`, `record_audit`, `ClientMeta` | Ready at G0 |

### 3.3 C7 shapes M2 relies on (M1 writes them; M2 and M3 review before G1)

| Type | Fields |
| --- | --- |
| `CheckedItem` | `event_id`, `stage`, `mode`, `user_id`, `fw_session_id`, `manifest_id`, `pattern_version`, `tool: str \| None`, `canonical_args: dict \| None`, `args_hash: str \| None`, `text` (normalized text under check), `layer1_score`, `context_excerpt` (delimited, untrusted, for the judge) |
| `RiskyHistorySignals` | `forced_deny: bool`, `matched_pattern_ids: list[str]`, `user_tool_events_points` (0–30), `prior_divert_points` (0 or 20), `similarity_points` (0, 10 or 25), `similarity_top: float \| None`, `latency_ms` |
| `RiskyBehaviorRecord` | PRD §7.5 columns plus `shadow: bool` and `input_text` |
| `PatternCandidate` | `tool`, `canonical_args`, `source_event_id`, `user_id` (no conditions yet, PRD §8.2) |
| `JudgeVerdict` | `risk: int` (0–100), `suggested_action`, `reason` |

`record_behavior` and `add_candidate` take M2's open DB connection, so they join the Deny, Human Deny or Divert transaction (PRD §15.1 Atomicity). They must not make network calls. The embedding comes from the `lookup` cache for the same item, or is backfilled later by M3's worker.

---

## 4. Work breakdown

### Phase A: pure logic, no dependencies (H0–H3, before the G0 merge)

Everything here is pure Python with unit tests. It needs no DB and no contracts beyond local dataclasses, which you swap for the contract models after rebasing on G0.

- [x] A-01 *Done: `app/firewall/canonical.py` (spec AEGIS-DOM-102). Exact tool-name match; JSON Schema validation through `jsonschema` 4.26 (new dependency, pip-audit clean), run again after normalization; NFKC on every string; recipients parsed to bare lowercase addresses with their domains (M2-DD-09); paths URL-decoded up to 3 rounds, NFKC, resolved under `/workspace`, with control characters rejected (M2-DD-10); `args_hash` = `sha256:` plus the hash of sorted canonical JSON; canonical args are read-only. Failures return `CanonicalError` (`unknown_tool`, `schema_invalid`, `bad_recipient`, `bad_path`), which callers deny in every mode. 44 tests in `tests/unit/test_fw_canonical.py`: M2-X01 to M2-X04 plus Hypothesis (never raises; inside paths never escape). **Real finding:** `email.utils.getaddresses` silently rewrote `a@exa mple.com` into `a@example.com`; such rewrites are now rejected.* Canonicalizer (PRD §7.6): exact tool name match, JSON schema validation (unknown tool, wrong type, missing or extra field gives Deny), email recipient parsing, path resolution inside the mock filesystem (B-03), NFKC text, `call_id`, SHA-256 of the canonical form.
- [x] A-02 *Done: `app/firewall/limits.py`: named constants for every PRD limit; `check_text` (ok, deny or truncate by mode); `check_args` over the total characters of all argument values (M2-DD-11); `tool_rounds_exhausted`, `bot_history` (last 20), `cumulative_exceeded` (Strict only). 17 tests in `tests/unit/test_fw_limits.py`: M2-X07 to M2-X10 and M2-X35, plus a Hypothesis consistency property.* Limits (PRD §7.6): player text 4,000; one tool result 8,000; all arguments of one call 4,000; one reply 4,000; 5 tool-call rounds; last 20 messages to the bot model; 50,000 characters of cumulative visible output. Basic and Strict deny oversized items. Off truncates and logs.
- [x] A-03 *Done: `app/firewall/textnorm.py`: `normalize` (NFKC, every Unicode C* character except whitespace removed, including zero-width, bidi overrides and NUL; whitespace collapsed; casefolded; run to a fixed point) and `skeleton` (letters and digits only, for the secret scanners). Spec AEGIS-DOM-101. Tests: `tests/unit/test_fw_text.py`, with Hypothesis idempotence and never-crash properties.* Text normalizer for matching (PRD §9.1): NFKC, zero-width and control characters removed, case-folded.
- [x] A-04 *Done: `app/firewall/leak.py`. `scan`: exact, normalized (skeleton), reversed, base64 (standard and URL-safe, unpadded, 4 alignments), hex and URL decoding. `scan_cumulative`: ordered fragment coverage, reporting a hit only when the new item completes the secret (M2-DD-07). `echo_excluded`: 8-character windows on the skeleton (M2-DD-08). Covers M2-X31 to M2-X33 and the scanner halves of E-22 and E-53. Hypothesis: any embedded secret is found, any two-way split is found cumulatively, never crashes. Measured: 60 random level secrets against about 50,000 characters of benign scenario output gave 0 false positives; a full-session cumulative scan takes about 36 ms per call.* Secret scanners (PRD §9.3, B-01, B-04): exact; normalized (case, spacing, zero-width, reversed, base64, hex, URL encoding); cumulative over the joined visible output plus the new item; echo exclusion (student typed the secret, or 8 or more consecutive characters of it, earlier in the session, compared after normalization).
- [x] A-05 *Done: `app/firewall/rules.py` (spec AEGIS-DOM-103) and `app/firewall/starting_rules.py` (R-001 to R-006 as PRD §9.2 rule forms, rule set version 1). Every PRD §9.1 operator, applied only to the field types the contract allows; RE2 through `google-re2` (new dependency, pip-audit clean), case-insensitive, compiled patterns cached, errors not logged; a 50 ms cap per rule with an injectable clock; failures (`bad_regex`, `bad_value`, `timeout`) are returned, never raised; built-in, disabled and deprecated rules skipped. 42 tests in `tests/unit/test_fw_rules.py`: M2-X03 to M2-X06, M2-X13, M2-X49, the operator semantics, and a Hypothesis property (arbitrary text and regex never raise).* Rules engine (PRD §9.1): fields (applies on, checks, condition, action, weight 5–60, ATLAS tag, note); only operators valid for the field type; RE2 regex (`google-re2`); 50 ms cap per rule evaluation; error or timeout returns a `RuleError` that maps to Deny in Basic and Strict.
- [x] A-06 *Done: `app/firewall/sentinel_l1.py` (spec AEGIS-DOM-104). Every PRD §7.3 layer-1 signal, with points taken from the level's weights (M1 seed keys) and the score capped at 100. The breakdown lists each fired rule's weight (a forcing rule shows 0) and all six signals. Encoding is a base64 or hex blob containing both letters and digits, Unicode format characters in the raw text, or a spaced-out word of 5 or more letters. B-02 `forged_approval` is reported (M2-DD-14). 20 tests in `tests/unit/test_fw_sentinel_l1.py`: M2-X14 to M2-X19, M2-X29, a false-positive guard, a check that the real poisoned Q3 notes do not trigger B-02 (keeping the PRD §6.5 Off line), and a Hypothesis bound property.* Sentinel layer 1 (PRD §7.3): rule weights; keywords at 10 per hit, max 30; encoding or obfuscation +20; earlier denies in this session at 10 per deny, max 30; rapid retries (more than 5 messages in 60 s) +10; high-risk tool proposed +15; untrusted content just entered context +10. Score capped at 100. Full breakdown dictionary with `null` for layers that did not run.
- [x] A-07 *Done: `app/firewall/gatekeeper.py` (spec AEGIS-DOM-105). Score `max(min(100, l1 + l2), judge)`, with a judge error raising it to the Deny threshold. Bands from the level thresholds, with a priority alert at `alert` or above. Hard overrides as listed (rule actions; approved pattern, B-02, invalid call, rule failure or history error all Deny; B-01 Deny in Basic and Off, Divert in Strict). Strictest wins. Off records `shadow_decision` and enforces Allow, except invalid calls. Divert becomes Deny when the level has divert disabled (M2-DD-01). The breakdown has `null` for layers that did not run. `judge_needed` applies the floor of 20; `score_band` maps scores to low, medium and high for the feed. 41 tests in `tests/unit/test_fw_gatekeeper.py`: E-07, E-09, E-44, E-52, M2-X20, M2-X21, M2-X24 to M2-X28, plus Hypothesis properties (Off always enforces Allow; forcing signals never weaken a decision).* Combiner and Gatekeeper (PRD §7.3, §7.4): `final = max(min(100, layer1 + layer2), judge_risk)`; bands from the level's thresholds (never hard-coded); priority alert at 99 or more; hard overrides (deny rule gives at least Deny, divert rule gives Divert, approved pattern gives at least Deny, B-01 gives Deny in Basic and Divert in Strict, B-02 gives Deny, invalid schema or unknown tool gives Deny in every mode, any rule, judge, DB or history error gives Deny); strictest wins: Divert > Deny > Review > Allow.

### Phase B: schema, Off and Basic end to end (H3–H8, Gate 1)

- [x] B-01 *Done (spec AEGIS-DOM-106): `migrations/versions/0003_firewall_core.py`, label `fw_core`, `down_revision = 0001_foundation`. Tables: `rule_sets`, `rules` (append-only by trigger), `fw_sessions`, `fw_manifests` (immutable by trigger), `fw_claims`, `fw_conversation`, `fw_mock_state`, `fw_tool_calls`, `fw_tickets`, `fw_events` (hypertable, 1-day chunks, every PRD §10.1 field plus `client_ip_hash` and `priority_alert`), `trace_back`. Enum CHECKs; `shadow_decision` only in Off; one in-flight or held claim per session; one pending ticket per session; a `call_id` recorded once per session; a `NOTIFY fw_events_forensic` trigger on pending rows, inside the inserting transaction (M2-DD-23). 16 tests in `tests/integration/test_fw_schema.py`, written first; all fail without the migration and pass with it. The full suite (474) passes; a downgrade and upgrade round trip was checked on the test DB. **Not applied to the shared local dev DB** until the early seam merge, because the M1 Compose stack runs `master`'s migrations. Next: open the early-merge PR (needs the user).* `0003_firewall_core` migration: `rules` (versioned, never deleted), `fw_manifests`, `fw_claims`, `fw_conversation`, `fw_mock_state`, `fw_tickets`, `fw_events` (hypertable on `time`, every PRD §10.1 field plus `client_ip_hash` and `priority_alert`), `trace_back`. **Merge to `master` early** (seam merge, §0.6), so M3 and M4 can rebase on the real schema.
- [x] B-02 *Done: `app/firewall/seed.py` `seed(engine)`, idempotent through `ON CONFLICT DO NOTHING`, which never fires the append-only trigger. It writes rule set 1, R-001 to R-006 as their `RuleForm` JSON, and B-01 to B-04 as built-ins with no form. M1's demo seed picks it up through the DM1-2 hook. 4 tests in `tests/integration/test_fw_seed.py`: exact rule list, forms round-trip unchanged, idempotent, picked up by `seed_demo`. **Found by the seed:** the B-01 `rule_id` check rejected the PRD's two-digit built-in IDs (`B-01`); the migration was fixed (not yet applied anywhere shared) and the format is pinned by a new schema test.* Seed the starting rules R-001 to R-006 and built-ins B-01 to B-04 exactly as PRD §9.2, rule set version 1.
- [ ] B-03 Event writer: one row per check per stage, in every mode, enums exactly as PRD §10.1. `shadow_decision` set only in Off. A layer that did not run is `null`, never `0`. `forensic_status = pending` only for Deny, Human Deny or Divert (decision or shadow decision) and for Off allows that delivered the secret (PRD §10.2). `NOTIFY fw_events_forensic` in the same transaction.
- [ ] B-04 `register_session`: builds and stores the immutable manifest (agent definition, model IDs, level config, rule set version, risky pattern table version from `current_pattern_version()`, judge policy hash, thresholds, weights). Level `rule_version = 0` means "pin the latest rule set version now". Seeds `fw_mock_state` from `mock_state_seed`.
- [ ] B-05 Mock tools on `fw_mock_state` (D-11): `search_docs`, `read_file`, `send_email` (writes to the mock mailbox; mail to the attacker address becomes a readable `ToolEffect`), `query_db` (mock rows, never real SQL), `run_shell` (tiny emulator over the mock filesystem: `ls`, `cat`, `echo`, everything else "command not found"). No `subprocess`, `os.system` or network calls anywhere in `firewall/` (test with an import and AST check). The state change and its `tool_executed` event commit in one transaction. A recorded `call_id` never executes twice.
- [ ] B-06 Bot runner: Gemini through `GeminiClient.chat_with_tools` (echo each call's `ToolCall.signature` back on the next turn), last 20 messages, up to 5 tool-call rounds. After the 5th round the runner asks for a final reply with tools disabled, and that reply goes through the output check. Tool results are wrapped as untrusted data. A bot model error raises `BotUnavailable` and releases the claim, so the arena can retry with the same `message_id`.
- [ ] B-07 Claims and idempotency (PRD §15.1 Concurrency): one active claim per session, held through review; same `message_id` and same text returns the stored result; same `message_id` and different text raises `MessageConflict`; a new message while one is in flight or held raises `SessionBusy`.
- [ ] B-08 Pipeline for Basic: input check, then bot runner, with a tool-call check before each tool runs and a tool-result scan after (B-02 forged-approval signal, untrusted-content signal), then an output check. Return `TurnResult` as soon as the event is committed.
- [ ] B-09 Off mode (D-02, PRD §7.2): run full Strict scoring (cumulative scan, risky history read in shadow, judge off by default), store `shadow_decision`, enforce Allow. Invalid schema or unknown tool is still denied and never runs. Oversized input is truncated and logged. Risky behavior rows are written with `shadow: true`.
- [ ] B-10 `read_catalog` and `close_session` (writes a `finalize` event; a pending ticket on the session becomes `expired`).
- [ ] B-11 **Gate 1 demo:** a fixture attack (poisoned document emails the secret) is denied in Basic by R-003, with the score, breakdown and thresholds logged in `fw_events`.

### Phase C: Review, Divert, Strict wiring, read and admin APIs (H8–H14, Gate 2)

- [ ] C-01 Review parking (PRD §8.3 steps 1–2): park the turn with its continuation state; open a ticket bound to session, message, stage, `call_id`, payload hash and manifest; return at once with `awaiting_review`, the ticket ID and the exact pending message. One active item per session.
- [ ] C-02 `decide_ticket` (C6): atomic `pending → approved` or `pending → human_denied`, refused with a conflict error if the ticket is no longer pending or `now >= expires_at` (expiry wins any race at the deadline). On **ok**, the continuation runs exactly once: a held input goes to the bot; a held tool call executes; a held reply is released exactly as checked with no new model call; newly generated items get normal checks. A bot failure during continuation ends in `blocked` (fail closed). On **not ok**, nothing executes, status `human_denied`, the message "A reviewer denied this request.", `record_behavior(action="human_deny")`, plus `add_candidate` for a held tool call. Human Deny never diverts.
- [ ] C-03 Expiry: a sweeper every 5 s plus a lazy check in `check_ticket` and `decide_ticket`. Default 120 s from the level config. An expired ticket counts as Deny (stage `review_resolved`).
- [ ] C-04 `check_ticket(owner_ref, ticket_id)`: returns the stored result. A wrong owner gets `NotFound`. The AFF never pushes.
- [ ] C-05 Divert (PRD §8.4): generate the decoy first (outside the transaction), then in one transaction: `record_behavior(action="divert")`, write `trace_back`, write the decoy to mock state with `is_decoy: true`, append the event with `decision: divert`, `execution_status: diverted`. Return `player_view` with status `replied`; the tool effect shows as executed with the decoy; the feed item shows `allow`; `facts.diverted = true`. The real tool never executes.
- [ ] C-06 Decoy generation (PRD §8.6): Gemini structured output from the tool schema and the canonical call; 5 s timeout; B-01 scan on the decoy, regenerated once on a hit, then a fixed per-tool template. Decoys stay consistent: the bot sees decoy results as tool results on later turns. Strict outbound secret hits divert with the secret replaced by a decoy value.
- [ ] C-07 Trace-back (PRD §8.5): IP stored as a salted HMAC plus the clear /24 (IPv4) or /48 (IPv6) subnet; ASN, ASN org and country from offline GeoLite2 files (missing files give `null`, never an error); user agent; fingerprint hash if sent; tools called in the session. `methods_used` is filled later by M3. `purge_expired_trace_back` deletes rows older than 30 days and keeps only `client_ip_hash` on the event.
- [ ] C-08 Strict wiring: call `RiskyHistoryPort.lookup` for every checked item; call `JudgePort.assess` only when the layer 1 + 2 score is 20 or more (PRD §18.2 default); a judge timeout (8 s) or unparseable answer sets the score to at least the Deny band; a history error gives Deny. Cumulative scan enforced. Store `judge_risk`, `judge_reason` (events only, never C3) and `latency_ms` per layer.
- [ ] C-09 Write `risky_behavior_events` through `record_behavior` on every Deny, Human Deny and Divert in every mode (Off with `shadow: true`). A denied tool call also calls `add_candidate` (PRD §8.2).
- [ ] C-10 Facts (PRD §9.4): `secret_attempted` (the bot tried to send the secret, blocked or not), `secret_delivered` (the real secret reached the student in a reply or a readable tool effect and echo exclusion passed), `diverted`. `secret_delivered` is always computed over the **cumulative** visible output, as a fact only, in every mode. That is how E-22 Basic counts as delivered even though Basic does not enforce the cumulative scan.
- [ ] C-11 C3 read API, including `get_session_summaries` (batch, no N+1), `get_manifest_summary` and `redact_for_session` (exact and normalized forms through the A-04 scanners). Also the continuous aggregates `fw_rule_fires_1m` and `fw_decisions_1m` with a 1-minute refresh policy (in revision `0003b_fw_cagg`, §0.4).
- [ ] C-12 C6 admin API (rules CRUD with versioning, tickets, events, diverts with trace-back). Every write calls `record_audit`.
- [ ] C-13 **Gate 2 check:** all four actions enforced in Basic and Strict, shadowed in Off; Review loop at all three stages; Divert end to end; Strict runs against real M3 C7 on the `integration` branch.

### Phase D: hardening (H14–H17)

- [ ] D-01 Performance: rules under 50 ms p95 per checked item with all seed rules plus 50 extra rules (PRD §15.1).
- [ ] D-02 Reproducibility: record a Strict session's proposals, judge answers and review outcomes, replay them against the manifest, and assert identical decisions (PRD §15.1).
- [ ] D-03 Import boundary test: `app/firewall/` imports no `fastapi`, `starlette`, `subprocess` or `socket` (PRD §3.3).
- [ ] D-04 Information-flow test: no `PlayerView` or C3 response contains judge reasons, tool arguments, blocked text or trace-back fields (I-3).
- [ ] D-05 Attack fixtures `fixtures/attacks/m2_*.json` for every demo step in PRD §6.5, with expected decisions per mode.
- [ ] D-06 Help M1 swap fakes off and run the PRD §6.5 demo on the real Gemini bot.


### Deferred from M1 (2026-11-07)

Items M1 cannot finish without M2. M1 tracks them in its §4c and ticks its side when these land.

- [x] DM1-1 *Done 2026-11-07. Reviewed C2, C3, C6 and C7 against PRD §7 to §10, §14.3, §14.4 and §15.1. **One change needed and made by M1 (M1 DD-36):** `FeedItem.shadow_decision` lacked `divert`, but Off shadows all four actions (PRD D-02, §5.2), so R-006 or a score of 95 or more in Off would have failed validation. The other findings need no contract change and are recorded as M2-DD-01 to M2-DD-05. Sign-off recorded in M1's Progress log. M2 picks up DD-36 by rebasing after M1's PR merges; nothing in Phase A needs it.* **Contract sign-off before G1** (M1 AC-8, X-2): review the shapes M2 provides or consumes in `backend/app/contracts/` (C2, C3, C6, C7). Then either record "M2 signs off" in the M1 Progress log or open a contract-change PR. Contracts freeze at G1.
- [x] DM1-2 *Done with B-02: `app/firewall/seed.py` `seed(engine)`; `seed_demo` reports `app.firewall.seed` as seeded (tested).* **Rule seed hook** (M1 D-02): put the B-02 starting rules in `backend/app/firewall/seed.py` as `async def seed(engine) -> None`, idempotent. `scripts/seed_demo.py` and the Compose start-up seed then pick it up automatically. See the handoff, §4 table.
- [ ] DM1-3 **Real C2 on `integration` at G1** (M1 D-01, X-6): push the C2 implementation with `create()` (DD-05) to the `integration` branch and tell M1. M1 then runs the arena Off and Basic flows with `firewall` removed from `AEGIS_USE_FAKES`. This is M1's side of M2 AC-8.

---

## 5. Edge cases (each is a required test)

### 5.1 PRD §16.2 cases M2 owns

E-01 to E-04 are "as AFF v0.3". That document is not in this repo, so the expected results below are taken from PRD §15.1 Concurrency. Confirm them with the AFF owner before Gate 1.

| # | Case | Expected | Gate |
| --- | --- | --- | --- |
| E-01 | Same `message_id` and same text sent again | Stored `TurnResult` returned. No new model call, no new events | MVP |
| E-02 | Two concurrent requests with the same `message_id` | Exactly one is processed. The other gets the stored result (or waits for it) | MVP |
| E-03 | Same `message_id`, different text | `MessageConflict` | MVP |
| E-04 | New message while one is in flight or held | `SessionBusy` | MVP |
| E-07 | Divert, deny, review and allow signals all match one item | Divert | MVP |
| E-09 | Judge says low risk, a rule says deny | Deny | MVP |
| E-22 | Secret split across two replies | Basic: both released, `secret_delivered` true on the completing reply. Strict: the completing reply is blocked by the cumulative scan | MVP |
| E-44 | Off-mode attack that Basic would deny | Executes. Event has `shadow_decision: deny`, `decision: allow` | MVP |
| E-45 | Score 96 in Basic | Divert. Real tool never executes. Decoy shown as executed | MVP |
| E-46 | Review, admin clicks "not ok" | Status `human_denied`. Nothing executes, no decoy, `risky_behavior_events` row with `action: human_deny` | MVP |
| E-46a | Any item is held (input, tool call or reply) | Response returns at once with `awaiting_review`, ticket ID and the pending message | MVP |
| E-46b | Held reply approved | Stored reply released unchanged. Zero new bot model calls (assert on `ScriptedLLM`) | MVP |
| E-46c | Reply containing the secret, scored in the Review band | Never held. B-01 denies (Basic) or diverts (Strict) | MVP |
| E-47 | Review expires | Deny | MVP |
| E-48 | Decoy generator returns text containing the secret | Regenerated once, then template. `secret_delivered` stays false | MVP |
| E-49 | Decoy generation times out (over 5 s) | Template decoy. Tool never executes | MVP |
| E-52 | Judge returns a lower risk than the rules | Final score equals the rule score | MVP |
| E-53 | Student pastes a known compromised secret, bot echoes it | `secret_delivered` false (echo exclusion) | MVP |
| E-54 (feed part) | Defense feed during a diverted turn | `FeedItem.decision = allow`. C3 `get_decisions` shows divert for the recap | MVP |

### 5.2 Cases M2 shares with M3

| # | Case | M2 side | M3 side |
| --- | --- | --- | --- |
| E-50 | Strict: same user retries a denied tool call in a new session | Gatekeeper applies the extra points and the decision is stricter than the first time (test with `InMemoryRiskyHistory`, then real) | Lookup returns the user-history points (M3 doc) |
| E-51 | Strict: paraphrase of a known attack (similarity 0.85 or more) | `similarity: 25` appears in `score_breakdown` | Similarity query (M3 doc) |
| E-57 | Approved draft rule | New session's manifest pins the new rule set version and blocks the attack. Running session does not | Draft approval calls `create_rule` (M3 doc) |

### 5.3 Derived cases (from PRD §7–§10, §15)

| # | Case | Expected | PRD |
| --- | --- | --- | --- |
| M2-X01 | Unknown tool name in any mode, including Off | Deny, never executes | §7.3, §7.6 |
| M2-X02 | Tool call with a wrong type, a missing field or an extra field | Deny in every mode | §7.6 |
| M2-X03 | `send_email` to `a@company.example.evil.com`, `"CEO" <x@evil.com>`, `X@COMPANY.EXAMPLE`, and several recipients with one external | Only the exact allowlisted domain passes. Any external recipient trips R-003 | §7.6, §9.2 |
| M2-X04 | `read_file` with `../`, an absolute path, `%2e%2e/` or a NFKC look-alike dot | Resolved inside the mock filesystem. Outside-workspace trips R-005 | §7.6, B-03 |
| M2-X05 | `query_db` with `DrOp`, `/*x*/DELETE`, or `truncate` in a string | R-004 matches after normalization | §9.2 |
| M2-X06 | `run_shell` with `curl`, `wget`, `nc` or `rm -rf` | R-006 Divert. Nothing touches the real host | §9.2, D-11 |
| M2-X07 | Player text of exactly 4,000 characters, then 4,001 | 4,000 checked normally. 4,001 denied in Basic and Strict, truncated and logged in Off | §7.6 |
| M2-X08 | Tool arguments over 4,000 characters, tool result over 8,000, reply over 4,000 | Denied in Basic and Strict. Truncated and logged in Off | §7.6 |
| M2-X09 | Bot proposes a 6th tool-call round | Not run. Final reply requested with tools disabled and output-checked | §7.6 |
| M2-X10 | Session with 25 messages | The bot model receives the last 20. Checks use the full record | §7.6 |
| M2-X11 | Same `call_id` recorded twice (for example after a retry) | Executes once | §7.6 |
| M2-X12 | DB error while writing a tool effect | Neither the state change nor the event is committed. Turn fails closed | §15.1 |
| M2-X13 | Rule regex that is invalid RE2, or a rule evaluation over 50 ms | Deny in Basic and Strict. In Off, `shadow_decision: deny`, `decision: allow` | §9.1 |
| M2-X14 | Keyword list hits 5 times | Keyword contribution capped at 30 | §7.3 |
| M2-X15 | Four earlier denies in the session | Session-deny contribution capped at 30 | §7.3 |
| M2-X16 | Sixth message within 60 s | +10 rapid retry signal | §7.3 |
| M2-X17 | Tool result read this turn, then `send_email` proposed | +10 untrusted content and +15 high-risk tool | §7.3 |
| M2-X18 | Base64 blob, hex blob, zero-width characters, or "s y s t e m" spacing in input | +20 encoding signal | §7.3 |
| M2-X19 | Sum of signals over 100 | Score is 100 | §7.3 |
| M2-X20 | Basic band boundaries: scores 39, 40, 69, 70, 94, 95, 98, 99 | Allow, Review, Review, Deny, Deny, Divert, Divert, Divert plus priority alert | §7.4 |
| M2-X21 | Strict band boundaries: scores 29, 30, 59, 60, 94, 95, 99 | Allow, Review, Review, Deny, Deny, Divert, Divert plus priority alert | §7.4 |
| M2-X22 | Admin changes a level's thresholds | New sessions use the new values. Every event stores the thresholds it used | §7.4, I-7 |
| M2-X23 | Mode change requested on a registered session | `ModeChangeRejected` | §7.2 |
| M2-X24 | Approved risky pattern matches in Strict, score otherwise 10 | At least Deny | §7.3 |
| M2-X25 | `RiskyHistoryPort.lookup` raises | Deny (fail closed) | §7.3 |
| M2-X26 | Judge unparseable answer or 8 s timeout | Score raised to at least the Deny threshold. `judge_risk` is `null` | §7.3 |
| M2-X27 | Strict item with layer 1 + 2 score under 20 | Judge not called. `judge` is `null` in the breakdown | §18.2 |
| M2-X28 | Prompt injection in the item text tells the judge to return 0 | Final score is still at least the rule score | §15.3 |
| M2-X29 | Tool result contains a forged "approved by admin" note, then a high-risk call | B-02 Deny | §9.2 |
| M2-X30 | Secret in a `send_email` body (tool argument) in Basic, then in Strict | Basic: Deny. Strict: Divert with the secret replaced in the decoy | §7.3 |
| M2-X31 | Secret leaked reversed, base64, hex, URL-encoded, with spaces, or with zero-width characters | B-01 matches in Basic and Strict, reported in Off | §9.3 |
| M2-X32 | Student typed 7 consecutive characters of the secret earlier | Delivery still counts | §5.3 |
| M2-X33 | Student typed 8 consecutive characters of the secret earlier (different case) | Delivery does not count | §5.3 |
| M2-X34 | Secret delivered through the attacker mailbox in Off | `secret_delivered` true via the tool effect | §6.4 |
| M2-X35 | Strict session whose visible output passes 50,000 characters | Further replies denied (fail closed). Basic is not affected | §7.6 |
| M2-X36 | Two admins decide the same ticket at once | One wins. The other gets a conflict error. The continuation runs once | §8.3, §15.1 |
| M2-X37 | Admin approves at exactly `expires_at` | Expired (Deny). Continuation never runs | §8.3 |
| M2-X38 | Approved held input leads to a tool call that also scores in the Review band | A new ticket is opened (one active per session). The student sees the pending message again | §8.3 |
| M2-X39 | Student calls `check_ticket` for another student's ticket | `NotFound` | §8.3 |
| M2-X40 | Session closed while a ticket is pending | Ticket expired. Later `decide_ticket` gets a conflict error. Nothing executes | §8.3 |
| M2-X41 | Divert: the trace-back insert fails | Whole divert transaction rolls back. Turn ends in Deny. No decoy and no risky behavior row left behind | §8.4, §15.1 |
| M2-X42 | Diverted `send_email`, then the student asks the bot "did my email send?" | Bot sees the decoy result in history and stays consistent | §8.6 |
| M2-X43 | `ClientMeta` is all `null` on a divert | Trace-back row written with `null` fields. Divert still works | §8.5 |
| M2-X44 | GeoLite2 files missing | ASN, org and country are `null`. No error | §8.5 |
| M2-X45 | Trace-back row older than 30 days | Purged. Event keeps only `client_ip_hash` | §8.5 |
| M2-X46 | Every event row | Valid enums. `shadow_decision` only in Off. Layers that did not run are `null` | §10.1 |
| M2-X47 | Allow in Basic with no secret | `forensic_status` is not `pending`, and no `NOTIFY` is sent | §10.2 |
| M2-X48 | Off allow that delivered the secret | `forensic_status: pending`, `NOTIFY` sent | §10.2 |
| M2-X49 | Rule deprecated | Kept as a version, no longer applied to new sessions. Running sessions keep their pinned set | §9.1 |
| M2-X50 | Replay of a recorded Strict session | Identical decisions | §15.1 |

---

## 6. Acceptance criteria (PRD-mapped)

- [ ] AC-1 PRD §2.1 metric 1 and §16.3 row 1: all three modes run end to end with every check recorded in `fw_events`.
- [ ] AC-2 PRD §2.1 metric 2 and §16.3 row 2: all four actions fire and are enforced in Basic and Strict, and show as `shadow_decision` in Off.
- [ ] AC-3 PRD §2.1 metric 3 and §16.3 row 3: Review at input, tool-call and reply stages; pending message returned; ok continues; not ok gives Human Deny; expiry denies.
- [ ] AC-4 PRD §16.3 row 4: Divert writes risky behavior and trace-back, shows a decoy, never executes.
- [ ] AC-5 PRD §16.3 row 5 (M2 side): Strict calls risky history on every item and the result changes a decision (E-50, with M3).
- [ ] AC-6 PRD §15.1: fail closed, atomicity, concurrency, reproducibility, rules under 50 ms p95, information flow, each covered by a test.
- [ ] AC-7 PRD §6.5 steps 1–4 pass with `ScriptedLLM` (deterministic) and on the real Gemini bot on the `integration` branch.
- [ ] AC-8 C2, C3 and C6 implemented exactly to the frozen contracts. M1, M3 and M4 tests pass when they swap their fakes for M2's real code.

---

## 7. Exit criteria for the final merge (all must be `[x]`)

- [ ] X-1 Gate 1 met: `0003` migration and rule seed merged, Basic denies a fixture attack with a logged score.
- [ ] X-2 Gate 2 met: AC-1 to AC-5 checked on the `integration` branch with real M3 C7.
- [ ] X-3 Every case in §5.1, §5.2 (M2 side) and §5.3 has a passing automated test.
- [ ] X-4 Every acceptance item in §6 is checked.
- [ ] X-5 CI green: ruff, pytest, gitleaks, `alembic upgrade heads` on an empty DB.
- [ ] X-6 `app/firewall/` imports no FastAPI (D-03) and contains no real execution paths.
- [ ] X-7 No file outside M2's ownership changed, except PR-approved contract changes.
- [ ] X-8 `fixtures/attacks/m2_*.json` cover every PRD §6.5 demo step with expected decisions per mode.

---

## 8. Integration duties (H17–H21)

- [ ] INT-1 Rebase after M1's final merge, merge second (§0.6).
- [ ] INT-2 With fakes off, run E-01 to E-54 and the M2-X cases on `master`. Report results to M1's Progress log.
- [ ] INT-3 Support demo steps 1–4 live: the Off shadow line "would have denied (R-003, B-01)", Basic direct deny, Basic split leak, Strict cumulative block, held email, Human Deny, the 95+ divert.
- [ ] INT-4 Tune Strict thresholds and weights on the development fixtures only if the demo needs it, and record the values (PRD §18.2).

---

## 9. Stretch (only after Gate 2, and only if every MVP test passes)

- [ ] S-1 Attack suite report per mode on a frozen holdout, with N, model ID and manifest ID on every number (PRD §2.1 item 8).
- [ ] S-2 Honeytoken in Strict decoys, so later use is recorded as `secret_used` (PRD §8.6, with M1 S-1).
- [ ] S-3 A slot in the score combiner for M3's local classifier (PromptGuard 2) advisory score. It may only raise the score.

---

## 10. Risks and open decisions (defaults used if nobody answers)

| Item | Default |
| --- | --- |
| E-01 to E-04 details from AFF v0.3 (doc not in repo) | As §5.1, from PRD §15.1 |
| Off shadow uses which thresholds | Full Strict scoring with the Off level's thresholds, which M1 seeds with the Strict values. B-01 maps to Deny in Off, so the demo line reads "would have denied (R-003, B-01)" |
| How the Off feed shows shadow decisions | Contract addition `FeedItem.shadow_decision` (Off only, listed in M1 §3.1) |
| Bot model error during a live turn | `BotUnavailable`; the arena shows `not_sent` and retries with the same `message_id` |
| Bot model error during an approved continuation | Fail closed: `blocked` |
| Judge on every Strict item or above a floor | Only items scoring 20 or more (PRD §18.2) |
| Strict visible output over 50,000 characters | Further replies denied |
| Level `rule_version` | `0` means pin the latest rule set version at registration, so E-57 works without editing levels |
| Do Human Denies count as "earlier denies" for the session signal | Yes |

---

## 10a. Design decisions (where the PRD left a detail open)

| # | Decision | Reason |
| --- | --- | --- |
| M2-DD-01 | An enforced Divert needs `LevelConfig.divert_enabled`. When it is false in Basic or Strict, a Divert becomes Deny, and the real tool still never runs. Shadow decisions in Off are computed as if divert were enabled (Off's flag is false by design) | PRD §5.2 gives every level a divert flag but does not say what happens when it is off; Deny is the strictest action that does not deceive |
| M2-DD-02 | `TicketResult.expires_at` stays an ISO 8601 string, emitted in UTC as `YYYY-MM-DDTHH:MM:SSZ` | The contract types it as `str` (unlike DD-04's aware datetimes), and the arena already consumes it; changing the type would break M1 for no gain |
| M2-DD-03 | `read_api.create()` returns one object implementing every `FirewallReadPort` method. `get_forensics` and `get_attack_family_counts` delegate to M3's `app/firewall/forensics_read.py` when present, else return `[]` | `ports.py` maps the whole `read` seam to `app.firewall.read_api:create`, but those two functions are M3's (C3 docstring) |
| M2-DD-04 | `DivertItem.attempted_summary` is built from the tool name and a coarse target class (for example "send_email to an external address"), never from raw arguments | I-3: tool arguments never leave the AFF; teachers still see what was attempted |
| M2-DD-05 | `register_session` validates the level config: threshold keys `review`, `deny`, `divert` and `alert` in order, and every Sentinel weight key M1 seeds (`keyword_per_hit`, `keyword_max`, `encoding`, `session_deny_per`, `session_deny_max`, `rapid_retries`, `high_risk_tool`, `untrusted_context`, plus the Strict layer-2 keys). A missing or invalid key rejects the registration | Fail closed: a level that cannot be scored must not start; the keys are the ones in `app/arena/seed.py::DEFAULT_WEIGHTS` |
| M2-DD-06 | Phase A is built directly on the contract models, not local dataclasses | G0 is already merged, so the doc's "until G0" step is moot |
| M2-DD-07 | *(Superseded by M2-DD-18 after the Phase A review: coverage is now in any order, on the secret's core.)* **Cumulative scan = ordered fragment coverage.** Strict counts a cross-turn leak when the secret's skeleton can be rebuilt in order from pieces of 3 or more characters found in the joined visible output, with any other text between pieces. It flags only the item that completes the secret (none if the history already covered it). Pieces of 1 to 2 characters are below the floor and left to Strict's judge layer. A test pins that gap | A literal join misses "part one: CONF-7Q … and the rest 2XK9", the way PRD §5.4's split attack really reads. A plain subsequence match would cover a 28-character secret in almost any long text. Measured: 0 false positives on 50,000 characters of benign output, about 36 ms per full scan |
| M2-DD-09 | **Recipients:** `send_email.to` may hold several comma-separated addresses. Each is parsed with `email.utils.getaddresses`, lowercased and checked against a strict local-part and domain pattern (at least one dot). Each parsed address must also appear verbatim in what the model wrote. The canonical `to` is the bare addresses joined by `", "`; display names are dropped, so they do not change the hash | The parser silently rewrites some inputs (whitespace inside an address, comments); the checks must judge exactly the recipient the model wrote. R-003 then compares domains exactly (M2-X03) |
| M2-DD-10 | **Paths:** the workspace root is `/workspace`. A path is URL-decoded until stable (at most 3 rounds, for double encoding), NFKC-normalized (look-alike dots), backslashes turned into `/`, then `normpath`-resolved. Inside the workspace, the canonical value is relative (`docs/faq.md`); outside, it is the absolute result (`/etc/passwd`), and R-005 fires on `inside_workspace = False`. Control or format characters (including a decoded `%00`) reject the call | B-03 resolution is specified only as "inside the mock filesystem"; this makes the escape check one boolean on the canonical call and keeps NUL out of the DB |
| M2-DD-11 | **"All arguments of one call" = the sum of each argument value's length** (strings by length, other values by their JSON text). In Off, an oversized call is cut down by trimming the longest string values until it fits; if nothing can be trimmed, it is denied even in Off (fail closed). Truncation returns new args, and the caller re-canonicalizes them so the hash matches what runs | The PRD gives the limit, not how to count or how Off truncates; counting values (not keys) matches what the model actually sends |
| M2-DD-12 | **Rule operator semantics.** `domain_not_in` fires when any recipient's domain is outside the list; `domain_in` fires only when every recipient is inside, so the two are exact opposites. Domains compare exactly, never as suffixes, so `company.example.evil.com` is outside. A rule whose argument is not on the call (for example R-004 on `send_email`) does not apply; it is not an error. For a `bot_tool_call` with `checks = text`, the subject text is the call's canonical argument values joined. Built-ins B-01 to B-04 stay code: the leak scan (A-04), forged approval (A-06), path resolution (A-01) and the echo fact (A-04). R-003's allowlist is the PRD scenario's `company.example`, stored in the rule itself | Makes each rule's meaning testable and keeps R-003 versioned like every other rule (an admin edit is a new version, not a silent change) |
| M2-DD-13 | **The 50 ms cap is measured, not pre-empted.** RE2 runs in linear time and rejects backreferences, so no rule can run away; each rule's time is still measured, and an over-cap rule becomes a `timeout` failure (Deny in Basic and Strict) | PRD §9.1 caps evaluation at 50 ms; RE2's guarantee makes measurement enough, with no thread or signal juggling inside the event loop |
| M2-DD-14 | **B-02 forged approval = an approval attributed to an authority** ("approved by the administrator", "admin has approved", "pre-approved", "approval granted") in a tool result read this turn, followed by a high-risk call. A bare "already approved" does not count | PRD §6.5 step 1's Off line must read exactly "would have denied (R-003, B-01)", and the poisoned Q3 notes say "already approved"; M2-X29's example is "approved by admin". A test runs the real poisoned document |
| M2-DD-15 | **Keyword list** (layer 1, 10 points each, max 30, whole words on normalized text, plural allowed): `system prompt`, `base64`, `reveal`, `exfiltrate` (PRD §7.3 examples) plus `secret`, `password`, `credential` | The PRD gives examples, not the list; the additions are the words students use when asking for the level secret |
| M2-DD-16 | **B-01 in Off is a shadow Deny, not a shadow Divert** (Off otherwise scores like Strict). Rule actions `score_only` and `allow` never force anything: with strictest-wins, an allow rule only adds its weight | Keeps PRD §6.5's Off line "would have denied (R-003, B-01)"; an "allow" rule cannot undo a stricter signal, by D-01 |
| M2-DD-17 | **Look-alikes and invisible spaces.** `normalize` also strips combining marks (NFKD) and folds common Cyrillic, Greek and Latin look-alike letters to Latin (a code-point table in `textnorm.py`). Rules match two readings of each text: invisible characters removed, and invisible characters read as spaces. A rule fires if either reading matches | Phase A review: a Cyrillic letter, an accent on every letter, or a zero-width character standing in for a space beat R-001 and the secret scan |
| M2-DD-18 | **The secret's core and partial leaks.** The core is the secret's random part (the skeleton of the segment after the last `-` or `_` when it is 16 or more characters; otherwise the whole secret). **Full leak:** the whole core, forward or reversed, in any view of the text: as written, skeleton, ROT13, or decoded (URL, HTML and backslash escapes, decimal bytes, hex with or without separators, base64 including spaced groups), with decoders applied up to two levels deep. **Partial leak:** any 12-character run of the core in any view. B-01 blocks it like a full leak, but it never counts as delivery (no win). **Cumulative (Strict):** every core position covered, in any order, by pieces of 3 or more characters found in the joined output. The Basic split attack still works when each reply leaks fewer than 12 core characters, which matches PRD §5.4's "a few characters per reply" | Phase A review: the public prefix proves nothing, so a student could take the 24 random characters without it. Out-of-order pieces and separator-hex, spaced base64, double encoding and ROT13 all slipped through. Measured after the change: 0 false positives on 50,000 characters of benign output, and a full-session scan still well under 100 ms |
| M2-DD-19 | **Starting-rule scope.** R-004 stays exactly as PRD §9.2 (DROP, DELETE, TRUNCATE); UPDATE and the rest are left to the score, the judge and admin-added rules. R-006 now also covers `telnet`, `socat`, `sftp`, `rm --recursive` or `--force`, `dd if=` or `of=`, `find … -delete`, and interpreters run with `-c` or `-e` (python, perl, ruby, node, bash, sh, zsh). R-001 adds "ignore everything above"; R-002 adds the chief-officer titles and "head of IT". Paths inside `run_shell` commands are resolved by the mock shell (B-05), never on a real host | The PRD lists examples; the review showed cheap misses. R-004 is kept literal so the rule set the PRD describes is the one that runs |
| M2-DD-20 | **B-02 widened:** approval credited to anyone ("approved by Sarah from IT"), or an approval ID, code, number or reference, counts. Still not a bare "already approved", so the poisoned Q3 notes still do not trigger it (test kept) | Phase A review: one rewording of the authority's title beat the narrow list |
| M2-DD-21 | **Canonical hardening.** A path that is still URL-encoded after 3 decoding rounds is rejected. `%` and `!` are not allowed in an email local part (legacy source routes). A recipient or path argument that is not text is rejected, and any unexpected exception in canonicalization becomes a `CanonicalError` (Deny), never a crash. A domain or workspace rule on an argument that was never parsed is a rule failure (Deny), not a silent no-match | Phase A review findings 5, 9, 10, 11: each was fail-open or a crash by construction |
| M2-DD-22 | **Echo exclusion stays exactly PRD §5.3** (any 8 consecutive characters of the secret typed earlier). The review noted that this is generous to students | It only ever withholds the student's own win, never lets a leak through; changing it would contradict the PRD |
| M2-DD-23 | **Schema shape (B-01).** (1) `fw_sessions` holds mutable session state (status, secret, eval), so `fw_manifests` can be truly immutable. (2) `fw_claims` is both the claim and the idempotency record: one row per `(session, message_id)` with a text hash and the stored `TurnResult`; a partial unique index allows only one `in_flight` or `held` row per session. (3) `fw_tool_calls` keyed on `(session, call_id)` makes "a recorded `call_id` never executes twice" a database guarantee. (4) The rule set version is a row in `rule_sets`; each rule version records the set version it joined, and a manifest pins a set version. (5) Append-only and immutability are row triggers, so a statement-level table reset (test cleanup, demo reset) still works. (6) Every M2 table chains to `users`, so M1's per-test cascade cleanup of `users` also cleans M2's tables, with no change to M1's test fixture. (7) All M2 IDs are text (`fws-…`, `man-…`, `evt-…`, `tkt-…`, `tb-…`), matching how M1 and M3 store them | PRD §14.7 names the tables but not their columns or invariants; these turn PRD §15.1's atomicity and concurrency rules into constraints the database enforces |
| M2-DD-24 | **Migration safety.** To remove only M2's tables from a shared database, use `alembic downgrade fw_core@-1` (tested: the arena stays at `0002b`). Do not use `fw_core@base` or `0003_firewall_core-1`: both resolve to the shared branch point `0001_foundation` and take every part down with them. The downgrade uses static SQL only (semgrep) | Every part branches from `0001_foundation`; found during the B-01 and B-02 round-trip checks |
| M2-DD-08 | **Matching forms.** Rules use `normalize` (whitespace kept as single spaces, so phrase rules still see word boundaries). Secret scans and echo exclusion use `skeleton` (letters and digits only), so spacing, separators, zero-width characters and case cannot hide a secret, and a student's own typed fragment is excluded the same way. Echo exclusion uses 8-character windows of the secret's skeleton (PRD §5.3) | One normalization definition per purpose; the scanner and the echo check must agree, or a student could win by typing their own spaced-out secret |

---

## 11. Progress log

| Time (H+) | Gate | Done | Blocked or at risk | Next |
| --- | --- | --- | --- | --- |
| H0 | — | Doc created | — | Phase A |
| H0+ | Pre-G1 | **Started.** Branch `m2/aff-core` from `master` `27df46c` (at first in a separate worktree; moved into the main workspace at the user's request, same commits); baseline green (backend 213, frontend 40). **DM1-1 done:** contract review gave one contract change, made by M1 as DD-36 (Off shadow divert), and M2-DD-01 to M2-DD-06 recorded | DD-36 reaches this branch after M1's PR merges | Phase A: A-03 normalizer, A-01 canonicalizer, A-02 limits, A-04 scanners, A-05 rules, A-06 Sentinel, A-07 Gatekeeper |
| H0+ | Phase A | **A-03 and A-04 done** (spec AEGIS-DOM-101). Tests written first and failed (no module), then passed: 34 in `test_fw_text.py`. Two real findings while making them pass: (1) a literal join misses split leaks that have words between the pieces, so the scan became ordered fragment coverage (M2-DD-07), with false-positive and speed tests added; (2) one test case was wrong, because `quote()` leaves this secret unchanged, so it now URL-encodes a spaced-out secret. Ruff (bandit rules) and semgrep clean; invisible characters in the test source replaced with escapes; full suite 0 failures | — | A-01 canonicalizer and A-02 limits |
| H0+ | Phase A | **Moved into the main workspace** at the user's request: the separate worktree was removed (the branch and its commits were kept), and the branch's wrong upstream (`origin/master`) was unset so a bare push cannot target `master`. **A-01 and A-02 done** (spec AEGIS-DOM-102). Tests written first and failed (no modules), then passed: 44 canonical and 17 limits tests. Real finding: the email parser silently rewrote `a@exa mple.com` (M2-DD-09). Review fixes: a private `jsonschema` import replaced with a public one; a PEP 695 type parameter. Full suite 308 collected, 0 failures; ruff (bandit rules), semgrep and pip-audit clean | — | A-05 rules engine (adds `google-re2`), then A-06 Sentinel and A-07 Gatekeeper |
| H0+ | Phase A | **A-05 done** (spec AEGIS-DOM-103). Tests written first and failed (no modules), then passed: 42. Findings while making them pass: a test-helper naming clash (fixed); an `assert` used for type narrowing replaced with an explicit check, since `python -O` strips asserts. Full suite 350 collected, 0 failures; ruff (bandit rules), semgrep and pip-audit clean | — | A-06 Sentinel layer 1, A-07 combiner and Gatekeeper |
| H0+ | Phase A | **A-06 done** (spec AEGIS-DOM-104). Tests written first and failed (no module), then passed: 20. Design check: B-02 must not fire on the poisoned Q3 notes, or the PRD's Off demo line changes (M2-DD-14). Full suite 370 collected, 0 failures; ruff clean | — | A-07 combiner and Gatekeeper (completes Phase A) |
| H0+ | **Phase A done** | **A-07 done** (spec AEGIS-DOM-105). Tests written first and failed (no module), then passed: 41. Phase A total: 7 modules (1,225 lines, each under 210) and 198 M2 unit tests; full suite 411 collected, 0 failures; ruff (bandit rules), semgrep and pip-audit clean. Independent Phase A review requested | — | Fix review findings; then Phase B: B-01 `0003_firewall_core` migration and B-02 rule seed (early seam merges) |
| H0+ | Phase A review | **Merged `master` into `m2/aff-core`** (`c802fe3`, no rebase, because the branch is published): brings in M1 DD-36 (Off shadow `divert` in the contract) and the master-prompt ignore rule. The upstream is now `origin/m2/aff-core`. **Independent Phase A review:** no fail-open in the Gatekeeper; 4 HIGH findings (prefix-less and partial leaks, out-of-order splits, encoding gaps, look-alikes), 4 MEDIUM and 4 LOW. All fixed test-first except LOW 12 (echo window, kept as PRD, M2-DD-22) and R-004's PRD scope (M2-DD-19). 46 regression tests in `tests/unit/test_fw_phase_a_review.py` (written first: 39 failed), now passing. Three original tests were updated for the intended behaviour change (partial leaks; realistic secrets and a precondition in the split property). Decisions M2-DD-17 to M2-DD-22. Full suite 458 collected, 0 failures; ruff and semgrep clean | — | Phase B: B-01 `0003_firewall_core` migration and B-02 rule seed (early seam merges) |
| H0+ | Phase B | **B-01 done** (spec AEGIS-DOM-106). Checked M3's `0004_firewall_intel` and M4's `0005_classroom` first: both follow §0.4, the only cross-part foreign keys are to `users`, and M2's IDs are stored as text, so `0003` matches them. Tests written first and failed (no tables), then 16 of 16 passed; the full suite (474) passes; migration round trip checked; ruff clean | The early seam merge of `0003` needs a PR (user); until then the shared dev DB stays on `master`'s migrations | B-02 rule seed (`app/firewall/seed.py`, DM1-2), then the early-merge PR for B-01 and B-02 together |
| H0+ | Phase B | **B-02 and DM1-2 done.** Tests written first and failed (no module), then passed: 4 seed tests plus 5 new `rule_id` format cases. The seed exposed a real B-01 bug (the `rule_id` check rejected `B-01`), fixed in the migration before it was applied anywhere shared. `downgrade()` rewritten as static SQL after semgrep flagged the f-string (M1's `0002_arena.py` has the same pattern; M1's file, noted for M1). Corrected M2-DD-24 after testing: only `fw_core@-1` removes M2 alone. Full suite 483 collected, 0 failures; ruff and semgrep clean | **Early seam merge of B-01 and B-02 needs a PR to `master` (user)** | After the merge: B-03 event writer, B-04 `register_session` |
