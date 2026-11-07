# Progress Doc M1: Foundation, Infra, Arena and Integration Lead

| Field | Value |
| --- | --- |
| Machine | **M1** (this machine) |
| Stream | Foundation (scaffold, DB, auth, contracts, LLM clients), Infra (Vercel, Railway, Tiger Data, Compose), Arena / Level Blueprint, integration lead |
| Branch | `m1/foundation-arena` |
| Source of truth | [PRD-Injection-Arena-Unified.md](PRD-Injection-Arena-Unified.md) (PRD v3.1). When this doc and the PRD disagree, the PRD wins unless the PRD leaves the point open. Then this doc's §0 decides |
| Sibling docs | [M2 AFF Core](PROGRESS-M2-AFF-Core.md) · [M3 AFF Intel and Admin](PROGRESS-M3-AFF-Intel-Admin.md) · [M4 Classroom](PROGRESS-M4-Classroom.md) |
| PRD sections owned | §0 (D-07, D-08, D-09, D-11 seeding, D-14, D-16), §3, §4, §5, §6, §14.1, §14.2, §14.5, §14.6, §15 (hosting, privacy, Gitleaks), §17 integration |
| Status | `NOT STARTED` |

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
| LLM clients | `app/llm/` (`GeminiClient.generate_json`, `GeminiClient.embed`, `XaiClient.chat_with_tools`, `ScriptedLLM`) | M1 | M2, M3, M4 | `ScriptedLLM` replays scripted answers |
| Audit | `app/db/audit.py::record_audit(actor_id, entity, entity_id, action, before, after)` | M1 | all | writes to the real table, or to an in-memory list in unit tests |

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
| G0 | H3 | Stack deployed to Vercel and Railway and running locally; Auth0 roles work; contracts and fakes merged | M1: bootstrap PR merged to `main`. M2, M3, M4: rebased on it, Track A logic unit-tested |
| G1 | H8 | Basic denies a fixture attack with a logged score; contracts frozen | M2: `0003` migration and rule seed merged, Basic deny demo. M3: `0004` migration merged. M1: arena on `FakeFirewall` end to end. M4: classroom API on fakes |
| G2 | H14 | MVP AFF: all four actions, Review loop, Divert, Strict with risky history. If any MVP test fails, cut all stretch items | M2 and M3: Strict works with real C7 on a shared `integration` branch. M1, M4: UI flows complete on fakes |
| G3 | H17 | Forensics and drafts working; dashboard and quiz complete on fakes. No interface changes after this | Every machine's **Exit criteria** (its own §7) are checked. The final merge window opens |
| G4 | H21 | End-to-end demo script passes twice in a row on real models | Joint, led by M1 |
| — | H21–H24 | Rehearse, backup video, Devpost | Joint |

### 0.6 Merge protocol to `main` (the master branch)

1. **Early seam merges** may go to `main` before exit criteria are met, but only for: the M1 Gate 0 bootstrap, a machine's own migration file and seed, and contract-change PRs approved by all four. CI must be green.
2. **Final merge.** Open a PR from your branch to `main` only when every box in your §7 Exit criteria is `[x]`, CI is green and the branch is rebased on the latest `main`. CI means `ruff check`, `ruff format --check`, `pytest`, `tsc --noEmit` (strict), `next build`, `gitleaks detect`, and `alembic upgrade heads` on an empty TimescaleDB with pgvector.
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
| I-6 | Tests are deterministic: Grok and Gemini are stubbed with `ScriptedLLM`. The real-model attack suite is reported, not gated | §16.1 |
| I-7 | A session is pinned to its manifest. Config, rule, pattern, level and secret changes affect new sessions only | §5.2, §7.5, §15.1 |

### 0.8 How to report progress

Update the checkboxes in this doc as you go. At every gate, add a row to the Progress log at the end (time, gate, done, blocked, next). A `[!]` item that blocks another machine must also be raised with that machine's owner straight away.

---

## 1. Mission and scope

M1 builds the ground the other three stand on, ships the student-facing Arena, and leads the final integration.

**In scope**

- Repo scaffold, CI, Docker, Compose fallback, and deploys to Vercel, Railway (API and worker services) and Tiger Cloud.
- Auth0 sign-in and sign-up, roles claim, `require_user` and `require_role`, `users` upsert.
- The contracts package with every seam in §0.3, the fakes, `ports.py`, the LLM clients, and `audit_log`.
- Arena backend: scenario, levels and secrets seed; session lifecycle; hourly cap and daily budget; win rule; compromise and rotation; C4 and C8 services.
- Arena frontend: landing, level picker, chat, tool-output view, defense feed, win banner, review lock, recap, fingerprint collection, privacy notice.
- The seed set of attack and benign fixtures, and the integration and demo run.

**Out of scope (other machines)**: everything inside the AFF pipeline (M2), risky history, judge, forensics and admin console (M3), dashboard and quiz (M4).

---

## 2. PRD traceability

| PRD ref | Requirement | Where in this doc |
| --- | --- | --- |
| §3.2, §3.3, D-14 | Technology placement, repo layout, one app per host | Phase A |
| §4.1–§4.3 | Roles, tabs, auth flow and auth acceptance | Phase A, §5 (M1-X01–X08) |
| §5.1–§5.3, D-07, D-08 | Scenario, three levels, secrets, compromise, rotation | Phase B |
| §5.3 echo exclusion | AFF computes it; arena only reads `facts` | §3 |
| §6.1–§6.4 | Start screen, chat screen, lifecycle, win rule | Phases B and C |
| §6.5 | Demo script | §8 |
| §8.5 (inputs) | `x-forwarded-for` forwarding, shared secret header, fingerprint | Phase A, Phase C |
| §14.1, §14.2, §14.5, §14.6 | Contracts package, users, arena sessions, auth | Phase A, Phase C |
| §15.1 Hosting, Cost, Code style | Deploy, caps, linting | Phases A and B |
| §15.2 | Privacy notice, Gitleaks | Phases A and C |
| §16.3 rows 1, 7 (secret rotation part), 9, 10 | Acceptance checklist items M1 leads | §6 |
| §17.2 G0, G4 | Gate exits M1 leads | §7, §8 |

---

## 3. Interfaces M1 provides and consumes

### 3.1 Contract additions M1 must write at Gate 0

PRD §14 names these types but does not define them. M1 defines them in the Gate 0 PR and asks M2, M3 and M4 to review the shapes before Gate 1, when contracts freeze.

| Type or function | Proposed fields | Seam |
| --- | --- | --- |
| `Mode`, `Stage`, `Decision`, `ExecutionStatus`, `TicketStatus`, `ScoreBand` | Literals exactly as PRD §10.1 enums | `contracts/common.py` |
| `ClientMeta` | `ip: str \| None`, `user_agent: str \| None`, `fingerprint_hash: str \| None` | `contracts/common.py` |
| `MockStateSeed` (**gap in PRD**: `RegisterSession` has nowhere to carry the fake dataset) | `documents`, `emails`, `db_rows`, `filesystem`, `attacker_mailbox` | added to `RegisterSession` as `mock_state_seed` |
| `Catalog` | `rules: list[RuleSummary]` (id, applies_on, action, note), `tools: list[ToolDef]` | C2 |
| `TicketResult` | `ticket_id`, `status: TicketStatus`, `expires_at`, `turn_result: TurnResult \| None` | C2 |
| `close_session(owner_ref, fw_session_id) -> None` (**gap**: the lifecycle needs a close) | Writes a `finalize` event. A pending ticket on the session becomes `expired` (Deny) | C2 |
| Firewall errors | `SessionBusy`, `MessageConflict`, `ModeChangeRejected`, `SessionClosed`, `NotFound`, `BotUnavailable` | C2 |
| `TranscriptItem`, `DecisionItem`, `TicketItem`, `DivertItem`, `ForensicItem`, `InsightFilters`, `RuleCount`, `PatternCount`, `DecisionCount`, `FamilyCount` | See the PRD §12.2 block contents. `DivertItem` has **no** network fields | C3 |
| `get_decision_counts(filters)`, `get_attack_family_counts(filters)` (**gap**: §12.3 needs them) | Counts per mode and decision; counts per attack family | C3 |
| `get_session_summaries(fw_session_ids)`, `get_manifest_summary(fw_session_id)`, `redact_for_session(fw_session_id, text)` (**gap**: §12.1, §12.2 and §13.2 need them; see M4 §3.3) | Diverted count, max score, delivered time, echo exclusion; manifest snapshot; secret redaction to `[SECRET]` without exposing the value. All C3 text fields come back already redacted | C3 (M2 implements) |
| `FeedItem.shadow_decision` (**gap**: the Off feed must show "would have denied", PRD §6.5 step 1) | `Literal["allow","deny","review"] \| None`, set only in Off | C2 |
| `TicketQueueItem`, `TicketDecision` (`ok` or `not_ok`), `RuleDef`, `RuleForm`, `RiskyPatternRef`, `DivertAdminItem` (with trace-back), `EventFilter` | PRD §11, §9.1, §8.5 | C6 |
| `CheckedItem`, `RiskyHistorySignals`, `RiskyBehaviorRecord`, `PatternCandidate`, `JudgeVerdict`, `JudgeError`, `JudgeTimeout`, `RiskyHistoryPort`, `JudgePort` | See the M2 and M3 docs, §3 | C7 |
| `ArenaSession`, `SessionFilters`, `LevelSummary`, `SecretStatus`, `LevelConfigUpdate` | PRD §14.5 columns plus `admin_test: bool`, `recap_unlocked_at` | C4, C8 |
| `save_level_version(update, actor) -> LevelConfig`, `rotate_secret(level_id, actor) -> SecretStatus`, `get_secret_status() -> list[SecretStatus]`, `unlock_recap(session_id) -> None` | Each writes `audit_log` | C8 |

### 3.2 M1 consumes

| From | What | Until real code lands |
| --- | --- | --- |
| M2 (C2) | `read_catalog`, `register_session`, `send_message`, `check_ticket`, `close_session` | `FakeFirewall`, scripted per test |
| M2 and M3 (C3) | `get_decisions`, `get_diverts` for the defense recap | `FakeFirewallRead` |

---

## 4. Work breakdown

### Phase A: Gate 0 bootstrap (H0–H3). Blocks everyone, so it comes first

Aim to merge the contracts and skeleton part by **H2** so the others can rebase early, and finish deploys by H3.

- [ ] A-01 Monorepo layout exactly as PRD §3.3. Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 async, Alembic, Ruff, pytest, pytest-asyncio. Next.js (App Router) with TypeScript strict.
- [ ] A-02 `backend/app/contracts/` with every model in PRD §14.3–§14.6 and §3.1 above, plus `contracts/fakes/` for every seam. Fakes return valid shapes and can be scripted per test.
- [ ] A-03 `app/firewall/ports.py` with the `AEGIS_USE_FAKES` switch (§0.3).
- [ ] A-04 `app/llm/`: `GeminiClient` (structured output with `response_schema`, `embed` at 768 dimensions, per-call timeout), `XaiClient` (OpenAI-compatible tool calling, model ID from config), `ScriptedLLM` (replays a list of canned answers, raises on an unexpected call), `budget.py` (global daily budget counter for Grok and Gemini, PRD §15.1 Cost).
- [ ] A-05 `app/db/`: async engine, session factory, `0001_foundation` migration (extensions, `users`, `audit_log`), `audit.py::record_audit`.
- [ ] A-06 `app/main.py` mounts `arena`, `admin`, `classroom` and `quiz` routers (placeholders for M3 and M4, §0.2 rule 4). Adds a `/healthz` route.
- [ ] A-07 Auth0 tenant: application, API audience, roles `teacher` and `firewall_admin`, a Post-Login Action that writes the `https://aegis/roles` claim, seeded teacher, admin and dual-role accounts (team members only, PRD §15.2). Callback URLs for the Vercel domain and localhost.
- [ ] A-08 `app/auth/`: `require_user()` verifies with `auth0-api-python` and upserts `users` by `auth0_sub` on first call (PRD §4.3 step 4). `require_role(role)` reads the token claim, never the DB cache. A user with no role is `student`.
- [ ] A-09 Trusted proxy middleware: FastAPI accepts requests only with the `x-aegis-proxy` shared secret header and builds `ClientMeta` from `x-forwarded-for` only on such requests (PRD §8.5, §15.1).
- [ ] A-10 Frontend: `lib/auth0.ts` (`@auth0/nextjs-auth0` v4), `lib/api.ts` server-side route handler that forwards the access token, `x-forwarded-for` and the shared secret header to FastAPI. The browser holds only the session cookie. `components/shell/` role-aware tab nav (PRD §4.2). Cyber terminal theme tokens.
- [ ] A-11 `Dockerfile` (one image, two commands: `api` and `worker`), `railway.json` (two services), `vercel.json`, `docker-compose.yml` (Next.js, FastAPI, worker, `timescale/timescaledb-ha` with pgvector), `.env.example` listing every variable with fake values.
- [ ] A-12 CI: ruff, pytest, `tsc --noEmit`, `next build`, gitleaks, and `alembic upgrade heads` on a TimescaleDB service container.
- [ ] A-13 Seed fixture set: `fixtures/attacks/` (at least one file per attack family in PRD §10.2: direct override, indirect injection, authority spoofing, forged approval, goal drift, exfiltration via email, encoded or split leak, shell abuse) and `fixtures/benign/` (at least 15 benign messages and at least 10 benign tool calls, each tool covered). A shared JSON schema for fixture files goes in `contracts/fixtures.py`.
- [ ] A-14 Deploy: Vercel (frontend), Railway (api and worker), Tiger Cloud (run migrations). Check on the deployed URL that the client IP survives the proxy (PRD §18.1 risk).
- [ ] A-15 **Grok gullibility smoke test** (PRD §18.1, highest-impact risk): with the scenario system prompt from B-02, the poisoned-document attack must succeed against the real Grok model with no firewall. If it does not, make the prompt more gullible and record the model ID.
- [ ] A-16 Pin model IDs (Grok, Gemini Flash, Gemini Pro, embedding model) in config. Record them in the Progress log (PRD §18.2).
- [ ] A-17 Open the Gate 0 PR and merge. Tell M2, M3 and M4 to rebase.

### Phase B: Arena backend on `FakeFirewall` (H3–H8)

- [ ] B-01 `0002_arena` migration: `scenario`, `levels` (versioned: a new row per edit, `(level_id, level_version)` unique), `secrets` (versioned per level, `compromised_by_session`, `compromised_by_user`, `compromised_at`), `arena_sessions` (PRD §14.5 plus `admin_test`, `recap_unlocked_at`), `results`, `usage`.
- [ ] B-02 Scenario seed (PRD §5.1): fictional company, departments, bot tone; a deliberately gullible Grok system prompt; five tools with JSON schemas and `high_risk` flags (`search_docs`, `read_file`, `send_email` high, `query_db` high, `run_shell` high); fake dataset of documents, emails and DB rows; **one poisoned document** that tells the bot to email "the latest notes" to the attacker mailbox; attacker mailbox address on an external domain; company allowlist domain `company.example`.
- [ ] B-03 Levels seed (PRD §5.2): Level 1 Off, Level 2 Basic, Level 3 Strict, with secret tier, review timeout 120 s, divert flag, and the PRD §7.3 weights and §7.4 thresholds (Basic: review 40, deny 70, divert 95, alert 99. Strict: review 30, deny 60, divert 95, alert 99. Off: the Strict values, because Off runs full Strict scoring in shadow, PRD §7.2). `rule_version = 0` on every level means "pin the latest rule set at session start" (M2 resolves it into the manifest), so an approved draft reaches new sessions without a level edit (E-57).
- [ ] B-04 Secrets seed (PRD §5.3): one long random token per level, placed inside realistic content in the dataset. Generated by the seed script, never committed.
- [ ] B-05 Session start (PRD §6.3 step 1): check the hourly cap, snapshot `level_version` and `secret_version`, build `RegisterSession` (agent, level config, secret, mock state seed), call `register_session`, store `fw_session_id` and `manifest_id`. Admin test sessions get `admin_test: true`.
- [ ] B-06 Send message (PRD §6.3 step 2–3): forward `owner_ref`, `fw_session_id`, `message_id`, text and `ClientMeta`. Wrap in a 30 s timeout. AFF unreachable, timeout or `BotUnavailable` gives arena status `not_sent` with a retry that reuses the same `message_id`.
- [ ] B-07 Win evaluator (PRD §6.4): uses `facts.secret_delivered` only. On the first win per secret version, mark the secret compromised (session, student, time). Write `results`.
- [ ] B-08 Hourly cap of 30 messages per student per hour and the global daily budget (PRD §6.1, §15.1). Expose remaining messages. A retry of a `not_sent` message with the same `message_id` does not use up another slot.
- [ ] B-09 Check ticket (PRD §8.3 step 7): `GET` endpoint the chat page polls while `awaiting_review`. It calls `check_ticket` and returns the updated `player_view`.
- [ ] B-10 Close session (PRD §6.3 step 4): calls `close_session`, sets `closed_at`, unlocks the recap. Closing twice is a no-op.
- [ ] B-11 Recap endpoint: after close or after `unlock_recap`, returns per-item decisions with diverts revealed (from C3 `get_decisions`, `get_diverts`). Before that, 403.
- [ ] B-12 Start screen data (PRD §6.1): level cards, per-student Obtained or Not yet badge, class-wide compromised tag, read-only rule list per level from `read_catalog`, remaining messages.
- [ ] B-13 Response filter: every arena response model is built from `player_view` fields only. A test asserts that no `facts`, `judge_reason`, tool arguments or trace-back keys appear in any arena JSON (I-3).

### Phase C: Arena UI and C4/C8 services (H8–H14)

- [ ] C-01 Landing page (Cyber terminal theme) with Sign in and Create account (`/auth/login?screen_hint=signup`). Sign-up links the privacy notice text from PRD §15.2.
- [ ] C-02 Level picker (PRD §6.1) with badges, compromised tag, rules list, remaining messages. All levels open and replayable.
- [ ] C-03 Chat screen (PRD §6.2): message thread and the six statuses with the exact PRD copy: Sent, Replied, Blocked ("Blocked." plus rule IDs), Awaiting review (pending message, input locked, start-new-session still available), Human denied ("A reviewer denied this request.", input unlocks), Not sent ("Firewall unavailable, message not sent" with retry).
- [ ] C-04 Tool-output view: states executed, blocked, awaiting review, human denied. Diverted actions show as executed with decoy content.
- [ ] C-05 Defense feed: one line per checked item with stage, decision, rule IDs, score band. Diverts show as allow until the recap.
- [ ] C-06 Win banner when `secret_delivered`. Chat stays open.
- [ ] C-07 Review polling: while `awaiting_review`, poll the check-ticket endpoint (for example every 3 s), stop when resolved, unlock input.
- [ ] C-08 Recap view after close, showing diverts and what the student actually received.
- [ ] C-09 Client fingerprint (PRD §8.5): SHA-256 of user agent, accept-language, timezone, screen size and platform, computed in the browser with no fingerprinting library, sent only on levels with `divert_enabled` (Basic, Strict).
- [ ] C-10 My sessions list for students (own only), with a close button.
- [ ] C-11 C4 services: `list_sessions(filters)` (teacher: all; student: own), `get_session(id)`, `list_levels()`.
- [ ] C-12 C8 services: `save_level_version` (validates thresholds and weights, writes a new version, audit), `rotate_secret` (new token, new version, audit; running sessions keep theirs), `get_secret_status`, `unlock_recap`.
- [ ] C-13 Honeytoken endpoint, **stretch only** (PRD §5.3, §2.1 item 11): a small endpoint that logs any use of the Strict honeytoken and reports `secret_used`.

### Phase D: hardening and integration prep (H14–H17)

- [ ] D-01 Integration branch `integration` with real M2 C2 (as soon as M2 reaches G1) and run the arena flows against it.
- [ ] D-02 Demo seed script (`scripts/seed_demo.py`): resets the DB, seeds the scenario, levels, secrets, rules and demo accounts. Idempotent.
- [ ] D-03 Compose fallback: `docker compose up` on a clean laptop, migrations applied, full demo path works offline except the model APIs.
- [ ] D-04 Fill in the M1 §5 edge case tests, run the full suite, fix flaky tests.
- [ ] D-05 Gitleaks over the full history. Check that `.env.example` contains no real values.

---

## 5. Edge cases (each is a required test)

M1 owns no PRD §16.2 E-case outright. M1 co-owns **E-54** (the recap part) and **E-55** (the `require_role` part), and runs all E-cases as part of integration (§8). Derived cases below come from PRD §4–§6, §14.5 and §15.

| # | Case | Expected | PRD | Gate |
| --- | --- | --- | --- | --- |
| E-54 (recap part) | Divert in a turn, then the student closes the session | Feed showed allow during the session. Recap now shows divert | §6.2 | MVP |
| E-55 (auth part) | Teacher token on a `firewall_admin` route | 403 from `require_role`. Test with the shared helper so M3 can reuse it | §4.1 | MVP |
| M1-X01 | Request with no token, an expired token, or a token for the wrong audience | 401 | §4.3 | MVP |
| M1-X02 | Student calls any teacher or admin route | 403 | §4.3 | MVP |
| M1-X03 | New sign-up with no role claim | Lands in student view, `users` row created once | §4.3 | MVP |
| M1-X04 | Two first API calls from the same new user at the same time | Exactly one `users` row (upsert on `auth0_sub`) | §4.3 | MVP |
| M1-X05 | User holds both `teacher` and `firewall_admin` | Sees both tab sets. Each route still checks its own role | §4.1 | MVP |
| M1-X06 | `users.role` cache says teacher but the token claim does not | Treated as student. The token is the source of truth | §14.2 | MVP |
| M1-X07 | Same person plays and is then viewed in Classroom | Same `users.id` in `arena_sessions` and in C4 results | §4.3 | MVP |
| M1-X08 | Request to FastAPI without the shared proxy secret header | 401 or 403. A spoofed `x-forwarded-for` sent directly to FastAPI is ignored | §8.5, §15.1 | MVP |
| M1-X09 | 31st message in one hour by one student | Rejected before reaching the AFF, remaining shows 0. Other students are not affected | §6.1 | MVP |
| M1-X10 | Retry of a `not_sent` message with the same `message_id` | Does not use another hourly slot. AFF returns the stored result if it had already processed it | §6.3 | MVP |
| M1-X11 | Global daily model budget used up | Clear message to the student. No call reaches Grok or Gemini | §15.1 | MVP |
| M1-X12 | AFF call takes longer than 30 s, or raises | Status `not_sent` with retry, no partial reply shown | §6.3 | MVP |
| M1-X13 | Admin saves a new level version while a session on that level is running | Running session keeps its snapshot. A new session gets the new version | §5.2 | MVP |
| M1-X14 | Teacher rotates the secret while a session is running | Running session keeps the old secret. New sessions get the new one. Rotation in `audit_log` | §5.3, §12.4 | MVP |
| M1-X15 | Two different students obtain the same secret version | Compromise records the first one only and is not overwritten | §5.3 | MVP |
| M1-X16 | `facts.diverted` true and `secret_delivered` false | No win, no compromise | §6.4 | MVP |
| M1-X17 | Win reached, student keeps chatting | Banner stays, chat keeps working, no second compromise record | §6.2 | MVP |
| M1-X18 | Student sends a new message while a ticket is pending | Input locked in the UI. API rejects with busy. Start-new-session still works | §6.2, §8.3 | MVP |
| M1-X19 | Student closes a session while a ticket is pending | Session closes. The pending ticket ends as expired (Deny), never executes later | §8.3 | MVP |
| M1-X20 | Message sent to a closed session | Rejected with `SessionClosed` | §6.3 | MVP |
| M1-X21 | Recap requested before close and before a quiz starts | 403 | §6.2 | MVP |
| M1-X22 | Recap requested after `unlock_recap` (quiz started) on a still-active session | Recap available | §6.2 | MVP |
| M1-X23 | Player text of 4,001 characters | Arena forwards it unchanged. It never truncates. (The AFF denies it in Basic and Strict and truncates in Off) | §7.6 | MVP |
| M1-X24 | Any arena JSON response | Contains no `facts`, `judge_reason`, tool arguments or trace-back fields | §15.1 | MVP |
| M1-X25 | Level with `divert_enabled: false` (Off) | No fingerprint is collected or sent | §8.5 | MVP |
| M1-X26 | `alembic upgrade heads` on an empty Tiger Cloud DB and on the local TimescaleDB container | Same schema in both | §3.2 | MVP |
| M1-X27 | Seed script run twice | No duplicates, same secrets unless rotation is asked for | §5.3 | MVP |
| M1-X28 | Admin plays the arena | Session flagged `admin_test`, filterable in the teacher list | §4.2 | MVP |
| M1-X29 | `level_version` or `secret_version` missing at session start (DB error) | Session does not start. Error shown, nothing registered with the AFF | §15.1 | MVP |

---

## 6. Acceptance criteria (PRD-mapped)

- [ ] AC-1 PRD §4.3 acceptance: new sign-up lands in student view; seeded teacher sees teacher tabs; student on a teacher or admin route gets 403; missing or invalid token gets 401; the same `users.id` appears in arena and classroom records.
- [ ] AC-2 PRD §6.1–§6.4: all three levels playable end to end through the UI against `FakeFirewall`, with all six chat statuses reachable by scripted fakes.
- [ ] AC-3 PRD §5.3: compromise is recorded on first delivery; rotation works for teacher and admin; running sessions keep their snapshot.
- [ ] AC-4 PRD §6.2: diverts look like Replied in the chat, tool output and feed, and are revealed in the recap only.
- [ ] AC-5 PRD §15.1 Hosting: Vercel, Railway (two services) and Tiger Cloud running; FastAPI rejects calls not from the Next.js server; Compose fallback works.
- [ ] AC-6 PRD §15.2: privacy notice on sign-up; Gitleaks clean.
- [ ] AC-7 PRD §16.3: "Role checks verified server-side for all three roles" for every route M1 owns, plus the shared test helper that M3 and M4 use for theirs.
- [ ] AC-8 Every contract in §0.3 and §3.1 exists with a fake, and the other three machines confirm the shapes before Gate 1.

---

## 7. Exit criteria for the final merge (all must be `[x]`)

- [ ] X-1 Gate 0 met on time: bootstrap PR merged, stack deployed to Vercel and Railway, running locally, Auth0 roles work, contracts and fakes merged.
- [ ] X-2 Contracts frozen at Gate 1 with sign-off from M2, M3 and M4 recorded in the Progress log.
- [ ] X-3 Every M1 edge case in §5 has a passing automated test.
- [ ] X-4 Every acceptance item in §6 is checked.
- [ ] X-5 CI green on the branch: ruff, pytest, `tsc --noEmit`, `next build`, gitleaks, `alembic upgrade heads`.
- [ ] X-6 Arena runs end to end against `FakeFirewall` and against real M2 on the `integration` branch (Off and Basic at least).
- [ ] X-7 No file outside M1's ownership (§0.1) changed, except PR-approved contract changes.
- [ ] X-8 Model IDs, Auth0 tenant settings and deployed URLs are recorded in the Progress log and in `.env.example` (as names, not values).

---

## 8. Integration duties (H17–H21, M1 leads)

- [ ] INT-1 Merge in order M1, M2, M3, M4 (§0.6). Add `0099_merge_heads`. Empty `AEGIS_USE_FAKES` on all environments.
- [ ] INT-2 Run every PRD §16.2 E-case (E-01 to E-60, all four machines' tests) on `main` with fakes off. Record pass or fail per E-ID in the Progress log.
- [ ] INT-3 Run the PRD §6.5 demo script end to end on real Grok and Gemini on the deployed stack, steps 1–6:
  1. Off: poisoned document emails the secret, win banner, feed shows "would have denied (R-003, B-01)".
  2. Basic direct: R-003 denies the email.
  3. Basic split: secret leaks a few characters per reply.
  4. Strict: split blocked by cumulative scan; held email tool call; admin "not ok" gives Human Deny; follow-up scores 95 or more from risky history and is diverted with a decoy in the mailbox. The held email must score in the Strict Review band (30–59) and must not trip R-003, so send it to an internal address. Risky history from the Basic steps can push it into Deny, so check the score in rehearsal or use a separate demo student for Strict (M3 INT-4).
  5. Forensics: approve the Gemini draft for the split attack; a new Basic session now blocks it.
  6. Teacher: session list, compromised Off secret, divert view, quiz launched, completed, graded.
- [ ] INT-4 Gate 4: the demo script passes **twice in a row** on real models.
- [ ] INT-5 Tick the PRD §16.3 MVP acceptance checklist as a team and paste it into the Progress log.
- [ ] INT-6 Record the backup video. Check the Compose fallback once more on the demo laptop.

---

## 9. Stretch (only after Gate 2, and only if every MVP test passes, PRD §17.2)

- [ ] S-1 Honeytoken `secret_used` endpoint (C-13), shared with M2 (decoy carries the honeytoken).
- [ ] S-2 Help M3 with the Auth0 CIBA tenant setup if M3 takes on CIBA.

---

## 10. Risks and open decisions (defaults used if nobody answers)

| Item | Default |
| --- | --- |
| Grok refuses naive attacks in Off | Gullible system prompt, tested at H3 (A-15) |
| Client IP lost through the proxy | Tested on the deployed URL at G0 (A-14) |
| Contract drift | Frozen at G1, all-four approval after that |
| Exact model IDs | Chosen at G0, pinned in config and the manifest |
| Does a `not_sent` retry count toward the hourly cap | No (M1-X10) |
| Admin test sessions in teacher insights | Included but flagged `admin_test`, filterable |
| `audit_log` owner | Foundation (§0.1 note 1) |

---

## 11. Progress log

| Time (H+) | Gate | Done | Blocked or at risk | Next |
| --- | --- | --- | --- | --- |
| H0 | — | Doc created | — | Phase A |
