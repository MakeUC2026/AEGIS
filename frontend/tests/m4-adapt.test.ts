import { describe, expect, it } from "vitest";

import {
  applyStudentNameFilter,
  filtersToApiQuery,
  toDetail,
  toInsights,
  toSecrets,
  toSessionList,
  type ApiDetail,
  type ApiInsights,
  type ApiSessionRow,
} from "@/app/classroom/_lib/adapt";
import { parseFilters } from "@/app/classroom/_lib/filters";
import { TOTAL_POINTS } from "@/app/quiz/_lib/rubric";

const row = (over: Partial<ApiSessionRow> = {}): ApiSessionRow => ({
  id: "s1",
  student_id: "u1",
  student_name: "Ada",
  level_id: "lvl-1",
  level_name: "Warm-up",
  mode: "off",
  status: "closed",
  admin_test: false,
  secret_obtained: true,
  secret_obtained_at: "2026-11-07T10:00:00Z",
  diverted_count: 0,
  max_sentinel_score: 6,
  started_at: "2026-11-07T09:50:00Z",
  quiz_status: "not_taken",
  quiz_score: null,
  quiz_best: null,
  quiz_attempts: 0,
  ...over,
});

describe("filtersToApiQuery", () => {
  it("maps UI filters to the API names and drops the name filter", () => {
    const f = parseFilters({ student: "ada", level: "lvl-2", mode: "strict", outcome: "obtained", diverted: "no", quiz_status: "done", admin_test: "yes" });
    const q = new URLSearchParams(filtersToApiQuery(f, "teacher"));
    expect(Object.fromEntries(q)).toEqual({ level: "lvl-2", mode: "strict", outcome: "obtained", diverted: "no", quiz_status: "done", admin_test: "true" });
  });
  it("sends nothing for an empty filter", () => {
    expect(filtersToApiQuery({}, "teacher")).toBe("");
  });
  it("never sends student-only extras for a student", () => {
    expect(filtersToApiQuery(parseFilters({ student: "x", admin_test: "yes" }), "student")).toBe("");
  });
});

describe("toSessionList", () => {
  it("maps rows and turns the stored percent back into exact points", () => {
    for (let points = 0; points <= TOTAL_POINTS; points++) {
      const percent = Math.round((points * 100) / TOTAL_POINTS);
      const out = toSessionList({ items: [row({ quiz_status: "done", quiz_score: percent })], total: 1, levels: [] });
      expect(out.rows[0].quizPoints).toBe(points);
    }
  });
  it("maps names, flags and levels", () => {
    const out = toSessionList({ items: [row({ admin_test: true, student_name: null })], total: 1, levels: [{ level_id: "lvl-1", name: "Warm-up" }] });
    expect(out.rows[0]).toMatchObject({ studentName: "Unknown student", adminTest: true, secretObtained: true, levelName: "Warm-up", quizId: null });
    expect(out.levels).toEqual([{ id: "lvl-1", name: "Warm-up" }]);
  });
  it("falls back to the level id when the name is missing", () => {
    expect(toSessionList({ items: [row({ level_name: null })], total: 1, levels: [] }).rows[0].levelName).toBe("lvl-1");
  });
});

describe("applyStudentNameFilter", () => {
  it("filters by name substring for staff and ignores it for students", () => {
    const rows = toSessionList({ items: [row(), row({ id: "s2", student_name: "Ben" })], total: 2, levels: [] }).rows;
    expect(applyStudentNameFilter(rows, "ben", "teacher").map((r) => r.id)).toEqual(["s2"]);
    expect(applyStudentNameFilter(rows, "ben", "student")).toHaveLength(2);
    expect(applyStudentNameFilter(rows, undefined, "teacher")).toHaveLength(2);
  });
});

const detail = (view: "staff" | "student"): ApiDetail => ({
  view,
  session: row(),
  outcome: { obtained: true, obtained_at: "2026-11-07T10:00:00Z", duration_s: 600, echo_excluded: false },
  transcript: [{ message_id: "m1", time: "2026-11-07T09:51:00Z", speaker: "student", text: "<script>alert(1)</script>", status: null, is_decoy: false }],
  decisions: view === "staff" ? [{ event_id: "e1", time: "2026-11-07T09:51:00Z", message_id: "m1", stage: "input_check", decision: "allow", shadow_decision: null, execution_status: "not_executed", sentinel_score: 6, score_breakdown: { rules: 6, judge: null }, thresholds_used: {}, rule_ids: ["R1"], risky_pattern_ids: [] }] : null,
  config: view === "staff" ? { level_id: "lvl-1", level_version: 1, mode: "off", rule_version: 1, pattern_version: 1, thresholds: { deny: 60 }, weights: {}, bot_model_id: "b", judge_model_id: null } : null,
  held_items: view === "staff" ? [{ ticket_id: "t1", stage: "tool_call_check", status: "approved", created_at: "2026-11-07T09:51:00Z", decided_at: null, decided_by_name: "Dee" }] : null,
  diverts: view === "staff" ? [{ event_id: "d1", time: "2026-11-07T09:52:00Z", stage: "tool_call_check", tool: "read_file", attempted_summary: "a", decoy_shown: "b" }] : null,
  forensics: view === "staff" ? [{ event_id: "f1", attack_family: "roleplay", atlas_techniques: [], summary: "s", missed_signals: [], would_have_blocked_in: [] }] : null,
});

describe("toDetail", () => {
  it("maps every staff block", () => {
    const d = toDetail(detail("staff"));
    expect(d.staff).toBe(true);
    expect(d.view.decisions[0]).toMatchObject({ id: "e1", score: 6, rules: ["R1"], breakdown: { rules: 6, judge: null } });
    expect(d.view.config.thresholds).toEqual({ deny: 60 });
    expect(d.view.heldItems[0]).toMatchObject({ decidedBy: "Dee", status: "approved" });
    expect(d.view.diverts[0]).toMatchObject({ tool: "read_file", attemptedSummary: "a", decoyShown: "b" });
    expect(d.view.forensics).toEqual({ family: "roleplay", summary: "s" });
    expect(d.view.outcome).toEqual({ obtained: true, at: "2026-11-07T10:00:00Z", echoExcluded: false });
  });
  it("marks the student view and leaves the staff blocks empty", () => {
    const d = toDetail(detail("student"));
    expect(d.staff).toBe(false);
    expect(d.view.decisions).toEqual([]);
    expect(d.view.diverts).toEqual([]);
    expect(d.view.forensics).toBeNull();
  });
  it("keeps hostile transcript text as plain data", () => {
    expect(toDetail(detail("staff")).view.transcript[0].text).toBe("<script>alert(1)</script>");
  });
});

const insights: ApiInsights = {
  overview: { students: 2, sessions: 3, sessions_per_student: 1.5, active_today: 1 },
  outcomes: [{ level_id: "lvl-1", level_name: "Warm-up", sessions: 2, obtained: 1, not_obtained: 1, rate: 0.5 }],
  defense: {
    top_rules: [{ rule_id: "R1", count: 4 }],
    decisions: [
      { mode: "basic", decision: "allow", count: 5 },
      { mode: "basic", decision: "deny", count: 2 },
      { mode: "basic", decision: "human_deny", count: 1 },
      { mode: "strict", decision: "divert", count: 3 },
    ],
    divert_count: 3,
  },
  attack_families: [{ attack_family: "roleplay", count: 2 }],
  risky_patterns: [{ pattern_id: "P1", count: 9 }],
  quiz: { taken: 1, open: 0, average_percent: null, lowest_items: [{ item: "defense_layer", title: "Defense layer", average: 1, n: 1 }] },
};

describe("toInsights", () => {
  it("groups decisions per mode and folds human denials into deny", () => {
    const i = toInsights(insights);
    expect(i.defense.decisionsPerMode).toEqual([
      { mode: "basic", allow: 5, review: 0, deny: 3, divert: 0 },
      { mode: "strict", allow: 0, review: 0, deny: 0, divert: 3 },
    ]);
    expect(i.overview).toEqual({ students: 2, sessions: 3, sessionsPerStudent: 1.5, activeToday: 1 });
    expect(i.outcomes[0]).toEqual({ levelName: "Warm-up", sessions: 2, obtained: 1, notObtained: 1, ratePercent: 50 });
    expect(i.quiz.averagePercent).toBeNull();
    expect(i.attackFamilies).toEqual([{ family: "roleplay", count: 2 }]);
  });
});

describe("toSecrets", () => {
  it("maps status rows without any value field", () => {
    const out = toSecrets({ items: [{ level_id: "lvl-1", level_name: "Warm-up", secret_version: 2, compromised: true, compromised_by_id: "u1", compromised_by_name: "Ada", compromised_by_session: "s1", compromised_at: "2026-11-07T10:00:00Z", created_at: "2026-11-06T10:00:00Z" }] });
    expect(out[0]).toEqual({ levelId: "lvl-1", levelName: "Warm-up", version: 2, compromised: true, by: "Ada", sessionId: "s1", at: "2026-11-07T10:00:00Z" });
  });
});
