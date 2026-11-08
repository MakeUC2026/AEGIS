// Maps the classroom API (snake_case JSON from backend/app/classroom/schemas.py) onto the
// view-models the Phase A screens already use. Pure functions, no I/O, so they are unit tested.
// Untrusted text (transcripts, diverts) passes through untouched; React escapes it on render.

import { TOTAL_POINTS } from "@/app/quiz/_lib/rubric";

import type { Filters } from "./filters";
import type { DecisionLine, Mode, QuizStatus, SessionDetail, SessionRow, ViewerKind } from "./types";

export interface ApiSessionRow {
  id: string;
  student_id: string;
  student_name: string | null;
  level_id: string;
  level_name: string | null;
  mode: Mode;
  status: "active" | "closed";
  admin_test: boolean;
  secret_obtained: boolean;
  secret_obtained_at: string | null;
  diverted_count: number;
  max_sentinel_score: number | null;
  started_at: string;
  quiz_status: QuizStatus;
  quiz_score: number | null; // percent of the latest attempt
  quiz_best: number | null;
  quiz_attempts: number;
}

export interface ApiSessionList {
  items: ApiSessionRow[];
  total: number;
  levels: { level_id: string; name: string }[];
}

export interface ApiDetail {
  view: "staff" | "student";
  session: ApiSessionRow;
  outcome: { obtained: boolean; obtained_at: string | null; duration_s: number | null; echo_excluded: boolean };
  transcript: {
    message_id: string;
    time: string;
    speaker: "student" | "bot" | "tool";
    text: string;
    status: string | null;
    is_decoy: boolean;
  }[];
  decisions:
    | {
        event_id: string;
        time: string;
        message_id: string;
        stage: string;
        decision: DecisionLine["decision"];
        shadow_decision: string | null;
        execution_status: string;
        sentinel_score: number;
        score_breakdown: Record<string, number | null>;
        thresholds_used: Record<string, number>;
        rule_ids: string[];
        risky_pattern_ids: string[];
      }[]
    | null;
  config: {
    level_id: string;
    level_version: number;
    mode: Mode;
    rule_version: number;
    pattern_version: number;
    thresholds: Record<string, number>;
    weights: Record<string, number>;
    bot_model_id: string;
    judge_model_id: string | null;
  } | null;
  held_items:
    | {
        ticket_id: string;
        stage: string;
        status: "pending" | "approved" | "human_denied" | "expired";
        created_at: string;
        decided_at: string | null;
        decided_by_name: string | null;
      }[]
    | null;
  diverts:
    | { event_id: string; time: string; stage: string; tool: string | null; attempted_summary: string; decoy_shown: string }[]
    | null;
  forensics:
    | {
        event_id: string;
        attack_family: string;
        atlas_techniques: string[];
        summary: string;
        missed_signals: string[];
        would_have_blocked_in: Mode[];
      }[]
    | null;
}

export interface ApiInsights {
  overview: { students: number; sessions: number; sessions_per_student: number; active_today: number };
  outcomes: { level_id: string; level_name: string; sessions: number; obtained: number; not_obtained: number; rate: number }[];
  defense: {
    top_rules: { rule_id: string; count: number }[];
    decisions: { mode: Mode; decision: string; count: number }[];
    divert_count: number;
  };
  attack_families: { attack_family: string; count: number }[];
  risky_patterns: { pattern_id: string; count: number }[];
  quiz: {
    taken: number;
    open: number;
    average_percent: number | null;
    lowest_items: { item: string; title: string; average: number; n: number }[];
  };
}

export interface ApiSecretList {
  items: {
    level_id: string;
    level_name: string | null;
    secret_version: number;
    compromised: boolean;
    compromised_by_id: string | null;
    compromised_by_name: string | null;
    compromised_by_session: string | null;
    compromised_at: string | null;
    created_at: string;
  }[];
}

const UNKNOWN_STUDENT = "Unknown student";
const YES_NO_TO_BOOL = { yes: "true", no: "false" } as const;

/** Query string for GET /classroom/sessions. The name filter stays in the page (the API filters
 *  by user id), and a student never sends staff-only filters. */
export function filtersToApiQuery(f: Filters, kind: ViewerKind): string {
  const p = new URLSearchParams();
  if (f.level) p.set("level", f.level);
  if (f.mode) p.set("mode", f.mode);
  if (f.outcome) p.set("outcome", f.outcome);
  if (f.diverted) p.set("diverted", f.diverted);
  if (f.quizStatus) p.set("quiz_status", f.quizStatus);
  if (f.adminTest && kind !== "student") p.set("admin_test", YES_NO_TO_BOOL[f.adminTest]);
  return p.toString();
}

/** The API stores the rounded percent of 17 points; this is the exact inverse. */
export function percentToPoints(percent: number | null): number | null {
  return percent === null ? null : Math.round((percent * TOTAL_POINTS) / 100);
}

export function toRow(r: ApiSessionRow): SessionRow {
  return {
    id: r.id,
    studentId: r.student_id,
    studentName: r.student_name ?? UNKNOWN_STUDENT,
    levelId: r.level_id,
    levelName: r.level_name ?? r.level_id,
    mode: r.mode,
    status: r.status,
    secretObtained: r.secret_obtained,
    divertedCount: r.diverted_count,
    maxSentinelScore: r.max_sentinel_score,
    startedAt: r.started_at,
    quizStatus: r.quiz_status,
    quizPoints: percentToPoints(r.quiz_score),
    quizId: null, // quiz ids arrive with the quiz API in phase C
    adminTest: r.admin_test,
  };
}

export function toSessionList(api: ApiSessionList): {
  rows: SessionRow[];
  total: number;
  levels: { id: string; name: string }[];
} {
  return {
    rows: api.items.map(toRow),
    total: api.total,
    levels: api.levels.map((l) => ({ id: l.level_id, name: l.name })),
  };
}

export function applyStudentNameFilter(rows: SessionRow[], needle: string | undefined, kind: ViewerKind): SessionRow[] {
  if (kind === "student" || !needle) return rows;
  const n = needle.toLowerCase();
  return rows.filter((r) => r.studentName.toLowerCase().includes(n));
}

const NO_CONFIG: SessionDetail["config"] = {
  levelVersion: 0,
  mode: "off",
  ruleVersion: 0,
  patternVersion: 0,
  thresholds: {},
  judgeModelId: null,
};

export function toDetail(api: ApiDetail): { staff: boolean; hasConfig: boolean; view: SessionDetail } {
  const c = api.config;
  return {
    staff: api.view === "staff",
    hasConfig: c !== null,
    view: {
      row: toRow(api.session),
      transcript: api.transcript.map((t) => ({
        id: t.message_id + ":" + t.speaker,
        time: t.time,
        speaker: t.speaker,
        text: t.text,
        status: (t.status as SessionDetail["transcript"][number]["status"]) ?? null,
        isDecoy: t.is_decoy,
      })),
      decisions: (api.decisions ?? []).map((d) => ({
        id: d.event_id,
        stage: d.stage,
        decision: d.decision,
        score: d.sentinel_score,
        breakdown: d.score_breakdown,
        rules: d.rule_ids,
        riskyPatterns: d.risky_pattern_ids,
      })),
      config: c
        ? {
            levelVersion: c.level_version,
            mode: c.mode,
            ruleVersion: c.rule_version,
            patternVersion: c.pattern_version,
            thresholds: c.thresholds,
            judgeModelId: c.judge_model_id,
          }
        : NO_CONFIG,
      outcome: { obtained: api.outcome.obtained, at: api.outcome.obtained_at, echoExcluded: api.outcome.echo_excluded },
      heldItems: (api.held_items ?? []).map((h) => ({
        id: h.ticket_id,
        stage: h.stage,
        status: h.status,
        decidedBy: h.decided_by_name,
      })),
      diverts: (api.diverts ?? []).map((v) => ({
        id: v.event_id,
        stage: v.stage,
        tool: v.tool,
        attemptedSummary: v.attempted_summary,
        decoyShown: v.decoy_shown,
      })),
      forensics: api.forensics?.[0] ? { family: api.forensics[0].attack_family, summary: api.forensics[0].summary } : null,
    },
  };
}

export interface InsightsData {
  overview: { students: number; sessions: number; sessionsPerStudent: number; activeToday: number };
  outcomes: { levelName: string; sessions: number; obtained: number; notObtained: number; ratePercent: number }[];
  defense: {
    topRules: { id: string; count: number }[];
    decisionsPerMode: { mode: Mode; allow: number; review: number; deny: number; divert: number }[];
    divertCount: number;
  };
  attackFamilies: { family: string; count: number }[];
  riskyPatterns: { id: string; count: number }[];
  quiz: { taken: number; open: number; averagePercent: number | null; lowestItems: { title: string; average: number }[] };
}

const MODE_ORDER: Mode[] = ["off", "basic", "strict"];

function decisionsPerMode(rows: ApiInsights["defense"]["decisions"]): InsightsData["defense"]["decisionsPerMode"] {
  const byMode = new Map<Mode, { allow: number; review: number; deny: number; divert: number }>();
  for (const r of rows) {
    const cur = byMode.get(r.mode) ?? { allow: 0, review: 0, deny: 0, divert: 0 };
    if (r.decision === "allow") cur.allow += r.count;
    else if (r.decision === "review") cur.review += r.count;
    else if (r.decision === "divert") cur.divert += r.count;
    else if (r.decision === "deny" || r.decision === "human_deny") cur.deny += r.count;
    byMode.set(r.mode, cur);
  }
  return MODE_ORDER.filter((m) => byMode.has(m)).map((m) => ({ mode: m, ...(byMode.get(m) as { allow: number; review: number; deny: number; divert: number }) }));
}

export function toInsights(api: ApiInsights): InsightsData {
  return {
    overview: {
      students: api.overview.students,
      sessions: api.overview.sessions,
      sessionsPerStudent: api.overview.sessions_per_student,
      activeToday: api.overview.active_today,
    },
    outcomes: api.outcomes.map((o) => ({
      levelName: o.level_name,
      sessions: o.sessions,
      obtained: o.obtained,
      notObtained: o.not_obtained,
      ratePercent: Math.round(o.rate * 100),
    })),
    defense: {
      topRules: api.defense.top_rules.map((r) => ({ id: r.rule_id, count: r.count })),
      decisionsPerMode: decisionsPerMode(api.defense.decisions),
      divertCount: api.defense.divert_count,
    },
    attackFamilies: api.attack_families.map((f) => ({ family: f.attack_family, count: f.count })),
    riskyPatterns: api.risky_patterns.map((p) => ({ id: p.pattern_id, count: p.count })),
    quiz: {
      taken: api.quiz.taken,
      open: api.quiz.open,
      averagePercent: api.quiz.average_percent,
      lowestItems: api.quiz.lowest_items.map((i) => ({ title: i.title, average: i.average })),
    },
  };
}

export interface SecretView {
  levelId: string;
  levelName: string;
  version: number;
  compromised: boolean;
  by: string | null;
  sessionId: string | null;
  at: string | null;
}

export function toSecrets(api: ApiSecretList): SecretView[] {
  return api.items.map((s) => ({
    levelId: s.level_id,
    levelName: s.level_name ?? s.level_id,
    version: s.secret_version,
    compromised: s.compromised,
    by: s.compromised_by_name,
    sessionId: s.compromised_by_session,
    at: s.compromised_at,
  }));
}
