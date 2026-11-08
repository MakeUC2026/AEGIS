import type { Mode, QuizStatus, SessionRow, ViewerKind } from "./types";

// Filter state lives in the URL (PRD §12.1, M4-X07). Unknown values are ignored (M4-X08).

export interface Filters {
  student?: string;
  level?: string;
  mode?: Mode;
  outcome?: "obtained" | "not_obtained";
  diverted?: "yes" | "no";
  quizStatus?: QuizStatus;
  adminTest?: "yes" | "no";
}

type Raw = Record<string, string | string[] | undefined>;

const MODES: readonly Mode[] = ["off", "basic", "strict"];
const OUTCOMES = ["obtained", "not_obtained"] as const;
const YES_NO = ["yes", "no"] as const;
const QUIZ_STATUSES: readonly QuizStatus[] = ["not_taken", "assigned", "in_progress", "done"];
const LEVEL_ID = /^[a-z0-9-]{1,32}$/;
const STUDENT_MAX = 64;

function first(raw: Raw, key: string): string | undefined {
  const v = raw[key];
  return Array.isArray(v) ? v[0] : v;
}

function oneOf<T extends string>(value: string | undefined, allowed: readonly T[]): T | undefined {
  return allowed.find((a) => a === value);
}

export function parseFilters(raw: Raw): Filters {
  const out: Filters = {};
  const student = first(raw, "student")?.trim().slice(0, STUDENT_MAX);
  if (student) out.student = student;
  const level = first(raw, "level");
  if (level && LEVEL_ID.test(level)) out.level = level;
  const mode = oneOf(first(raw, "mode"), MODES);
  if (mode) out.mode = mode;
  const outcome = oneOf(first(raw, "outcome"), OUTCOMES);
  if (outcome) out.outcome = outcome;
  const diverted = oneOf(first(raw, "diverted"), YES_NO);
  if (diverted) out.diverted = diverted;
  const quizStatus = oneOf(first(raw, "quiz_status"), QUIZ_STATUSES);
  if (quizStatus) out.quizStatus = quizStatus;
  const adminTest = oneOf(first(raw, "admin_test"), YES_NO);
  if (adminTest) out.adminTest = adminTest;
  return out;
}

export function toQueryString(f: Filters): string {
  const p = new URLSearchParams();
  if (f.student) p.set("student", f.student);
  if (f.level) p.set("level", f.level);
  if (f.mode) p.set("mode", f.mode);
  if (f.outcome) p.set("outcome", f.outcome);
  if (f.diverted) p.set("diverted", f.diverted);
  if (f.quizStatus) p.set("quiz_status", f.quizStatus);
  if (f.adminTest) p.set("admin_test", f.adminTest);
  return p.toString();
}

export interface Viewer {
  kind: ViewerKind;
  userId: string;
}

export function applyFilters(rows: readonly SessionRow[], f: Filters, viewer: Viewer): SessionRow[] {
  // A student sees their own sessions only; the student filter is ignored (M4-X01).
  const scoped =
    viewer.kind === "student" ? rows.filter((r) => r.studentId === viewer.userId) : [...rows];
  const needle = viewer.kind === "student" ? undefined : f.student?.toLowerCase();
  return scoped.filter(
    (r) =>
      (!needle || r.studentName.toLowerCase().includes(needle)) &&
      (!f.level || r.levelId === f.level) &&
      (!f.mode || r.mode === f.mode) &&
      (!f.outcome || r.secretObtained === (f.outcome === "obtained")) &&
      (!f.diverted || (r.divertedCount > 0) === (f.diverted === "yes")) &&
      (!f.quizStatus || r.quizStatus === f.quizStatus) &&
      (!f.adminTest || r.adminTest === (f.adminTest === "yes")),
  );
}
