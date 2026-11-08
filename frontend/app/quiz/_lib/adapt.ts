// Maps the quiz API (backend/app/quiz/schemas.py) onto view-models. Pure functions, no I/O.
// Question prompts, options and chat text are untrusted: they pass through untouched and React
// escapes them on render. The public quiz carries no answers (E-60); correctness arrives per
// question, after the student answers it (M4-X22).

export type ApiQuizStatus = "assigned" | "in_progress" | "grading_failed" | "done";

export type ApiQuestion =
  | { id: string; type: "mcq"; topic: string; prompt: string; options: string[] }
  | { id: string; type: "free_response"; topic: string; prompt: string; max_follow_ups: number };

export interface ApiQuizView {
  quiz_id: string;
  session_id: string;
  rubric_version: string;
  status: ApiQuizStatus;
  attempt_number: number;
  questions: ApiQuestion[];
  answered: { question_id: string; chosen_index: number; correct: boolean; explanation: string }[];
  turns: { question_id: string; seq: number; role: "student" | "classmate"; text: string }[];
}

export interface ApiResult {
  quiz_id: string;
  session_id: string;
  attempt_number: number;
  status: ApiQuizStatus;
  mcq_points: number | null;
  mcq_max: number;
  total_points: number | null;
  max_points: number;
  percent: number | null;
  feedback: string | null;
  items: { key: string; title: string; score: number; max: number }[] | null;
}

export interface ApiAttemptList {
  session_id: string;
  attempts: {
    quiz_id: string;
    attempt_number: number;
    status: ApiQuizStatus;
    percent: number | null;
    created_at: string;
    finished_at: string | null;
  }[];
  latest_percent: number | null;
  best_percent: number | null;
}

export interface ApiMineList {
  items: { quiz_id: string; session_id: string; attempt_number: number; status: ApiQuizStatus; percent: number | null; created_at: string }[];
}

export interface RunQuestion {
  id: string;
  type: "mcq" | "free_response";
  topic: string;
  prompt: string;
  options: string[];
}

export interface AnsweredMcq {
  chosenIndex: number;
  correct: boolean;
  explanation: string;
}

export interface ChatLine {
  who: "me" | "them";
  text: string;
}

export interface QuizRun {
  quizId: string;
  sessionId: string;
  status: ApiQuizStatus;
  attempt: number;
  questions: RunQuestion[];
  answered: Record<string, AnsweredMcq>;
  chats: Record<string, ChatLine[]>;
}

export function toQuizRun(api: ApiQuizView): QuizRun {
  const answered: Record<string, AnsweredMcq> = {};
  for (const a of api.answered) {
    answered[a.question_id] = { chosenIndex: a.chosen_index, correct: a.correct, explanation: a.explanation };
  }
  const chats: Record<string, ChatLine[]> = {};
  for (const t of [...api.turns].sort((a, b) => a.seq - b.seq)) {
    (chats[t.question_id] ??= []).push({ who: t.role === "student" ? "me" : "them", text: t.text });
  }
  return {
    quizId: api.quiz_id,
    sessionId: api.session_id,
    status: api.status,
    attempt: api.attempt_number,
    questions: api.questions.map((q) => ({
      id: q.id,
      type: q.type,
      topic: q.topic,
      prompt: q.prompt,
      options: q.type === "mcq" ? q.options : [],
    })),
    answered,
    chats,
  };
}

/** Where a resumed quiz starts: the first MCQ without an answer, else the first free response. */
export function firstUnansweredStep(run: QuizRun): number {
  const idx = run.questions.findIndex((q) => q.type === "mcq" && !(q.id in run.answered));
  if (idx >= 0) return idx;
  const fr = run.questions.findIndex((q) => q.type === "free_response");
  return fr >= 0 ? fr : run.questions.length;
}

export interface ResultView {
  quizId: string;
  sessionId: string;
  attempt: number;
  failed: boolean;
  percent: number | null;
  total: number | null;
  max: number;
  mcqPoints: number | null;
  mcqMax: number;
  feedback: string | null;
  items: { key: string; title: string; score: number; max: number }[] | null;
}

export function toResultView(api: ApiResult): ResultView {
  return {
    quizId: api.quiz_id,
    sessionId: api.session_id,
    attempt: api.attempt_number,
    failed: api.status === "grading_failed",
    percent: api.percent,
    total: api.total_points,
    max: api.max_points,
    mcqPoints: api.mcq_points,
    mcqMax: api.mcq_max,
    feedback: api.feedback,
    items: api.items,
  };
}

export interface AttemptsView {
  latest: number | null;
  best: number | null;
  rows: { quizId: string; attempt: number; status: ApiQuizStatus; percent: number | null; createdAt: string }[];
}

export function toAttempts(api: ApiAttemptList): AttemptsView {
  return {
    latest: api.latest_percent,
    best: api.best_percent,
    rows: api.attempts.map((a) => ({
      quizId: a.quiz_id,
      attempt: a.attempt_number,
      status: a.status,
      percent: a.percent,
      createdAt: a.created_at,
    })),
  };
}

const GENERIC = "Something went wrong. Please try again.";

/** Budget (429) and generation (502) messages are written for people by the API; anything else is
 *  replaced so raw server detail never reaches the screen. */
export function errorMessage(status: number, detail: string): string {
  if (status === 429 || status === 502) return detail;
  if (status === 403) return "You are not allowed to do that.";
  if (status === 404) return "That quiz could not be found.";
  return GENERIC;
}

/** Whether a stored conversation has ended: the last word is the student's (a closing turn gets no
 *  reply) or they already answered the first prompt plus every allowed follow-up. */
export function chatClosed(lines: readonly ChatLine[], maxFollowUps: number): boolean {
  if (lines.length === 0) return false;
  if (lines[lines.length - 1].who === "me") return true;
  return lines.filter((l) => l.who === "me").length > maxFollowUps;
}
