import { TOTAL_POINTS } from "@/app/quiz/_lib/rubric";

import type { QuizStatus } from "./types";

const QUIZ_LABELS: Record<QuizStatus, string> = {
  not_taken: "Not taken",
  assigned: "Assigned",
  in_progress: "In progress",
  done: "Done",
};

export function quizStatusLabel(status: QuizStatus): string {
  return QUIZ_LABELS[status];
}

export function outcomeLabel(obtained: boolean): string {
  return obtained ? "Obtained" : "Not obtained";
}

export function formatScore(points: number | null): string {
  if (points === null) return "-";
  return `${points} / ${TOTAL_POINTS} (${Math.round((points * 100) / TOTAL_POINTS)}%)`;
}

// Fixed locale and UTC so server and browser render the same text (no hydration drift).
export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "-";
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}
