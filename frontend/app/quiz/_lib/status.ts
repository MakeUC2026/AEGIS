import type { QuizStatus } from "@/app/classroom/_lib/types";

import type { ApiQuizStatus } from "./adapt";

/** The list pill only knows four states; a failed grading shows as "In progress" with a retry. */
export function toListStatus(status: ApiQuizStatus): { pill: QuizStatus; action: string } {
  switch (status) {
    case "done":
      return { pill: "done", action: "View result" };
    case "grading_failed":
      return { pill: "in_progress", action: "Grade again" };
    case "assigned":
      return { pill: "assigned", action: "Start" };
    default:
      return { pill: "in_progress", action: "Resume" };
  }
}
