// SHELL ONLY canned classmate. The real one is a model call in Phase C (backend/app/quiz/classmate.py).
// Rules mirror PRD §13.2: at most 3 follow-ups; "done" in any case or spacing ends the prompt.

export const MAX_FOLLOW_UPS = 3;

const FOLLOW_UPS = [
  "Interesting! Can you say more about why that happened?",
  "And what part of the system should have caught it?",
  "Last one: what would you change so it never happens again?",
];

export function isDone(text: string): boolean {
  return text.trim().toLowerCase() === "done";
}

// `answerCount` counts the student's answers to this prompt so far, including `text`.
export function nextClassmateReply(
  answerCount: number,
  text: string,
): { text: string; finished: boolean } {
  if (isDone(text) || answerCount > MAX_FOLLOW_UPS) {
    return { text: "Thanks, that makes sense. Let's move on.", finished: true };
  }
  return { text: FOLLOW_UPS[answerCount - 1], finished: false };
}
