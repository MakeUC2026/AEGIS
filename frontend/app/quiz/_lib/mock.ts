// MOCK quizzes for the Phase A shells. The public view has no answers (E-60). Real data comes
// from the API in Phase C; the demo answers live in mock-key.ts and exist only for the shell.

import { computeResult, type ItemKey, type QuizResult } from "./rubric";

export interface MockQuestion {
  id: string;
  type: "mcq" | "free_response";
  topic: string;
  prompt: string;
  options?: string[];
}

export interface MockQuiz {
  id: string;
  sessionId: string;
  studentId: string;
  studentName: string;
  status: "in_progress" | "done";
  questions: MockQuestion[];
  result?: QuizResult & {
    feedback: { right: string; missing: string; lookAt: string };
  };
}

const QUESTIONS: MockQuestion[] = [
  { id: "q1", type: "mcq", topic: "attack", prompt: "Which technique did your message use?", options: ["Direct override", "Indirect injection via a document", "Authority claim", "Split leak"] },
  { id: "q2", type: "mcq", topic: "why", prompt: "Why did the bot follow the hidden text?", options: ["It trusted the document as instructions", "The password was weak", "The student was an admin", "A rule was switched off by the teacher"] },
  { id: "q3", type: "mcq", topic: "defense_layer", prompt: "Which layer made the difference in Strict?", options: ["A fixed rule", "The cumulative scan", "The judge", "Risky history"] },
  { id: "q4", type: "mcq", topic: "prevention", prompt: "Which fix would stop this for good?", options: ["Longer passwords", "Treat documents as data and allowlist email recipients", "Ban the word 'ignore'", "Turn the bot off"] },
  { id: "q5", type: "mcq", topic: "divert", prompt: "Were you diverted, and how could you tell?", options: ["No, the answers were real", "Yes, the result looked too convenient", "Yes, the bot said so", "Not possible to know"] },
  { id: "q6", type: "free_response", topic: "attack", prompt: "Explain to a classmate what the attacker did and why it nearly worked." },
  { id: "q7", type: "free_response", topic: "defense_layer", prompt: "Which part of the firewall stopped it, and how would you prevent it for good?" },
];

const DONE_ITEMS: Record<ItemKey, number> = { attack: 3, why: 2, defense_layer: 1, prevention: 2 };

export const MOCK_QUIZZES: readonly MockQuiz[] = [
  { id: "qz-1", sessionId: "s-102", studentId: "Ada (student)", studentName: "Ada (student)", status: "in_progress", questions: QUESTIONS },
  {
    id: "qz-2",
    sessionId: "s-101",
    studentId: "Ada (student)",
    studentName: "Ada (student)",
    status: "done",
    questions: QUESTIONS,
    result: {
      ...computeResult(4, DONE_ITEMS),
      feedback: {
        right: "You named indirect injection and explained that the bot trusted the document.",
        missing: "You did not name which layer made the difference, or give a concrete fix.",
        lookAt: "Open the decisions in your session and find the stage where the score jumped.",
      },
    },
  },
  {
    id: "qz-3",
    sessionId: "s-106",
    studentId: "Ben (student)",
    studentName: "Ben (student)",
    status: "done",
    questions: QUESTIONS,
    result: {
      ...computeResult(3, { attack: 2, why: 1, defense_layer: 1, prevention: 1 }),
      feedback: {
        right: "You spotted that the attack came through a document.",
        missing: "Why the bot trusted it, and what would have blocked it.",
        lookAt: "Compare Off and Strict on the same message.",
      },
    },
  },
];

export function mockQuiz(id: string): MockQuiz | undefined {
  return MOCK_QUIZZES.find((q) => q.id === id);
}
