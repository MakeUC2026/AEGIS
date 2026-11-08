import { describe, expect, it } from "vitest";

import {
  errorMessage,
  firstUnansweredStep,
  toAttempts,
  toQuizRun,
  toResultView,
  type ApiQuizView,
  type ApiResult,
} from "@/app/quiz/_lib/adapt";

const view = (over: Partial<ApiQuizView> = {}): ApiQuizView => ({
  quiz_id: "qz1",
  session_id: "s1",
  rubric_version: "r1",
  status: "in_progress",
  attempt_number: 1,
  questions: [
    { id: "q1", type: "mcq", topic: "attack", prompt: "<script>alert(1)</script>", options: ["a", "b", "c"] },
    { id: "q2", type: "mcq", topic: "why", prompt: "why?", options: ["a", "b", "c"] },
    { id: "q6", type: "free_response", topic: "attack", prompt: "explain", max_follow_ups: 3 },
  ],
  answered: [{ question_id: "q1", chosen_index: 1, correct: false, explanation: "because" }],
  turns: [
    { question_id: "q6", seq: 1, role: "classmate", text: "explain" },
    { question_id: "q6", seq: 2, role: "student", text: "my answer" },
  ],
  ...over,
});

describe("toQuizRun", () => {
  it("keeps prompts as plain text and maps answered questions", () => {
    const run = toQuizRun(view());
    expect(run.questions[0].prompt).toBe("<script>alert(1)</script>");
    expect(run.answered.q1).toEqual({ chosenIndex: 1, correct: false, explanation: "because" });
    expect(run.answered.q2).toBeUndefined();
  });

  it("groups turns per question in sequence order", () => {
    const run = toQuizRun(view({ turns: [
      { question_id: "q6", seq: 2, role: "student", text: "b" },
      { question_id: "q6", seq: 1, role: "classmate", text: "a" },
    ] }));
    expect(run.chats.q6.map((c) => c.text)).toEqual(["a", "b"]);
    expect(run.chats.q6.map((c) => c.who)).toEqual(["them", "me"]);
  });
});

describe("firstUnansweredStep", () => {
  it("resumes at the first MCQ without an answer", () => {
    expect(firstUnansweredStep(toQuizRun(view()))).toBe(1);
  });
  it("goes to the first free response once every MCQ is answered", () => {
    const run = toQuizRun(view({ answered: [
      { question_id: "q1", chosen_index: 0, correct: true, explanation: "x" },
      { question_id: "q2", chosen_index: 0, correct: true, explanation: "x" },
    ] }));
    expect(firstUnansweredStep(run)).toBe(2);
  });
});

const result = (over: Partial<ApiResult> = {}): ApiResult => ({
  quiz_id: "qz1",
  session_id: "s1",
  attempt_number: 1,
  status: "done",
  mcq_points: 4,
  mcq_max: 5,
  total_points: 12,
  max_points: 17,
  percent: 71,
  feedback: "Good.",
  items: null,
  ...over,
});

describe("toResultView", () => {
  it("hides per-item grades for students (items null)", () => {
    const v = toResultView(result());
    expect(v.items).toBeNull();
    expect(v.percent).toBe(71);
    expect(v.failed).toBe(false);
  });
  it("passes teacher items through", () => {
    const v = toResultView(result({ items: [{ key: "attack", title: "Attack", score: 3, max: 3 }] }));
    expect(v.items?.[0]).toEqual({ key: "attack", title: "Attack", score: 3, max: 3 });
  });
  it("flags grading_failed", () => {
    const v = toResultView(result({ status: "grading_failed", percent: null, total_points: null, mcq_points: null, feedback: null }));
    expect(v.failed).toBe(true);
    expect(v.percent).toBeNull();
  });
});

describe("toAttempts", () => {
  it("returns latest and best", () => {
    const a = toAttempts({
      session_id: "s1",
      attempts: [{ quiz_id: "q2", attempt_number: 2, status: "done", percent: 80, created_at: "2026-11-07T10:00:00Z", finished_at: null }],
      latest_percent: 80,
      best_percent: 90,
    });
    expect(a.latest).toBe(80);
    expect(a.best).toBe(90);
    expect(a.rows[0].quizId).toBe("q2");
  });
});

describe("errorMessage", () => {
  it("uses the server's clear message for budget and generation failures", () => {
    expect(errorMessage(429, "Budget used")).toBe("Budget used");
    expect(errorMessage(502, "Try again")).toBe("Try again");
  });
  it("is generic for other statuses and never echoes raw detail", () => {
    expect(errorMessage(500, "Traceback ...")).toBe("Something went wrong. Please try again.");
    expect(errorMessage(403, "forbidden")).toBe("You are not allowed to do that.");
  });
});

import { chatClosed } from "@/app/quiz/_lib/adapt";

describe("chatClosed", () => {
  it("is open before any answer", () => {
    expect(chatClosed([], 3)).toBe(false);
  });
  it("is closed when the last line is the student's (no reply follows a closing turn)", () => {
    expect(chatClosed([{ who: "them", text: "q" }, { who: "me", text: "done" }], 3)).toBe(true);
  });
  it("is open while the classmate has the last word", () => {
    expect(chatClosed([{ who: "them", text: "q" }, { who: "me", text: "a" }, { who: "them", text: "why?" }], 3)).toBe(false);
  });
  it("is closed once the student answered more than the follow-up limit allows", () => {
    const lines = Array.from({ length: 4 }, () => [{ who: "me" as const, text: "a" }, { who: "them" as const, text: "?" }]).flat();
    expect(chatClosed(lines, 3)).toBe(true);
  });
});
