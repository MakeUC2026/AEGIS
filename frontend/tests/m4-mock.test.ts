import { describe, expect, it } from "vitest";

import { MOCK_SESSIONS, mockDetail } from "@/app/classroom/_lib/mock";
import { MOCK_INSIGHTS, MOCK_SECRETS } from "@/app/classroom/_lib/mock-class";
import { MOCK_QUIZZES, mockQuiz } from "@/app/quiz/_lib/mock";

const NETWORK_KEY = /^(ip|ip_?address|subnet|asn|country|user_?agent|fingerprint\w*)$/i;

function keysDeep(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) value.forEach((v) => keysDeep(v, out));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      keysDeep(v, out);
    }
  }
  return out;
}

describe("mock sessions", () => {
  it("have unique ids and cover the interesting states", () => {
    const ids = MOCK_SESSIONS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(MOCK_SESSIONS.some((s) => s.secretObtained)).toBe(true);
    expect(MOCK_SESSIONS.some((s) => s.divertedCount > 0)).toBe(true);
    expect(MOCK_SESSIONS.some((s) => s.adminTest)).toBe(true);
    for (const q of ["not_taken", "assigned", "in_progress", "done"]) {
      expect(MOCK_SESSIONS.some((s) => s.quizStatus === q)).toBe(true);
    }
  });
  it("use sentinel scores in 0..100", () => {
    for (const s of MOCK_SESSIONS) {
      if (s.maxSentinelScore !== null) {
        expect(s.maxSentinelScore).toBeGreaterThanOrEqual(0);
        expect(s.maxSentinelScore).toBeLessThanOrEqual(100);
      }
    }
  });
});

describe("mock detail", () => {
  it("has no network data anywhere (M4-X06)", () => {
    for (const s of MOCK_SESSIONS) {
      const d = mockDetail(s.id);
      if (!d) continue;
      expect(keysDeep(d).filter((k) => NETWORK_KEY.test(k))).toEqual([]);
    }
  });
  it("returns undefined for an unknown id", () => {
    expect(mockDetail("nope")).toBeUndefined();
  });
  it("includes a hostile transcript line to prove escaping (M4-X19)", () => {
    const text = JSON.stringify(mockDetail("s-101")?.transcript);
    expect(text).toContain("<script>");
  });
  it("marks decoys and keeps divert attempted vs believed apart", () => {
    const d = mockDetail("s-103");
    expect(d?.transcript.some((t) => t.isDecoy)).toBe(true);
    expect(d?.diverts[0]).toHaveProperty("attemptedSummary");
    expect(d?.diverts[0]).toHaveProperty("decoyShown");
  });
});

describe("mock class data", () => {
  it("insights hold every PRD panel", () => {
    expect(Object.keys(MOCK_INSIGHTS).sort()).toEqual(
      ["attackFamilies", "defense", "overview", "outcomes", "quiz", "riskyPatterns"].sort(),
    );
  });
  it("secrets never include a secret value", () => {
    const text = JSON.stringify(MOCK_SECRETS);
    expect(text).not.toMatch(/DEMO_|sk-|secret_value|"value"/i);
  });
});

describe("mock quizzes", () => {
  it("the public view has no answer fields", () => {
    for (const q of MOCK_QUIZZES) {
      const text = JSON.stringify(q);
      expect(text).not.toMatch(/answer_?index|explanation|answerKey/i);
    }
  });
  it("covers in-progress and done", () => {
    expect(mockQuiz("qz-1")?.status).toBe("in_progress");
    expect(mockQuiz("qz-2")?.status).toBe("done");
    expect(mockQuiz("zzz")).toBeUndefined();
  });
});

describe("mock consistency", () => {
  it("a session's quiz score equals its quiz result total", () => {
    for (const s of MOCK_SESSIONS) {
      if (!s.quizId) continue;
      const q = mockQuiz(s.quizId);
      expect(q, s.id).toBeDefined();
      expect(q?.sessionId).toBe(s.id);
      expect(q?.result?.total ?? null, s.id).toBe(s.quizPoints);
    }
  });
});

describe("viewer keys (dev users are keyed by display name in the shell)", () => {
  it("each dev student owns some sessions and some quizzes", () => {
    for (const name of ["Ada (student)", "Ben (student)"]) {
      expect(MOCK_SESSIONS.some((s) => s.studentId === name)).toBe(true);
      expect(MOCK_QUIZZES.some((q) => q.studentId === name)).toBe(true);
    }
  });
});
