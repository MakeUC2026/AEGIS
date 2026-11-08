import { describe, expect, it } from "vitest";

import { applyFilters, parseFilters, toQueryString } from "@/app/classroom/_lib/filters";
import { MOCK_SESSIONS } from "@/app/classroom/_lib/mock";

describe("parseFilters (M4-X07, M4-X08)", () => {
  it("reads every filter from the URL", () => {
    const f = parseFilters({
      student: "ada",
      level: "level-2",
      mode: "strict",
      outcome: "obtained",
      diverted: "yes",
      quiz_status: "done",
      admin_test: "no",
    });
    expect(f).toEqual({
      student: "ada",
      level: "level-2",
      mode: "strict",
      outcome: "obtained",
      diverted: "yes",
      quizStatus: "done",
      adminTest: "no",
    });
  });
  it("ignores unknown values instead of failing", () => {
    const f = parseFilters({ mode: "turbo", outcome: "maybe", diverted: "1", quiz_status: "x", level: "../x" });
    expect(f).toEqual({});
  });
  it("takes the first value of a repeated parameter and trims text", () => {
    expect(parseFilters({ mode: ["basic", "off"], student: "  ben  " })).toEqual({
      mode: "basic",
      student: "ben",
    });
  });
  it("caps the student text length and drops blanks", () => {
    expect(parseFilters({ student: "x".repeat(500) }).student).toHaveLength(64);
    expect(parseFilters({ student: "   " })).toEqual({});
  });
});

describe("toQueryString", () => {
  it("round-trips through parseFilters and is stable", () => {
    const f = parseFilters({ mode: "strict", diverted: "yes", student: "ada" });
    const qs = toQueryString(f);
    expect(qs).toBe("student=ada&mode=strict&diverted=yes");
    const back = Object.fromEntries(new URLSearchParams(qs));
    expect(parseFilters(back)).toEqual(f);
  });
  it("is empty for no filters", () => {
    expect(toQueryString({})).toBe("");
  });
});

describe("applyFilters", () => {
  const staff = { kind: "teacher" as const, userId: "Cho (teacher)" };
  it("filters by mode, outcome, diverted, quiz status and admin test", () => {
    const strict = applyFilters(MOCK_SESSIONS, { mode: "strict" }, staff);
    expect(strict.length).toBeGreaterThan(0);
    expect(strict.every((s) => s.mode === "strict")).toBe(true);
    const diverted = applyFilters(MOCK_SESSIONS, { diverted: "yes" }, staff);
    expect(diverted.every((s) => s.divertedCount > 0)).toBe(true);
    const notDiverted = applyFilters(MOCK_SESSIONS, { diverted: "no" }, staff);
    expect(notDiverted.every((s) => s.divertedCount === 0)).toBe(true);
    const tests = applyFilters(MOCK_SESSIONS, { adminTest: "yes" }, staff);
    expect(tests.length).toBeGreaterThan(0);
    expect(tests.every((s) => s.adminTest)).toBe(true);
    const done = applyFilters(MOCK_SESSIONS, { quizStatus: "done" }, staff);
    expect(done.every((s) => s.quizStatus === "done")).toBe(true);
  });
  it("matches student names case-insensitively", () => {
    const rows = applyFilters(MOCK_SESSIONS, { student: "ADA" }, staff);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((s) => s.studentName.toLowerCase().includes("ada"))).toBe(true);
  });
  it("forces a student to their own sessions whatever the URL says (M4-X01)", () => {
    const me = { kind: "student" as const, userId: "Ada (student)" };
    const rows = applyFilters(MOCK_SESSIONS, { student: "ben" }, me);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((s) => s.studentId === "Ada (student)")).toBe(true);
  });
  it("does not mutate its input", () => {
    const copy = [...MOCK_SESSIONS];
    applyFilters(MOCK_SESSIONS, { mode: "off" }, staff);
    expect(MOCK_SESSIONS).toEqual(copy);
  });
});
