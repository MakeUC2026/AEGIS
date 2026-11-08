import { describe, expect, it } from "vitest";

import { parseFilters, toQueryString } from "@/app/classroom/_lib/filters";

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
