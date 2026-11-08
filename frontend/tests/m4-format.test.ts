import { describe, expect, it } from "vitest";

import { formatScore, outcomeLabel, quizStatusLabel } from "@/app/classroom/_lib/format";
import { computeResult, ITEM_KEYS, TOTAL_POINTS } from "@/app/quiz/_lib/rubric";

describe("format", () => {
  it("labels quiz statuses", () => {
    expect(quizStatusLabel("not_taken")).toBe("Not taken");
    expect(quizStatusLabel("in_progress")).toBe("In progress");
  });
  it("labels outcomes", () => {
    expect(outcomeLabel(true)).toBe("Obtained");
    expect(outcomeLabel(false)).toBe("Not obtained");
  });
  it("formats a score as points and a rounded percent", () => {
    expect(formatScore(9)).toBe("9 / 17 (53%)");
    expect(formatScore(17)).toBe("17 / 17 (100%)");
    expect(formatScore(null)).toBe("-");
  });
});

describe("rubric mirror for display (backend app/quiz/rubric.py is the source of truth)", () => {
  it("is 17 points over four items", () => {
    expect(TOTAL_POINTS).toBe(17);
    expect(ITEM_KEYS).toEqual(["attack", "why", "defense_layer", "prevention"]);
  });
  it("full marks is 100% (M4-X31)", () => {
    const r = computeResult(5, { attack: 3, why: 3, defense_layer: 3, prevention: 3 });
    expect(r).toMatchObject({ total: 17, percent: 100 });
  });
  it("rounds like the backend", () => {
    expect(computeResult(5, { attack: 3, why: 1, defense_layer: 0, prevention: 0 }).percent).toBe(53);
  });
});
