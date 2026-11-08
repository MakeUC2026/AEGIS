import { describe, expect, it } from "vitest";

import { isDone, nextClassmateReply, MAX_FOLLOW_UPS } from "@/app/quiz/_lib/classmate-mock";

describe("isDone (M4-X24)", () => {
  it.each(["done", " Done ", "DONE", "\tdOnE\n"])("accepts %j", (t) => {
    expect(isDone(t)).toBe(true);
  });
  it.each(["", "not done", "done!", "I am done explaining"])("rejects %j", (t) => {
    expect(isDone(t)).toBe(false);
  });
});

describe("nextClassmateReply (M4-X23)", () => {
  it("asks a follow-up after each of the first three answers", () => {
    for (let n = 1; n <= MAX_FOLLOW_UPS; n++) {
      const r = nextClassmateReply(n, "some answer");
      expect(r.finished).toBe(false);
      expect(r.text.length).toBeGreaterThan(0);
    }
  });
  it("stops straight away when the student says done", () => {
    const r = nextClassmateReply(1, " Done ");
    expect(r.finished).toBe(true);
  });
  it("never asks more than three follow-ups", () => {
    expect(nextClassmateReply(MAX_FOLLOW_UPS + 1, "more").finished).toBe(true);
    expect(nextClassmateReply(9, "more").finished).toBe(true);
  });
});
