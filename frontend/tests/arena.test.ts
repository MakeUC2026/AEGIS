import { describe, expect, it } from "vitest";

import { computeFingerprint, inputLocked, newMessageId, statusLine, type Turn } from "@/lib/arena";

const turn = (over: Partial<Turn>): Turn => ({
  message_id: "m1",
  text: "hi",
  status: "replied",
  reply: "hello",
  tool_effects: [],
  ticket_id: null,
  defense_feed: [],
  ...over,
});

describe("statusLine (exact PRD §6.2 copy)", () => {
  it("replied shows the bot reply", () => {
    expect(statusLine(turn({ status: "replied", reply: "hello" }))).toBe("hello");
  });
  it("blocked shows 'Blocked.' plus the rule IDs that fired", () => {
    const t = turn({
      status: "blocked",
      reply: "I can't help with that.",
      defense_feed: [{ stage: "tool_call_check", decision: "deny", rule_ids: ["R-003"], score_band: "high" }],
    });
    expect(statusLine(t)).toBe("Blocked. (R-003)");
  });
  it("awaiting review shows the pending message", () => {
    expect(statusLine(turn({ status: "awaiting_review", reply: null }))).toBe(
      "Your request is pending human review. The result will appear here once a reviewer decides.",
    );
  });
  it("human denied shows the reviewer message", () => {
    expect(statusLine(turn({ status: "human_denied", reply: null }))).toBe("A reviewer denied this request.");
  });
  it("not sent shows the firewall-unavailable message", () => {
    expect(statusLine(turn({ status: "not_sent", reply: null }))).toBe("Firewall unavailable, message not sent");
  });
  it("sent shows a waiting line", () => {
    expect(statusLine(turn({ status: "sent", reply: null }))).toBe("Waiting for the assistant…");
  });
});

describe("inputLocked", () => {
  it("locks only while a turn awaits review", () => {
    expect(inputLocked([turn({}), turn({ status: "awaiting_review" })])).toBe(true);
    expect(inputLocked([turn({ status: "human_denied" })])).toBe(false);
    expect(inputLocked([])).toBe(false);
  });
});

describe("newMessageId", () => {
  it("is unique and matches the API pattern", () => {
    const ids = new Set(Array.from({ length: 50 }, newMessageId));
    expect(ids.size).toBe(50);
    for (const id of ids) expect(id).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
  });
});

describe("computeFingerprint (PRD §8.5: SHA-256, no fingerprinting library)", () => {
  it("is a stable 64-char hex hash of the five fields", async () => {
    const parts = { userAgent: "UA", language: "en-US", timezone: "UTC", screen: "1280x800", platform: "Linux" };
    const a = await computeFingerprint(parts);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await computeFingerprint(parts)).toBe(a);
    expect(await computeFingerprint({ ...parts, timezone: "EST" })).not.toBe(a);
  });
});
