// MOCK DATA for insights and secrets (Phase A shells). Synthetic only; no secret values exist here.

export const MOCK_INSIGHTS = {
  overview: { students: 2, sessions: 7, sessionsPerStudent: 3.5, activeToday: 2 },
  outcomes: [
    { levelName: "Level 1", obtained: ["Ada (student)", "Ben (student)"], notYet: [] as string[] },
    { levelName: "Level 2", obtained: [] as string[], notYet: ["Ada (student)", "Ben (student)"] },
    { levelName: "Level 3", obtained: [] as string[], notYet: ["Ada (student)", "Ben (student)"] },
  ],
  defense: {
    topRules: [
      { id: "R-EXFIL-01", count: 14 },
      { id: "R-AUTH-02", count: 9 },
      { id: "R-SHELL-01", count: 4 },
    ],
    decisionsPerMode: [
      { mode: "off", allow: 22, review: 0, deny: 0, divert: 0 },
      { mode: "basic", allow: 18, review: 3, deny: 7, divert: 0 },
      { mode: "strict", allow: 12, review: 4, deny: 9, divert: 3 },
    ],
    divertCount: 3,
  },
  attackFamilies: [
    { family: "indirect_injection", count: 6 },
    { family: "exfiltration_via_email", count: 4 },
    { family: "authority_spoofing", count: 2 },
  ],
  riskyPatterns: [
    { id: "P-12", count: 7 },
    { id: "P-31", count: 3 },
  ],
  quiz: {
    taken: 2,
    open: 2,
    averagePercent: 59,
    lowestItems: [
      { key: "defense_layer", average: 1.0 },
      { key: "prevention", average: 1.5 },
    ],
  },
} as const;

export const MOCK_SECRETS = [
  { levelId: "level-1", levelName: "Level 1", version: 2, compromised: true, by: "Ben (student)", at: "2026-11-07T08:52:00Z" },
  { levelId: "level-2", levelName: "Level 2", version: 1, compromised: false, by: null, at: null },
  { levelId: "level-3", levelName: "Level 3", version: 1, compromised: false, by: null, at: null },
] as const;
