import { describe, expect, it } from "vitest";

import { canAssignQuiz, canOpenSession, canView, viewerKind } from "@/app/classroom/_lib/access";

describe("viewerKind (roles are checked on the server too; this only drives the shell)", () => {
  it("treats no staff role as a student", () => {
    expect(viewerKind([])).toBe("student");
    expect(viewerKind(["student"])).toBe("student");
  });
  it("teacher wins over firewall admin", () => {
    expect(viewerKind(["firewall_admin", "teacher"])).toBe("teacher");
    expect(viewerKind(["firewall_admin"])).toBe("firewall_admin");
  });
  it("ignores unknown roles", () => {
    expect(viewerKind(["root", "admin"])).toBe("student");
  });
});

describe("canView", () => {
  it("insights are teacher only (M4-X03)", () => {
    expect(canView("insights", ["teacher"])).toBe(true);
    expect(canView("insights", [])).toBe(false);
    expect(canView("insights", ["firewall_admin"])).toBe(false);
  });
  it("secrets are for teacher and firewall admin, not students (M4-X03, M4-X05)", () => {
    expect(canView("secrets", ["teacher"])).toBe(true);
    expect(canView("secrets", ["firewall_admin"])).toBe(true);
    expect(canView("secrets", [])).toBe(false);
  });
  it("the student quiz list is for students only", () => {
    expect(canView("quiz_list", [])).toBe(true);
    expect(canView("quiz_list", ["teacher"])).toBe(false);
    expect(canView("quiz_list", ["firewall_admin"])).toBe(false);
  });
  it("sessions list and quiz page are open to every signed-in role", () => {
    for (const roles of [[], ["teacher"], ["firewall_admin"]]) {
      expect(canView("sessions", roles)).toBe(true);
      expect(canView("quiz", roles)).toBe(true);
    }
  });
});

describe("canAssignQuiz (M4-X04)", () => {
  it("teacher only", () => {
    expect(canAssignQuiz(["teacher"])).toBe(true);
    expect(canAssignQuiz(["firewall_admin"])).toBe(false);
    expect(canAssignQuiz([])).toBe(false);
  });
});

describe("canOpenSession (M4-X02)", () => {
  it("students only open their own", () => {
    expect(canOpenSession([], "Ada (student)", "Ada (student)")).toBe(true);
    expect(canOpenSession([], "Ada (student)", "Ben (student)")).toBe(false);
  });
  it("staff open any session", () => {
    expect(canOpenSession(["teacher"], "Cho (teacher)", "Ben (student)")).toBe(true);
    expect(canOpenSession(["firewall_admin"], "Dee (firewall admin)", "Ben (student)")).toBe(true);
  });
});
