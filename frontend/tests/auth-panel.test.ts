import { describe, expect, it } from "vitest";

import { panelCopy } from "@/components/auth/panel-copy";

describe("panelCopy (sign-in theme, PRD §4.3)", () => {
  const links = { signIn: "/auth/login", signUp: "/auth/login?screen_hint=signup" };

  it("sign in mode enters the arena through the sign-in route", () => {
    const copy = panelCopy("signin", links);
    expect(copy.title).toBe("Welcome back");
    expect(copy.cta).toBe("Enter the Arena");
    expect(copy.href).toBe("/auth/login");
    expect(copy.showRoleNote).toBe(false);
  });

  it("sign up mode uses the signup screen hint and shows the student-role note", () => {
    const copy = panelCopy("signup", links);
    expect(copy.title).toBe("Create your account");
    expect(copy.cta).toBe("Create account");
    expect(copy.href).toBe("/auth/login?screen_hint=signup");
    expect(copy.showRoleNote).toBe(true);
  });
});
