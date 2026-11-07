// Role-aware tabs (PRD §4.2). Visibility only: every route is still checked on the server.

export type Role = "student" | "teacher" | "firewall_admin";

export interface Tab {
  href: string;
  label: string;
}

const TABS_BY_ROLE: Readonly<Record<Role, readonly Tab[]>> = {
  student: [
    { href: "/arena", label: "Arena" },
    { href: "/arena/sessions", label: "My sessions" },
    { href: "/quiz", label: "Quizzes" },
  ],
  teacher: [{ href: "/classroom", label: "Classroom" }],
  firewall_admin: [
    { href: "/arena", label: "Arena" },
    { href: "/classroom", label: "Classroom" },
    { href: "/admin", label: "Firewall" },
  ],
};

function isRole(value: string): value is Role {
  return Object.hasOwn(TABS_BY_ROLE, value);
}

export function tabsFor(roles: readonly string[]): Tab[] {
  const seen = new Set<string>();
  return roles
    .filter(isRole)
    .flatMap((role) => TABS_BY_ROLE[role])
    .filter((tab) => {
      if (seen.has(tab.href)) return false;
      seen.add(tab.href);
      return true;
    });
}
