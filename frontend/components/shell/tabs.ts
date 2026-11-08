// Role-aware navigation (PRD §4.2), grouped into the two sections of the app:
// Agent Framework (arena + firewall console) and Classroom. Visibility only: every route is
// still checked on the server.

import type { IconName } from "@/components/shell/Icon";

export type Role = "student" | "teacher" | "firewall_admin";
export type SectionId = "framework" | "classroom";

export interface Tab {
  href: string;
  label: string;
  icon: IconName;
}

export interface Section {
  id: SectionId;
  label: string;
  tabs: Tab[];
}

const SECTION_LABEL: Readonly<Record<SectionId, string>> = {
  framework: "Agent Framework",
  classroom: "Classroom",
};

const STAFF_CLASSROOM: readonly Tab[] = [
  { href: "/classroom", label: "Sessions", icon: "users" },
  { href: "/classroom/insights", label: "Insights", icon: "chart" },
  { href: "/classroom/secrets", label: "Secrets", icon: "key" },
];

const TABS_BY_ROLE: Readonly<Record<Role, Readonly<Record<SectionId, readonly Tab[]>>>> = {
  student: {
    framework: [{ href: "/arena", label: "Practice", icon: "chat" }],
    classroom: [
      { href: "/classroom", label: "Home", icon: "home" },
      { href: "/quiz", label: "Quizzes", icon: "check" },
      { href: "/arena/sessions", label: "My sessions", icon: "clock" },
    ],
  },
  teacher: { framework: [], classroom: STAFF_CLASSROOM },
  firewall_admin: {
    framework: [
      { href: "/admin/overview", label: "Overview", icon: "grid" },
      { href: "/admin/logs", label: "Live firewall", icon: "pulse" },
      { href: "/arena", label: "Practice", icon: "chat" },
      { href: "/admin", label: "Console", icon: "shield" },
    ],
    classroom: STAFF_CLASSROOM,
  },
};

function isRole(value: string): value is Role {
  return Object.hasOwn(TABS_BY_ROLE, value);
}

export function sectionsFor(roles: readonly string[]): Section[] {
  const known = roles.filter(isRole);
  const seen = new Set<string>();
  return (Object.keys(SECTION_LABEL) as SectionId[])
    .map((id) => ({
      id,
      label: SECTION_LABEL[id],
      tabs: known
        .flatMap((role) => TABS_BY_ROLE[role][id])
        .filter((tab) => (seen.has(tab.href) ? false : (seen.add(tab.href), true))),
    }))
    .filter((s) => s.tabs.length > 0);
}

// Flat list in nav order; the first entry is the role's home page.
export function tabsFor(roles: readonly string[]): Tab[] {
  return sectionsFor(roles).flatMap((s) => s.tabs);
}

// The tab whose href is the longest prefix of the path ("/classroom" vs "/classroom/insights").
export function activeHref(tabs: readonly Tab[], path: string): string | null {
  let best: string | null = null;
  for (const { href } of tabs) {
    if ((path === href || path.startsWith(`${href}/`)) && href.length > (best?.length ?? 0)) best = href;
  }
  return best;
}
