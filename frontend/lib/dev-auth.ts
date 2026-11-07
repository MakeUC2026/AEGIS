// Dev sign-in mode (DD-12): synthetic users and a guard. Never available when APP_ENV=production.
// Token signing lives in lib/dev-token.ts (server only).

export interface DevUser {
  id: string;
  name: string;
  email: string;
  roles: readonly string[];
}

export const DEV_USERS: readonly DevUser[] = [
  { id: "dev|student-ada", name: "Ada (student)", email: "ada@students.example", roles: [] },
  { id: "dev|student-ben", name: "Ben (student)", email: "ben@students.example", roles: [] },
  { id: "dev|teacher-cho", name: "Cho (teacher)", email: "cho@staff.example", roles: ["teacher"] },
  { id: "dev|admin-dee", name: "Dee (firewall admin)", email: "dee@staff.example", roles: ["firewall_admin"] },
  {
    id: "dev|both-eli",
    name: "Eli (teacher + firewall admin)",
    email: "eli@staff.example",
    roles: ["teacher", "firewall_admin"],
  },
];

type Env = Readonly<Record<string, string | undefined>>;

export function devAuthAllowed(env: Env = process.env): boolean {
  return env.AEGIS_AUTH_MODE === "dev" && env.APP_ENV !== "production";
}

export function findDevUser(id: string): DevUser | undefined {
  return DEV_USERS.find((u) => u.id === id);
}
