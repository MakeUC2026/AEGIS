import type { ViewerKind } from "./types";

// Shell-level role logic (PRD §4.2). It decides what to show; the API checks roles again (I-4).

export type Screen = "sessions" | "detail" | "insights" | "secrets" | "quiz" | "quiz_list";

export function viewerKind(roles: readonly string[]): ViewerKind {
  if (roles.includes("teacher")) return "teacher";
  if (roles.includes("firewall_admin")) return "firewall_admin";
  return "student";
}

export function canView(screen: Screen, roles: readonly string[]): boolean {
  const kind = viewerKind(roles);
  switch (screen) {
    case "insights":
      return kind === "teacher";
    case "secrets":
      return kind === "teacher" || kind === "firewall_admin";
    case "quiz_list":
      return kind === "student";
    default:
      return true;
  }
}

export function canAssignQuiz(roles: readonly string[]): boolean {
  return viewerKind(roles) === "teacher";
}

export function canOpenSession(roles: readonly string[], viewerId: string, ownerId: string): boolean {
  return viewerKind(roles) !== "student" || viewerId === ownerId;
}
