// Copy for the sign-in / sign-up panel (theme from "Arena Sign-in Themes", Cyber terminal skin).
// The real credential form is Auth0 Universal Login: this panel only links to it (PRD §4.3).

export type PanelMode = "signin" | "signup";

export interface PanelLinks {
  signIn: string;
  signUp: string;
}

export interface PanelCopy {
  title: string;
  hint: string;
  cta: string;
  href: string;
  showRoleNote: boolean;
}

export function panelCopy(mode: PanelMode, links: PanelLinks): PanelCopy {
  if (mode === "signup") {
    return {
      title: "Create your account",
      hint: "Takes under a minute. You will land in the Arena.",
      cta: "Create account",
      href: links.signUp,
      showRoleNote: true,
    };
  }
  return {
    title: "Welcome back",
    hint: "One account opens the Arena and the Classroom.",
    cta: "Enter the Arena",
    href: links.signIn,
    showRoleNote: false,
  };
}
