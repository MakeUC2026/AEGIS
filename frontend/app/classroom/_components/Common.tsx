import Link from "next/link";

import type { QuizStatus, ViewerKind } from "../_lib/types";
import { quizStatusLabel } from "../_lib/format";
import styles from "./classroom.module.css";

export function MockBadge() {
  return (
    <span className={styles.mock} title="Phase A shell: this screen shows mock data, not real sessions">
      Mock data
    </span>
  );
}

export function AccessDenied({ what, home }: { what: string; home: string }) {
  return (
    <main>
      <div className={styles.denied} role="alert">
        <h1>Access denied</h1>
        <p>You do not have access to {what}.</p>
        <Link href={home}>Go back</Link>
      </div>
    </main>
  );
}

type Tone = "good" | "warn" | "bad" | "info" | "quiet";

export function Pill({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return <span className={`${styles.pill} ${styles[tone]}`}>{children}</span>;
}

const QUIZ_TONE: Record<QuizStatus, Tone> = {
  not_taken: "quiet",
  assigned: "warn",
  in_progress: "info",
  done: "good",
};

export function QuizStatusPill({ status }: { status: QuizStatus }) {
  return <Pill tone={QUIZ_TONE[status]}>{quizStatusLabel(status)}</Pill>;
}

export function ScreenNav({ kind, current }: { kind: ViewerKind; current: "sessions" | "insights" | "secrets" }) {
  const items = [
    { id: "sessions", href: "/classroom", label: "Sessions", show: true },
    { id: "insights", href: "/classroom/insights", label: "Insights", show: kind === "teacher" },
    { id: "secrets", href: "/classroom/secrets", label: "Secrets", show: kind !== "student" },
  ] as const;
  return (
    <nav className={styles.subnav} aria-label="Classroom sections">
      {items
        .filter((i) => i.show)
        .map((i) => (
          <Link key={i.id} href={i.href} aria-current={i.id === current ? "page" : undefined}>
            {i.label}
          </Link>
        ))}
    </nav>
  );
}
