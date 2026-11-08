import Link from "next/link";

import type { QuizStatus } from "../_lib/types";
import { quizStatusLabel } from "../_lib/format";
import styles from "./classroom.module.css";

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

export function Unavailable({ what }: { what: string }) {
  return (
    <div className={styles.denied} role="alert">
      <h2>Could not load {what}</h2>
      <p>The classroom service did not answer. Reload the page to try again.</p>
    </div>
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
