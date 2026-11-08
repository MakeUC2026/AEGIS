import cls from "@/app/classroom/_components/classroom.module.css";

import type { ResultView } from "../_lib/adapt";
import { RegradeButton } from "./QuizButtons";
import styles from "./quiz.module.css";

// Students see score and feedback; teachers also see the grade per rubric item (PRD §13.1, M4-X34).
// Feedback is model text built from the grade and answer key: rendered as plain text only.
export function QuizResultView({ result, canRegrade }: { result: ResultView; canRegrade: boolean }) {
  if (result.failed) {
    return (
      <div className={styles.card} role="alert">
        <h2>Grading did not finish</h2>
        <p>No points were awarded this time. Your answers are saved, so you can ask for grading again.</p>
        {canRegrade ? <RegradeButton quizId={result.quizId} /> : null}
      </div>
    );
  }
  return (
    <div className={cls.grid}>
      <section className={cls.block} aria-labelledby="r-score">
        <h2 id="r-score">Score</h2>
        <p className={styles.scoreBig}>{result.percent ?? 0}%</p>
        <p className="muted">
          {result.total ?? 0} of {result.max} points · attempt {result.attempt}
        </p>
        {result.items ? (
          <ul className={styles.items} style={{ marginTop: 16 }}>
            <li>
              <span>Multiple choice</span>
              <span className={cls.num}>
                {result.mcqPoints ?? 0} / {result.mcqMax}
              </span>
            </li>
            {result.items.map((i) => (
              <li key={i.key}>
                <span>{i.title}</span>
                <span className={cls.num}>
                  {i.score} / {i.max}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </section>
      <section className={cls.block} aria-labelledby="r-feedback">
        <h2 id="r-feedback">Feedback</h2>
        <p className={styles.feedback}>{result.feedback ?? "No feedback was written."}</p>
      </section>
    </div>
  );
}
