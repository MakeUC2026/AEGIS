import cls from "@/app/classroom/_components/classroom.module.css";

import { ITEM_KEYS, ITEM_MAX, ITEM_TITLES, MCQ_MAX, TOTAL_POINTS } from "../_lib/rubric";
import type { MockQuiz } from "../_lib/mock";
import styles from "./quiz.module.css";

// Students see score and feedback; teachers also see the grade per rubric item (PRD §13.1, M4-X34).
export function QuizResultView({ quiz, showItems }: { quiz: MockQuiz; showItems: boolean }) {
  const r = quiz.result;
  if (!r) return <p className="muted">No result yet. The quiz is still in progress.</p>;
  return (
    <div className={cls.grid}>
      <section className={cls.block} aria-labelledby="r-score">
        <h2 id="r-score">Score</h2>
        <p className={styles.scoreBig}>{r.percent}%</p>
        <p className="muted">
          {r.total} of {TOTAL_POINTS} points
        </p>
        {showItems ? (
          <ul className={styles.items} style={{ marginTop: 16 }}>
            <li>
              <span>Multiple choice</span>
              <span className={cls.num}>
                {r.mcqPoints} / {MCQ_MAX}
              </span>
            </li>
            {ITEM_KEYS.map((k) => (
              <li key={k}>
                <span>{ITEM_TITLES[k]}</span>
                <span className={cls.num}>
                  {r.items[k]} / {ITEM_MAX}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </section>
      <section className={cls.block} aria-labelledby="r-feedback">
        <h2 id="r-feedback">Feedback</h2>
        <dl className={styles.fb}>
          <div>
            <dt>What was right</dt>
            <dd>{r.feedback.right}</dd>
          </div>
          <div>
            <dt>What was missing</dt>
            <dd>{r.feedback.missing}</dd>
          </div>
          <div>
            <dt>One thing to look at</dt>
            <dd>{r.feedback.lookAt}</dd>
          </div>
        </dl>
      </section>
    </div>
  );
}
