import type { InsightsData } from "../_lib/adapt";
import styles from "./classroom.module.css";

function Bars({ rows, scale }: { rows: readonly { label: string; value: number }[]; scale?: number }) {
  const max = scale ?? Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className={styles.bars}>
      {rows.map((r) => (
        <li key={r.label}>
          <span>{r.label}</span>
          <span className={styles.bar} aria-hidden="true">
            <i style={{ width: `${(r.value / max) * 100}%` }} />
          </span>
          <span className={styles.num}>{r.value}</span>
        </li>
      ))}
    </ul>
  );
}

const M2 = "Waiting for M2.";

function Empty({ when, text }: { when: boolean; text: string }) {
  return when ? <p className="muted">{text}</p> : null;
}

// Fixed 6-column grid: rows of 1, 2, 3 and 1 cards that fill the width, so no holes appear
// whatever the data size. Stacks to one column on small screens.
export function InsightsView({ data: I }: { data: InsightsData }) {
  const stat = (value: React.ReactNode, label: string) => (
    <div className={styles.stat}>
      <strong>{value}</strong>
      <span className="muted">{label}</span>
    </div>
  );
  return (
    <div className={styles.insights}>
      <section className={`${styles.block} ${styles.span6}`} aria-labelledby="i-overview">
        <h2 id="i-overview">Class overview</h2>
        <div className={styles.stats}>
          {stat(I.overview.students, "students")}
          {stat(I.overview.sessions, "sessions")}
          {stat(I.overview.sessionsPerStudent, "per student")}
          {stat(I.overview.activeToday, "active today")}
          {stat(I.defense.divertCount, "diverts")}
        </div>
      </section>

      <section className={`${styles.block} ${styles.span3}`} aria-labelledby="i-outcomes">
        <h2 id="i-outcomes">Outcomes per level</h2>
        <Empty when={I.outcomes.length === 0} text="No levels yet." />
        {I.outcomes.length ? (
          <table className={styles.simpleTable}>
            <thead>
              <tr><th scope="col">Level</th><th scope="col">Sessions</th><th scope="col">Obtained</th><th scope="col">Not yet</th><th scope="col">Rate</th></tr>
            </thead>
            <tbody>
              {I.outcomes.map((o) => (
                <tr key={o.levelName}>
                  <th scope="row">{o.levelName}</th>
                  <td className={styles.num}>{o.sessions}</td>
                  <td className={styles.num}>{o.obtained}</td>
                  <td className={styles.num}>{o.notObtained}</td>
                  <td className={styles.num}>{o.ratePercent}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>

      <section className={`${styles.block} ${styles.span3}`} aria-labelledby="i-modes">
        <h2 id="i-modes">Decisions per mode</h2>
        <Empty when={I.defense.decisionsPerMode.length === 0} text={`No decisions yet. ${M2}`} />
        {I.defense.decisionsPerMode.length ? (
          <table className={styles.simpleTable}>
            <thead>
              <tr><th scope="col">Mode</th><th scope="col">Allow</th><th scope="col">Review</th><th scope="col">Deny</th><th scope="col">Divert</th></tr>
            </thead>
            <tbody>
              {I.defense.decisionsPerMode.map((m) => (
                <tr key={m.mode}>
                  <th scope="row">{m.mode}</th>
                  <td className={styles.num}>{m.allow}</td>
                  <td className={styles.num}>{m.review}</td>
                  <td className={styles.num}>{m.deny}</td>
                  <td className={styles.num}>{m.divert}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>

      <section className={`${styles.block} ${styles.span2}`} aria-labelledby="i-rules">
        <h2 id="i-rules">Rules fired most</h2>
        <Empty when={I.defense.topRules.length === 0} text={`No rules fired yet. ${M2}`} />
        <Bars rows={I.defense.topRules.map((r) => ({ label: r.id, value: r.count }))} />
      </section>

      <section className={`${styles.block} ${styles.span2}`} aria-labelledby="i-families">
        <h2 id="i-families">Attack families</h2>
        <Empty when={I.attackFamilies.length === 0} text={`No attacks classified yet. ${M2}`} />
        <Bars rows={I.attackFamilies.map((f) => ({ label: f.family.replaceAll("_", " "), value: f.count }))} />
      </section>

      <section className={`${styles.block} ${styles.span2}`} aria-labelledby="i-patterns">
        <h2 id="i-patterns">Risky patterns</h2>
        <Empty when={I.riskyPatterns.length === 0} text={`No risky patterns matched yet. ${M2}`} />
        <Bars rows={I.riskyPatterns.map((p) => ({ label: p.id, value: p.count }))} />
      </section>

      <section className={`${styles.block} ${styles.span6}`} aria-labelledby="i-quiz">
        <h2 id="i-quiz">Quiz</h2>
        <div className={styles.quizRow}>
          <div className={styles.stats}>
            {stat(I.quiz.taken, "taken")}
            {stat(I.quiz.open, "open")}
            {stat(I.quiz.averagePercent === null ? "-" : `${I.quiz.averagePercent}%`, "average score")}
          </div>
          <div>
            <p className={styles.sub}>Lowest rubric items (average out of 3)</p>
            <Empty when={I.quiz.lowestItems.length === 0} text="No graded quizzes yet." />
            <Bars scale={3} rows={I.quiz.lowestItems.map((x) => ({ label: x.title, value: x.average }))} />
          </div>
        </div>
      </section>
    </div>
  );
}
