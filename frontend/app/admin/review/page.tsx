import s from "../admin.module.css";
import { tickets } from "../mock";

// A-07 shell. D-01 adds 2-3 s polling, the live countdown and the decide calls.
export default function ReviewQueue() {
  const sorted = [...tickets].sort((a, b) => Number(b.priority_alert) - Number(a.priority_alert));
  return (
    <section aria-labelledby="h-review">
      <h2 id="h-review">Review queue</h2>
      <p className={s.note}>Mock data. Priority alerts (99+) stay at the top.</p>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Ticket</th>
              <th>Stage</th>
              <th>Student command</th>
              <th>Held</th>
              <th>Score</th>
              <th>Rules</th>
              <th>Expires</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((t) => (
              <tr key={t.ticket_id} className={t.priority_alert ? s.priority : undefined}>
                <td>
                  {t.ticket_id}
                  {t.priority_alert && <span className={s.tag}>priority</span>}
                </td>
                <td>{t.stage}</td>
                <td>{t.student_command}</td>
                <td>
                  {t.held_tool ? (
                    <code>
                      {t.held_tool} {JSON.stringify(t.held_args)}
                    </code>
                  ) : (
                    (t.held_reply ?? <span className="muted">player message</span>)
                  )}
                </td>
                <td>
                  <strong>{t.sentinel_score}</strong>
                  <div className="muted">
                    {Object.entries(t.score_breakdown)
                      .map(([k, v]) => `${k}: ${v ?? "n/a"}`)
                      .join(", ")}
                  </div>
                </td>
                <td>{t.rule_ids.join(", ")}</td>
                <td>
                  <time dateTime={t.expires_at}>{t.expires_at.slice(11, 19)} UTC</time>
                </td>
                <td className={s.actions}>
                  <button type="button" className="button" disabled>
                    ok
                  </button>
                  <button type="button" className="button" disabled>
                    not ok (Human Deny)
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
