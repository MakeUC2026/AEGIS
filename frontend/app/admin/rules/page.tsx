import s from "../admin.module.css";
import { rules } from "../mock";

// A-07 shell. D-01 adds the rule form (operators filtered by field type, RE2 check on save).
export default function Rules() {
  return (
    <section aria-labelledby="h-rules">
      <h2 id="h-rules">Rules</h2>
      <p className={s.note}>Mock data. Rules are versioned and deprecated, never deleted.</p>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Version</th>
              <th>Applies on</th>
              <th>Condition</th>
              <th>Action</th>
              <th>Weight</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.rule_id}>
                <td>
                  {r.rule_id}
                  {r.builtin && <span className={s.tag}>built-in</span>}
                </td>
                <td>v{r.version}</td>
                <td>{r.applies_on}</td>
                <td>
                  <code>{r.summary}</code>
                </td>
                <td>{r.action}</td>
                <td>{r.weight ?? "-"}</td>
                <td>{r.deprecated ? "deprecated" : r.enabled ? "enabled" : "disabled"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
