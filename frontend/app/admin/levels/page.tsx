import s from "../admin.module.css";
import { levels } from "../mock";

// A-07 shell. D-01 adds editing; each save creates a new level version through C8.
export default function Levels() {
  return (
    <section aria-labelledby="h-levels">
      <h2 id="h-levels">Levels</h2>
      <p className={s.note}>Mock data. Changes apply to new sessions only.</p>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Level</th>
              <th>Mode</th>
              <th>Version</th>
              <th>Rule set</th>
              <th>Review / Deny / Divert / Alert</th>
              <th>Signal weights</th>
              <th>Review timeout</th>
              <th>Divert</th>
            </tr>
          </thead>
          <tbody>
            {levels.map((l) => (
              <tr key={l.level_id}>
                <td>{l.name}</td>
                <td>{l.mode}</td>
                <td>v{l.version}</td>
                <td>v{l.rule_set_version}</td>
                <td>
                  {l.thresholds.review} / {l.thresholds.deny} / {l.thresholds.divert} /{" "}
                  {l.thresholds.alert}
                </td>
                <td className="muted">
                  {Object.entries(l.weights)
                    .map(([k, v]) => `${k}: ${v}`)
                    .join(", ")}
                </td>
                <td>{l.review_timeout_s === null ? "—" : `${l.review_timeout_s} s`}</td>
                <td>{l.divert_enabled ? "on" : "off"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
