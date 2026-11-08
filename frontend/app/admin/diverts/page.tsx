import s from "../admin.module.css";
import { diverts } from "../mock";

// A-07 shell. Trace-back data is firewall-admin only (PRD §8.5, E-55) and purged after 30 days.
export default function Diverts() {
  return (
    <section aria-labelledby="h-diverts">
      <h2 id="h-diverts">Diverts and trace-back</h2>
      <p className={s.note}>Mock data.</p>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Trace</th>
              <th>Time</th>
              <th>Session</th>
              <th>Tool</th>
              <th>Decoy shown</th>
              <th>Trace-back</th>
              <th>Methods</th>
            </tr>
          </thead>
          <tbody>
            {diverts.map((d) => (
              <tr key={d.trace_id}>
                <td>{d.trace_id}</td>
                <td>
                  <time dateTime={d.time}>{d.time.slice(0, 19).replace("T", " ")} UTC</time>
                </td>
                <td>
                  {d.fw_session_id}
                  <div className="muted">{d.user}</div>
                </td>
                <td>{d.tool}</td>
                <td>
                  <code>{d.decoy}</code>
                </td>
                <td>
                  <div>ip: {d.ip_hash ?? "n/a"}</div>
                  <div>
                    asn: {d.asn_org ?? "n/a"} ({d.country ?? "n/a"})
                  </div>
                  <div>ua: {d.user_agent ?? "n/a"}</div>
                </td>
                <td>
                  {d.methods_used.map((m) => (
                    <span key={m} className={s.tag}>
                      {m}
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
