import { AccessDenied, ScreenNav, Unavailable } from "../_components/Common";
import { InsightsView } from "../_components/InsightsView";
import styles from "../_components/classroom.module.css";
import { toInsights, type ApiInsights } from "../_lib/adapt";
import { canView } from "../_lib/access";
import { load } from "../_lib/load";
import { requireViewer } from "../_lib/viewer";

// Teachers only (PRD §12.3). The API repeats the check, so a forged request gets a 403 as well.
export default async function Page() {
  const viewer = await requireViewer();
  if (!canView("insights", viewer.roles)) {
    return <AccessDenied what="class insights (teachers only)" home="/classroom" />;
  }
  const loaded = await load<ApiInsights>(["classroom", "insights"]);
  return (
    <main>
      <div className={styles.head}>
        <h1>Class insights</h1>
      </div>
      <p className={styles.lead}>How the class is doing. Defense numbers refresh about once a minute. Admin test sessions are left out.</p>
      <ScreenNav kind={viewer.kind} current="insights" />
      {loaded.ok ? (
        <InsightsView data={toInsights(loaded.data)} />
      ) : loaded.reason === "forbidden" ? (
        <AccessDenied what="class insights (teachers only)" home="/classroom" />
      ) : (
        <Unavailable what="insights" />
      )}
    </main>
  );
}
