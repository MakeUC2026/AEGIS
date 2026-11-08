import { AccessDenied, Unavailable } from "../_components/Common";
import { InsightsView } from "../_components/InsightsView";
import { toInsights, type ApiInsights } from "../_lib/adapt";
import { canView } from "../_lib/access";
import { load } from "../_lib/load";
import { requireViewer } from "../_lib/viewer";

// Teachers and firewall admins (PRD §12.3, admin reads everything). The API repeats the check, so a forged request gets a 403 as well.
export default async function Page() {
  const viewer = await requireViewer();
  if (!canView("insights", viewer.roles)) {
    return <AccessDenied what="class insights" home="/classroom" />;
  }
  const loaded = await load<ApiInsights>(["classroom", "insights"]);
  return (
    <main>
      <div className="page-head">
        <div>
          <p className="eyebrow learn">Classroom</p>
          <h1>Class insights</h1>
          <p className="muted">Refreshes about once a minute. Admin tests are left out.</p>
        </div>
      </div>
      {loaded.ok ? (
        <InsightsView data={toInsights(loaded.data)} />
      ) : loaded.reason === "forbidden" ? (
        <AccessDenied what="class insights" home="/classroom" />
      ) : (
        <Unavailable what="insights" />
      )}
    </main>
  );
}
