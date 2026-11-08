import { LogsView } from "./LogsView";

// Live firewall. `?event=<id>` preselects an event (links from Overview).
export default async function Page({ searchParams }: { searchParams: Promise<{ event?: string | string[] }> }) {
  const { event } = await searchParams;
  return <LogsView initialId={typeof event === "string" ? event : undefined} />;
}
