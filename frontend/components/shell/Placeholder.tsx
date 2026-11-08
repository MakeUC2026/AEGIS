import { redirect } from "next/navigation";

import { getMe } from "@/lib/server-api";

interface Props {
  title: string;
  owner: string;
}

// Gate 0 placeholder for pages another machine owns (M1 §0.2 rule 4). Shows no data.
export async function Placeholder({ title, owner }: Props) {
  if (!(await getMe())) redirect("/");
  return (
    <main>
      <h1>{title}</h1>
      <p className="muted">This screen is being built by {owner}.</p>
    </main>
  );
}
