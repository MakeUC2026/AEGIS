import { redirect } from "next/navigation";

import { AuthPanel } from "@/components/auth/AuthPanel";
import { AuthStage } from "@/components/auth/AuthStage";
import { tabsFor } from "@/components/shell/tabs";
import { getMe } from "@/lib/server-api";
import { googleSignInPath, signInPath, signUpPath } from "@/lib/session";

// Landing and sign-in (PRD §4.3 step 1). Signed-in users go straight to their role's home page.
export default async function Landing() {
  const me = await getMe();
  const home = me ? tabsFor(me.roles)[0]?.href : undefined;
  if (home) redirect(home);
  return (
    <AuthStage>
      <AuthPanel signInHref={signInPath()} signUpHref={signUpPath()} googleHref={googleSignInPath()} />
    </AuthStage>
  );
}
