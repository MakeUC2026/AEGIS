import Link from "next/link";

import { AuthPanel } from "@/components/auth/AuthPanel";
import { AuthStage } from "@/components/auth/AuthStage";
import { tabsFor } from "@/components/shell/tabs";
import { getMe } from "@/lib/server-api";
import { googleSignInPath, signInPath, signUpPath } from "@/lib/session";

// Landing and sign-in (PRD §4.3 step 1), styled after the "Cyber terminal" sign-in theme.
export default async function Landing() {
  const me = await getMe();
  if (!me) {
    return (
      <AuthStage>
        <AuthPanel signInHref={signInPath()} signUpHref={signUpPath()} googleHref={googleSignInPath()} />
      </AuthStage>
    );
  }
  const home = tabsFor(me.roles)[0]?.href;
  return (
    <AuthStage>
      <section className="auth-panel">
        <div>
          <h2>Signed in</h2>
          <p className="hint">You are signed in as {me.name ?? me.email ?? "a user"}.</p>
        </div>
        {home ? (
          <Link className="btn-primary" href={home}>
            Continue
          </Link>
        ) : null}
      </section>
    </AuthStage>
  );
}
