"use client";

import Link from "next/link";
import { useState } from "react";

import { type PanelMode, panelCopy } from "@/components/auth/panel-copy";

interface Props {
  signInHref: string;
  signUpHref: string;
  googleHref: string | null; // null in dev sign-in mode
}

// Right-hand panel of the sign-in stage. Links to Auth0 Universal Login; never collects passwords.
export function AuthPanel({ signInHref, signUpHref, googleHref }: Props) {
  const [mode, setMode] = useState<PanelMode>("signin");
  const copy = panelCopy(mode, { signIn: signInHref, signUp: signUpHref });
  return (
    <section className="auth-panel">
      <div className="seg" role="group" aria-label="Account mode">
        <button type="button" aria-pressed={mode === "signin"} onClick={() => setMode("signin")}>
          Sign in
        </button>
        <button type="button" aria-pressed={mode === "signup"} onClick={() => setMode("signup")}>
          Sign up
        </button>
      </div>
      <div>
        <h2>{copy.title}</h2>
        <p className="hint">{copy.hint}</p>
      </div>
      <div className="auth-actions">
        {/* Full navigation: the Auth0 routes are not client-side pages. */}
        <a className="btn-primary" href={copy.href}>
          {copy.cta}
        </a>
        {googleHref ? (
          <>
            <div className="or">or</div>
            <a className="btn-alt" href={googleHref}>
              Continue with Google
            </a>
          </>
        ) : null}
      </div>
      {copy.showRoleNote ? (
        <div className="roles">
          New accounts are students. Teacher accounts are set up by your school and sign in here.
          By signing up you accept the <Link href="/privacy">privacy notice</Link>.
        </div>
      ) : (
        <p className="hint">
          Read the <Link href="/privacy">privacy notice</Link>.
        </p>
      )}
    </section>
  );
}
