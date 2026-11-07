import type { Metadata } from "next";
import { Chakra_Petch, JetBrains_Mono } from "next/font/google";

import { Shell } from "@/components/shell/Shell";
import { getMe } from "@/lib/server-api";
import { signInPath, signOutPath } from "@/lib/session";

import "./globals.css";

// Self-hosted at build time by next/font: no runtime request to Google (CSP font-src 'self').
const display = Chakra_Petch({ subsets: ["latin"], weight: ["500", "700"], variable: "--font-chakra" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "600"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "Injection Arena",
  description: "Attack an AI assistant, see which defense stopped you, then explain it.",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const me = await getMe();
  return (
    <html lang="en" className={`${display.variable} ${mono.variable}`}>
      <body>
        {me ? <Shell me={me} signInPath={signInPath()} signOutPath={signOutPath()} /> : null}
        {children}
      </body>
    </html>
  );
}
