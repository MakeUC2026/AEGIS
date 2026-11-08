import type { Metadata } from "next";
import { Chakra_Petch, Inter, JetBrains_Mono } from "next/font/google";

import { Shell } from "@/components/shell/Shell";
import { sectionsFor } from "@/components/shell/tabs";
import { getMe } from "@/lib/server-api";
import { signOutPath } from "@/lib/session";

import "./globals.css";

// Self-hosted at build time by next/font: no runtime request to Google (CSP font-src 'self').
const display = Chakra_Petch({ subsets: ["latin"], weight: ["500", "700"], variable: "--font-chakra" });
const body = Inter({ subsets: ["latin"], variable: "--font-inter" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "600"], variable: "--font-jetbrains" });

export const metadata: Metadata = {
  title: "AEGIS",
  description: "Attack an AI assistant, see which defense stopped you, then explain it.",
};

function roleLabel(roles: readonly string[]): string {
  if (roles.includes("firewall_admin")) return roles.includes("teacher") ? "Admin · Teacher" : "Firewall admin";
  return roles.includes("teacher") ? "Teacher" : "Student";
}

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const me = await getMe();
  return (
    <html lang="en" className={`${display.variable} ${body.variable} ${mono.variable}`}>
      <body>
        {me ? (
          <div className="frame">
            <Shell sections={sectionsFor(me.roles)} name={me.name ?? me.email ?? "You"} roleLabel={roleLabel(me.roles)} signOutPath={signOutPath()} />
            <div>{children}</div>
          </div>
        ) : (
          children
        )}
      </body>
    </html>
  );
}
