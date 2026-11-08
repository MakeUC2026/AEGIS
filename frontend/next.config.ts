import type { NextConfig } from "next";

// Static security headers for every response. The Content-Security-Policy is per request (it
// carries a nonce), so proxy.ts sets it; see lib/csp.ts.
const nextConfig: NextConfig = {
  poweredByHeader: false,
  output: "standalone",
  // DD-16: every page is per-user and request-time; Cache Components is off.
  cacheComponents: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
