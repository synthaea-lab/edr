/** @type {import('next').NextConfig} */
const nextConfig = {
  // The production image copies .next/standalone (Dockerfile, runner stage).
  output: 'standalone',
  experimental: {
    // instrumentation.ts: the decoy shutdown flush and the start-up table check.
    instrumentationHook: true,
    serverActions: {
      enabled: true,
    },
  },
  // mTLS proxy passes agent identity via header
  async headers() {
    return [
      {
        source: '/api/ingest/:path*',
        headers: [
          {
            key: 'X-Client-Cert-Verified',
            value: 'SUCCESS',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
