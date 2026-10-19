import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Как в скелете create-next-app для Next.js 16.
  cacheComponents: true,
  partialPrefetching: true,
  // Корень — сам пример, а не репозиторий с его package-lock.json.
  outputFileTracingRoot: __dirname,
  turbopack: { root: __dirname },
};

export default nextConfig;
