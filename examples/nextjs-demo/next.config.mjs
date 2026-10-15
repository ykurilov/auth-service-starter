import { fileURLToPath } from 'node:url';

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Не включаем соседние проекты/lock-файлы в tracing сборки примера.
  outputFileTracingRoot: fileURLToPath(new URL('.', import.meta.url)),
  // Модуль auth написан с импортами вида './x.js' (стандарт ESM).
  // Webpack сам не сопоставляет их с .ts-файлами — указываем явно.
  webpack: (config) => {
    config.resolve.extensionAlias = { '.js': ['.ts', '.js'] };
    return config;
  },
};

export default nextConfig;
