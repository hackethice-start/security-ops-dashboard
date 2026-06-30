import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'REACT_APP_');

  // Map all REACT_APP_* vars to process.env.REACT_APP_* so existing code works unchanged
  const defines = Object.fromEntries(
    Object.entries(env).map(([k, v]) => [`process.env.${k}`, JSON.stringify(v)])
  );

  return {
    plugins: [react()],
    envPrefix: 'REACT_APP_',
    define: defines,
    build: {
      outDir: 'build',       // keep same output dir so Dockerfile COPY still works
      sourcemap: false,
    },
  };
});
