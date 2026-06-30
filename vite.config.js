import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'REACT_APP_');

  return {
    plugins: [react()],
    build: { outDir: 'build', sourcemap: false },
    define: {
      // Explicit fallback for every REACT_APP_* var used in the dashboard.
      // Empty string = mock data mode. Populated at build time via Docker build-args.
      'process.env.REACT_APP_FORTINET_HOST':         JSON.stringify(env.REACT_APP_FORTINET_HOST         || ''),
      'process.env.REACT_APP_FORTINET_APIKEY':        JSON.stringify(env.REACT_APP_FORTINET_APIKEY        || ''),
      'process.env.REACT_APP_PALOALTO_HOST':          JSON.stringify(env.REACT_APP_PALOALTO_HOST          || ''),
      'process.env.REACT_APP_PALOALTO_APIKEY':        JSON.stringify(env.REACT_APP_PALOALTO_APIKEY        || ''),
      'process.env.REACT_APP_UPGUARD_APIKEY':         JSON.stringify(env.REACT_APP_UPGUARD_APIKEY         || ''),
      'process.env.REACT_APP_AZURE_TENANT_ID':        JSON.stringify(env.REACT_APP_AZURE_TENANT_ID        || ''),
      'process.env.REACT_APP_AZURE_CLIENT_ID':        JSON.stringify(env.REACT_APP_AZURE_CLIENT_ID        || ''),
      'process.env.REACT_APP_AZURE_CLIENT_SECRET':    JSON.stringify(env.REACT_APP_AZURE_CLIENT_SECRET    || ''),
      'process.env.REACT_APP_AZURE_SUBSCRIPTION_ID':  JSON.stringify(env.REACT_APP_AZURE_SUBSCRIPTION_ID  || ''),
      'process.env.REACT_APP_QUALYS_USERNAME':        JSON.stringify(env.REACT_APP_QUALYS_USERNAME        || ''),
      'process.env.REACT_APP_QUALYS_PASSWORD':        JSON.stringify(env.REACT_APP_QUALYS_PASSWORD        || ''),
      'process.env.REACT_APP_ME_HOST':                JSON.stringify(env.REACT_APP_ME_HOST                || ''),
      'process.env.REACT_APP_ME_APIKEY':              JSON.stringify(env.REACT_APP_ME_APIKEY              || ''),
      'process.env.REACT_APP_API_BASE_URL':           JSON.stringify(env.REACT_APP_API_BASE_URL           || ''),
    },
  };
});
