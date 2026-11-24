import { defineConfig, loadEnv, type ProxyOptions } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const adminBackendTarget = env.ADMIN_BACKEND_TARGET || "http://127.0.0.1:8004";
  const devPort = Number(env.VITE_PORT || 5175);
  const previewPort = Number(env.VITE_PREVIEW_PORT || 4175);

  // Admin authentication uses backend-managed HttpOnly session cookies and CSRF
  // protection. Never inject service tokens or credentials from the Vite proxy.
  const adminProxy: ProxyOptions = {
    target: adminBackendTarget,
    changeOrigin: true,
    rewrite: (requestPath: string) =>
      requestPath.replace(/^\/(?:admin-api|search-admin-api)/, ""),
  };

  return {
    plugins: [react()],
    base: env.VITE_BASE_PATH || "./",
    server: {
      host: "127.0.0.1",
      port: devPort,
      strictPort: true,
      proxy: {
        "/admin-api": adminProxy,
        "/search-admin-api": adminProxy,
      },
    },
    preview: {
      host: "127.0.0.1",
      port: previewPort,
      strictPort: true,
      proxy: {
        "/admin-api": adminProxy,
        "/search-admin-api": adminProxy,
      },
    },
    build: {
      outDir: "dist",
      emptyOutDir: true,
    },
  };
});
