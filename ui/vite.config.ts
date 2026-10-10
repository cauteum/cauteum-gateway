import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const gateway = process.env.CAUTEUM_GATEWAY_TARGET ?? "https://127.0.0.1:7443";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/v1/auth/oidc": { target: gateway, changeOrigin: true, secure: false },
      "/cauteum.control.v1": { target: gateway, changeOrigin: true, secure: false },
    },
  },
});
