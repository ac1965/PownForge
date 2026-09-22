import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev-only proxy so the SPA can call the FastAPI backend (pownforge web
// serve, default port 8420) without CORS: the browser only ever talks to
// this Vite origin, which forwards /api (including WebSocket) through.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8420",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
  },
});
