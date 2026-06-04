import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy API/WS calls to the FastAPI backend on :8000 during dev.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/topology": "http://localhost:8000",
      "/run": "http://localhost:8000",
      "/healthz": "http://localhost:8000",
      "/ws": { target: "ws://localhost:8000", ws: true },
    },
  },
});
