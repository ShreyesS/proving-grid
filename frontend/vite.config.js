import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/state": "http://localhost:8000",
      "/run": "http://localhost:8000",
      "/topology": "http://localhost:8000",
      "/memory": "http://localhost:8000",
      "/eval": "http://localhost:8000",
      "/patch": "http://localhost:8000",
      "/ws": {
        target: "ws://localhost:8000",
        ws: true,
      },
    },
  },
});
