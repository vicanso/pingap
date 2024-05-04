import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

function manualChunks(id: string) {
  if (id.includes("node_modules")) {
    return "vendor";
  }
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    rollupOptions: {
      output: {
        manualChunks,
      },
    },
  },
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:3018",
      },
    },
  },
});
