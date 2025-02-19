import { defineConfig } from "vite";
import path from "path";
import react from "@vitejs/plugin-react-swc";

function manualChunks(id: string) {
  if (id.includes("node_modules")) {
    return "vendor";
  }
  if (id.includes("components/ui")) {
    return "ui";
  }
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: "./",
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    chunkSizeWarningLimit: 1024 * 1024,
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
