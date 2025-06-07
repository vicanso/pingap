import { defineConfig } from "vite";
import path from "path";
import react from "@vitejs/plugin-react-swc";
import tailwindcss from "@tailwindcss/vite";


function getModuleName(id: string) {
  const arr = id.split(path.sep);
  const index = arr.indexOf("node_modules");
  if (index === -1 || index === arr.length - 1) {
    return "";
  }
  return arr[index + 1];
}

function manualChunks(id: string) {
  const module = getModuleName(id);
  if (
    [
      "axios",
      "crypto-js",
      "date-fns",
      "radash",
      "react",
      "zod",
      "zustand",
    ].includes(module)
  ) {
    return "common";
  }
  if (id.includes("node_modules")) {
    return "vendor";
  }
  if (id.includes("components/ui")) {
    return "ui";
  }
}



// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
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
