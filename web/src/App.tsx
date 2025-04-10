import React from "react";
import { Toaster } from "@/components/ui/sonner";
import { RouterProvider } from "react-router-dom";
import { ThemeProvider } from "@/components/theme-provider";
import router from "@/routers";

export default function Home() {
  return (
    <React.StrictMode>
      <ThemeProvider storageKey="vite-ui-theme">
        <Toaster />
        <RouterProvider router={router} />
      </ThemeProvider>
    </React.StrictMode>
  );
}
