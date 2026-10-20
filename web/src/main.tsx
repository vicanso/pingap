import { StrictMode } from "react";

import { createRoot } from "react-dom/client";
import App from "./App.tsx";
// The faces are bundled, Latin only: the admin is often served where it
// cannot reach a font host, and Chinese falls back to the system's CJK faces
// named in the stack.
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "./index.css";
import "./i18n";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
