import { invoke, isTauri } from "@tauri-apps/api/core";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/app/App";
import { selectSource, type DevEnv } from "@/lib/connection/sources";
import "./index.css";

// Read the dev-only variables behind the DEV flag, one key at a time. In a production build DEV is
// the constant `false`, so the bundler drops this branch and no development token or address can
// end up in shipped code (passing the whole import.meta.env would inline every VITE_* value).
const env: DevEnv = import.meta.env.DEV
  ? {
      DEV: true,
      VITE_TAPNETTRACK_API_URL: import.meta.env.VITE_TAPNETTRACK_API_URL,
      VITE_TAPNETTRACK_API_TOKEN: import.meta.env.VITE_TAPNETTRACK_API_TOKEN,
    }
  : { DEV: false };

const source = selectSource({ isTauri: isTauri(), invoke, env });

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");

createRoot(root).render(
  <StrictMode>
    <App source={source} />
  </StrictMode>,
);
