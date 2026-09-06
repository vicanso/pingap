import {
  createHashRouter,
  Navigate,
  useParams,
} from "react-router-dom";
import { lazy, Suspense, type ReactNode } from "react";
import Root from "@/pages/Root";
import RouteError from "@/pages/RouteError";
import { LoadingPage } from "@/components/loading";

// Eager: shell + error boundary. Everything else is route-split so the first
// paint stays light and unused config pages are not downloaded up front.
const Home = lazy(() => import("@/pages/Home"));
const Basic = lazy(() => import("@/pages/Basic"));
const Servers = lazy(() => import("@/pages/Servers"));
const Locations = lazy(() => import("@/pages/Locations"));
const Upstreams = lazy(() => import("@/pages/Upstreams"));
const Plugins = lazy(() => import("@/pages/Plugins"));
const Certificates = lazy(() => import("@/pages/Certificates"));
const Config = lazy(() => import("@/pages/Config"));
const Storages = lazy(() => import("@/pages/Storages"));
const Login = lazy(() => import("@/pages/Login"));
const NotFound = lazy(() => import("@/pages/NotFound"));

export const HOME = "/";
export const BASIC = "/basic";
export const SERVERS = "/servers";
export const LOCATIONS = "/locations";
export const UPSTREAMS = "/upstreams";
export const PLUGINS = "/plugins";
export const CERTIFICATES = "/certificates";
export const STORAGES = "/storages";
export const CONFIG = "/config";
export const LOGIN = "/login";

function suspense(element: ReactNode) {
  return <Suspense fallback={<LoadingPage />}>{element}</Suspense>;
}

/**
 * Accepts legacy/path-style entity URLs (`/locations/baidu`) and rewrites them
 * to the canonical query form (`/locations?name=baidu`) the edit pages read.
 */
function RedirectNamedEntity({ base }: { base: string }) {
  const { name } = useParams();
  const target = name
    ? `${base}?name=${encodeURIComponent(name)}`
    : base;
  return <Navigate to={target} replace />;
}

const entityBases = [
  SERVERS,
  LOCATIONS,
  UPSTREAMS,
  PLUGINS,
  CERTIFICATES,
  STORAGES,
] as const;

// Everything inside the app shell. Login is deliberately not here.
const pages = [
  { path: HOME, element: suspense(<Home />) },
  { path: BASIC, element: suspense(<Basic />) },
  { path: SERVERS, element: suspense(<Servers />) },
  { path: LOCATIONS, element: suspense(<Locations />) },
  { path: UPSTREAMS, element: suspense(<Upstreams />) },
  { path: PLUGINS, element: suspense(<Plugins />) },
  { path: CERTIFICATES, element: suspense(<Certificates />) },
  { path: CONFIG, element: suspense(<Config />) },
  { path: STORAGES, element: suspense(<Storages />) },
  // Path-style aliases so pasted `/locations/foo` links still open the form.
  ...entityBases.map((base) => ({
    path: `${base}/:name`,
    element: <RedirectNamedEntity base={base} />,
  })),
  // In-shell 404 — keeps sidebar/header; must stay last among children.
  { path: "*", element: suspense(<NotFound />) },
];

const router = createHashRouter([
  {
    element: <Root />,
    // Catches a throw from Root itself, where the shell cannot be kept.
    errorElement: <RouteError />,
    // Per page as well, so a crash in one route renders inside the layout and
    // leaves the sidebar and header usable instead of blanking the app.
    children: pages.map((page) => ({ ...page, errorElement: <RouteError /> })),
  },
  {
    // Outside the shell on purpose: the sidebar lists every config section and
    // the top bar polls the process, neither of which a visitor who has not
    // signed in should see or trigger. The layout route above is pathless, so
    // it only matches when one of its children does — /login falls through here.
    path: LOGIN,
    element: suspense(<Login />),
    errorElement: <RouteError />,
  },
]);

export default router;

export function goToHome() {
  router.navigate(HOME);
}

export function goToConfig() {
  router.navigate(CONFIG);
}

export function goToLogin() {
  router.navigate(LOGIN);
}
