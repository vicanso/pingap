import { createHashRouter } from "react-router-dom";
import Root from "@/pages/Root";
import Home from "@/pages/Home";
import Basic from "@/pages/Basic";
import Servers from "@/pages/Servers";
import Locations from "@/pages/Locations";
import Upstreams from "@/pages/Upstreams";
import Plugins from "@/pages/Plugins";
import Certificates from "@/pages/Certificates";
import Config from "@/pages/Config";
import Storages from "@/pages/Storages";

export const HOME = "/";
export const BASIC = "/basic";
export const SERVERS = "/servers";
export const LOCATIONS = "/locations";
export const UPSTREMAS = "/upstreams";
export const PLUGINS = "/plugins";
export const CERTIFICATES = "/certificates";
export const STORAGES = "/storages";
export const CONFIG = "/config";

const router = createHashRouter([
  {
    element: <Root />,
    children: [
      {
        path: HOME,
        element: <Home />,
      },
      {
        path: BASIC,
        element: <Basic />,
      },
      {
        path: SERVERS,
        element: <Servers />,
      },
      {
        path: LOCATIONS,
        element: <Locations />,
      },
      {
        path: UPSTREMAS,
        element: <Upstreams />,
      },
      {
        path: PLUGINS,
        element: <Plugins />,
      },
      {
        path: CERTIFICATES,
        element: <Certificates />,
      },
      {
        path: CONFIG,
        element: <Config />,
      },
      {
        path: STORAGES,
        element: <Storages />,
      },
    ],
  },
]);

export default router;

export function goToHome() {
  router.navigate(HOME);
}

export function goToConfig() {
  router.navigate(CONFIG);
}
