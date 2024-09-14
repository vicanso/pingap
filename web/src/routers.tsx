import { createHashRouter } from "react-router-dom";
import Home from "@/pages/Home";
import Basic from "@/pages/Basic";
import Servers from "@/pages/Servers";
import Locations from "@/pages/Locations";
import Upstreams from "@/pages/Upstreams";
import Plugins from "@/pages/Plugins";
import Certificates from "@/pages/Certificates";

export const HOME = "/";
export const BASIC = "/basic";
export const SERVERS = "/servers";
export const LOCATIONS = "/locations";
export const UPSTREMAS = "/upstreams";
export const PLUGINS = "/plugins";
export const CERTIFICATES = "/certificates";

const router = createHashRouter([
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
]);

export default router;
