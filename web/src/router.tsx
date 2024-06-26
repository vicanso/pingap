import { createHashRouter } from "react-router-dom";
import Home from "./pages/home";
import BasicInfo from "./pages/basic-info";
import ServerInfo from "./pages/server-info";
import LocationInfo from "./pages/location-info";
import UpstreamInfo from "./pages/upstream-info";
import PluginInfo from "./pages/plugin-info";
import TomlPreview from "./pages/toml-preview";
import CertificateInfo from "./pages/certificate-info";

const PAHT_HOME = "/";
const PATH_BASIC_INFO = "/basic-info";
const PATH_SERVER_INFO = "/server-info/:name";
const PATH_LOCATION_INFO = "/location-info/:name";
const PATH_UPSTREAM_INFO = "/upstream-info/:name";
const PATH_PLUGIN_INFO = "/plugin-info/:name";
const PATH_CERTIFICATE_INFO = "/certificate-info/:name";
const PATH_TOML_PREVIEW = "/toml-preivew";

const router = createHashRouter([
  {
    path: PAHT_HOME,
    element: <Home />,
  },
  {
    path: PATH_BASIC_INFO,
    element: <BasicInfo />,
  },
  {
    path: PATH_SERVER_INFO,
    element: <ServerInfo />,
  },
  {
    path: PATH_LOCATION_INFO,
    element: <LocationInfo />,
  },
  {
    path: PATH_UPSTREAM_INFO,
    element: <UpstreamInfo />,
  },
  {
    path: PATH_PLUGIN_INFO,
    element: <PluginInfo />,
  },
  {
    path: PATH_CERTIFICATE_INFO,
    element: <CertificateInfo />,
  },
  {
    path: PATH_TOML_PREVIEW,
    element: <TomlPreview />,
  },
]);

export function goToLogin() {
  router.navigate("");
}

export function goToHome() {
  router.navigate(PAHT_HOME);
}

export function goToBasicInfo() {
  router.navigate(PATH_BASIC_INFO);
}

export function goToServerInfo(name: string) {
  router.navigate(PATH_SERVER_INFO.replace(":name", name));
}

export function goToLoationInfo(name: string) {
  router.navigate(PATH_LOCATION_INFO.replace(":name", name));
}

export function goToUpstreamInfo(name: string) {
  router.navigate(PATH_UPSTREAM_INFO.replace(":name", name));
}

export function goToPluginInfo(name: string) {
  router.navigate(PATH_PLUGIN_INFO.replace(":name", name));
}

export function goToCertificateInfo(name: string) {
  router.navigate(PATH_CERTIFICATE_INFO.replace(":name", name));
}

export function goToTomlPrevew() {
  router.navigate(PATH_TOML_PREVIEW);
}

export function goBack() {
  router.navigate(-1);
}

export default router;
