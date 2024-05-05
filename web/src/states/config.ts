import request from "../helpers/request";
import { create } from "zustand";

interface Upstream {
  addrs: string[];
  algo?: string;
  sni?: string;
  alpn?: string;
  health_check?: string;
  ipv4_only?: boolean;
  connection_timeout?: string;
  total_connection_timeout?: string;
  read_timeout?: string;
  idle_timeout?: string;
  write_timeout?: string;
  verify_cert?: boolean;
  remark?: string;
}

interface Location {
  upstream: string;
  path?: string;
  host?: string;
  weight?: number;
  proxy_headers?: string[];
  headers?: string[];
  rewrite?: string;
  proxy_plugins?: string[];
  remark?: string;
}

export function getLocationWeight(location: Location) {
  if (location.weight) {
    return location.weight;
  }
  let weight = 0;
  let path = location.path || "";
  if (path.startsWith("=")) {
    weight += 1024;
  } else if (path.startsWith("~")) {
    weight += 256;
  } else {
    weight += 512;
  }
  weight += path.length;
  if (location.host) {
    weight += 128;
  }
  return weight;
}

interface Server {
  addr: string;
  access_log?: string;
  locations?: string[];
  threads?: number;
  tls_cert?: string;
  tls_key?: string;
  lets_encrypt?: string;
  enabled_h2?: boolean;
  remark?: string;
}

interface ProxyPlugin {
  value: string;
  category: string;
  step?: number;
  remark?: string;
}

interface Basic {
  error_template?: string;
  name?: string;
  pid_file?: string;
  upgrade_sock?: string;
  user?: string;
  group?: string;
  threads?: number;
  work_stealing?: boolean;
  grace_period?: string;
  graceful_shutdown_timeout?: string;
  upstream_keepalive_pool_size?: number;
  log_capacity?: number;
  log_level?: string;
  auto_restart_check_interval?: string;
  cache_max_size?: number;
  sentry?: string;
  pyroscope?: string;
  webhook?: string;
  webhook_type?: string;
  webhook_notifications?: string[];
}

interface Config {
  basic: Basic;
  upstreams?: Record<string, Upstream>;
  locations?: Record<string, Location>;
  servers?: Record<string, Server>;
  proxy_plugins?: Record<string, ProxyPlugin>;
}

interface ConfigState {
  data: Config;
  initialized: boolean;
  version: string;
  fetch: () => Promise<Config>;
  update: (
    category: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<void>;
  remove: (category: string, name: string) => Promise<void>;
}

const random = (length = 8) => {
  // Declare all characters
  let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  // Pick characers randomly
  let str = "";
  for (let i = 0; i < length; i++) {
    str += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  return str;
};

const useConfigStore = create<ConfigState>()((set, get) => ({
  data: {
    basic: {} as Basic,
  },
  version: random(),
  initialized: false,
  fetch: async () => {
    const { data } = await request.get<Config>("/configs");
    set({
      initialized: true,
      data,
    });
    return data;
  },
  update: async (
    category: string,
    name: string,
    updateData: Record<string, unknown>,
  ) => {
    await request.post(`/configs/${category}/${name}`, updateData);
    set({
      version: random(),
    });
    await get().fetch();
  },
  remove: async (category: string, name: string) => {
    await request.delete(`/configs/${category}/${name}`);
    set({
      version: random(),
    });
    await get().fetch();
  },
}));

export default useConfigStore;
