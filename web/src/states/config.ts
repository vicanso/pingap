import request from "../helpers/request";
import { create } from "zustand";

interface Upstream {
  addrs: string[];
  algo?: string;
  sni?: string;
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
  gzip_level?: number;
  br_level?: number;
  zstd_level?: number;
  remark?: string;
}

interface Server {
  addr: string;
  access_log?: string;
  locations?: string[];
  threads?: number;
  tls_cert?: string;
  tls_key?: string;
  stats_path?: string;
  admin_path?: string;
  remark?: string;
}

interface Config {
  upstreams?: Record<string, Upstream>;
  locations?: Record<string, Location>;
  servers?: Record<string, Server>;
  error_template?: string;
  pid_file?: string;
  upgrade_sock?: string;
  user?: string;
  group?: string;
  threads?: number;
  work_stealing?: boolean;
  grace_period?: string;
  graceful_shutdown_timeout?: string;
  upstream_keepalive_pool_size?: number;
  log_level?: string;
  sentry?: string;
  webhook?: string;
  webhook_type?: string;
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
  data: {},
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
}));

export default useConfigStore;
