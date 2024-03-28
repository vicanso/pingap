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
}

interface Location {
  upstream: string;
  path?: string;
  host?: string;
  proxy_headers?: string[];
  headers?: string[];
  rewrite?: string;
}

interface Server {
  addr: string;
  access_log?: string;
  locations?: string[];
  tls_cert?: string;
  tls_key?: string;
  stats_path?: string;
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
}

interface ConfigState {
  data: Config;
  initialized: boolean;
  fetch: () => Promise<Config>;
  update: (
    category: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<void>;
}

const useConfigStore = create<ConfigState>()((set, get) => ({
  data: {},
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
    const { data } = await request.get<Config>("/configs");
    set({
      data,
    });
  },
}));

export default useConfigStore;
