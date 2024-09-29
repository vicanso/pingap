import request from "@/helpers/request";
import { random } from "@/helpers/util";
import { create } from "zustand";

export interface Upstream {
  addrs: string[];
  discovery?: string;
  update_frequency?: string;
  algo?: string;
  sni?: string;
  alpn?: string;
  health_check?: string;
  ipv4_only?: boolean;
  enable_tracer?: boolean;
  connection_timeout?: string;
  total_connection_timeout?: string;
  read_timeout?: string;
  idle_timeout?: string;
  write_timeout?: string;
  verify_cert?: boolean;
  tcp_idle?: string;
  tcp_interval?: string;
  tcp_probe_count?: number;
  tcp_recv_buf?: number;
  tcp_fast_open?: boolean;
  remark?: string;
}

export interface Location {
  upstream: string;
  path?: string;
  host?: string;
  weight?: number;
  proxy_set_headers?: string[];
  proxy_add_headers?: string[];
  rewrite?: string;
  client_max_body_size?: string;
  plugins?: string[];
  remark?: string;
}

export function getLocationWeight(location: Location) {
  if (location.weight) {
    return location.weight;
  }
  let weight = 0;
  const path = location.path || "";
  if (path.length > 1) {
    if (path.startsWith("=")) {
      weight += 1024;
    } else if (path.startsWith("~")) {
      weight += 256;
    } else {
      weight += 512;
    }
  }
  weight += path.length;
  if (location.host) {
    weight += 128;
  }
  return weight;
}

export interface Server {
  addr: string;
  access_log?: string;
  locations?: string[];
  threads?: number;
  tls_cert?: string;
  tls_key?: string;
  lets_encrypt?: string;
  certificate_file?: string;
  enabled_h2?: boolean;
  global_certificates?: boolean;
  tls_cipher_list?: string;
  tls_ciphersuites?: string;
  tls_min_version?: string;
  tls_max_version?: string;
  tcp_idle?: string;
  tcp_interval?: string;
  tcp_probe_count?: number;
  tcp_fastopen?: number;
  prometheus_metrics?: string;
  otlp_exporter?: string;
  remark?: string;
}

export interface Certificate {
  domains?: string;
  tls_cert?: string;
  tls_key?: string;
  tls_chain?: string;
  certificate_file?: string;
  acme?: string;
  is_default?: boolean;
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
  log_buffered_size?: string;
  log_format_json?: boolean;
  log_level?: string;
  auto_restart_check_interval?: string;
  cache_max_size?: number;
  cache_directory?: string;
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
  plugins?: Record<string, Record<string, unknown>>;
  certificates?: Record<string, Certificate>;
}

interface ConfigState {
  data: Config;
  toml: string;
  initialized: boolean;
  version: string;
  fetch: () => Promise<Config>;
  fetchToml: () => Promise<string>;
  update: (
    category: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<void>;
  remove: (category: string, name: string) => Promise<void>;
}

const useConfigState = create<ConfigState>()((set, get) => ({
  data: {
    basic: {} as Basic,
  },
  toml: "",
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
  fetchToml: async () => {
    const { data } = await request.get<string>("/configs/toml");
    set({
      toml: data,
    });
    return data;
  },
  update: async (
    category: string,
    name: string,
    data: Record<string, unknown>,
  ) => {
    const updateData: Record<string, unknown> = {};
    Object.keys(data).forEach((key) => {
      if (data[key] == null) {
        return;
      }
      updateData[key] = data[key];
    });
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

export default useConfigState;
