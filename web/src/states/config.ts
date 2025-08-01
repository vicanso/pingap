import request from "@/helpers/request";
import { random } from "@/helpers/util";
import { create } from "zustand";

export interface CertificateInfo {
  not_after: number;
  not_before: number;
}

export interface Upstream {
  addrs: string[];
  discovery?: string;
  update_frequency?: string;
  dns_server?: string;
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
  tcp_user_timeout?: string;
  tcp_probe_count?: number;
  tcp_recv_buf?: number;
  tcp_fast_open?: boolean;
  includes?: string[];
  remark?: string;
}

export interface Location {
  upstream: string;
  path?: string;
  host?: string;
  weight?: number;
  proxy_set_headers?: string[];
  proxy_add_headers?: string[];
  enable_reverse_proxy_headers?: boolean;
  rewrite?: string;
  client_max_body_size?: string;
  max_processing?: number;
  plugins?: string[];
  includes?: string[];
  grpc_web?: boolean;
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
    let exists_regex = false;
    location.host.split(",").forEach((host) => {
      if (host.startsWith("~")) {
        exists_regex = true;
      }
    });
    if (!exists_regex) {
      weight += 128;
    } else {
      weight += location.host.length;
    }
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
  enable_server_timing?: boolean;
  global_certificates?: boolean;
  downstream_read_timeout?: string;
  downstream_write_timeout?: string;
  reuse_port?: boolean;
  tls_cipher_list?: string;
  tls_ciphersuites?: string;
  tls_min_version?: string;
  tls_max_version?: string;
  tcp_idle?: string;
  tcp_user_timeout?: string;
  tcp_interval?: string;
  tcp_probe_count?: number;
  tcp_fastopen?: number;
  prometheus_metrics?: string;
  otlp_exporter?: string;
  includes?: string[];
  modules?: string[];
  remark?: string;
}

export interface Certificate {
  domains?: string;
  tls_cert?: string;
  tls_key?: string;
  certificate_file?: string;
  acme?: string;
  is_default?: boolean;
  is_ca?: boolean;
  buffer_days?: number;
  remark?: string;
}

export interface Storage {
  category: string;
  secret?: string;
  value: string;
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
  listener_tasks_per_fd?: number;
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
  storages?: Record<string, Storage>;
}

interface ConfigState {
  data: Config;
  originalToml: string;
  fullToml: string;
  initialized: boolean;
  version: string;
  fetch: () => Promise<Config>;
  fetchToml: () => Promise<void>;
  update: (
    category: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<void>;
  importToml: (data: string) => Promise<void>;
  remove: (category: string, name: string) => Promise<void>;
  getIncludeOptions: () => string[];
  getCertificateInfos: () => Promise<Record<string, CertificateInfo>>;
}

const useConfigState = create<ConfigState>()((set, get) => ({
  data: {
    basic: {} as Basic,
  },
  fullToml: "",
  originalToml: "",
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
    const { data } = await request.get<{
      full: string;
      original: string;
    }>("/configs/toml");
    set({
      fullToml: data.full,
      originalToml: data.original,
    });
    return;
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
  importToml: async (data: string) => {
    await request.post(`/configs/import`, data);
  },
  remove: async (category: string, name: string) => {
    await request.delete(`/configs/${category}/${name}`);
    set({
      version: random(),
    });
    await get().fetch();
  },
  getIncludeOptions: (category?: string) => {
    const storages = get().data.storages || {};
    const keys = Object.keys(storages);
    if (!category) {
      return keys;
    }
    const includes: string[] = [];
    keys.forEach((key) => {
      const storage = storages[key];
      if (storage.category === category) {
        includes.push(key);
      }
    });
    return includes;
  },
  getCertificateInfos: async () => {
    const { data } =
      await request.get<Record<string, CertificateInfo>>(`/certificates`);
    return data;
  },
}));

export default useConfigState;
