import request from "@/helpers/request";
import { random } from "@/helpers/util";
import { create } from "zustand";

export interface CertificateInfo {
  domains?: string[];
  acme?: string | null;
  not_after: number;
  not_before: number;
  issuer?: string;
  issuer_cn?: string;
  is_ca?: boolean;
  ocsp_stapling?: boolean;
  ocsp_stapled?: boolean;
  chain_count?: number;
  renewal_days?: number;
}

export interface ConfigDiffResult {
  valid: boolean;
  updated_categories: string[];
  diff: string[];
  restart_required?: boolean;
  left_for_restart?: string[];
  restart_unsupported: string;
}

export interface ConfigSnapshotItem {
  id: string;
  created_at: number;
  source: string;
  remark: string;
  hash: string;
  lines: number;
  toml: string;
}

class DryRunCaptured extends Error {
  result: ConfigDiffResult;

  constructor(result: ConfigDiffResult) {
    super("dry_run_captured");
    this.result = result;
  }
}

let dryRunActive = false;

export interface Upstream {
  addrs: string[];
  discovery?: string;
  update_frequency?: string;
  dns_server?: string;
  dns_domain?: string;
  dns_search?: string;
  algo?: string;
  fail_open?: boolean;
  slow_start?: string;
  sni?: string;
  alpn?: string;
  max_h2_streams?: number;
  strip_hop_by_hop?: boolean;
  strip_connection_nominated?: boolean;
  reject_malformed_connection_nominations?: boolean;
  h1_upgrade?: string;
  ca?: string;
  client_cert?: string;
  client_key?: string;
  h2_stream_window_size?: string;
  h2_connection_window_size?: string;
  health_check?: string;
  ipv4_only?: boolean;
  enable_tracer?: boolean;
  enable_backend_stats?: boolean;
  backend_failure_status_code?: string;
  circuit_break_max_consecutive_failures?: number;
  circuit_break_max_failure_percent?: number;
  circuit_break_min_requests_threshold?: number;
  circuit_break_half_open_consecutive_success_threshold?: number;
  circuit_break_open_duration?: string;
  backend_stats_interval?: string;
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
  send_proxy_protocol?: string;
  includes?: string[];
  remark?: string;
}

export interface Location {
  upstream: string;
  fallback_upstream?: string;
  path?: string;
  host?: string;
  weight?: number;
  proxy_set_headers?: string[];
  proxy_add_headers?: string[];
  max_retries?: number;
  max_retry_window?: string;
  retry_status_codes?: string;
  connection_timeout?: string;
  read_timeout?: string;
  write_timeout?: string;
  enable_reverse_proxy_headers?: boolean;
  rewrite?: string;
  client_max_body_size?: string;
  max_processing?: number;
  plugins?: string[];
  includes?: string[];
  grpc_web?: boolean;
  remark?: string;
  match_headers?: string[];
  match_query?: string[];
  match_cookies?: string[];
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
  h2_max_concurrent_streams?: number;
  h2_max_header_list_size?: string;
  h2_initial_window_size?: string;
  h2_initial_connection_window_size?: string;
  h2_idle_timeout?: string;
  h1_pipelining?: boolean;
  keepalive_request_limit?: number;
  enable_server_timing?: boolean;
  global_certificates?: boolean;
  strict_sni?: boolean;
  ja4?: boolean;
  proxy_protocol?: boolean;
  downstream_read_timeout?: string;
  downstream_write_timeout?: string;
  min_send_rate?: string;
  total_drain_timeout?: string;
  allow_ips?: string[];
  deny_ips?: string[];
  reuse_port?: boolean;
  tls_cipher_list?: string;
  tls_ciphersuites?: string;
  tls_min_version?: string;
  tls_max_version?: string;
  tls_client_ca?: string;
  tls_client_crl?: string;
  tls_client_auth?: string;
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
  dns_challenge?: boolean;
  tls_alpn_challenge?: boolean;
  dns_provider?: string;
  dns_service_url?: string;
  is_ca?: boolean;
  buffer_days?: number;
  acme_directory?: string;
  acme_ca?: string;
  acme_eab_kid?: string;
  acme_eab_hmac?: string;
  acme_contact?: string;
  acme_key_type?: string;
  ocsp_stapling?: boolean;
  remark?: string;
}

export interface Storage {
  category: string;
  secret?: string;
  value: string;
  remark?: string;
  created_at?: number;
}

export interface Stream {
  addr: string;
  upstream?: string;
  sni_routes?: Record<string, string>;
  proxy_protocol?: boolean;
  send_proxy_protocol?: string;
  access_log?: string;
  global_certificates?: boolean;
  tls_cipher_list?: string;
  tls_ciphersuites?: string;
  tls_min_version?: string;
  tls_max_version?: string;
  tls_client_ca?: string;
  tls_client_crl?: string;
  tls_client_auth?: string;
  connect_timeout?: string;
  idle_timeout?: string;
  sni_read_timeout?: string;
  max_connections?: number;
  allow_ips?: string[];
  deny_ips?: string[];
  threads?: number;
  reuse_port?: boolean;
  tcp_fastopen?: number;
  tcp_idle?: string;
  tcp_interval?: string;
  tcp_user_timeout?: string;
  tcp_probe_count?: number;
  includes?: string[];
  remark?: string;
}

interface Basic {
  error_template?: string;
  name?: string;
  labels?: string[];
  pid_file?: string;
  error_log?: string;
  upgrade_sock?: string;
  working_directory?: string;
  restart_ready_timeout?: string;
  user?: string;
  group?: string;
  threads?: number;
  max_blocking_threads?: number;
  work_stealing?: boolean;
  listener_tasks_per_fd?: number;
  downstream_tls_offload_threadpools?: number;
  downstream_tls_offload_thread_per_pool?: number;
  upstream_connect_offload_threadpools?: number;
  upstream_connect_offload_thread_per_pool?: number;
  grace_period?: string;
  graceful_shutdown_timeout?: string;
  upstream_keepalive_pool_size?: number;
  log_buffered_size?: string;
  log_format_json?: boolean;
  log_compress_algorithm?: string;
  log_compress_level?: number;
  log_compress_days_ago?: number;
  log_compress_time_point_hour?: number;
  log_level?: string;
  auto_restart_check_interval?: string;
  sentry?: string;
  pyroscope?: string;
  webhook?: string;
  webhook_type?: string;
  webhook_notifications?: string[];
  trusted_proxies?: string[];
  webhook_batch_window?: string;
  webhook_batch_max_events?: number;
  webhook_min_level?: string;
  webhook_headers?: string[];
  webhook_secret?: string;
  webhook_template?: string;
  webhook_retries?: number;
  docker_labels_enabled?: boolean;
  docker_labels_server?: string;
  docker_labels_tls_server?: string;
}

interface Config {
  basic: Basic;
  upstreams?: Record<string, Upstream>;
  locations?: Record<string, Location>;
  servers?: Record<string, Server>;
  streams?: Record<string, Stream>;
  plugins?: Record<string, Record<string, unknown>>;
  certificates?: Record<string, Certificate>;
  storages?: Record<string, Storage>;
}

export interface History {
  created_at: number;
  data: Record<string, unknown>;
}

export interface QuickSitePayload {
  name: string;
  domains: string[];
  upstreams: string[];
  path?: string;
  addr?: string;
  existing_server?: string;
  tls_mode: "none" | "acme" | "custom";
  tls_cert?: string;
  tls_key?: string;
  enable_reverse_proxy_headers?: boolean;
  enable_compression?: boolean;
  enable_security_headers?: boolean;
}

export interface QuickSiteResult {
  server: string;
  server_created: boolean;
  location: string;
  upstream: string;
  certificate?: string;
  plugins: string[];
}

export interface PresetPluginDef {
  name: string;
  config: Record<string, unknown>;
}

export interface ApplyPluginPresetPayload {
  save_preset_name?: string;
  save_preset_description?: string;
  plugins?: PresetPluginDef[];
  plugin_names?: string[];
  locations?: string[];
  position?: "prepend" | "append";
  overwrite_plugins?: boolean;
}

export interface ApplyPluginPresetResult {
  created_plugins: string[];
  reused_plugins: string[];
  updated_locations: string[];
  saved_preset?: string;
}

interface ConfigState {
  data: Config;
  certificateInfos: Record<string, CertificateInfo>;
  originalToml: string;
  fullToml: string;
  hcl: string;
  kdl: string;
  initialized: boolean;
  version: string;
  fetch: () => Promise<Config>;
  fetchFullConfig: () => Promise<void>;
  update: (
    category: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<void>;
  captureDryRun: (
    runSave: () => Promise<void>,
  ) => Promise<ConfigDiffResult | null>;
  previewImportDiff: (
    data: string,
    format?: "toml" | "hcl" | "kdl",
  ) => Promise<ConfigDiffResult>;
  importToml: (data: string, format?: "toml" | "hcl" | "kdl") => Promise<void>;
  getSnapshots: () => Promise<ConfigSnapshotItem[]>;
  createSnapshot: (remark?: string) => Promise<ConfigSnapshotItem>;
  createQuickSite: (payload: QuickSitePayload) => Promise<QuickSiteResult>;
  applyPluginPreset: (
    payload: ApplyPluginPresetPayload,
  ) => Promise<ApplyPluginPresetResult>;
  remove: (category: string, name: string) => Promise<void>;
  getIncludeOptions: (category?: string) => string[];
  getCertificateInfos: () => Promise<Record<string, CertificateInfo>>;
  getHistory: (category: string, name: string) => Promise<History[]>;
}

const useConfigState = create<ConfigState>()((set, get) => ({
  data: {
    basic: {} as Basic,
  },
  certificateInfos: {},
  fullToml: "",
  originalToml: "",
  hcl: "",
  kdl: "",
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
  fetchFullConfig: async () => {
    const { data } = await request.get<{
      full: string;
      hcl: string;
      kdl: string;
      original: string;
    }>("/configs/full");
    set({
      fullToml: data.full || "",
      originalToml: data.original || "",
      hcl: data.hcl || "",
      kdl: data.kdl || "",
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
    const encodedCategory = encodeURIComponent(category);
    const encodedName = encodeURIComponent(name);
    if (dryRunActive) {
      const { data: diffResult } = await request.post<ConfigDiffResult>(
        `/configs/${encodedCategory}/${encodedName}?dry_run=1`,
        updateData,
      );
      throw new DryRunCaptured(diffResult);
    }
    await request.post(
      `/configs/${encodedCategory}/${encodedName}`,
      updateData,
    );
    await get().fetch();
    set({
      version: random(),
    });
  },
  captureDryRun: async (runSave: () => Promise<void>) => {
    dryRunActive = true;
    try {
      await runSave();
      return null;
    } catch (err) {
      if (err instanceof DryRunCaptured) {
        return err.result;
      }
      throw err;
    } finally {
      dryRunActive = false;
    }
  },
  previewImportDiff: async (data: string, format?: "toml" | "hcl" | "kdl") => {
    const url = format ? `/configs/diff?format=${format}` : "/configs/diff";
    const { data: diffResult } = await request.post<ConfigDiffResult>(
      url,
      data,
    );
    return diffResult;
  },
  importToml: async (data: string, format?: "toml" | "hcl" | "kdl") => {
    const url = format ? `/configs/import?format=${format}` : "/configs/import";
    await request.post(url, data);
    await get().fetch();
    set({
      version: random(),
    });
  },
  getSnapshots: async () => {
    const { data } = await request.get<{ snapshots?: ConfigSnapshotItem[] }>(
      "/configs/snapshots",
    );
    return data.snapshots || [];
  },
  createSnapshot: async (remark?: string) => {
    const { data } = await request.post<ConfigSnapshotItem>(
      "/configs/snapshots",
      { remark },
    );
    return data;
  },
  createQuickSite: async (payload: QuickSitePayload) => {
    const { data } = await request.post<QuickSiteResult>(
      `/configs/quick-site`,
      payload,
    );
    await get().fetch();
    try {
      await get().getCertificateInfos();
    } catch {
      // Certificate metadata refresh is best-effort.
    }
    set({
      version: random(),
    });
    return data;
  },
  applyPluginPreset: async (payload: ApplyPluginPresetPayload) => {
    const { data } = await request.post<ApplyPluginPresetResult>(
      `/configs/apply-plugin-preset`,
      payload,
    );
    await get().fetch();
    set({
      version: random(),
    });
    return data;
  },
  remove: async (category: string, name: string) => {
    await request.delete(
      `/configs/${encodeURIComponent(category)}/${encodeURIComponent(name)}`,
    );
    await get().fetch();
    set({
      version: random(),
    });
  },
  getIncludeOptions: (category?: string) => {
    const storages = get().data.storages || {};
    const keys = Object.keys(storages);
    if (!category) {
      return keys.filter((key) => storages[key]?.category !== "plugin_preset");
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
    set({
      certificateInfos: data,
    });
    return data;
  },
  getHistory: async (category: string, name: string) => {
    const { data } = await request.get<{ history: History[] }>(
      `/config-history/${encodeURIComponent(category)}/${encodeURIComponent(name)}`,
    );
    return data.history;
  },
}));

export default useConfigState;
