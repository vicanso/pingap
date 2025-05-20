import request from "@/helpers/request";
import { create } from "zustand";

interface UpstreamHealthyStatus {
  healthy: number;
  total: number;
  unhealthy_backends: string[];
}

interface Basic {
  start_time: number;
  version: string;
  rustc_version: string;
  memory: string;
  arch: string;
  kernel: string;
  config_hash: string;
  pid: string;
  user: string;
  group: string;
  threads: number;
  accepted: number;
  processing: number;
  cpus: number;
  physical_cpus: number;
  used_memory: string;
  total_memory: string;
  enabled_full: boolean;
  enabled_pyroscope: boolean;
  fd_count: number;
  tcp_count: number;
  tcp6_count: number;
  supported_plugins: string[];
  upstream_healthy_status: Record<string, UpstreamHealthyStatus>;
}

interface ConfigState {
  data: Basic;
  initialized: boolean;
  fetch: () => Promise<Basic>;
  restart: () => Promise<void>;
}

const useBasicState = create<ConfigState>()((set) => ({
  data: {
    start_time: 0,
    version: "",
    rustc_version: "",
    memory: "",
    arch: "",
    kernel: "",
    config_hash: "",
    pid: "",
    user: "",
    group: "",
    threads: 0,
    accepted: 0,
    processing: 0,
    cpus: 0,
    physical_cpus: 0,
    used_memory: "",
    total_memory: "",
    enabled_full: false,
    enabled_pyroscope: false,
    fd_count: 0,
    tcp_count: 0,
    tcp6_count: 0,
    supported_plugins: [],
    upstream_healthy_status: {},
  },
  initialized: false,
  fetch: async () => {
    const { data } = await request.get<Basic>("/basic");
    set({
      initialized: true,
      data,
    });
    return data;
  },
  restart: async () => {
    await request.post("/restart");
  },
}));

export default useBasicState;
