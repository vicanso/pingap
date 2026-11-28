import request from "@/helpers/request";
import { create } from "zustand";

export interface StreamTrafficSummary {
  active_connections: number;
  connections_total: number;
  tx_bytes: number;
  rx_bytes: number;
}

export interface UpstreamTraffic {
  requests: number[];
  errors: number[];
  /** The requests that got a response header: what the wait is of. */
  latency_count: number[];
  latency_avg: number[];
  latency_max: number[];
}

/** What `/api/traffic` answers: one value per bucket, the oldest first. */
export interface TrafficSnapshot {
  interval: number;
  time: number[];
  requests: number[];
  status_2xx: number[];
  status_3xx: number[];
  status_4xx: number[];
  status_5xx: number[];
  /** The requests the latency is of: not the upgraded connections. */
  latency_count: number[];
  latency_avg: number[];
  latency_p95: number[];
  latency_max: number[];
  upstreams: Record<string, UpstreamTraffic>;
  streams?: Record<string, StreamTrafficSummary>;
  cache_memory_evictions?: number;
}

/** Formats a byte count into `0 B` or 1-decimal binary units (`KiB`..`TiB`). */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  if (bytes < 1024) {
    return `${Math.round(bytes)} B`;
  }
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(1)} ${units[idx]}`;
}

interface TrafficState {
  data: TrafficSnapshot | null;
  initialized: boolean;
  fetch: () => Promise<TrafficSnapshot | null>;
}

export const useTrafficState = create<TrafficState>()((set) => ({
  data: null,
  initialized: false,
  fetch: async () => {
    const { data } = await request.get<TrafficSnapshot>("/traffic");
    set({
      data,
      initialized: true,
    });
    return data ?? null;
  },
}));

export default useTrafficState;
