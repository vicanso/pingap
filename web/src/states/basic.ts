import request from "@/helpers/request";
import { create } from "zustand";

interface Basic {
  start_time: number;
  version: string;
  rustc_version: string;
  memory: string;
  arch: string;
  config_hash: string;
  pid: string;
  user: string;
  group: string;
  threads: number;
  accepted: number;
  processing: number;
}

interface ConfigState {
  data: Basic;
  initialized: boolean;
  fetch: () => Promise<Basic>;
}

const useBasicState = create<ConfigState>()((set) => ({
  data: {
    start_time: 0,
    version: "",
    rustc_version: "",
    memory: "",
    arch: "",
    config_hash: "",
    pid: "",
    user: "",
    group: "",
    threads: 0,
    accepted: 0,
    processing: 0,
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
}));

export default useBasicState;
