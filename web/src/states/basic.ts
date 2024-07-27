import request from "../helpers/request";
import { create } from "zustand";

interface Basic {
  start_time: number;
  version: string;
  rustc_version: string;
  memory: string;
  arch: string;
  config_hash: string;
}

interface ConfigState {
  data: Basic;
  initialized: boolean;
  fetch: () => Promise<Basic>;
}

const useBasicStore = create<ConfigState>()((set, get) => ({
  data: {
    start_time: 0,
    version: "",
    rustc_version: "",
    memory: "",
    arch: "",
    config_hash: "",
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

export default useBasicStore;
