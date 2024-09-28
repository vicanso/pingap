export interface ExFormOption {
  label: string;
  option: string;
  value: string | number | boolean | null;
}
import { pascal } from "radash";

export function getPluginSteps(category: string) {
  const defaultPluginSteps = newStringOptions(
    ["request", "proxy_upstream", "response"],
    true,
  );

  const pluginSupportSteps: Record<string, number[]> = {};
  pluginSupportSteps[PluginCategory.STATS] = [0, 1];
  pluginSupportSteps[PluginCategory.LIMIT] = [0, 1];
  pluginSupportSteps[PluginCategory.COMPRESSION] = [0];
  pluginSupportSteps[PluginCategory.ACCEPT_ENCODING] = [0];
  pluginSupportSteps[PluginCategory.ADMIN] = [0, 1];
  pluginSupportSteps[PluginCategory.DIRECTORY] = [0, 1];
  pluginSupportSteps[PluginCategory.MOCK] = [0, 1];
  pluginSupportSteps[PluginCategory.REQUEST_ID] = [0, 1];
  pluginSupportSteps[PluginCategory.IP_RESTRICTION] = [0, 1];
  pluginSupportSteps[PluginCategory.KEY_AUTH] = [0, 1];
  pluginSupportSteps[PluginCategory.BASIC_AUTH] = [0];
  pluginSupportSteps[PluginCategory.COMBINED_AUTH] = [0];
  pluginSupportSteps[PluginCategory.JWT] = [0, 1];
  pluginSupportSteps[PluginCategory.CACHE] = [0];
  pluginSupportSteps[PluginCategory.REDIRECT] = [0];
  pluginSupportSteps[PluginCategory.PING] = [0];
  pluginSupportSteps[PluginCategory.RESPONSE_HEADERS] = [2];
  pluginSupportSteps[PluginCategory.REFERER_RESTRICTION] = [0, 1];
  pluginSupportSteps[PluginCategory.CSRF] = [0];
  pluginSupportSteps[PluginCategory.CORS] = [0, 1];

  const steps = pluginSupportSteps[category];
  if (steps) {
    const arr: ExFormOption[] = [];
    for (let index = 0; index < defaultPluginSteps.length; index++) {
      if (steps.indexOf(index) !== -1) {
        arr.push(defaultPluginSteps[index]);
      }
    }
    return arr;
  }
  return defaultPluginSteps;
}

export function newBooleanOptions() {
  const options: ExFormOption[] = [
    {
      label: "Yes",
      option: "yes",
      value: true,
    },
    {
      label: "No",
      option: "no",
      value: false,
    },
    {
      label: "None",
      option: "none",
      value: null,
    },
  ];
  return options;
}

export function newStringOptions(
  values: string[],
  pascalFormat: boolean,
  withNone = false,
) {
  const options: ExFormOption[] = values.map((value) => {
    let label = value;
    if (pascalFormat) {
      label = pascal(value);
    }
    return {
      label,
      option: value,
      value: value,
    };
  });
  if (withNone) {
    options.unshift({
      label: "None",
      option: "none",
      value: "",
    });
  }
  return options;
}

export enum ExFormItemCategory {
  TEXT = "text",
  CHECKBOX = "checkbox",
  LABEL = "label",
  TEXTAREA = "textarea",
  SELECT = "select",
  MULTI_SELECT = "multiSelect",
  RADIOS = "radios",
  NUMBER = "number",
  DATETIME = "datetime",
  EDITOR = "editor",
  TEXTS = "texts",
  JSON = "json",
  KV_LIST = "kvList",
  SORT_CHECKBOXS = "sortCheckboxs",
  COMBINED_AUTHS = "combinedAuths",
}

export enum PluginCategory {
  STATS = "stats",
  LIMIT = "limit",
  COMPRESSION = "compression",
  ACCEPT_ENCODING = "accept_encoding",
  ADMIN = "admin",
  DIRECTORY = "directory",
  MOCK = "mock",
  REQUEST_ID = "request_id",
  IP_RESTRICTION = "ip_restriction",
  KEY_AUTH = "key_auth",
  BASIC_AUTH = "basic_auth",
  COMBINED_AUTH = "combined_auth",
  JWT = "jwt",
  CACHE = "cache",
  REDIRECT = "redirect",
  PING = "ping",
  RESPONSE_HEADERS = "response_headers",
  REFERER_RESTRICTION = "referer_restriction",
  CSRF = "csrf",
  CORS = "cors",
}
