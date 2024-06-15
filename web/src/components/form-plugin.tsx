import * as React from "react";
import TextField from "@mui/material/TextField";
import FormControl from "@mui/material/FormControl";
import { useTranslation } from "react-i18next";
import Grid from "@mui/material/Grid";
import FormControlLabel from "@mui/material/FormControlLabel";
import Radio from "@mui/material/Radio";
import FormLabel from "@mui/material/FormLabel";
import RadioGroup from "@mui/material/RadioGroup";

import {
  CheckBoxItem,
  FormSelectField,
  FormTwoInputFields,
} from "./form-common";

export enum PluginCategory {
  STATS = "stats",
  LIMIT = "limit",
  COMPRESSION = "compression",
  ADMIN = "admin",
  DIRECTORY = "directory",
  MOCK = "mock",
  REQUEST_ID = "request_id",
  IP_RESTRICTION = "ip_restriction",
  KEY_AUTH = "key_auth",
  BASIC_AUTH = "basic_auth",
  JWT = "jwt",
  CACHE = "cache",
  REDIRECT = "redirect",
  PING = "ping",
  RESPONSE_HEADERS = "response_headers",
  REFERER_RESTRICTION = "referer_restriction",
  CSRF = "csrf",
}

export function getPluginSteps(category: string) {
  const defaultPluginSteps = [
    {
      label: "Request",
      option: 0,
      value: "request",
    },
    {
      label: "Proxy Upstream",
      option: 1,
      value: "proxy_upstream",
    },
    {
      label: "Response",
      option: 2,
      value: "response",
    },
  ];

  const pluginSupportSteps: Record<string, number[]> = {};
  pluginSupportSteps[PluginCategory.STATS] = [0, 1];
  pluginSupportSteps[PluginCategory.LIMIT] = [0, 1];
  pluginSupportSteps[PluginCategory.COMPRESSION] = [];
  pluginSupportSteps[PluginCategory.ADMIN] = [0, 1];
  pluginSupportSteps[PluginCategory.DIRECTORY] = [0, 1];
  pluginSupportSteps[PluginCategory.MOCK] = [0, 1];
  pluginSupportSteps[PluginCategory.REQUEST_ID] = [0, 1];
  pluginSupportSteps[PluginCategory.IP_RESTRICTION] = [0, 1];
  pluginSupportSteps[PluginCategory.KEY_AUTH] = [0, 1];
  pluginSupportSteps[PluginCategory.BASIC_AUTH] = [0, 1];
  pluginSupportSteps[PluginCategory.JWT] = [0, 1];
  pluginSupportSteps[PluginCategory.CACHE] = [0];
  pluginSupportSteps[PluginCategory.REDIRECT] = [0];
  pluginSupportSteps[PluginCategory.PING] = [0];
  pluginSupportSteps[PluginCategory.RESPONSE_HEADERS] = [2];
  pluginSupportSteps[PluginCategory.REFERER_RESTRICTION] = [0, 1];
  pluginSupportSteps[PluginCategory.CSRF] = [0, 1];

  const steps = pluginSupportSteps[category];
  if (steps) {
    const arr = defaultPluginSteps.filter((item) => {
      return steps.indexOf(item.option) !== -1;
    });
    return arr;
  }
  return defaultPluginSteps;
}

export function FormPluginField({
  category,
  value,
  id,
  onUpdate,
}: {
  value: Record<string, unknown>;
  category: string;
  id: string;
  onUpdate: (data: Record<string, unknown>) => void;
}) {
  const { t } = useTranslation();
  const key = `${id}-${category}`;
  const [data, setData] = React.useState(value);

  const fields: {
    category: "text" | "number" | "select" | "checkbox" | "textlist";
    key: string;
    label: string;
    valueLabel?: string;
    valueWidth?: string;
    addLabel?: string;
    divide?: string;
    id: string;
    span: number;
    options?: string[] | CheckBoxItem[];
  }[] = [];

  const boolOptions = [
    {
      label: "Yes",
      option: 1,
      value: true,
    },
    {
      label: "No",
      option: 0,
      value: false,
    },
    {
      label: "None",
      option: -1,
      value: null,
    },
  ];

  switch (category) {
    case PluginCategory.LIMIT: {
      fields.push(
        {
          category: "select",
          key: "type",
          label: t("form.limitCategory"),
          id: "limit-category",
          span: 6,
          options: ["rate", "inflight"],
        },
        {
          category: "select",
          key: "tag",
          label: t("form.limitTag"),
          id: "limit-tag",
          span: 6,
          options: ["cookie", "header", "query", "ip"],
        },
        {
          category: "text",
          key: "key",
          label: t("form.limitKey"),
          id: "limit-key",
          span: 6,
        },
        {
          category: "number",
          key: "max",
          label: t("form.limitMax"),
          id: "limit-max",
          span: 6,
        },
        {
          category: "text",
          key: "interval",
          label: t("form.limitInterval"),
          id: "limit-interval",
          span: 6,
        },
      );
      break;
    }
    case PluginCategory.COMPRESSION: {
      fields.push(
        {
          category: "number",
          key: "gzip_level",
          label: t("form.compressionGzipLevel"),
          id: "compresssion-gzip",
          span: 4,
        },
        {
          category: "number",
          key: "br_level",
          label: t("form.compressionBrLevel"),
          id: "compresssion-br",
          span: 4,
        },
        {
          category: "number",
          key: "zstd_level",
          label: t("form.compressionZstdLevel"),
          id: "compresssion-zstd",
          span: 4,
        },
        {
          category: "checkbox",
          key: "decompression",
          label: t("form.compressionDecompression"),
          id: "compresssion-decompression",
          options: boolOptions,
          span: 6,
        },
      );
      break;
    }
    case PluginCategory.ADMIN: {
      fields.push(
        {
          category: "text",
          key: "path",
          label: t("form.adminPath"),
          id: "admin-path",
          span: 6,
        },
        {
          category: "number",
          key: "ip_fail_limit",
          label: t("form.adminIpFailLimit"),
          id: "admin-ip-fail-limit",
          span: 6,
        },
        {
          category: "textlist",
          key: "authorizations",
          label: t("form.adminAuthorization"),
          id: "admin-authorization",
          addLabel: t("form.adminAuthorizationAdd"),
          span: 12,
        },
      );
      break;
    }
    case PluginCategory.DIRECTORY: {
      fields.push(
        {
          category: "text",
          key: "path",
          label: t("form.dirPath"),
          id: "dir-path",
          span: 6,
        },
        {
          category: "text",
          key: "index",
          label: t("form.dirIndex"),
          id: "dir-index",
          span: 6,
        },
        {
          category: "number",
          key: "chunk_size",
          label: t("form.dirChunkSize"),
          id: "dir-chunk-size",
          span: 6,
        },
        {
          category: "checkbox",
          key: "autoindex",
          label: t("form.dirAutoIndex"),
          id: "dir-auto-index",
          span: 6,
          options: boolOptions,
        },
        {
          category: "text",
          key: "max_age",
          label: t("form.dirMaxAge"),
          id: "dir-max-age",
          span: 6,
        },
        {
          category: "checkbox",
          key: "cache_private",
          label: t("form.dirCachePrivate"),
          id: "dir-cache-private",
          span: 6,
          options: boolOptions,
        },
        {
          category: "text",
          key: "charset",
          label: t("form.dirCharset"),
          id: "dir-chartset",
          span: 6,
        },
        {
          category: "checkbox",
          key: "download",
          label: t("form.dirDownload"),
          id: "dir-download",
          span: 6,
          options: boolOptions,
        },
        {
          category: "textlist",
          key: "headers",
          label: t("form.dirHeaderName"),
          valueLabel: t("form.dirHeaderValue"),
          id: "dir-headers",
          span: 12,
          divide: ":",
          addLabel: t("form.dirHeaderAdd"),
        },
      );
      break;
    }
    case PluginCategory.REQUEST_ID: {
      fields.push(
        {
          category: "select",
          key: "algorithm",
          label: t("form.requestIdAlgo"),
          id: "request-id-algo",
          span: 4,
          options: ["uuid", "nanoid"],
        },
        {
          category: "number",
          key: "size",
          label: t("form.requestIdLength"),
          id: "request-id-length",
          span: 4,
        },
        {
          category: "text",
          key: "header_name",
          label: t("form.requestIdHeaderName"),
          id: "request-id-header-name",
          span: 4,
        },
      );
      break;
    }
    case PluginCategory.IP_RESTRICTION: {
      fields.push(
        {
          category: "select",
          key: "type",
          label: t("form.ipRestrictionMode"),
          id: "ip-restriction-mode",
          span: 12,
          options: [
            {
              label: t("form.ipRestrictionAllow"),
              option: 0,
              value: "allow",
            },
            {
              label: t("form.ipRestrictionDeny"),
              option: 1,
              value: "deny",
            },
          ],
        },
        {
          category: "textlist",
          key: "ip_list",
          label: t("form.ipList"),
          addLabel: t("form.ipRestrictionAdd"),
          id: "ip-restriction-list",
          span: 12,
        },
        {
          category: "text",
          key: "message",
          label: t("form.ipRestrictionMessage"),
          id: "ip-restriction-message",
          span: 12,
        },
      );
      break;
    }
    case PluginCategory.REFERER_RESTRICTION: {
      fields.push(
        {
          category: "select",
          key: "type",
          label: t("form.refererRestrictionMode"),
          id: "referer-restriction-mode",
          span: 12,
          options: [
            {
              label: t("form.refererRestrictionAllow"),
              option: 0,
              value: "allow",
            },
            {
              label: t("form.refererRestrictionDeny"),
              option: 1,
              value: "deny",
            },
          ],
        },
        {
          category: "textlist",
          key: "referer_list",
          label: t("form.refererList"),
          addLabel: t("form.refererRestrictionAdd"),
          id: "ip-restriction-list",
          span: 12,
        },
        {
          category: "text",
          key: "message",
          label: t("form.refererRestrictionMessage"),
          id: "referer-restriction-message",
          span: 12,
        },
      );
      break;
    }
    case PluginCategory.KEY_AUTH: {
      fields.push(
        {
          category: "text",
          key: "query",
          label: t("form.keyAuthQuery"),
          id: "key-auth-query",
          span: 4,
        },
        {
          category: "text",
          key: "header",
          label: t("form.keyAuthHeader"),
          id: "key-auth-header",
          span: 4,
        },
        {
          category: "checkbox",
          key: "hide_credentials",
          label: t("form.keyAuthHideCredentials"),
          id: "key-auth-hide-credentials",
          span: 4,
          options: boolOptions,
        },
        {
          category: "textlist",
          key: "keys",
          label: t("form.keyAuthValues"),
          id: "key-auth-values",
          addLabel: t("form.keyAuthAdd"),
          span: 12,
        },
      );
      break;
    }
    case PluginCategory.BASIC_AUTH: {
      fields.push(
        {
          category: "textlist",
          key: "authorizations",
          label: t("form.basicAuthList"),
          id: "key-auth-values",
          addLabel: t("form.keyAuthAdd"),
          span: 12,
        },
        {
          category: "checkbox",
          key: "hide_credentials",
          label: t("form.basicAuthHideCredentials"),
          id: "basic-auth-hide-credentials",
          span: 4,
          options: boolOptions,
        },
      );
      break;
    }
    case PluginCategory.JWT: {
      fields.push(
        {
          category: "text",
          key: "header",
          label: t("form.jwtAuthHeader"),
          id: "jwt-auth-header",
          span: 4,
        },
        {
          category: "text",
          key: "query",
          label: t("form.jwtAuthQuery"),
          id: "jwt-auth-query",
          span: 4,
        },
        {
          category: "text",
          key: "cookie",
          label: t("form.jwtAuthCookie"),
          id: "jwt-auth-cookie",
          span: 4,
        },
        {
          category: "text",
          key: "auth_path",
          label: t("form.jwtSignPath"),
          id: "jwt-sign-path",
          span: 6,
        },
        {
          category: "checkbox",
          key: "algorithm",
          label: t("form.jwtSignAlgorithm"),
          id: "jwt-sign-algorithm",
          span: 6,
          options: [
            {
              label: "HS256",
              option: 1,
              value: "HS256",
            },
            {
              label: "HS512",
              option: 2,
              value: "HS512",
            },
          ],
        },
        {
          category: "text",
          key: "secret",
          label: t("form.jwtAuthSecret"),
          id: "jwt-auth-secret",
          span: 12,
        },
      );
      break;
    }
    case PluginCategory.REDIRECT: {
      fields.push(
        {
          category: "text",
          key: "prefix",
          label: t("form.redirectPrefix"),
          id: "redirect-prefix",
          span: 6,
        },
        {
          category: "checkbox",
          key: "http_to_https",
          label: t("form.redirectHttps"),
          id: "redirect-to-https",
          span: 6,
          options: boolOptions,
        },
      );
      break;
    }
    case PluginCategory.PING: {
      fields.push({
        category: "text",
        key: "path",
        label: t("form.pingPath"),
        id: "ping-path",
        span: 12,
      });
      break;
    }
    case PluginCategory.MOCK: {
      fields.push(
        {
          category: "text",
          key: "path",
          label: t("form.mockPath"),
          id: "mock-path",
          span: 6,
        },
        {
          category: "number",
          key: "status",
          label: t("form.mockStats"),
          id: "mock-status",
          span: 6,
        },
        {
          category: "textlist",
          key: "headers",
          label: t("form.mockHeaderName"),
          valueLabel: t("form.mockHeaderValue"),
          id: "mock-headers",
          span: 12,
          divide: ":",
          addLabel: t("form.mockHeader"),
        },
        {
          category: "text",
          key: "data",
          label: t("form.mockData"),
          id: "mock-data",
          span: 12,
        },
      );
      break;
    }
    case PluginCategory.CSRF: {
      fields.push(
        {
          category: "text",
          key: "token_path",
          label: t("form.csrfTokenPath"),
          id: "csrf-token-path",
          span: 6,
        },
        {
          category: "text",
          key: "name",
          label: t("form.csrfName"),
          id: "csrf-name",
          span: 6,
        },
        {
          category: "text",
          key: "key",
          label: t("form.csrfKey"),
          id: "csrf-key",
          span: 6,
        },
        {
          category: "text",
          key: "ttl",
          label: t("form.csrfTtl"),
          id: "csrf-ttl",
          span: 6,
        },
      );
      break;
    }
    case PluginCategory.RESPONSE_HEADERS: {
      fields.push(
        {
          category: "textlist",
          key: "add_headers",
          label: t("form.responseHeadersAddHeaderName"),
          valueLabel: t("form.responseHeadersAddHeaderValue"),
          id: "response-headers-add-headers",
          span: 12,
          divide: ":",
          addLabel: t("form.responseHeadersAdd"),
        },
        {
          category: "textlist",
          key: "set_headers",
          label: t("form.responseHeadersSetHeaderName"),
          valueLabel: t("form.responseHeadersSetHeaderValue"),
          id: "response-headers-set-headers",
          span: 12,
          divide: ":",
          addLabel: t("form.responseHeadersSet"),
        },
        {
          category: "textlist",
          key: "remove_headers",
          label: t("form.responseHeadersRemoveHeaderName"),
          id: "response-headers-remove-headers",
          span: 12,
          divide: "",
          addLabel: t("form.responseHeadersRemove"),
        },
      );
      break;
    }
    case PluginCategory.CACHE: {
      fields.push(
        {
          category: "text",
          key: "lock",
          label: t("form.cacheLock"),
          id: "cache-lock",
          span: 6,
        },
        {
          category: "text",
          key: "max_file_size",
          label: t("form.cacheMaxFileSize"),
          id: "cache-max-file-size",
          span: 6,
        },
        {
          category: "text",
          key: "namespace",
          label: t("form.cacheNamespace"),
          id: "cache-namespace",
          span: 6,
        },
        {
          category: "text",
          key: "max_ttl",
          label: t("form.cacheMaxTtl"),
          id: "cache-max-ttl",
          span: 6,
        },
        {
          category: "checkbox",
          key: "eviction",
          label: t("form.cacheEviction"),
          id: "cache-eviction",
          span: 6,
          options: boolOptions,
        },
        {
          category: "checkbox",
          key: "predictor",
          label: t("form.cachePredictor"),
          id: "cache-predictor",
          span: 6,
          options: boolOptions,
        },
        {
          category: "textlist",
          key: "headers",
          label: t("form.cacheHeaders"),
          id: "cache-headers",
          addLabel: t("form.cacheHeadersAdd"),
          span: 12,
        },
      );
      break;
    }
    default: {
      fields.push({
        category: "text",
        key: "path",
        label: t("form.statsPath"),
        id: "stats-path",
        span: 12,
      });
      break;
    }
  }
  const items = fields.map((field) => {
    let dom = <></>;
    switch (field.category) {
      case "select": {
        dom = (
          <FormControl fullWidth={true}>
            <FormSelectField
              label={field.label}
              options={field.options}
              value={(data[field.key] as string) || ""}
              onUpdate={(value) => {
                const current: Record<string, unknown> = {};
                current[field.key] = value;
                const newValues = Object.assign({}, data, current);
                setData(newValues);
                onUpdate(newValues);
              }}
            />
          </FormControl>
        );
        break;
      }
      case "number": {
        dom = (
          <TextField
            fullWidth={true}
            label={field.label}
            variant="outlined"
            style={{
              marginLeft: 0,
            }}
            defaultValue={(data[field.key] as string) || ""}
            sx={{ ml: 1, flex: 1 }}
            onChange={(e) => {
              const original = e.target.value.trim();
              const value = Number(original);
              const current: Record<string, unknown> = {};
              current[field.key] = value;
              const newValues = Object.assign({}, data, current);
              if (!original || Number.isNaN(value)) {
                delete newValues[field.key];
              }
              setData(newValues);
              onUpdate(newValues);
            }}
          />
        );
        break;
      }
      case "checkbox": {
        let options = (field.options as CheckBoxItem[]) || [];
        let defaultValue = -1;
        let labelItems = options.map((opt, index) => {
          if (data[field.key] === opt.value) {
            defaultValue = opt.option;
          }
          return (
            <FormControlLabel
              key={field.id + "-label-" + index}
              value={opt.option}
              control={<Radio />}
              label={opt.label}
            />
          );
        });

        dom = (
          <React.Fragment>
            <FormLabel id={field.id}>{field.label}</FormLabel>
            <RadioGroup
              row
              aria-labelledby={field.id}
              defaultValue={defaultValue}
              name="radio-buttons-group"
              onChange={(e) => {
                let value = Number(e.target.value);
                let currentValue;
                options.forEach((opt) => {
                  if (opt.option === value) {
                    currentValue = opt.value;
                  }
                });
                const current: Record<string, unknown> = {};
                current[field.key] = currentValue;
                const newValues = Object.assign({}, data, current);
                setData(newValues);
                onUpdate(newValues);
              }}
            >
              {labelItems}
            </RadioGroup>
          </React.Fragment>
        );
        break;
      }
      case "textlist": {
        dom = (
          <FormTwoInputFields
            id={field.id}
            divide={field.divide || ""}
            values={(data[field.key] as string[]) || []}
            label={field.label}
            valueLabel={field.valueLabel || ""}
            valueWidth={field.valueWidth || ""}
            addButtonFullWidth={true}
            onUpdate={(value) => {
              const current: Record<string, unknown> = {};
              current[field.key] = value;
              const newValues = Object.assign({}, data, current);
              setData(newValues);
              onUpdate(newValues);
            }}
            addLabel={field.addLabel || ""}
          />
        );

        break;
      }
      default: {
        dom = (
          <TextField
            fullWidth={true}
            label={field.label}
            variant="outlined"
            style={{
              marginLeft: 0,
            }}
            defaultValue={(data[field.key] as string) || ""}
            sx={{ ml: 1, flex: 1 }}
            onChange={(e) => {
              const value = e.target.value.trim();
              const current: Record<string, unknown> = {};
              current[field.key] = value;
              const newValues = Object.assign({}, data, current);
              setData(newValues);
              onUpdate(newValues);
            }}
          />
        );
        break;
      }
    }

    return (
      <Grid
        item
        xs={field.span}
        key={`${key}-${field.id}`}
        id={`${key}-${field.id}`}
      >
        {dom}
      </Grid>
    );
  });

  const list = (
    <Grid container spacing={2}>
      {items}
    </Grid>
  );

  return <React.Fragment>{list}</React.Fragment>;
}
