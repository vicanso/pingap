import * as React from "react";
import TextField from "@mui/material/TextField";
import FormControl from "@mui/material/FormControl";
import Stack from "@mui/material/Stack";
import Box from "@mui/material/Box";
import { useTranslation } from "react-i18next";
import Paper from "@mui/material/Paper";
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
  IP_LIMIT = "ip_limit",
  KEY_AUTH = "key_auth",
  BASIC_AUTH = "basic_auth",
  CACHE = "cache",
  REDIRECT_HTTPS = "redirect_https",
  PING = "ping",
  RESPONSE_HEADERS = "response_headers",
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
      label: "Upstream Response",
      option: 2,
      value: "upstream_response",
    },
  ];

  const pluginSupportSteps: Record<string, number[]> = {};
  pluginSupportSteps[PluginCategory.STATS] = [0, 1];
  pluginSupportSteps[PluginCategory.LIMIT] = [0, 1];
  pluginSupportSteps[PluginCategory.COMPRESSION] = [0, 1];
  pluginSupportSteps[PluginCategory.ADMIN] = [0, 1];
  pluginSupportSteps[PluginCategory.DIRECTORY] = [0, 1];
  pluginSupportSteps[PluginCategory.MOCK] = [0, 1];
  pluginSupportSteps[PluginCategory.REQUEST_ID] = [0, 1];
  pluginSupportSteps[PluginCategory.IP_LIMIT] = [0, 1];
  pluginSupportSteps[PluginCategory.KEY_AUTH] = [0, 1];
  pluginSupportSteps[PluginCategory.BASIC_AUTH] = [0, 1];
  pluginSupportSteps[PluginCategory.CACHE] = [0];
  pluginSupportSteps[PluginCategory.REDIRECT_HTTPS] = [0];
  pluginSupportSteps[PluginCategory.PING] = [0];
  pluginSupportSteps[PluginCategory.RESPONSE_HEADERS] = [2];

  const steps = pluginSupportSteps[category];
  if (steps) {
    const arr = defaultPluginSteps.filter((item) => {
      return steps.indexOf(item.option) !== -1;
    });
    return arr;
  }
  return defaultPluginSteps;
}

export function formatPluginCategory(value: string) {
  switch (value) {
    case PluginCategory.STATS: {
      return "stats";
    }
    case PluginCategory.LIMIT: {
      return "limit";
    }
    case PluginCategory.COMPRESSION: {
      return "compression";
    }
    case PluginCategory.ADMIN: {
      return "admin";
    }
    case PluginCategory.DIRECTORY: {
      return "directory";
    }
    case PluginCategory.MOCK: {
      return "mock";
    }
    case PluginCategory.REQUEST_ID: {
      return "requestId";
    }
    case PluginCategory.IP_LIMIT: {
      return "ipLimit";
    }
    case PluginCategory.KEY_AUTH: {
      return "keyAuth";
    }
    case PluginCategory.BASIC_AUTH: {
      return "basicAuth";
    }
    case PluginCategory.CACHE: {
      return "cache";
    }
    case PluginCategory.REDIRECT_HTTPS: {
      return "redirectHttps";
    }
    case PluginCategory.PING: {
      return "ping";
    }
    case PluginCategory.RESPONSE_HEADERS: {
      return "responseHeaders";
    }
  }
  return "";
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
    category: "text" | "number" | "select" | "checkbox";
    key: string;
    label: string;
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
          label: t("form.gzip"),
          id: "compresssion-gzip",
          span: 4,
        },
        {
          category: "number",
          key: "br_level",
          label: t("form.br"),
          id: "compresssion-br",
          span: 4,
        },
        {
          category: "number",
          key: "zstd_level",
          label: t("form.zstd"),
          id: "compresssion-zstd",
          span: 4,
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
          category: "text",
          key: "authorization",
          label: t("form.adminAuthorization"),
          id: "admin-authorization",
          span: 6,
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
          span: 6,
          options: ["uuid", "nanoid"],
        },
        {
          category: "number",
          key: "size",
          label: t("form.requestIdLength"),
          id: "request-id-length",
          span: 6,
        },
      );
      break;
    }
    case PluginCategory.IP_LIMIT: {
      fields.push(
        {
          category: "select",
          key: "type",
          label: t("form.limitMode"),
          id: "ip-limit-mode",
          span: 6,
          options: [
            {
              label: "Allow",
              option: 0,
              value: 0,
            },
            {
              label: "Deny",
              option: 1,
              value: 1,
            },
          ],
        },
        {
          category: "text",
          key: "ip_list",
          label: t("form.ipList"),
          id: "ip-limit-list",
          span: 6,
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

  // const arr: string[] = [];
  // const fields: {
  //   label: string;
  //   options?: string[] | CheckBoxItem[];
  // }[] = [];
  // const padding = " ";

  // const defaultMockInfo: {
  //   status: null | number;
  //   headers: string[];
  //   data: string;
  //   path: string;
  // } = {
  //   status: null,
  //   path: "",
  //   headers: [],
  //   data: "",
  // };

  // const defaultResponseHeaders: {
  //   add_headers: string[];
  //   remove_headers: string[];
  //   set_headers: string[];
  // } = {
  //   add_headers: [],
  //   remove_headers: [],
  //   set_headers: [],
  // };

  // switch (category) {
  //   case PluginCategory.COMPRESSION: {
  //     arr.push(...value.split(padding));
  //     fields.push(
  //       {
  //         label: t("form.gzip"),
  //       },
  //       {
  //         label: t("form.br"),
  //       },
  //       {
  //         label: t("form.zstd"),
  //       },
  //     );
  //     break;
  //   }
  //   case PluginCategory.ADMIN: {
  //     arr.push(...value.split(padding));
  //     fields.push(
  //       {
  //         label: t("form.adminPath"),
  //       },
  //       {
  //         label: t("form.basicAuth"),
  //       },
  //     );
  //     break;
  //   }
  //   case PluginCategory.LIMIT: {
  //     arr.push(...value.split(padding));
  //     fields.push(
  //       {
  //         label: t("form.limitCategory"),
  //         options: ["rate", "inflight"],
  //       },
  //       {
  //         label: t("form.limitValue"),
  //       },
  //     );
  //     break;
  //   }
  //   case PluginCategory.DIRECTORY: {
  //     arr.push(value);
  //     fields.push({
  //       label: t("form.staticDirectory"),
  //     });
  //     break;
  //   }
  //   case PluginCategory.REQUEST_ID: {
  //     arr.push(...value.split(padding));
  //     fields.push(
  //       {
  //         label: t("form.algoForId"),
  //         options: ["uuid", "nanoid"],
  //       },
  //       {
  //         label: t("form.lengthForId"),
  //       },
  //     );
  //     break;
  //   }
  //   case PluginCategory.IP_LIMIT: {
  //     arr.push(...value.split(padding));
  //     fields.push(
  //       {
  //         label: t("form.ipList"),
  //       },
  //       {
  //         label: t("form.limitMode"),
  //         options: [
  //           {
  //             label: t("form.allow"),
  //             value: "0",
  //             option: 0,
  //           },
  //           {
  //             label: t("form.deny"),
  //             value: "1",
  //             option: 1,
  //           },
  //         ],
  //       },
  //     );
  //     break;
  //   }
  //   case PluginCategory.KEY_AUTH: {
  //     arr.push(...value.split(padding));
  //     fields.push(
  //       {
  //         label: t("form.keyName"),
  //       },
  //       {
  //         label: t("form.keyValues"),
  //       },
  //     );
  //     break;
  //   }
  //   case PluginCategory.BASIC_AUTH: {
  //     arr.push(value);
  //     fields.push({
  //       label: t("form.basicAuthList"),
  //     });
  //     break;
  //   }
  //   case PluginCategory.MOCK: {
  //     if (value) {
  //       try {
  //         Object.assign(defaultMockInfo, JSON.parse(value));
  //       } catch (err) {
  //         console.error(err);
  //       }
  //     }
  //     break;
  //   }
  //   case PluginCategory.CACHE: {
  //     arr.push(value);
  //     fields.push({
  //       label: t("form.cacheStorage"),
  //     });
  //     break;
  //   }
  //   case PluginCategory.REDIRECT_HTTPS: {
  //     arr.push(value);
  //     fields.push({
  //       label: t("form.redirectPrefix"),
  //     });
  //     break;
  //   }
  //   case PluginCategory.PING: {
  //     arr.push(value);
  //     fields.push({
  //       label: t("form.pingPath"),
  //     });
  //     break;
  //   }
  //   case PluginCategory.RESPONSE_HEADERS: {
  //     value.split(" ").forEach((item) => {
  //       const value = item.trim();
  //       if (!value) {
  //         return;
  //       }
  //       let last = value.substring(1);
  //       if (item.startsWith("+")) {
  //         defaultResponseHeaders.add_headers.push(last);
  //       } else if (item.startsWith("-")) {
  //         defaultResponseHeaders.remove_headers.push(last);
  //       } else {
  //         defaultResponseHeaders.set_headers.push(value);
  //       }
  //     });
  //     break;
  //   }
  //   default: {
  //     arr.push(value);
  //     fields.push({
  //       label: t("form.statsPath"),
  //     });
  //     break;
  //   }
  // }
  // const [newValues, setNewValues] = React.useState(arr);
  // const [mockInfo, setMockInfo] = React.useState(defaultMockInfo);
  // const [responseHeaders, setResponseHeaders] = React.useState(
  //   defaultResponseHeaders,
  // );

  // const updateResponseHeaders = (headers: {
  //   add_headers: string[];
  //   remove_headers: string[];
  //   set_headers: string[];
  // }) => {
  //   setResponseHeaders(headers);
  //   const arr = headers.set_headers.slice(0);
  //   headers.add_headers.forEach((item) => {
  //     arr.push(`+${item}`);
  //   });
  //   headers.remove_headers.forEach((item) => {
  //     arr.push(`-${item}`);
  //   });
  //   onUpdate(arr.join(" "));
  // };

  // if (category == PluginCategory.MOCK) {
  //   return (
  //     <Stack direction="column" spacing={2}>
  //       <TextField
  //         key={`${key}-path`}
  //         id={`${key}-path`}
  //         label={t("form.mockPath")}
  //         variant="outlined"
  //         defaultValue={mockInfo.path}
  //         sx={{ ml: 1, flex: 1 }}
  //         onChange={(e) => {
  //           const data = Object.assign({}, mockInfo);
  //           data.path = e.target.value.trim();
  //           setMockInfo(data);
  //           onUpdate(JSON.stringify(data));
  //         }}
  //       />
  //       <TextField
  //         key={`${key}-status`}
  //         id={`${key}-status`}
  //         label={t("form.mockStats")}
  //         variant="outlined"
  //         defaultValue={mockInfo.status}
  //         sx={{ ml: 1, flex: 1 }}
  //         onChange={(e) => {
  //           const value = Number(e.target.value.trim());
  //           const data = Object.assign({}, mockInfo);
  //           if (value) {
  //             data.status = value;
  //           } else {
  //             data.status = null;
  //           }
  //           setMockInfo(data);
  //           onUpdate(JSON.stringify(data));
  //         }}
  //       />
  //       <FormTwoInputFields
  //         id={id}
  //         divide={":"}
  //         values={mockInfo.headers}
  //         label={t("form.headerName")}
  //         valueLabel={t("form.headerValue")}
  //         onUpdate={(headers) => {
  //           const data = Object.assign({}, mockInfo);
  //           data.headers = headers;
  //           setMockInfo(data);
  //           onUpdate(JSON.stringify(data));
  //         }}
  //         addLabel={t("form.mockHeader")}
  //       />
  //       <TextField
  //         id={`${key}-data`}
  //         label={t("form.mockData")}
  //         multiline
  //         minRows={3}
  //         variant="outlined"
  //         defaultValue={mockInfo.data}
  //         onChange={(e) => {
  //           const data = Object.assign({}, mockInfo);
  //           data.data = e.target.value;
  //           setMockInfo(data);
  //           onUpdate(JSON.stringify(data));
  //         }}
  //       />
  //     </Stack>
  //   );
  // }
  // if (category == PluginCategory.RESPONSE_HEADERS) {
  //   return (
  //     <Stack direction="column" spacing={2}>
  //       <FormTwoInputFields
  //         id={`${id}-set-headers`}
  //         divide={":"}
  //         values={responseHeaders.set_headers as string[]}
  //         label={t("form.headerName")}
  //         valueLabel={t("form.headerValue")}
  //         onUpdate={(data) => {
  //           const headers = Object.assign({}, responseHeaders);
  //           headers.set_headers = data;
  //           updateResponseHeaders(headers);
  //         }}
  //         addLabel={t("form.setHeader")}
  //       />
  //       <FormTwoInputFields
  //         id={`${id}-add-headers`}
  //         divide={":"}
  //         values={responseHeaders.add_headers as string[]}
  //         label={t("form.headerName")}
  //         valueLabel={t("form.headerValue")}
  //         onUpdate={(data) => {
  //           const headers = Object.assign({}, responseHeaders);
  //           headers.add_headers = data;
  //           updateResponseHeaders(headers);
  //         }}
  //         addLabel={t("form.header")}
  //       />
  //       <TextField
  //         id={`${id}-remove-headers`}
  //         label={t("form.removeHeader")}
  //         variant="outlined"
  //         defaultValue={responseHeaders.remove_headers.join(" ") || ""}
  //         sx={{ ml: 1, flex: 1 }}
  //         style={{
  //           marginLeft: "0px",
  //         }}
  //         onChange={(e) => {
  //           const value = e.target.value.trim();
  //           const headers = Object.assign({}, responseHeaders);
  //           headers.remove_headers = value.split(" ");
  //           updateResponseHeaders(headers);
  //         }}
  //       />
  //     </Stack>
  //   );
  // }
  // const items = fields.map((item, index) => {
  //   if (item.options) {
  //     return (
  //       <Box
  //         key={`${key}-${index}`}
  //         id={`${key}-${index}`}
  //         sx={{ ml: 1, flex: 1 }}
  //         style={{
  //           marginLeft: `${index * 15}px`,
  //         }}
  //       >
  //         <FormControl fullWidth={true}>
  //           <FormSelectField
  //             label={item.label}
  //             options={item.options as string[]}
  //             value={newValues[index] || ""}
  //             onUpdate={(value) => {
  //               const arr = newValues.slice(0);
  //               arr[index] = value;
  //               onUpdate(arr.join(padding));
  //               setNewValues(arr);
  //             }}
  //           />
  //         </FormControl>
  //       </Box>
  //     );
  //   }
  //   return (
  //     <TextField
  //       key={`${key}-${index}`}
  //       id={`${key}-${index}`}
  //       label={item.label}
  //       variant="outlined"
  //       defaultValue={newValues[index] || ""}
  //       sx={{ ml: 1, flex: 1 }}
  //       style={{
  //         marginLeft: `${index * 15}px`,
  //       }}
  //       onChange={(e) => {
  //         const value = e.target.value.trim();
  //         const arr = newValues.slice(0);
  //         arr[index] = value;
  //         onUpdate(arr.join(padding));
  //         setNewValues(arr);
  //       }}
  //     />
  //   );
  // });

  // const list = (
  //   <Paper
  //     sx={{
  //       display: "flex",
  //       marginBottom: "15px",
  //       alignItems: "center",
  //       width: "100%",
  //     }}
  //   >
  //     {items}
  //   </Paper>
  // );

  // return <React.Fragment>{list}</React.Fragment>;
}
