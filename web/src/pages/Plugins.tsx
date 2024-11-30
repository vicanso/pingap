import { LoadingPage } from "@/components/loading";
import useConfigState from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import React from "react";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
  PluginCategory,
  getPluginSteps,
} from "@/constants";
import { useSearchParams } from "react-router-dom";
import { useEffect } from "react";
import { useShallow } from "zustand/react/shallow";

function getPluginConfig(
  name: string,
  plugins?: Record<string, Record<string, unknown>>,
) {
  if (!plugins) {
    return {} as Record<string, unknown>;
  }
  return (plugins[name] || {}) as Record<string, unknown>;
}

export default function Plugins() {
  const pluginI18n = useI18n("plugin");
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, update, remove] = useConfigState(
    useShallow((state) => [
      state.data,
      state.initialized,
      state.update,
      state.remove,
    ]),
  );

  const newPlugin = "*";
  const plugins = Object.keys(config.plugins || {});
  plugins.sort();
  plugins.unshift(newPlugin);

  const [currentPlugin, setCurrentPlugin] = React.useState(
    searchParams.get("name") || newPlugin,
  );
  const pluginConfig = getPluginConfig(currentPlugin, config.plugins);
  const [currentCategory, setCurrentCategory] = React.useState(
    (pluginConfig.catregory as string) || "",
  );

  useEffect(() => {
    setCurrentPlugin(searchParams.get("name") || newPlugin);
  }, [searchParams]);
  if (!initialized) {
    return <LoadingPage />;
  }

  const handleSelectPlugin = (name: string) => {
    setCurrentPlugin(name);
    const conf = getPluginConfig(name, config.plugins);
    setCurrentCategory(conf.category as string);
    if (name === newPlugin) {
      searchParams.delete("name");
    } else {
      searchParams.set("name", name);
    }
    setSearchParams(searchParams);
  };

  const items: ExFormItem[] = [];
  if (currentPlugin === newPlugin) {
    items.unshift(
      {
        name: "category",
        label: pluginI18n("category"),
        placeholder: "",
        defaultValue: currentCategory,
        category: ExFormItemCategory.RADIOS,
        span: 6,
        options: newStringOptions(
          [
            PluginCategory.STATS,
            PluginCategory.PING,
            PluginCategory.ADMIN,
            PluginCategory.DIRECTORY,
            PluginCategory.MOCK,
            PluginCategory.REDIRECT,
            PluginCategory.CACHE,

            PluginCategory.REQUEST_ID,
            PluginCategory.COMPRESSION,
            PluginCategory.ACCEPT_ENCODING,

            // auth
            PluginCategory.KEY_AUTH,
            PluginCategory.BASIC_AUTH,
            PluginCategory.JWT,
            PluginCategory.COMBINED_AUTH,

            // limit
            PluginCategory.LIMIT,
            PluginCategory.IP_RESTRICTION,
            PluginCategory.UA_RESTRICTION,
            PluginCategory.REFERER_RESTRICTION,
            PluginCategory.CSRF,
            PluginCategory.CORS,

            // response
            PluginCategory.RESPONSE_HEADERS,
          ],
          true,
        ),
      },
      {
        name: "_name_",
        label: pluginI18n("name"),
        placeholder: pluginI18n("namePlaceholder"),
        defaultValue: "",
        span: 6,
        category: ExFormItemCategory.TEXT,
      },
    );
  } else {
    items.unshift({
      name: "category",
      label: pluginI18n("category"),
      placeholder: "",
      defaultValue: pluginConfig.category as string,
      category: ExFormItemCategory.LABEL,
      span: 6,
    });
  }
  const category = currentCategory || (pluginConfig.category as string);
  if (category) {
    const options = getPluginSteps(category);
    if (options.length !== 0) {
      items.push({
        name: "step",
        label: pluginI18n("step"),
        placeholder: "",
        defaultValue: (pluginConfig.step as string) || options[0].value,
        category: ExFormItemCategory.RADIOS,
        options,
        span: 6,
      });
    }
  }
  switch (category) {
    case PluginCategory.STATS: {
      items.push({
        name: "path",
        label: pluginI18n("statsPath"),
        placeholder: pluginI18n("statsPathPlaceholder"),
        defaultValue: pluginConfig.path as string,
        span: 6,
        category: ExFormItemCategory.TEXT,
      });
      break;
    }
    case PluginCategory.PING: {
      items.push({
        name: "path",
        label: pluginI18n("pingPath"),
        placeholder: pluginI18n("pingPathPlaceholder"),
        defaultValue: pluginConfig.path as string,
        span: 6,
        category: ExFormItemCategory.TEXT,
      });
      break;
    }
    case PluginCategory.ADMIN: {
      items.push(
        {
          name: "path",
          label: pluginI18n("adminPath"),
          placeholder: pluginI18n("adminPathPlaceholder"),
          defaultValue: (pluginConfig.path || "") as string,
          span: 2,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "max_age",
          label: pluginI18n("adminMaxAge"),
          placeholder: pluginI18n("adminMaxAgePalceholder"),
          defaultValue: (pluginConfig.max_age || "") as string,
          span: 2,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "ip_fail_limit",
          label: pluginI18n("adminIpFailLimit"),
          placeholder: pluginI18n("adminIpFailLimitPlaceholder"),
          defaultValue: Number(pluginConfig.ip_fail_limit || 0),
          span: 2,
          category: ExFormItemCategory.NUMBER,
        },
        {
          name: "authorizations",
          label: pluginI18n("adminAuthorization"),
          placeholder: pluginI18n("adminAuthorizationPlaceholder"),
          defaultValue: (pluginConfig.authorizations || []) as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
      );
      break;
    }
    case PluginCategory.DIRECTORY: {
      items.push(
        {
          name: "path",
          label: pluginI18n("dirPath"),
          placeholder: pluginI18n("dirPathPlaceholder"),
          defaultValue: pluginConfig.path as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "index",
          label: pluginI18n("dirIndex"),
          placeholder: pluginI18n("dirIndexPlaceholder"),
          defaultValue: pluginConfig.index as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "chunk_size",
          label: pluginI18n("dirChunkSize"),
          placeholder: pluginI18n("dirChunkSizePlaceholder"),
          defaultValue: pluginConfig.chunk_size as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "autoindex",
          label: pluginI18n("dirAutoIndex"),
          placeholder: "",
          defaultValue: pluginConfig.autoindex as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
        {
          name: "max_age",
          label: pluginI18n("dirMaxAge"),
          placeholder: pluginI18n("dirMaxAgePlaceholder"),
          defaultValue: pluginConfig.max_age as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "private",
          label: pluginI18n("dirCachePrivate"),
          placeholder: "",
          defaultValue: pluginConfig.private as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
        {
          name: "charset",
          label: pluginI18n("dirCharset"),
          placeholder: pluginI18n("dirCharsetPlaceholder"),
          defaultValue: pluginConfig.charset as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "download",
          label: pluginI18n("dirDownload"),
          placeholder: "",
          defaultValue: pluginConfig.download as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
        {
          name: "headers",
          label: pluginI18n("dirHeaderName"),
          placeholder: pluginI18n("dirHeaderNamePlaceholder"),
          defaultValue: pluginConfig.headers as string[],
          span: 6,
          category: ExFormItemCategory.KV_LIST,
        },
      );
      break;
    }
    case PluginCategory.MOCK: {
      items.push(
        {
          name: "path",
          label: pluginI18n("mockPath"),
          placeholder: pluginI18n("mockPathPlaceholder"),
          defaultValue: pluginConfig.path as string,
          span: 2,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "status",
          label: pluginI18n("mockStatus"),
          placeholder: pluginI18n("mockStatusPlaceholder"),
          defaultValue: pluginConfig.status as number,
          span: 2,
          category: ExFormItemCategory.NUMBER,
        },
        {
          name: "delay",
          label: pluginI18n("mockResponseDelay"),
          placeholder: pluginI18n("mockResponseDelayPlaceholder"),
          defaultValue: pluginConfig.delay as string,
          span: 2,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "headers",
          label: pluginI18n("mockHeaderName"),
          placeholder: pluginI18n("mockHeaderNamePlaceholder"),
          defaultValue: pluginConfig.headers as string[],
          span: 6,
          category: ExFormItemCategory.KV_LIST,
        },
        {
          name: "data",
          label: pluginI18n("mockData"),
          placeholder: pluginI18n("mockDataPlaceholder"),
          defaultValue: pluginConfig.data as string,
          span: 6,
          category: ExFormItemCategory.TEXTAREA,
          rows: 5,
        },
      );
      break;
    }
    case PluginCategory.REDIRECT: {
      items.push(
        {
          name: "prefix",
          label: pluginI18n("redirectPrefix"),
          placeholder: pluginI18n("redirectPrefixPlaceholder"),
          defaultValue: pluginConfig.prefix as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "http_to_https",
          label: pluginI18n("redirectHttps"),
          placeholder: "",
          defaultValue: pluginConfig.http_to_https as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
      );
      break;
    }
    case PluginCategory.CACHE: {
      items.push(
        {
          name: "lock",
          label: pluginI18n("cacheLock"),
          placeholder: pluginI18n("cacheLockPlaceholder"),
          defaultValue: pluginConfig.lock as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "max_file_size",
          label: pluginI18n("cacheMaxFileSize"),
          placeholder: pluginI18n("cacheMaxFileSizePlaceholder"),
          defaultValue: pluginConfig.max_file_size as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "namespace",
          label: pluginI18n("cacheNamespace"),
          placeholder: pluginI18n("cacheNamespacePlaceholder"),
          defaultValue: pluginConfig.namespace as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "max_ttl",
          label: pluginI18n("cacheMaxTtl"),
          placeholder: pluginI18n("cacheMaxTtlPlaceholder"),
          defaultValue: pluginConfig.max_ttl as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "eviction",
          label: pluginI18n("cacheEviction"),
          placeholder: "",
          defaultValue: pluginConfig.eviction as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
        {
          name: "predictor",
          label: pluginI18n("cachePredictor"),
          placeholder: "",
          defaultValue: pluginConfig.predictor as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
        {
          name: "skip",
          label: pluginI18n("cacheSkip"),
          placeholder: pluginI18n("cacheSkipPlaceholder"),
          defaultValue: pluginConfig.skip as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "check_cache_control",
          label: pluginI18n("checkCacheControl"),
          placeholder: "",
          defaultValue: pluginConfig.check_cache_control as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
        {
          name: "headers",
          label: pluginI18n("cacheHeaders"),
          placeholder: pluginI18n("cacheHeadersPlaceholder"),
          defaultValue: pluginConfig.headers as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
        {
          name: "purge_ip_list",
          label: pluginI18n("cachePurgeIpList"),
          placeholder: pluginI18n("cachePurgeIpListPlaceholder"),
          defaultValue: pluginConfig.purge_ip_list as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
      );
      break;
    }
    case PluginCategory.REQUEST_ID: {
      items.push(
        {
          name: "algorithm",
          label: pluginI18n("requestIdAlgo"),
          placeholder: pluginI18n("requestIdAlgoPlaceholder"),
          defaultValue: pluginConfig.algorithm as string,
          span: 2,
          category: ExFormItemCategory.RADIOS,
          options: newStringOptions(["uuid", "nanoid"], false),
        },
        {
          name: "size",
          label: pluginI18n("requestIdLength"),
          placeholder: pluginI18n("requestIdLengthPlaceholder"),
          defaultValue: pluginConfig.size as number,
          span: 2,
          category: ExFormItemCategory.NUMBER,
        },
        {
          name: "header_name",
          label: pluginI18n("requestIdHeaderName"),
          placeholder: pluginI18n("requestIdHeaderNamePlaceholder"),
          defaultValue: pluginConfig.header_name as string,
          span: 2,
          category: ExFormItemCategory.TEXT,
        },
      );
      break;
    }
    case PluginCategory.COMPRESSION: {
      items.push(
        {
          name: "gzip_level",
          label: pluginI18n("compressionGzipLevel"),
          placeholder: pluginI18n("compressionGzipLevelPlaceholder"),
          defaultValue: pluginConfig.gzip_level as number,
          span: 2,
          category: ExFormItemCategory.NUMBER,
        },
        {
          name: "br_level",
          label: pluginI18n("compressionBrLevel"),
          placeholder: pluginI18n("compressionBrLevelPlaceholder"),
          defaultValue: pluginConfig.br_level as number,
          span: 2,
          category: ExFormItemCategory.NUMBER,
        },
        {
          name: "zstd_level",
          label: pluginI18n("compressionZstdLevel"),
          placeholder: pluginI18n("compressionZstdLevelPlaceholder"),
          defaultValue: pluginConfig.zstd_level as number,
          span: 2,
          category: ExFormItemCategory.NUMBER,
        },
        {
          name: "decompression",
          label: pluginI18n("compressionDecompression"),
          placeholder: "",
          defaultValue: pluginConfig.decompression as boolean,
          span: 6,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
      );
      break;
    }
    case PluginCategory.ACCEPT_ENCODING: {
      items.push(
        {
          name: "encodings",
          label: pluginI18n("acceptEncodingList"),
          placeholder: pluginI18n("acceptEncodingListPlaceholder"),
          defaultValue: pluginConfig.encodings as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "only_one_encoding",
          label: pluginI18n("acceptEncodingOnlyOne"),
          placeholder: "",
          defaultValue: pluginConfig.only_one_encoding as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
      );
      break;
    }
    case PluginCategory.KEY_AUTH: {
      items.push(
        {
          name: "query",
          label: pluginI18n("keyAuthQuery"),
          placeholder: pluginI18n("keyAuthQueryPlaceholder"),
          defaultValue: pluginConfig.query as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "header",
          label: pluginI18n("keyAuthHeader"),
          placeholder: pluginI18n("keyAuthHeaderPlaceholder"),
          defaultValue: pluginConfig.header as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "delay",
          label: pluginI18n("keyAuthFailDelay"),
          placeholder: pluginI18n("keyAuthFailDelayPlaceholder"),
          defaultValue: pluginConfig.delay as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "hide_credentials",
          label: pluginI18n("keyAuthHideCredentials"),
          placeholder: pluginI18n("keyAuthHideCredentialsPlaceholder"),
          defaultValue: pluginConfig.hide_credentials as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
        {
          name: "keys",
          label: pluginI18n("keyAuthValues"),
          placeholder: pluginI18n("keyAuthValuesPlaceholder"),
          defaultValue: pluginConfig.keys as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
      );
      break;
    }
    case PluginCategory.BASIC_AUTH: {
      items.push(
        {
          name: "authorizations",
          label: pluginI18n("basicAuthList"),
          placeholder: pluginI18n("basicAuthListPlaceholder"),
          defaultValue: pluginConfig.authorizations as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
        {
          name: "delay",
          label: pluginI18n("basicAuthFailDelay"),
          placeholder: pluginI18n("basicAuthFailDelayPlaceholder"),
          defaultValue: pluginConfig.delay as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "hide_credentials",
          label: pluginI18n("basicAuthHideCredentials"),
          placeholder: pluginI18n("basicAuthHideCredentialsPlaceholder"),
          defaultValue: pluginConfig.hide_credentials as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
      );
      break;
    }
    case PluginCategory.JWT: {
      items.push(
        {
          name: "header",
          label: pluginI18n("jwtAuthHeader"),
          placeholder: pluginI18n("jwtAuthHeaderPlaceholder"),
          defaultValue: pluginConfig.header as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "query",
          label: pluginI18n("jwtAuthQuery"),
          placeholder: pluginI18n("jwtAuthQueryPlaceholder"),
          defaultValue: pluginConfig.query as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "cookie",
          label: pluginI18n("jwtAuthCookie"),
          placeholder: pluginI18n("jwtAuthCookiePlaceholder"),
          defaultValue: pluginConfig.cookie as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "auth_path",
          label: pluginI18n("jwtSignPath"),
          placeholder: pluginI18n("jwtSignPathPlaceholder"),
          defaultValue: pluginConfig.auth_path as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "delay",
          label: pluginI18n("jwtAuthFailDelay"),
          placeholder: pluginI18n("jwtAuthFailDelayPlaceholder"),
          defaultValue: pluginConfig.delay as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "algorithm",
          label: pluginI18n("jwtSignAlgorithm"),
          placeholder: "",
          defaultValue: pluginConfig.algorithm as string,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newStringOptions(["HS256", "HS512"], false),
        },
        {
          name: "secret",
          label: pluginI18n("jwtAuthSecret"),
          placeholder: pluginI18n("jwtAuthSecretPlaceholder"),
          defaultValue: pluginConfig.secret as string,
          span: 6,
          category: ExFormItemCategory.TEXT,
        },
      );
      break;
    }
    case PluginCategory.COMBINED_AUTH: {
      items.push({
        name: "authorizations",
        label: pluginI18n("combinedAuthAuthorizations"),
        placeholder: "",
        defaultValue: pluginConfig.authorizations as [],
        span: 6,
        category: ExFormItemCategory.COMBINED_AUTHS,
      });
      break;
    }
    case PluginCategory.LIMIT: {
      items.push(
        {
          name: "type",
          label: pluginI18n("limitCategory"),
          placeholder: "",
          defaultValue: pluginConfig.type as string,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newStringOptions(["rate", "inflight"], true),
        },
        {
          name: "tag",
          label: pluginI18n("limitTag"),
          placeholder: "",
          defaultValue: pluginConfig.tag as string,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newStringOptions(["cookie", "header", "query", "ip"], true),
        },
        {
          name: "key",
          label: pluginI18n("limitKey"),
          placeholder: pluginI18n("limitKeyPlaceholder"),
          defaultValue: pluginConfig.key as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "max",
          label: pluginI18n("limitMax"),
          placeholder: pluginI18n("limitMaxPlaceholder"),
          defaultValue: pluginConfig.max as number,
          span: 3,
          category: ExFormItemCategory.NUMBER,
        },
        {
          name: "interval",
          label: pluginI18n("limitInterval"),
          placeholder: pluginI18n("limitIntervalPlaceholder"),
          defaultValue: pluginConfig.interval as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
      );
      break;
    }
    case PluginCategory.IP_RESTRICTION: {
      items.push(
        {
          name: "type",
          label: pluginI18n("ipRestrictionMode"),
          placeholder: "",
          defaultValue: pluginConfig.type as string,
          span: 6,
          category: ExFormItemCategory.RADIOS,
          options: newStringOptions(["allow", "deny"], true),
        },
        {
          name: "ip_list",
          label: pluginI18n("ipList"),
          placeholder: pluginI18n("ipListPlaceholder"),
          defaultValue: pluginConfig.ip_list as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
        {
          name: "message",
          label: pluginI18n("ipRestrictionMessage"),
          placeholder: pluginI18n("ipRestrictionMessagePlaceholder"),
          defaultValue: pluginConfig.message as string,
          span: 6,
          category: ExFormItemCategory.TEXT,
        },
      );
      break;
    }
    case PluginCategory.REFERER_RESTRICTION: {
      items.push(
        {
          name: "type",
          label: pluginI18n("refererRestrictionMode"),
          placeholder: "",
          defaultValue: pluginConfig.type as string,
          span: 6,
          category: ExFormItemCategory.RADIOS,
          options: newStringOptions(["allow", "deny"], true),
        },
        {
          name: "referer_list",
          label: pluginI18n("refererList"),
          placeholder: pluginI18n("refererListPlaceholder"),
          defaultValue: pluginConfig.referer_list as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
        {
          name: "message",
          label: pluginI18n("refererRestrictionMessage"),
          placeholder: pluginI18n("refererRestrictionMessagePlaceholder"),
          defaultValue: pluginConfig.message as string,
          span: 6,
          category: ExFormItemCategory.TEXT,
        },
      );
      break;
    }
    case PluginCategory.UA_RESTRICTION: {
      items.push(
        {
          name: "type",
          label: pluginI18n("uaRestrictionMode"),
          placeholder: "",
          defaultValue: pluginConfig.type as string,
          span: 6,
          category: ExFormItemCategory.RADIOS,
          options: newStringOptions(["allow", "deny"], true),
        },
        {
          name: "ua_list",
          label: pluginI18n("uaList"),
          placeholder: pluginI18n("uaListPlaceholder"),
          defaultValue: pluginConfig.ua_list as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
        {
          name: "message",
          label: pluginI18n("uaRestrictionMessage"),
          placeholder: pluginI18n("uaRestrictionMessagePlaceholder"),
          defaultValue: pluginConfig.message as string,
          span: 6,
          category: ExFormItemCategory.TEXT,
        },
      );
      break;
    }
    case PluginCategory.CSRF: {
      items.push(
        {
          name: "token_path",
          label: pluginI18n("csrfTokenPath"),
          placeholder: pluginI18n("csrfTokenPathPlaceholder"),
          defaultValue: pluginConfig.token_path as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "name",
          label: pluginI18n("csrfName"),
          placeholder: pluginI18n("csrfNamePlaceholder"),
          defaultValue: pluginConfig.name as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "key",
          label: pluginI18n("csrfKey"),
          placeholder: pluginI18n("csrfKeyPlaceholder"),
          defaultValue: pluginConfig.key as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "ttl",
          label: pluginI18n("csrfTtl"),
          placeholder: pluginI18n("csrfTtlPlaceholder"),
          defaultValue: pluginConfig.ttl as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
      );
      break;
    }
    case PluginCategory.CORS: {
      items.push(
        {
          name: "path",
          label: pluginI18n("corsPath"),
          placeholder: pluginI18n("corsPathPlaceholder"),
          defaultValue: pluginConfig.path as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "allow_origin",
          label: pluginI18n("corsAllowOrigin"),
          placeholder: pluginI18n("corsAllowOriginPlaceholder"),
          defaultValue: pluginConfig.allow_origin as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "allow_methods",
          label: pluginI18n("corsAllowMethods"),
          placeholder: pluginI18n("corsAllowMethodsPlaceholder"),
          defaultValue: pluginConfig.allow_methods as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "allow_headers",
          label: pluginI18n("corsAllowHeaders"),
          placeholder: pluginI18n("corsAllowHeadersPlaceholder"),
          defaultValue: pluginConfig.allow_headers as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "allow_credentials",
          label: pluginI18n("corsAllowCredentials"),
          placeholder: "",
          defaultValue: pluginConfig.allow_credentials as boolean,
          span: 3,
          category: ExFormItemCategory.RADIOS,
          options: newBooleanOptions(),
        },
        {
          name: "max_age",
          label: pluginI18n("corsMaxAge"),
          placeholder: pluginI18n("corsMaxAgePlaceholder"),
          defaultValue: pluginConfig.max_age as string,
          span: 3,
          category: ExFormItemCategory.TEXT,
        },
        {
          name: "expose_headers",
          label: pluginI18n("corsExposeHeaders"),
          placeholder: pluginI18n("corsExposeHeadersPlaceholder"),
          defaultValue: pluginConfig.expose_headers as string,
          span: 6,
          category: ExFormItemCategory.TEXT,
        },
      );
      break;
    }
    case PluginCategory.RESPONSE_HEADERS: {
      items.push(
        {
          name: "add_headers",
          label: pluginI18n("responseHeadersAddHeader"),
          placeholder: pluginI18n("responseHeadersAddHeaderPlaceholder"),
          defaultValue: pluginConfig.add_headers as string[],
          span: 6,
          category: ExFormItemCategory.KV_LIST,
        },
        {
          name: "set_headers",
          label: pluginI18n("responseHeadersSetHeader"),
          placeholder: pluginI18n("responseHeadersSetHeaderPlaceholder"),
          defaultValue: pluginConfig.set_headers as string[],
          span: 6,
          category: ExFormItemCategory.KV_LIST,
        },
        {
          name: "remove_headers",
          label: pluginI18n("responseHeadersRemoveHeader"),
          placeholder: pluginI18n("responseHeadersRemoveHeaderPlaceholder"),
          defaultValue: pluginConfig.remove_headers as string[],
          span: 6,
          category: ExFormItemCategory.TEXTS,
        },
        {
          name: "rename_headers",
          label: pluginI18n("responseHeadersRenameHeader"),
          placeholder: pluginI18n("responseHeadersRenamePlaceholder"),
          defaultValue: pluginConfig.rename_headers as string[],
          span: 6,
          category: ExFormItemCategory.KV_LIST,
        },
      );
      break;
    }
    default: {
      break;
    }
  }
  if (category) {
    items.push({
      name: "remark",
      label: pluginI18n("remark"),
      placeholder: "",
      defaultValue: pluginConfig.remark as string,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    });
  }

  const schema = z.object({
    step: z.string(),
  });
  let key = currentPlugin;
  if (currentPlugin == newPlugin) {
    key = `new-plugin-${category}`;
  }
  const onRemove = async () => {
    return remove("plugin", currentPlugin).then(() => {
      handleSelectPlugin(newPlugin);
    });
  };

  return (
    <div className="grow lg:border-l overflow-auto p-4">
      <ExForm
        category="plugin"
        key={key}
        items={items}
        schema={schema}
        onValueChange={(value) => {
          const category = value.category as string;
          if (category && category !== currentCategory) {
            setCurrentCategory(category);
          }
        }}
        onRemove={currentPlugin === newPlugin ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentPlugin;
          if (name === newPlugin) {
            name = value["_name_"] as string;
          }
          delete value["_name_"];
          await update("plugin", name, value);
          handleSelectPlugin(name);
        }}
      />
    </div>
  );
}
