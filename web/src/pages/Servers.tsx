import { LoadingPage } from "@/components/loading";
import useBasicState from "@/states/basic";
import useConfigState, { getLocationWeight, Server } from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import React from "react";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";
import { newZodDuration, omitEmptyArrayString } from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useEffect } from "react";
import { useShallow } from "zustand/react/shallow";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";

function getServerConfig(name: string, servers?: Record<string, Server>) {
  if (!servers) {
    return {} as Server;
  }
  return (servers[name] || {}) as Server;
}

export default function Servers() {
  const serverI18n = useI18n("server");
  const i18n = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();
  const [config, initialized, update, remove, getIncludeOptions] =
    useConfigState(
      useShallow((state) => [
        state.data,
        state.initialized,
        state.update,
        state.remove,
        state.getIncludeOptions,
      ]),
    );
  const [basicInfo] = useBasicState(useShallow((state) => [state.data]));

  const newServer = "*";
  const servers = Object.keys(config.servers || {});
  servers.sort();
  servers.unshift(newServer);

  const [currentServer, setCurrentServer] = React.useState(
    searchParams.get("name") || newServer,
  );
  useEffect(() => {
    setCurrentServer(searchParams.get("name") || newServer);
  }, [searchParams]);
  if (!initialized) {
    return <LoadingPage />;
  }
  const locations = Object.keys(config.locations || {});
  const getWeight = (name: string) => {
    const lo = (config.locations || {})[name];
    if (lo) {
      return getLocationWeight(lo);
    }
    return -1;
  };
  locations.sort((a, b) => {
    return getWeight(b) - getWeight(a);
  });

  const handleSelectServer = (name: string) => {
    setCurrentServer(name);
    if (name === newServer) {
      searchParams.delete("name");
    } else {
      searchParams.set("name", name);
    }
    setSearchParams(searchParams);
  };

  const serverConfig = getServerConfig(currentServer, config.servers);
  const items: ExFormItem[] = [
    {
      name: "addr",
      label: serverI18n("addr"),
      placeholder: serverI18n("addrPlaceholder"),
      defaultValue: serverConfig.addr,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "locations",
      label: serverI18n("locations"),
      placeholder: serverI18n("locationsPlaceholder"),
      span: 3,
      defaultValue: serverConfig.locations,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(locations, false),
    },
    {
      name: "threads",
      label: serverI18n("threads"),
      placeholder: serverI18n("threadsPlaceholder"),
      defaultValue: serverConfig.threads,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "global_certificates",
      label: serverI18n("globalCertificates"),
      placeholder: "",
      defaultValue: serverConfig.global_certificates,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "access_log",
      label: serverI18n("accessLog"),
      placeholder: serverI18n("accessLogPlaceholder"),
      defaultValue: serverConfig.access_log,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "enabled_h2",
      label: serverI18n("enabledH2"),
      placeholder: "",
      defaultValue: serverConfig.enabled_h2,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "enable_server_timing",
      label: serverI18n("enabledServerTiming"),
      placeholder: "",
      defaultValue: serverConfig.enable_server_timing,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "downstream_read_timeout",
      label: serverI18n("downstreamReadTimeout"),
      placeholder: serverI18n("downstreamReadTimeoutPlaceholder"),
      defaultValue: serverConfig.downstream_read_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "downstream_write_timeout",
      label: serverI18n("downstreamWriteTimeout"),
      placeholder: serverI18n("downstreamWriteTimeoutPlaceholder"),
      defaultValue: serverConfig.downstream_write_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "reuse_port",
      label: serverI18n("reusePort"),
      placeholder: "",
      defaultValue: serverConfig.reuse_port,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "modules",
      label: serverI18n("modules"),
      placeholder: serverI18n("modulesPlaceholder"),
      defaultValue: serverConfig.modules,
      span: 3,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(["grpc-web"], false),
    },
    {
      name: "includes",
      label: i18n("includes"),
      placeholder: i18n("includesPlaceholder"),
      defaultValue: serverConfig.includes,
      span: 6,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(getIncludeOptions(), false),
    },
    {
      name: "tls_cipher_list",
      label: serverI18n("tlsCipherList"),
      placeholder: serverI18n("tlsCipherListPlaceholder"),
      defaultValue: serverConfig.tls_cipher_list,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tls_ciphersuites",
      label: serverI18n("tlsCiphersuites"),
      placeholder: serverI18n("tlsCiphersuitesPlaceholder"),
      defaultValue: serverConfig.tls_ciphersuites,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tls_min_version",
      label: serverI18n("tlsMinVersion"),
      placeholder: "",
      defaultValue: serverConfig.tls_min_version,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["tlsv1.1", "tlsv1.2", "tlsv1.3"], false),
    },
    {
      name: "tls_max_version",
      label: serverI18n("tlsMaxVersion"),
      placeholder: "",
      defaultValue: serverConfig.tls_max_version,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["tlsv1.1", "tlsv1.2", "tlsv1.3"], false),
    },
    {
      name: "tcp_fastopen",
      label: serverI18n("tcpFastOpen"),
      placeholder: serverI18n("tcpFastOpenPlaceholder"),
      defaultValue: serverConfig.tcp_fastopen,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "tcp_user_timeout",
      label: serverI18n("tcpUserTimeout"),
      placeholder: serverI18n("tcpUserTimeoutPlaceholder"),
      defaultValue: serverConfig.tcp_user_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_idle",
      label: serverI18n("tcpIdle"),
      placeholder: serverI18n("tcpIdlePlaceholder"),
      defaultValue: serverConfig.tcp_idle,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_interval",
      label: serverI18n("tcpInterval"),
      placeholder: serverI18n("tcpIntervalPlaceholder"),
      defaultValue: serverConfig.tcp_interval,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_probe_count",
      label: serverI18n("tcpProbeCount"),
      placeholder: serverI18n("tcpProbeCountPlaceholder"),
      defaultValue: serverConfig.tcp_probe_count,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
  ];

  if (basicInfo.features.includes("tracing")) {
    items.push(
      {
        name: "prometheus_metrics",
        label: serverI18n("prometheusMetrics"),
        placeholder: serverI18n("prometheusMetricsPlaceholder"),
        defaultValue: serverConfig.prometheus_metrics,
        span: 6,
        category: ExFormItemCategory.TEXT,
      },
      {
        name: "otlp_exporter",
        label: serverI18n("otlpExporter"),
        placeholder: serverI18n("otlpExporterPlaceholder"),
        defaultValue: serverConfig.otlp_exporter,
        span: 6,
        category: ExFormItemCategory.TEXT,
      },
    );
  }
  items.push({
    name: "remark",
    label: serverI18n("remark"),
    placeholder: "",
    defaultValue: serverConfig.remark,
    span: 6,
    category: ExFormItemCategory.TEXTAREA,
  });
  let defaultShow = 7;
  if (currentServer === newServer) {
    defaultShow++;
    items.unshift({
      name: "name",
      label: serverI18n("name"),
      placeholder: serverI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const schema = z.object({
    addr: z.string().min(1),
    tcp_idle: newZodDuration().optional(),
    tcp_interval: newZodDuration().optional(),
  });

  const onRemove = async () => {
    return remove("server", currentServer).then(() => {
      handleSelectServer(newServer);
    });
  };

  const selectItems = servers.map((server) => {
    let name = server;
    if (name === newServer) {
      name = "new";
    }
    return (
      <SelectItem key={server} value={server}>
        {name}
      </SelectItem>
    );
  });

  return (
    <div className="grow overflow-auto p-4">
      <div className="flex flex-row gap-2 mb-2">
        <Label>{serverI18n("server")}:</Label>
        <Select
          value={currentServer}
          onValueChange={(value) => {
            if (value === newServer) {
              searchParams.delete("name");
            } else {
              searchParams.set("name", value);
            }
            setSearchParams(searchParams);
          }}
        >
          <SelectTrigger className="w-[180px] cursor-pointer">
            <SelectValue placeholder={serverI18n("serverPlaceholder")} />
          </SelectTrigger>
          <SelectContent>{selectItems}</SelectContent>
        </Select>
      </div>
      <ExForm
        category="server"
        key={currentServer}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onRemove={currentServer === newServer ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentServer;
          if (name === newServer) {
            name = value["name"] as string;
          }
          omitEmptyArrayString(value);
          await update("server", name, value);
          handleSelectServer(name);
        }}
      />
    </div>
  );
}
