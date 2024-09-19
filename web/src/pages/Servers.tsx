import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";
import { LoadingPage } from "@/components/loading";
import useConfigState, { getLocationWeight, Server } from "@/states/config";
import {
  ExForm,
  ExFormItem,
  ExFormItemCategory,
  newBooleanOptions,
  newStringOptions,
} from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import React from "react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

function getServerConfig(name: string, servers?: Record<string, Server>) {
  if (!servers) {
    return {} as Server;
  }
  return (servers[name] || {}) as Server;
}

export default function Servers() {
  const serverCurrentKey = "servers.current";
  const serverI18n = useI18n("server");
  const [config, initialized, update] = useConfigState((state) => [
    state.data,
    state.initialized,
    state.update,
  ]);

  const newServer = "*";
  const servers = Object.keys(config.servers || {});
  servers.sort();
  servers.unshift(newServer);

  const [currentServer, setCurrentServer] = React.useState(
    localStorage.getItem(serverCurrentKey) || servers[0],
  );
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

  const triggers = servers.map((item) => {
    let label: string;
    if (item === newServer) {
      label = "New";
    } else {
      label = item;
    }
    return (
      <TabsTrigger key={item} value={item} className="px-6">
        {label}
      </TabsTrigger>
    );
  });

  const handleSelectServer = (name: string) => {
    localStorage.setItem(serverCurrentKey, name);
    setCurrentServer(name);
  };

  const tabs = (
    <Tabs value={currentServer} onValueChange={handleSelectServer}>
      <TabsList className="grid grid-flow-col auto-cols-max">
        {triggers}
      </TabsList>
    </Tabs>
  );
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
      options: newStringOptions(locations),
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
      options: newStringOptions(["tlsv1.1", "tlsv1.2", "tlsv1.3"]),
    },
    {
      name: "tls_max_version",
      label: serverI18n("tlsMaxVersion"),
      placeholder: "",
      defaultValue: serverConfig.tls_max_version,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["tlsv1.1", "tlsv1.2", "tlsv1.3"]),
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
    {
      name: "remark",
      label: serverI18n("remark"),
      placeholder: "",
      defaultValue: serverConfig.remark,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];
  if (currentServer === newServer) {
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
  });

  return (
    <>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          {tabs}
          <div className="p-2" />
          <ExForm
            key={currentServer}
            items={items}
            schema={schema}
            defaultShow={6}
            onSave={async (value) => {
              let name = currentServer;
              if (name === newServer) {
                name = value["name"] as string;
              }
              await update("server", name, value);
              handleSelectServer(name);
            }}
          />
        </div>
      </div>
    </>
  );
}
