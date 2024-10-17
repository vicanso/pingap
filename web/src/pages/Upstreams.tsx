import { LoadingPage } from "@/components/loading";
import { MainSidebar } from "@/components/sidebar-nav";
import { useI18n } from "@/i18n";
import useConfigState, { Upstream } from "@/states/config";
import React from "react";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";
import { formatLabel, newZodBytes, newZodDuration } from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useEffect } from "react";
import { ScrollRestoration } from "react-router-dom";

function getUpstreamConfig(name: string, upstreams?: Record<string, Upstream>) {
  if (!upstreams) {
    return {} as Upstream;
  }
  return (upstreams[name] || {}) as Upstream;
}

export default function Upstreams() {
  const upstreamI18n = useI18n("upstream");
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, update, remove] = useConfigState((state) => [
    state.data,
    state.initialized,
    state.update,
    state.remove,
  ]);
  const newUpstream = "*";
  const upstreams = Object.keys(config.upstreams || {});
  upstreams.sort();
  upstreams.unshift(newUpstream);
  const [currentUpstream, setCurrentUpstream] = React.useState(
    searchParams.get("name") || newUpstream,
  );
  useEffect(() => {
    setCurrentUpstream(searchParams.get("name") || newUpstream);
  }, [searchParams]);
  if (!initialized) {
    return <LoadingPage />;
  }

  const handleSelectUpstream = (name: string) => {
    setCurrentUpstream(name);
    if (name === newUpstream) {
      searchParams.delete("name");
    } else {
      searchParams.set("name", name);
    }
    setSearchParams(searchParams);
  };

  const upstreamConfig = getUpstreamConfig(currentUpstream, config.upstreams);

  const items: ExFormItem[] = [
    {
      name: "addrs",
      label: upstreamI18n("addrs"),
      placeholder: upstreamI18n("addrsPlaceholder"),
      defaultValue: upstreamConfig.addrs,
      span: 6,
      category: ExFormItemCategory.KV_LIST,
      separator: " ",
      cols: [3, 1],
    },
    {
      name: "discovery",
      label: upstreamI18n("discovery"),
      placeholder: upstreamI18n("discoveryPlaceholder"),
      defaultValue: upstreamConfig.discovery,
      span: 3,
      category: ExFormItemCategory.SELECT,
      options: newStringOptions(["common", "dns", "docker"], true),
    },
    {
      name: "update_frequency",
      label: upstreamI18n("updateFrequency"),
      placeholder: upstreamI18n("updateFrequencyPlaceholder"),
      defaultValue: upstreamConfig.update_frequency,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "algo",
      label: upstreamI18n("algo"),
      placeholder: upstreamI18n("algoPlaceholder"),
      defaultValue: upstreamConfig.algo,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "health_check",
      label: upstreamI18n("healthCheck"),
      placeholder: upstreamI18n("healthCheckPlaceholder"),
      defaultValue: upstreamConfig.health_check,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "connection_timeout",
      label: upstreamI18n("connectionTimeout"),
      placeholder: upstreamI18n("connectionTimeoutPlaceholder"),
      defaultValue: upstreamConfig.connection_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "total_connection_timeout",
      label: upstreamI18n("totalConnectionTimeout"),
      placeholder: upstreamI18n("totalConnectionTimeoutPlaceholder"),
      defaultValue: upstreamConfig.total_connection_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "read_timeout",
      label: upstreamI18n("readTimeout"),
      placeholder: upstreamI18n("readTimeoutPlaceholder"),
      defaultValue: upstreamConfig.read_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "write_timeout",
      label: upstreamI18n("writeTimeout"),
      placeholder: upstreamI18n("writeTimeoutPlaceholder"),
      defaultValue: upstreamConfig.write_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "idle_timeout",
      label: upstreamI18n("idleTimeout"),
      placeholder: upstreamI18n("idleTimeoutPlaceholder"),
      defaultValue: upstreamConfig.idle_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "alpn",
      label: upstreamI18n("alpn"),
      placeholder: "",
      defaultValue: upstreamConfig.alpn,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: [
        {
          label: "http1",
          option: "H1",
          value: "H1",
        },
        {
          label: "http2",
          option: "H2",
          value: "H2",
        },
        {
          label: "http2http1",
          option: "H2H1",
          value: "H2H1",
        },
        {
          label: "None",
          option: "",
          value: null,
        },
      ],
    },
    {
      name: "sni",
      label: upstreamI18n("sni"),
      placeholder: upstreamI18n("sniPlaceholder"),
      defaultValue: upstreamConfig.sni,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "verify_cert",
      label: upstreamI18n("verifyCert"),
      placeholder: "",
      defaultValue: upstreamConfig.verify_cert,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "ipv4_only",
      label: upstreamI18n("ipv4Only"),
      placeholder: "",
      defaultValue: upstreamConfig.ipv4_only,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "enable_tracer",
      label: upstreamI18n("enableTracer"),
      placeholder: "",
      defaultValue: upstreamConfig.enable_tracer,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "tcp_fast_open",
      label: upstreamI18n("tcpFastOpen"),
      placeholder: "",
      defaultValue: upstreamConfig.tcp_fast_open,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "tcp_recv_buf",
      label: upstreamI18n("tcpRecvBuf"),
      placeholder: upstreamI18n("tcpRecvBufPlaceholder"),
      defaultValue: upstreamConfig.tcp_recv_buf,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_idle",
      label: upstreamI18n("tcpIdle"),
      placeholder: upstreamI18n("tcpIdlePlaceholder"),
      defaultValue: upstreamConfig.tcp_idle,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_interval",
      label: upstreamI18n("tcpInterval"),
      placeholder: upstreamI18n("tcpIntervalPlaceholder"),
      defaultValue: upstreamConfig.tcp_interval,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_probe_count",
      label: upstreamI18n("tcpProbeCount"),
      placeholder: upstreamI18n("tcpProbeCountPlaceholder"),
      defaultValue: upstreamConfig.tcp_probe_count,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "remark",
      label: upstreamI18n("remark"),
      placeholder: "",
      defaultValue: upstreamConfig.remark,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];
  let defaultShow = 3;
  if (currentUpstream === newUpstream) {
    defaultShow++;
    items.unshift({
      name: "name",
      label: upstreamI18n("name"),
      placeholder: upstreamI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const schema = z.object({
    addrs: z.array(z.string()),
    update_frequency: newZodDuration().optional(),
    connection_timeout: newZodDuration().optional(),
    total_connection_timeout: newZodDuration().optional(),
    read_timeout: newZodDuration().optional(),
    idle_timeout: newZodDuration().optional(),
    write_timeout: newZodDuration().optional(),
    tcp_idle: newZodDuration().optional(),
    tcp_interval: newZodDuration().optional(),
    tcp_recv_buf: newZodBytes().optional(),
  });

  const onRemove = async () => {
    return remove("upstream", currentUpstream).then(() => {
      handleSelectUpstream(newUpstream);
    });
  };

  return (
    <>
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          <h2 className="h-8 mb-1">
            <span className="border-b-2 border-solid p-1 border-[rgb(var(--foreground-rgb))]">
              {formatLabel(currentUpstream)}
            </span>
          </h2>
          <ExForm
            category="upstream"
            key={currentUpstream}
            items={items}
            schema={schema}
            defaultShow={defaultShow}
            onRemove={currentUpstream === newUpstream ? undefined : onRemove}
            onSave={async (value) => {
              let name = currentUpstream;
              if (name === newUpstream) {
                name = value["name"] as string;
              }
              await update("upstream", name, value);
              handleSelectUpstream(name);
            }}
          />
        </div>
      </div>
      <ScrollRestoration />
    </>
  );
}
