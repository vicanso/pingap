import { LoadingPage } from "@/components/loading";
import { useI18n } from "@/i18n";
import useConfigState, { Upstream } from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { sortIntoSections } from "@/components/ex-form-sections";
import { z } from "zod";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";
import {
  newZodBytes,
  newZodDuration,
  omitEmptyArrayString,
} from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import History from "@/pages/History";
import { EntityBadge } from "@/components/config-entity-badge";
import { PageShell } from "@/components/page-shell";
import { ConfigEntityList, EntityText } from "@/components/config-entity-list";
import { UPSTREAMS } from "@/routers";
import useBasicState from "@/states/basic";
import { cn } from "@/lib/utils";

function getUpstreamConfig(name: string, upstreams?: Record<string, Upstream>) {
  if (!upstreams) {
    return {} as Upstream;
  }
  return (upstreams[name] || {}) as Upstream;
}

export default function Upstreams() {
  const upstreamI18n = useI18n("upstream");
  const i18n = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, update, remove, getIncludeOptions, version] =
    useConfigState(
      useShallow((state) => [
        state.data,
        state.initialized,
        state.update,
        state.remove,
        state.getIncludeOptions,
        state.version,
      ]),
    );
  const [basicInfo] = useBasicState(useShallow((state) => [state.data]));
  const sec = {
    backends: upstreamI18n("sectionBackends"),
    balancing: upstreamI18n("sectionBalancing"),
    timeout: upstreamI18n("sectionTimeout"),
    tls: upstreamI18n("sectionTls"),
    resilience: upstreamI18n("sectionResilience"),
    tcp: upstreamI18n("sectionTcp"),
  };

  const newUpstream = "*";
  const upstreams = Object.keys(config.upstreams || {});
  upstreams.sort();
  // No `name` in the url means the category overview, `*` means the create form.
  const currentUpstream = searchParams.get("name") || "";

  if (!initialized) {
    return <LoadingPage />;
  }

  if (!currentUpstream) {
    return (
      <ConfigEntityList<Upstream>
        title={upstreamI18n("title")}
        summary={upstreamI18n("summary", { count: upstreams.length })}
        nameLabel={upstreamI18n("name")}
        addLabel={upstreamI18n("add")}
        emptyText={upstreamI18n("empty")}
        basePath={UPSTREAMS}
        newValue={newUpstream}
        names={upstreams}
        values={config.upstreams || {}}
        columns={[
          {
            key: "addrs",
            label: upstreamI18n("addrs"),
            render: (value) => (
              <EntityText
                value={(value?.addrs || [])
                  .map((addr) => addr.split(" ")[0])
                  .join(", ")}
              />
            ),
          },
          {
            key: "discovery",
            label: upstreamI18n("discovery"),
            render: (value) => <EntityText value={value?.discovery} />,
          },
          {
            key: "algo",
            label: upstreamI18n("algo"),
            render: (value) => <EntityText value={value?.algo} />,
          },
          {
            key: "healthyStatus",
            label: upstreamI18n("healthyStatus"),
            render: (_value, name) => {
              // Only upstreams have a real runtime status; it comes from the
              // health checker via /basic, not from the config.
              const status = basicInfo.upstream_healthy_status[name];
              if (!status) {
                return <EntityText />;
              }
              return (
                <span
                  className={cn(
                    "tabular-nums",
                    status.healthy === 0 && "text-rose-600 dark:text-rose-400",
                    status.healthy > 0 &&
                      status.healthy < status.total &&
                      "text-amber-600 dark:text-amber-400",
                  )}
                >
                  {status.healthy}/{status.total}
                </span>
              );
            },
          },
        ]}
      />
    );
  }

  const handleSelectUpstream = (name: string) => {
    searchParams.set("name", name);
    setSearchParams(searchParams);
  };

  const backToList = () => {
    searchParams.delete("name");
    setSearchParams(searchParams);
  };

  const upstreamConfig = getUpstreamConfig(currentUpstream, config.upstreams);

  const items: ExFormItem[] = [
    {
      name: "addrs",
      section: sec.backends,
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
      section: sec.backends,
      label: upstreamI18n("discovery"),
      placeholder: upstreamI18n("discoveryPlaceholder"),
      defaultValue: upstreamConfig.discovery,
      span: 3,
      category: ExFormItemCategory.SELECT,
      options: newStringOptions(
        ["static", "dns", "docker", "transparent"],
        true,
        true,
      ),
    },
    {
      name: "update_frequency",
      section: sec.backends,
      label: upstreamI18n("updateFrequency"),
      placeholder: upstreamI18n("updateFrequencyPlaceholder"),
      defaultValue: upstreamConfig.update_frequency,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "dns_server",
      section: sec.backends,
      label: upstreamI18n("dnsServer"),
      placeholder: upstreamI18n("dnsServerPlaceholder"),
      defaultValue: upstreamConfig.dns_server,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "dns_domain",
      section: sec.backends,
      label: upstreamI18n("dnsDomain"),
      placeholder: upstreamI18n("dnsDomainPlaceholder"),
      defaultValue: upstreamConfig.dns_domain,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "dns_search",
      section: sec.backends,
      label: upstreamI18n("dnsSearch"),
      placeholder: upstreamI18n("dnsSearchPlaceholder"),
      defaultValue: upstreamConfig.dns_search,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "includes",
      section: sec.backends,
      label: i18n("includes"),
      placeholder: i18n("includesPlaceholder"),
      defaultValue: upstreamConfig.includes,
      span: 6,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(getIncludeOptions(), false),
    },
    {
      name: "algo",
      section: sec.balancing,
      label: upstreamI18n("algo"),
      placeholder: upstreamI18n("algoPlaceholder"),
      defaultValue: upstreamConfig.algo,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "health_check",
      section: sec.balancing,
      label: upstreamI18n("healthCheck"),
      placeholder: upstreamI18n("healthCheckPlaceholder"),
      defaultValue: upstreamConfig.health_check,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "connection_timeout",
      section: sec.timeout,
      label: upstreamI18n("connectionTimeout"),
      placeholder: upstreamI18n("connectionTimeoutPlaceholder"),
      defaultValue: upstreamConfig.connection_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "total_connection_timeout",
      section: sec.timeout,
      label: upstreamI18n("totalConnectionTimeout"),
      placeholder: upstreamI18n("totalConnectionTimeoutPlaceholder"),
      defaultValue: upstreamConfig.total_connection_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "read_timeout",
      section: sec.timeout,
      label: upstreamI18n("readTimeout"),
      placeholder: upstreamI18n("readTimeoutPlaceholder"),
      defaultValue: upstreamConfig.read_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "write_timeout",
      section: sec.timeout,
      label: upstreamI18n("writeTimeout"),
      placeholder: upstreamI18n("writeTimeoutPlaceholder"),
      defaultValue: upstreamConfig.write_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "idle_timeout",
      section: sec.timeout,
      label: upstreamI18n("idleTimeout"),
      placeholder: upstreamI18n("idleTimeoutPlaceholder"),
      defaultValue: upstreamConfig.idle_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "alpn",
      section: sec.tls,
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
      name: "max_h2_streams",
      section: sec.tls,
      label: upstreamI18n("maxH2Streams"),
      placeholder: upstreamI18n("maxH2StreamsPlaceholder"),
      defaultValue: upstreamConfig.max_h2_streams,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "sni",
      section: sec.tls,
      label: upstreamI18n("sni"),
      placeholder: upstreamI18n("sniPlaceholder"),
      defaultValue: upstreamConfig.sni,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "verify_cert",
      section: sec.tls,
      label: upstreamI18n("verifyCert"),
      placeholder: "",
      defaultValue: upstreamConfig.verify_cert,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "ipv4_only",
      section: sec.tls,
      label: upstreamI18n("ipv4Only"),
      placeholder: "",
      defaultValue: upstreamConfig.ipv4_only,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "enable_tracer",
      section: sec.resilience,
      label: upstreamI18n("enableTracer"),
      placeholder: "",
      defaultValue: upstreamConfig.enable_tracer,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "enable_backend_stats",
      section: sec.resilience,
      label: upstreamI18n("enableBackendStats"),
      placeholder: "",
      defaultValue: upstreamConfig.enable_backend_stats,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "backend_failure_status_code",
      section: sec.resilience,
      label: upstreamI18n("backendFailureStatusCode"),
      placeholder: upstreamI18n("backendFailureStatusCodePlaceholder"),
      defaultValue: upstreamConfig.backend_failure_status_code,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "backend_stats_interval",
      section: sec.resilience,
      label: upstreamI18n("backendStatsInterval"),
      placeholder: upstreamI18n("backendStatsIntervalPlaceholder"),
      defaultValue: upstreamConfig.backend_stats_interval,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "circuit_break_max_consecutive_failures",
      section: sec.resilience,
      label: upstreamI18n("circuitBreakMaxConsecutiveFailures"),
      placeholder: upstreamI18n(
        "circuitBreakMaxConsecutiveFailuresPlaceholder",
      ),
      defaultValue: upstreamConfig.circuit_break_max_consecutive_failures,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "circuit_break_max_failure_percent",
      section: sec.resilience,
      label: upstreamI18n("circuitBreakMaxFailurePercent"),
      placeholder: upstreamI18n("circuitBreakMaxFailurePercentPlaceholder"),
      defaultValue: upstreamConfig.circuit_break_max_failure_percent,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "circuit_break_min_requests_threshold",
      section: sec.resilience,
      label: upstreamI18n("circuitBreakMinRequestsThreshold"),
      placeholder: upstreamI18n("circuitBreakMinRequestsThresholdPlaceholder"),
      defaultValue: upstreamConfig.circuit_break_min_requests_threshold,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "circuit_break_half_open_consecutive_success_threshold",
      section: sec.resilience,
      label: upstreamI18n("circuitBreakHalfOpenConsecutiveSuccessThreshold"),
      placeholder: upstreamI18n(
        "circuitBreakHalfOpenConsecutiveSuccessThresholdPlaceholder",
      ),
      defaultValue:
        upstreamConfig.circuit_break_half_open_consecutive_success_threshold,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "circuit_break_open_duration",
      section: sec.resilience,
      label: upstreamI18n("circuitBreakOpenDuration"),
      placeholder: upstreamI18n("circuitBreakOpenDurationPlaceholder"),
      defaultValue: upstreamConfig.circuit_break_open_duration,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_fast_open",
      section: sec.tcp,
      label: upstreamI18n("tcpFastOpen"),
      placeholder: "",
      defaultValue: upstreamConfig.tcp_fast_open,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "tcp_user_timeout",
      section: sec.tcp,
      label: upstreamI18n("tcpUserTimeout"),
      placeholder: upstreamI18n("tcpUserTimeoutPlaceholder"),
      defaultValue: upstreamConfig.tcp_user_timeout,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_recv_buf",
      section: sec.tcp,
      label: upstreamI18n("tcpRecvBuf"),
      placeholder: upstreamI18n("tcpRecvBufPlaceholder"),
      defaultValue: upstreamConfig.tcp_recv_buf,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_idle",
      section: sec.tcp,
      label: upstreamI18n("tcpIdle"),
      placeholder: upstreamI18n("tcpIdlePlaceholder"),
      defaultValue: upstreamConfig.tcp_idle,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_interval",
      section: sec.tcp,
      label: upstreamI18n("tcpInterval"),
      placeholder: upstreamI18n("tcpIntervalPlaceholder"),
      defaultValue: upstreamConfig.tcp_interval,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_probe_count",
      section: sec.tcp,
      label: upstreamI18n("tcpProbeCount"),
      placeholder: upstreamI18n("tcpProbeCountPlaceholder"),
      defaultValue: upstreamConfig.tcp_probe_count,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "remark",
      section: sec.backends,
      label: upstreamI18n("remark"),
      placeholder: "",
      defaultValue: upstreamConfig.remark,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];
  if (currentUpstream === newUpstream) {
    items.unshift({
      name: "name",
      section: sec.backends,
      label: upstreamI18n("name"),
      placeholder: upstreamI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const defaultShow = sortIntoSections(
    items,
    [
      sec.backends,
      sec.balancing,
      sec.timeout,
      sec.tls,
      sec.resilience,
      sec.tcp,
    ],
    [sec.backends, sec.balancing],
  );

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
      backToList();
    });
  };

  return (
    <PageShell
      title={upstreamI18n("title")}
      description={upstreamI18n("description")}
      width="narrow"
      backTo={UPSTREAMS}
      backLabel={i18n("backToList")}
      badge={
        <EntityBadge
          name={currentUpstream}
          isNew={currentUpstream === newUpstream}
        />
      }
      actions={
        currentUpstream !== newUpstream ? (
          <History
            category="upstream"
            name={currentUpstream}
            onRestore={async (data) => {
              await update("upstream", currentUpstream, data);
            }}
          />
        ) : undefined
      }
    >
      <ExForm
        category="upstream"
        key={`${currentUpstream}-${version}`}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onRemove={currentUpstream === newUpstream ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentUpstream;
          if (name === newUpstream) {
            name = value["name"] as string;
          }
          omitEmptyArrayString(value);
          await update("upstream", name, value);
          handleSelectUpstream(name);
        }}
      />
    </PageShell>
  );
}
