import { LoadingPage } from "@/components/loading";
import useConfigState, { Stream } from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { sortIntoSections } from "@/components/ex-form-sections";
import { z } from "zod";
import { useI18n } from "@/i18n";
import {
  ExFormItemCategory,
  newBooleanOptions,
  newStringOptions,
} from "@/constants";
import { newZodDuration, omitEmptyArrayString } from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import History from "@/pages/History";
import { EntityBadge } from "@/components/config-entity-badge";
import { PageShell } from "@/components/page-shell";
import { ConfigEntityList, EntityText } from "@/components/config-entity-list";
import { ConfigEntitySummary } from "@/components/config-entity-summary";
import { STREAMS } from "@/routers";

function getStreamConfig(
  name: string,
  streams?: Record<string, Stream>,
): Stream {
  if (!streams) {
    return {} as Stream;
  }
  return streams[name] || ({} as Stream);
}

function parseSniRoutesList(values: string[]): Record<string, string> {
  const routes: Record<string, string> = {};
  for (const row of values) {
    const idx = row.indexOf("=");
    if (idx <= 0) {
      continue;
    }
    const host = row.slice(0, idx).trim();
    const upstream = row.slice(idx + 1).trim();
    if (host && upstream) {
      routes[host] = upstream;
    }
  }
  return routes;
}

export default function Streams() {
  const streamI18n = useI18n("stream");
  const i18n = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, version, update, remove, getIncludeOptions] =
    useConfigState(
      useShallow((state) => [
        state.data,
        state.initialized,
        state.version,
        state.update,
        state.remove,
        state.getIncludeOptions,
      ]),
    );

  if (!initialized) {
    return <LoadingPage />;
  }

  const newStream = "*";
  const streamNames = Object.keys(config.streams || {});
  streamNames.sort();
  const currentStream = searchParams.get("name") || "";

  if (!currentStream) {
    const values = config.streams || {};
    const hasThreads = streamNames.some(
      (name) => values[name]?.threads != null,
    );
    return (
      <ConfigEntityList
        title={streamI18n("title")}
        summary={streamI18n("summary", { count: streamNames.length })}
        nameLabel={streamI18n("stream")}
        addLabel={streamI18n("add")}
        emptyText={streamI18n("empty")}
        basePath={STREAMS}
        newValue={newStream}
        names={streamNames}
        values={values}
        columns={[
          {
            key: "addr",
            label: streamI18n("addr"),
            render: (value) => <EntityText value={value?.addr} />,
          },
          {
            key: "upstream",
            label: streamI18n("upstream"),
            render: (value) => <EntityText value={value?.upstream} />,
          },
          {
            key: "sni_routes",
            label: streamI18n("sniRoutes"),
            render: (value) => {
              const rules = Object.entries(value?.sni_routes || {}).map(
                ([host, up]) => `${host}=${up}`,
              );
              return <EntityText value={rules.join(", ")} />;
            },
          },
          ...(hasThreads
            ? [
                {
                  key: "threads",
                  label: streamI18n("threads"),
                  render: (value: Stream | undefined) => (
                    <EntityText value={value?.threads} />
                  ),
                },
              ]
            : []),
        ]}
      />
    );
  }

  const handleSelectStream = (name: string) => {
    searchParams.set("name", name);
    setSearchParams(searchParams);
  };

  const backToList = () => {
    searchParams.delete("name");
    setSearchParams(searchParams);
  };

  const sec = {
    basic: streamI18n("sectionBasic"),
    routing: streamI18n("sectionRouting"),
    limits: streamI18n("sectionLimits"),
    tcp: streamI18n("sectionTcp"),
  };

  const upstreams = Object.keys(config.upstreams || {}).sort();
  const streamConfig = getStreamConfig(currentStream, config.streams);
  const sniRouteEntries = Object.entries(streamConfig.sni_routes || {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([host, upstream]) => `${host}=${upstream}`);

  const items: ExFormItem[] = [
    {
      name: "addr",
      section: sec.basic,
      label: streamI18n("addr"),
      placeholder: streamI18n("addrPlaceholder"),
      tips: streamI18n("addrTips"),
      defaultValue: streamConfig.addr,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "upstream",
      section: sec.routing,
      label: streamI18n("upstream"),
      placeholder: streamI18n("upstreamPlaceholder"),
      tips: streamI18n("upstreamTips"),
      defaultValue: streamConfig.upstream || "",
      span: 3,
      category: ExFormItemCategory.SELECT,
      options: newStringOptions(upstreams, false, true),
    },
    {
      name: "sni_routes",
      section: sec.routing,
      label: streamI18n("sniRoutes"),
      placeholder: streamI18n("sniRoutesPlaceholder"),
      tips: streamI18n("sniRoutesTips"),
      defaultValue: sniRouteEntries,
      separator: "=",
      span: 6,
      category: ExFormItemCategory.KV_LIST,
    },
    {
      name: "proxy_protocol",
      section: sec.routing,
      label: streamI18n("proxyProtocol"),
      placeholder: "",
      tips: streamI18n("proxyProtocolTips"),
      defaultValue: streamConfig.proxy_protocol,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "includes",
      section: sec.basic,
      label: i18n("includes"),
      placeholder: i18n("includesPlaceholder"),
      defaultValue: streamConfig.includes,
      span: 6,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(getIncludeOptions(), false),
    },
    {
      name: "connect_timeout",
      section: sec.limits,
      label: streamI18n("connectTimeout"),
      placeholder: streamI18n("connectTimeoutPlaceholder"),
      defaultValue: streamConfig.connect_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "idle_timeout",
      section: sec.limits,
      label: streamI18n("idleTimeout"),
      placeholder: streamI18n("idleTimeoutPlaceholder"),
      defaultValue: streamConfig.idle_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "sni_read_timeout",
      section: sec.limits,
      label: streamI18n("sniReadTimeout"),
      placeholder: streamI18n("sniReadTimeoutPlaceholder"),
      tips: streamI18n("sniReadTimeoutTips"),
      defaultValue: streamConfig.sni_read_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "max_connections",
      section: sec.limits,
      label: streamI18n("maxConnections"),
      placeholder: streamI18n("maxConnectionsPlaceholder"),
      defaultValue: streamConfig.max_connections,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "allow_ips",
      section: sec.limits,
      label: streamI18n("allowIps"),
      placeholder: streamI18n("allowIpsPlaceholder"),
      tips: streamI18n("ipAclTips"),
      defaultValue: streamConfig.allow_ips,
      span: 3,
      category: ExFormItemCategory.TEXTS,
    },
    {
      name: "deny_ips",
      section: sec.limits,
      label: streamI18n("denyIps"),
      placeholder: streamI18n("denyIpsPlaceholder"),
      tips: streamI18n("ipAclTips"),
      defaultValue: streamConfig.deny_ips,
      span: 3,
      category: ExFormItemCategory.TEXTS,
    },
    {
      name: "threads",
      section: sec.tcp,
      label: streamI18n("threads"),
      placeholder: streamI18n("threadsPlaceholder"),
      tips: streamI18n("threadsTips"),
      defaultValue: streamConfig.threads,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "reuse_port",
      section: sec.tcp,
      label: streamI18n("reusePort"),
      placeholder: "",
      defaultValue: streamConfig.reuse_port,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "tcp_fastopen",
      section: sec.tcp,
      label: streamI18n("tcpFastOpen"),
      placeholder: streamI18n("tcpFastOpenPlaceholder"),
      defaultValue: streamConfig.tcp_fastopen,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "tcp_user_timeout",
      section: sec.tcp,
      label: streamI18n("tcpUserTimeout"),
      placeholder: streamI18n("tcpUserTimeoutPlaceholder"),
      defaultValue: streamConfig.tcp_user_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_idle",
      section: sec.tcp,
      label: streamI18n("tcpIdle"),
      placeholder: streamI18n("tcpIdlePlaceholder"),
      defaultValue: streamConfig.tcp_idle,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_interval",
      section: sec.tcp,
      label: streamI18n("tcpInterval"),
      placeholder: streamI18n("tcpIntervalPlaceholder"),
      defaultValue: streamConfig.tcp_interval,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_probe_count",
      section: sec.tcp,
      label: streamI18n("tcpProbeCount"),
      placeholder: streamI18n("tcpProbeCountPlaceholder"),
      defaultValue: streamConfig.tcp_probe_count,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "remark",
      section: sec.basic,
      label: streamI18n("remark"),
      placeholder: "",
      defaultValue: streamConfig.remark,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];

  if (currentStream === newStream) {
    items.unshift({
      name: "name",
      section: sec.basic,
      label: streamI18n("name"),
      placeholder: streamI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const defaultShow = sortIntoSections(
    items,
    [sec.basic, sec.routing, sec.limits, sec.tcp],
    [sec.basic, sec.routing],
  );

  const schema = z.object({
    addr: z.string().min(1),
    connect_timeout: newZodDuration().optional(),
    idle_timeout: newZodDuration().optional(),
    sni_read_timeout: newZodDuration().optional(),
    tcp_idle: newZodDuration().optional(),
    tcp_interval: newZodDuration().optional(),
    tcp_user_timeout: newZodDuration().optional(),
  });

  const onRemove = async () => {
    return remove("stream", currentStream).then(() => {
      backToList();
    });
  };

  return (
    <PageShell
      title={streamI18n("title")}
      description={streamI18n("description")}
      width="narrow"
      backTo={STREAMS}
      backLabel={i18n("backToList")}
      badge={
        <EntityBadge name={currentStream} isNew={currentStream === newStream} />
      }
      actions={
        currentStream !== newStream ? (
          <History
            category="stream"
            name={currentStream}
            onRestore={async (data) => {
              await update("stream", currentStream, data);
            }}
          />
        ) : undefined
      }
    >
      {currentStream !== newStream && (
        <ConfigEntitySummary
          fields={[
            { label: streamI18n("addr"), value: streamConfig.addr, mono: true },
            {
              label: streamI18n("upstream"),
              value: streamConfig.upstream || undefined,
            },
            {
              label: streamI18n("sniRoutes"),
              value:
                sniRouteEntries.length > 0
                  ? sniRouteEntries.join(", ")
                  : undefined,
              mono: true,
            },
            {
              label: streamI18n("threads"),
              value:
                streamConfig.threads === 0
                  ? "auto"
                  : streamConfig.threads != null
                    ? streamConfig.threads
                    : undefined,
            },
          ]}
        />
      )}
      <ExForm
        category="stream"
        key={`${currentStream}-${version}`}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onRemove={currentStream === newStream ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentStream;
          if (name === newStream) {
            name = value["name"] as string;
          }
          const data: Record<string, unknown> = {
            ...(config.streams || {})[currentStream],
            ...value,
          };
          if (Array.isArray(data.sni_routes)) {
            const parsed = parseSniRoutesList(data.sni_routes as string[]);
            data.sni_routes = Object.keys(parsed).length > 0 ? parsed : null;
          }
          if (data.upstream === "") {
            data.upstream = null;
          }
          omitEmptyArrayString(data);
          await update("stream", name, data);
          handleSelectStream(name);
        }}
      />
    </PageShell>
  );
}
