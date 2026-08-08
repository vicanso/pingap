import { LoadingPage } from "@/components/loading";
import useBasicState from "@/states/basic";
import useConfigState, { getLocationWeight, Server } from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { sortIntoSections } from "@/components/ex-form-sections";
import { z } from "zod";
import { useI18n } from "@/i18n";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";
import { newZodDuration, omitEmptyArrayString } from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import History from "@/pages/History";
import { EntityBadge } from "@/components/config-entity-badge";
import { PageShell } from "@/components/page-shell";
import { ConfigEntityList, EntityText } from "@/components/config-entity-list";
import { SERVERS } from "@/routers";

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
    basic: serverI18n("sectionBasic"),
    logging: serverI18n("sectionLogging"),
    tls: serverI18n("sectionTls"),
    connection: serverI18n("sectionConnection"),
    tcp: serverI18n("sectionTcp"),
  };

  const newServer = "*";
  const servers = Object.keys(config.servers || {});
  servers.sort();

  // No `name` in the url means the category overview, `*` means the create form.
  const currentServer = searchParams.get("name") || "";

  if (!initialized) {
    return <LoadingPage />;
  }

  if (!currentServer) {
    return (
      <ConfigEntityList<Server>
        title={serverI18n("title")}
        summary={serverI18n("summary", { count: servers.length })}
        nameLabel={serverI18n("name")}
        addLabel={serverI18n("add")}
        emptyText={serverI18n("empty")}
        basePath={SERVERS}
        newValue={newServer}
        names={servers}
        values={config.servers || {}}
        columns={[
          {
            key: "addr",
            label: serverI18n("addr"),
            render: (value) => <EntityText value={value?.addr} />,
          },
          {
            key: "locations",
            label: serverI18n("locations"),
            render: (value) => (
              <EntityText value={(value?.locations || []).join(", ")} />
            ),
          },
          {
            key: "threads",
            label: serverI18n("threads"),
            render: (value) => <EntityText value={value?.threads} />,
          },
        ]}
      />
    );
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
    searchParams.set("name", name);
    setSearchParams(searchParams);
  };

  const backToList = () => {
    searchParams.delete("name");
    setSearchParams(searchParams);
  };

  const serverConfig = getServerConfig(currentServer, config.servers);
  const items: ExFormItem[] = [
    {
      name: "addr",
      section: sec.basic,
      label: serverI18n("addr"),
      placeholder: serverI18n("addrPlaceholder"),
      defaultValue: serverConfig.addr,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "locations",
      section: sec.basic,
      label: serverI18n("locations"),
      placeholder: serverI18n("locationsPlaceholder"),
      span: 3,
      defaultValue: serverConfig.locations,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(locations, false),
    },
    {
      name: "threads",
      section: sec.basic,
      label: serverI18n("threads"),
      placeholder: serverI18n("threadsPlaceholder"),
      defaultValue: serverConfig.threads,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "global_certificates",
      section: sec.tls,
      label: serverI18n("globalCertificates"),
      placeholder: "",
      defaultValue: serverConfig.global_certificates,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "access_log",
      section: sec.logging,
      label: serverI18n("accessLog"),
      placeholder: serverI18n("accessLogPlaceholder"),
      defaultValue: serverConfig.access_log,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "enabled_h2",
      section: sec.connection,
      label: serverI18n("enabledH2"),
      placeholder: "",
      defaultValue: serverConfig.enabled_h2,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "enable_server_timing",
      section: sec.logging,
      label: serverI18n("enabledServerTiming"),
      placeholder: "",
      defaultValue: serverConfig.enable_server_timing,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "downstream_read_timeout",
      section: sec.connection,
      label: serverI18n("downstreamReadTimeout"),
      placeholder: serverI18n("downstreamReadTimeoutPlaceholder"),
      defaultValue: serverConfig.downstream_read_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "downstream_write_timeout",
      section: sec.connection,
      label: serverI18n("downstreamWriteTimeout"),
      placeholder: serverI18n("downstreamWriteTimeoutPlaceholder"),
      defaultValue: serverConfig.downstream_write_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "reuse_port",
      section: sec.connection,
      label: serverI18n("reusePort"),
      placeholder: "",
      defaultValue: serverConfig.reuse_port,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "modules",
      section: sec.basic,
      label: serverI18n("modules"),
      placeholder: serverI18n("modulesPlaceholder"),
      defaultValue: serverConfig.modules,
      span: 3,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(["grpc-web"], false),
    },
    {
      name: "includes",
      section: sec.basic,
      label: i18n("includes"),
      placeholder: i18n("includesPlaceholder"),
      defaultValue: serverConfig.includes,
      span: 6,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(getIncludeOptions(), false),
    },
    {
      name: "tls_cipher_list",
      section: sec.tls,
      label: serverI18n("tlsCipherList"),
      placeholder: serverI18n("tlsCipherListPlaceholder"),
      defaultValue: serverConfig.tls_cipher_list,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tls_ciphersuites",
      section: sec.tls,
      label: serverI18n("tlsCiphersuites"),
      placeholder: serverI18n("tlsCiphersuitesPlaceholder"),
      defaultValue: serverConfig.tls_ciphersuites,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tls_min_version",
      section: sec.tls,
      label: serverI18n("tlsMinVersion"),
      placeholder: "",
      defaultValue: serverConfig.tls_min_version,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["tlsv1.1", "tlsv1.2", "tlsv1.3"], false),
    },
    {
      name: "tls_max_version",
      section: sec.tls,
      label: serverI18n("tlsMaxVersion"),
      placeholder: "",
      defaultValue: serverConfig.tls_max_version,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["tlsv1.1", "tlsv1.2", "tlsv1.3"], false),
    },
    {
      name: "tcp_fastopen",
      section: sec.tcp,
      label: serverI18n("tcpFastOpen"),
      placeholder: serverI18n("tcpFastOpenPlaceholder"),
      defaultValue: serverConfig.tcp_fastopen,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "tcp_user_timeout",
      section: sec.tcp,
      label: serverI18n("tcpUserTimeout"),
      placeholder: serverI18n("tcpUserTimeoutPlaceholder"),
      defaultValue: serverConfig.tcp_user_timeout,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_idle",
      section: sec.tcp,
      label: serverI18n("tcpIdle"),
      placeholder: serverI18n("tcpIdlePlaceholder"),
      defaultValue: serverConfig.tcp_idle,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_interval",
      section: sec.tcp,
      label: serverI18n("tcpInterval"),
      placeholder: serverI18n("tcpIntervalPlaceholder"),
      defaultValue: serverConfig.tcp_interval,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "tcp_probe_count",
      section: sec.tcp,
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
        section: sec.logging,
        label: serverI18n("prometheusMetrics"),
        placeholder: serverI18n("prometheusMetricsPlaceholder"),
        defaultValue: serverConfig.prometheus_metrics,
        span: 6,
        category: ExFormItemCategory.TEXT,
      },
      {
        name: "otlp_exporter",
        section: sec.logging,
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
    section: sec.basic,
    label: serverI18n("remark"),
    placeholder: "",
    defaultValue: serverConfig.remark,
    span: 6,
    category: ExFormItemCategory.TEXTAREA,
  });
  if (currentServer === newServer) {
    items.unshift({
      name: "name",
      section: sec.basic,
      label: serverI18n("name"),
      placeholder: serverI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const defaultShow = sortIntoSections(
    items,
    [sec.basic, sec.logging, sec.tls, sec.connection, sec.tcp],
    [sec.basic, sec.logging],
  );

  const schema = z.object({
    addr: z.string().min(1),
    tcp_idle: newZodDuration().optional(),
    tcp_interval: newZodDuration().optional(),
  });

  const onRemove = async () => {
    return remove("server", currentServer).then(() => {
      backToList();
    });
  };

  return (
    <PageShell
      title={serverI18n("title")}
      description={serverI18n("description")}
      width="narrow"
      backTo={SERVERS}
      backLabel={i18n("backToList")}
      badge={
        <EntityBadge name={currentServer} isNew={currentServer === newServer} />
      }
      actions={
        currentServer !== newServer ? (
          <History
            category="server"
            name={currentServer}
            onRestore={async (data) => {
              await update("server", currentServer, data);
            }}
          />
        ) : undefined
      }
    >
      <ExForm
        category="server"
        key={`${currentServer}-${version}`}
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
    </PageShell>
  );
}
