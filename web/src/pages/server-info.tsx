import useConfigStore, { getLocationWeight } from "../states/config";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";

import Loading from "../components/loading";
import FormEditor from "../components/form-editor";
import { goToServerInfo } from "../router";
import { FormItem, FormItemCategory } from "../components/form-common";

export default function ServerInfo() {
  const { t } = useTranslation();

  const [initialized, config, update, remove] = useConfigStore((state) => [
    state.initialized,
    state.data,
    state.update,
    state.remove,
  ]);
  const { name } = useParams();
  if (!initialized) {
    return <Loading />;
  }
  let created = false;
  let serverName = name;
  if (name == "*") {
    created = true;
    serverName = "";
  }
  const servers = config.servers || {};
  const currentNames = Object.keys(servers);
  const server = servers[serverName || ""] || {};
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

  const arr: FormItem[] = [
    {
      id: "addr",
      label: t("server.addr"),
      defaultValue: server.addr,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "locations",
      label: t("server.locations"),
      defaultValue: server.locations,
      span: 6,
      category: FormItemCategory.LOCATION,
      options: locations,
    },
    {
      id: "threads",
      label: t("server.threads"),
      defaultValue: server.threads,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "tcp_fastopen",
      label: t("server.tcpFastOpen"),
      defaultValue: server.tcp_fastopen,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "tcp_idle",
      label: t("server.tcpIdle"),
      defaultValue: server.tcp_idle,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "tcp_interval",
      label: t("server.tcpInterval"),
      defaultValue: server.tcp_interval,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "tcp_probe_count",
      label: t("server.tcpProbeCount"),
      defaultValue: server.tcp_probe_count,
      span: 4,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "access_log",
      label: t("server.accessLog"),
      defaultValue: server.access_log,
      span: 12,
      category: FormItemCategory.TEXT,
    },

    {
      id: "tls_cert",
      label: t("server.tlsCert"),
      defaultValue: server.tls_cert,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
    {
      id: "tls_key",
      label: t("server.tlsKey"),
      defaultValue: server.tls_key,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
    {
      id: "lets_encrypt",
      label: t("server.letsEncrypt"),
      defaultValue: server.lets_encrypt,
      span: 8,
      category: FormItemCategory.TEXT,
    },
    {
      id: "enabled_h2",
      label: t("server.enabledH2"),
      defaultValue: server.enabled_h2,
      span: 4,
      category: FormItemCategory.CHECKBOX,
      options: [
        {
          label: "Enable",
          option: 1,
          value: true,
        },
        {
          label: "Disable",
          option: 2,
          value: false,
        },
        {
          label: "None",
          option: -1,
          value: null,
        },
      ],
    },
    {
      id: "remark",
      label: t("server.remark"),
      defaultValue: server.remark,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
  ];

  const onUpsert = async (newName: string, data: Record<string, unknown>) => {
    let serverName = name || "";
    if (created) {
      serverName = newName;
    }
    return update("server", serverName, data).then(() => {
      if (created) {
        goToServerInfo(serverName);
      }
    });
  };
  const onRemove = async () => {
    return remove("server", name || "").then(() => {
      goToServerInfo("*");
    });
  };
  return (
    <FormEditor
      key={name}
      title={t("server.title")}
      description={t("server.description")}
      items={arr}
      onUpsert={onUpsert}
      onRemove={onRemove}
      created={created}
      currentNames={currentNames}
    />
  );
}
