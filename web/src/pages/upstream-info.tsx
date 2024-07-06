import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import Loading from "../components/loading";
import FormEditor from "../components/form-editor";
import { goToUpstreamInfo } from "../router";
import { FormItem, FormItemCategory } from "../components/form-common";

export default function UpstreamInfo() {
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
  let upstreamName = name;
  if (name == "*") {
    created = true;
    upstreamName = "";
  }
  const upstreams = config.upstreams || {};
  const upstream = upstreams[upstreamName || ""] || {};
  const currentNames = Object.keys(upstreams);

  const arr: FormItem[] = [
    {
      id: "addrs",
      label: t("upstream.addrs"),
      defaultValue: upstream.addrs,
      span: 12,
      category: FormItemCategory.ADDRS,
    },
    {
      id: "discovery",
      label: t("upstream.discovery"),
      defaultValue: upstream.discovery,
      span: 6,
      category: FormItemCategory.CHECKBOX,
      options: [
        {
          label: "common",
          option: 1,
          value: "common",
        },
        {
          label: "dns",
          option: 2,
          value: "dns",
        },
        {
          label: "None",
          option: -1,
          value: null,
        },
      ],
    },
    {
      id: "update_frequency",
      label: t("upstream.updateFrequency"),
      defaultValue: upstream.update_frequency,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "algo",
      label: t("upstream.algo"),
      defaultValue: upstream.algo,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "health_check",
      label: t("upstream.healthCheck"),
      defaultValue: upstream.health_check,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "connection_timeout",
      label: t("upstream.connectionTimeout"),
      defaultValue: upstream.connection_timeout,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "total_connection_timeout",
      label: t("upstream.totalConnectionTimeout"),
      defaultValue: upstream.total_connection_timeout,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "read_timeout",
      label: t("upstream.readTimeout"),
      defaultValue: upstream.read_timeout,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "write_timeout",
      label: t("upstream.writeTimeout"),
      defaultValue: upstream.write_timeout,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "idle_timeout",
      label: t("upstream.idleTimeout"),
      defaultValue: upstream.idle_timeout,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "alpn",
      label: t("upstream.alpn"),
      defaultValue: upstream.alpn,
      span: 4,
      category: FormItemCategory.CHECKBOX,
      options: [
        {
          label: "http1",
          option: 1,
          value: "H1",
        },
        {
          label: "http2",
          option: 2,
          value: "H2",
        },
        {
          label: "http2http1",
          option: 3,
          value: "H2H1",
        },
        {
          label: "None",
          option: -1,
          value: null,
        },
      ],
    },
    {
      id: "sni",
      label: t("upstream.sni"),
      defaultValue: upstream.sni,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "verify_cert",
      label: t("upstream.verifyCert"),
      defaultValue: upstream.verify_cert,
      span: 4,
      category: FormItemCategory.CHECKBOX,
      options: [
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
      ],
    },
    {
      id: "ipv4_only",
      label: t("upstream.ipv4Only"),
      defaultValue: upstream.ipv4_only,
      span: 4,
      category: FormItemCategory.CHECKBOX,
      options: [
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
      ],
    },
    {
      id: "enable_tracer",
      label: t("upstream.enableTracer"),
      defaultValue: upstream.enable_tracer,
      span: 4,
      category: FormItemCategory.CHECKBOX,
      options: [
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
      ],
    },
    {
      id: "tcp_fast_open",
      label: t("upstream.tcpFastOpen"),
      defaultValue: upstream.tcp_fast_open,
      span: 4,
      category: FormItemCategory.CHECKBOX,
      options: [
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
      ],
    },
    {
      id: "tcp_recv_buf",
      label: t("upstream.tcpRecvBuf"),
      defaultValue: upstream.tcp_recv_buf,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "tcp_idle",
      label: t("upstream.tcpIdle"),
      defaultValue: upstream.tcp_idle,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "tcp_interval",
      label: t("upstream.tcpInterval"),
      defaultValue: upstream.tcp_interval,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "tcp_probe_count",
      label: t("upstream.tcpProbeCount"),
      defaultValue: upstream.tcp_probe_count,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "remark",
      label: t("upstream.remark"),
      defaultValue: upstream.remark,
      span: 13,
      category: FormItemCategory.TEXTAREA,
    },
  ];

  const onUpsert = async (newName: string, data: Record<string, unknown>) => {
    let upstreamName = name || "";
    if (created) {
      upstreamName = newName;
    }
    return update("upstream", upstreamName, data).then(() => {
      if (created) {
        goToUpstreamInfo(upstreamName);
      }
    });
  };
  const onRemove = async () => {
    return remove("upstream", name || "").then(() => {
      goToUpstreamInfo("*");
    });
  };
  return (
    <FormEditor
      key={name}
      title={t("upstream.title")}
      description={t("upstream.description")}
      items={arr}
      onUpsert={onUpsert}
      onRemove={onRemove}
      created={created}
      currentNames={currentNames}
      hiddenIndex={2}
    />
  );
}
