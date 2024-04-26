import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";

import Loading from "../components/loading";
import FormEditor, {
  FormItem,
  FormItemCategory,
} from "../components/form-editor";

export default function UpstreamInfo() {
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
      label: "Upstream Addrs",
      defaultValue: upstream.addrs,
      span: 12,
      category: FormItemCategory.ADDRS,
    },
    {
      id: "algo",
      label: "Load balancer algorithm",
      defaultValue: upstream.algo,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "health_check",
      label: "Health Check",
      defaultValue: upstream.health_check,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "connection_timeout",
      label: "Connection Timeout",
      defaultValue: upstream.connection_timeout,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "total_connection_timeout",
      label: "Total Connection Timeout",
      defaultValue: upstream.total_connection_timeout,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "read_timeout",
      label: "Read Timeout",
      defaultValue: upstream.read_timeout,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "write_timeout",
      label: "Write Timeout",
      defaultValue: upstream.write_timeout,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "idle_timeout",
      label: "Idle Timeout",
      defaultValue: upstream.idle_timeout,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "alpn",
      label: "Alpn",
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
          label: "http2http2",
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
      label: "Sni",
      defaultValue: upstream.sni,
      span: 4,
      category: FormItemCategory.TEXT,
    },
    {
      id: "verify_cert",
      label: "Verify Cert",
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
      label: "Ipv4 Only",
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
      id: "remark",
      label: "Remark",
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
    return update("upstream", upstreamName, data);
  };
  const onRemove = async () => {
    return remove("upstream", name || "");
  };
  return (
    <FormEditor
      key={name}
      title="Modify upstream configuration"
      description="Change the upstream configuration"
      items={arr}
      onUpsert={onUpsert}
      onRemove={onRemove}
      created={created}
      currentNames={currentNames}
    />
  );
}
