import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";

import Loading from "../components/loading";
import FormEditor, {
  FormItem,
  FormItemCategory,
  ProxyPluginCategory,
} from "../components/form-editor";

export default function ProxyPluginInfo() {
  const [initialized, config, update] = useConfigStore((state) => [
    state.initialized,
    state.data,
    state.update,
  ]);
  const { name } = useParams();
  if (!initialized) {
    return <Loading />;
  }
  let created = false;
  let pluginName = name;
  if (name == "*") {
    created = true;
    pluginName = "";
  }
  const proxyPlugins = config.proxy_plugins || {};
  const proxyPlugin = proxyPlugins[pluginName || ""] || {};
  const currentNames = Object.keys(proxyPlugins);

  const arr: FormItem[] = [
    {
      id: "category",
      label: "Proxy Plugin Category",
      defaultValue: proxyPlugin.category,
      category: FormItemCategory.CHECKBOX,
      span: 12,
      options: [
        {
          label: "Stats",
          option: 0,
          value: ProxyPluginCategory.STATS,
        },
        {
          label: "Limit",
          option: 1,
          value: ProxyPluginCategory.LIMIT,
        },
        {
          label: "Compression",
          option: 2,
          value: ProxyPluginCategory.COMPRESSION,
        },
        {
          label: "Admin",
          option: 3,
          value: ProxyPluginCategory.ADMIN,
        },
        {
          label: "Directory",
          option: 4,
          value: ProxyPluginCategory.DIRECTORY,
        },
        {
          label: "Mock",
          option: 5,
          value: ProxyPluginCategory.MOCK,
        },
      ],
    },
    {
      id: "value",
      label: "Proxy Plugin Config",
      defaultValue: proxyPlugin.value,
      category: FormItemCategory.PROXY_PLUGIN,
      span: 12,
    },
    {
      id: "remark",
      label: "Remark",
      defaultValue: proxyPlugin.remark,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
  ];

  const onUpsert = async (newName: string, data: Record<string, unknown>) => {
    let pluginName = name || "";
    if (created) {
      pluginName = newName;
    }
    if (!data.category) {
      data.category = ProxyPluginCategory.STATS;
    }

    return update("proxy_plugin", pluginName, data);
  };
  return (
    <FormEditor
      key={name}
      title="Modify proxy plugin configuration"
      description="Change the proxy plugin configuration"
      items={arr}
      onUpsert={onUpsert}
      created={created}
      currentNames={currentNames}
    />
  );
}
