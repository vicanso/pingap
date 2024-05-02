import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";

import Loading from "../components/loading";
import FormEditor, {
  FormItem,
  FormItemCategory,
  ProxyPluginCategory,
} from "../components/form-editor";
import { goToProxyPluginInfo } from "../router";

export default function ProxyPluginInfo() {
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
      id: "step",
      label: "Proxy Exec Step",
      defaultValue: proxyPlugin.step,
      category: FormItemCategory.CHECKBOX,
      span: 6,
      options: [
        {
          label: "Request Filter",
          option: 0,
          value: "request-filter",
        },
        {
          label: "Proxy Upstream Filter",
          option: 1,
          value: "proxy-upstream-filter",
        },
      ],
    },
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
        {
          label: "Request Id",
          option: 6,
          value: ProxyPluginCategory.REQUEST_ID,
        },
        {
          label: "Ip Limit",
          option: 7,
          value: ProxyPluginCategory.IP_LIMIT,
        },
        {
          label: "Key Auth",
          option: 8,
          value: ProxyPluginCategory.KEY_AUTH,
        },
        {
          label: "Basic Auth",
          option: 9,
          value: ProxyPluginCategory.BASIC_AUTH,
        },
        {
          label: "Cache",
          option: 10,
          value: ProxyPluginCategory.CACHE,
        },
        {
          label: "Redirect Https",
          option: 11,
          value: ProxyPluginCategory.REDIRECT_HTTPS,
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

    return update("proxy_plugin", pluginName, data).then(() => {
      if (created) {
        goToProxyPluginInfo(pluginName);
      }
    });
  };
  const onRemove = async () => {
    return remove("proxy_plugin", name || "").then(() => {
      goToProxyPluginInfo("*");
    });
  };
  return (
    <FormEditor
      key={name}
      title="Modify proxy plugin configuration"
      description="Change the proxy plugin configuration"
      items={arr}
      onUpsert={onUpsert}
      onRemove={onRemove}
      created={created}
      currentNames={currentNames}
    />
  );
}
