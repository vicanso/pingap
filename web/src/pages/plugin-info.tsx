import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";

import Loading from "../components/loading";
import FormEditor from "../components/form-editor";
import { goToPluginInfo } from "../router";
import { FormItem, FormItemCategory } from "../components/form-common";
import { PluginCategory } from "../components/form-plugin";

export default function ProxyPluginInfo() {
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
  let pluginName = name;
  if (name == "*") {
    created = true;
    pluginName = "";
  }
  const proxyPlugins = config.plugins || {};
  const proxyPlugin = proxyPlugins[pluginName || ""] || {};
  const currentNames = Object.keys(proxyPlugins);

  // PluginCategory.CACHE
  const plugins = [
    PluginCategory.STATS,
    PluginCategory.PING,
    PluginCategory.ADMIN,
    PluginCategory.DIRECTORY,
    PluginCategory.MOCK,
    PluginCategory.REDIRECT,

    PluginCategory.REQUEST_ID,
    PluginCategory.COMPRESSION,

    // auth
    PluginCategory.KEY_AUTH,
    PluginCategory.BASIC_AUTH,
    PluginCategory.JWT,

    // limit
    PluginCategory.LIMIT,
    PluginCategory.IP_RESTRICTION,
    PluginCategory.REFERER_RESTRICTION,
    PluginCategory.CSRF,

    // response
    PluginCategory.RESPONSE_HEADERS,
  ];
  const pluginOptions = plugins.map((item, index) => {
    return {
      label: item.toString(),
      option: index,
      value: item,
    };
  });

  const arr: FormItem[] = [
    {
      id: "category",
      label: t("plugin.category"),
      defaultValue: proxyPlugin.category,
      category: FormItemCategory.CHECKBOX,
      span: 12,
      disabled: !created,
      options: pluginOptions,
    },
    {
      id: "step",
      label: t("plugin.step"),
      defaultValue: proxyPlugin.step as string,
      category: FormItemCategory.PLUGIN_STEP,
      span: 6,
    },
    {
      id: "value",
      label: t("plugin.config"),
      defaultValue: proxyPlugin,
      category: FormItemCategory.PLUGIN,
      span: 12,
    },
    {
      id: "remark",
      label: t("plugin.remark"),
      defaultValue: proxyPlugin.remark as string,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
  ];

  const onUpsert = async (newName: string, data: Record<string, unknown>) => {
    let pluginName = name || "";
    if (created) {
      pluginName = newName;
    }
    const newData = Object.assign({}, data.value, data);
    if (!newData.category) {
      newData.category = plugins[0];
    }
    delete newData["value"];

    return update("plugin", pluginName, newData).then(() => {
      if (created) {
        goToPluginInfo(pluginName);
      }
    });
  };
  const onRemove = async () => {
    return remove("plugin", name || "").then(() => {
      goToPluginInfo("*");
    });
  };
  return (
    <FormEditor
      key={name}
      title={t("plugin.title")}
      description={t("plugin.description")}
      items={arr}
      onUpsert={onUpsert}
      onRemove={onRemove}
      created={created}
      currentNames={currentNames}
    />
  );
}
