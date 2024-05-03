import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";

import Loading from "../components/loading";
import FormEditor, {
  CheckBoxItem,
  FormItem,
  FormItemCategory,
  formatProxyPluginCategory,
} from "../components/form-editor";
import { goToLoationInfo } from "../router";

export default function LocationInfo() {
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
  let locationName = name;
  if (name == "*") {
    created = true;
    locationName = "";
  }
  const locations = config.locations || {};
  const location = locations[locationName || ""] || {};
  const upstreams = Object.keys(config.upstreams || {});
  const currentNames = Object.keys(locations);
  const proxyPluginOptions: CheckBoxItem[] = [
    {
      label: "pingap:stats",
      option: 0,
      value: "pingap:stats",
    },
    {
      label: "pingap:compression",
      option: 1,
      value: "pingap:compression",
    },
    {
      label: "pingap:requestId",
      option: 2,
      value: "pingap:requestId",
    },
    {
      label: "pingap:ping",
      option: 3,
      value: "pingap:ping",
    },
  ];
  if (config.proxy_plugins) {
    Object.keys(config.proxy_plugins).forEach((name) => {
      const item = (config.proxy_plugins || {})[name];
      proxyPluginOptions.push({
        label: `${name}(${formatProxyPluginCategory(item.category)})`,
        option: proxyPluginOptions.length,
        value: name,
      });
    });
  }

  const arr: FormItem[] = [
    {
      id: "host",
      label: t("location.host"),
      defaultValue: location.host,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "path",
      label: t("location.path"),
      defaultValue: location.path,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upstream",
      label: t("location.upstream"),
      defaultValue: location.upstream,
      span: 6,
      category: FormItemCategory.UPSTREAM,
      options: upstreams,
    },
    {
      id: "weight",
      label: t("location.weight"),
      defaultValue: location.weight,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "headers",
      label: t("location.headers"),
      defaultValue: location.headers,
      span: 6,
      category: FormItemCategory.HEADERS,
    },
    {
      id: "proxy_headers",
      label: t("location.proxyHeaders"),
      defaultValue: location.proxy_headers,
      span: 6,
      category: FormItemCategory.PROXY_HEADERS,
    },
    {
      id: "rewrite",
      label: t("location.rewrite"),
      defaultValue: location.rewrite,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "proxy_plugins",
      label: t("location.proxyPlugins"),
      defaultValue: location.proxy_plugins,
      span: 12,
      options: proxyPluginOptions,
      category: FormItemCategory.PROXY_PLUGIN_SELECT,
    },
    {
      id: "remark",
      label: t("location.remark"),
      defaultValue: location.remark,
      span: 13,
      category: FormItemCategory.TEXTAREA,
    },
  ];

  const onUpsert = async (newName: string, data: Record<string, unknown>) => {
    let locationName = name || "";
    if (created) {
      locationName = newName;
    }
    return update("location", locationName, data).then(() => {
      if (created) {
        goToLoationInfo(locationName);
      }
    });
  };
  const onRemove = async () => {
    return remove("location", name || "").then(() => {
      goToLoationInfo("*");
    });
  };
  return (
    <FormEditor
      key={name}
      title={t("location.title")}
      description={t("location.description")}
      items={arr}
      onRemove={onRemove}
      onUpsert={onUpsert}
      created={created}
      currentNames={currentNames}
    />
  );
}
