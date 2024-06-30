import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";

import Loading from "../components/loading";
import FormEditor from "../components/form-editor";
import { goToLoationInfo } from "../router";
import {
  FormItem,
  FormItemCategory,
  CheckBoxItem,
} from "../components/form-common";

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
  if (config.plugins) {
    Object.keys(config.plugins).forEach((name) => {
      const item = (config.plugins || {})[name];
      proxyPluginOptions.push({
        label: `${name}(${item.category || ""})`,
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
      id: "rewrite",
      label: t("location.rewrite"),
      defaultValue: location.rewrite,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "proxy_set_headers",
      label: t("location.proxySetHeaders"),
      defaultValue: location.proxy_set_headers,
      span: 6,
      category: FormItemCategory.PROXY_SET_HEADERS,
    },
    {
      id: "proxy_add_headers",
      label: t("location.proxyAddHeaders"),
      defaultValue: location.proxy_add_headers,
      span: 6,
      category: FormItemCategory.PROXY_ADD_HEADERS,
    },
    {
      id: "weight",
      label: t("location.weight"),
      defaultValue: location.weight,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "client_max_body_size",
      label: t("location.clientMaxBodySize"),
      defaultValue: location.client_max_body_size,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "plugins",
      label: t("location.plugins"),
      defaultValue: location.plugins,
      span: 12,
      options: proxyPluginOptions,
      category: FormItemCategory.PLUGIN_SELECT,
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
      hiddenIndex={5}
    />
  );
}
