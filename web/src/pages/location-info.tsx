import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";

import Loading from "../components/loading";
import FormEditor, {
  CheckBoxItem,
  FormItem,
  FormItemCategory,
} from "../components/form-editor";

export default function LocationInfo() {
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
  ];
  if (config.proxy_plugins) {
    Object.keys(config.proxy_plugins).forEach((name) => {
      const item = (config.proxy_plugins || {})[name];
      proxyPluginOptions.push({
        label: `${name}(${item.category})`,
        option: proxyPluginOptions.length,
        value: name,
      });
    });
  }

  const arr: FormItem[] = [
    {
      id: "host",
      label: "Host",
      defaultValue: location.host,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "path",
      label: "Path",
      defaultValue: location.path,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upstream",
      label: "Upstream",
      defaultValue: location.upstream,
      span: 6,
      category: FormItemCategory.UPSTREAM,
      options: upstreams,
    },
    {
      id: "weight",
      label: "Weight",
      defaultValue: location.weight,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "headers",
      label: "Headers",
      defaultValue: location.headers,
      span: 6,
      category: FormItemCategory.HEADERS,
    },
    {
      id: "proxy_headers",
      label: "Proxy Headers",
      defaultValue: location.proxy_headers,
      span: 6,
      category: FormItemCategory.PROXY_HEADERS,
    },
    {
      id: "rewrite",
      label: "Rewrite",
      defaultValue: location.rewrite,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "proxy_plugins",
      label: "Proxy Plugins",
      defaultValue: location.proxy_plugins,
      span: 12,
      options: proxyPluginOptions,
      category: FormItemCategory.PROXY_PLUGIN_SELECT,
    },
    {
      id: "remark",
      label: "Remark",
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
    return update("location", locationName, data);
  };
  return (
    <FormEditor
      key={name}
      title="Modify location configuration"
      description="Change the location configuration"
      items={arr}
      onUpsert={onUpsert}
      created={created}
      currentNames={currentNames}
    />
  );
}
