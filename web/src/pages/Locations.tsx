import { LoadingPage } from "@/components/loading";
import { useI18n } from "@/i18n";
import useConfigState, { Location } from "@/states/config";
import React from "react";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { pascal } from "radash";
import { z } from "zod";
import {
  ExFormItemCategory,
  newBooleanOptions,
  newStringOptions,
} from "@/constants";
import { newZodBytes, omitEmptyArray } from "@/helpers/util";
import { formatLabel } from "@/helpers/html";
import { useSearchParams } from "react-router-dom";
import { useEffect } from "react";
import { useShallow } from "zustand/react/shallow";

function getLocationConfig(name: string, locations?: Record<string, Location>) {
  if (!locations) {
    return {} as Location;
  }
  return (locations[name] || {}) as Location;
}

export default function Locations() {
  const locationI18n = useI18n("location");
  const i18n = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, update, remove, getIncludeOptions] =
    useConfigState(
      useShallow((state) => [
        state.data,
        state.initialized,
        state.update,
        state.remove,
        state.getIncludeOptions,
      ]),
    );

  const newLocation = "*";
  const locations = Object.keys(config.locations || {});
  locations.sort();
  locations.unshift(newLocation);
  const [currentLocation, setCurrentLocation] = React.useState(
    searchParams.get("name") || newLocation,
  );
  useEffect(() => {
    setCurrentLocation(searchParams.get("name") || newLocation);
  }, [searchParams]);

  if (!initialized) {
    return <LoadingPage />;
  }

  const upstreams = Object.keys(config.upstreams || {});

  const handleSelectLocation = (name: string) => {
    setCurrentLocation(name);
    if (name === newLocation) {
      searchParams.delete("name");
    } else {
      searchParams.set("name", name);
    }
    setSearchParams(searchParams);
  };

  const plugins = newStringOptions(
    [
      "pingap:stats",
      "pingap:compression",
      "pingap:requestId",
      "pingap:ping",
      "pingap:acceptEncodingAdjustment",
    ].sort(),
    false,
  );

  const currentPlugins = config.plugins || {};
  Object.keys(currentPlugins)
    .sort()
    .forEach((name) => {
      const item = currentPlugins[name];
      plugins.push({
        label: pascal(`${name}(${item.category || ""})`),
        option: name,
        value: name,
      });
    });

  const locationConfig = getLocationConfig(currentLocation, config.locations);

  const items: ExFormItem[] = [
    {
      name: "host",
      label: locationI18n("host"),
      placeholder: locationI18n("hostPlaceholder"),
      defaultValue: locationConfig.host,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "path",
      label: locationI18n("path"),
      placeholder: locationI18n("pathPlaceholder"),
      defaultValue: locationConfig.path,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "upstream",
      label: locationI18n("upstream"),
      placeholder: locationI18n("upstreamPlaceholder"),
      defaultValue: locationConfig.upstream,
      span: 3,
      category: ExFormItemCategory.INPUT_SELECT,
      options: newStringOptions(upstreams, false, true),
    },
    {
      name: "rewrite",
      label: locationI18n("rewrite"),
      placeholder: locationI18n("rewritePlaceholder"),
      defaultValue: locationConfig.rewrite,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "proxy_set_headers",
      label: locationI18n("proxySetHeaders"),
      placeholder: locationI18n("proxySetHeadersPlaceholder"),
      defaultValue: locationConfig.proxy_set_headers,
      span: 3,
      category: ExFormItemCategory.KV_LIST,
    },
    {
      name: "proxy_add_headers",
      label: locationI18n("proxyAddHeaders"),
      placeholder: locationI18n("proxyAddHeadersPlaceholder"),
      defaultValue: locationConfig.proxy_add_headers,
      span: 3,
      category: ExFormItemCategory.KV_LIST,
    },
    {
      name: "enable_reverse_proxy_headers",
      label: locationI18n("enableReverseProxyHeaders"),
      placeholder: "",
      defaultValue: locationConfig.enable_reverse_proxy_headers,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "includes",
      label: i18n("includes"),
      placeholder: i18n("includesPlaceholder"),
      defaultValue: locationConfig.includes,
      span: 3,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(getIncludeOptions(), false),
    },
    {
      name: "grpc_web",
      label: locationI18n("grpcWeb"),
      placeholder: "",
      defaultValue: locationConfig.grpc_web,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "weight",
      label: locationI18n("weight"),
      placeholder: locationI18n("weightPlaceholder"),
      defaultValue: locationConfig.weight,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "client_max_body_size",
      label: locationI18n("clientMaxBodySize"),
      placeholder: locationI18n("clientMaxBodySizePlaceholder"),
      defaultValue: locationConfig.client_max_body_size,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "max_processing",
      label: locationI18n("maxProcessing"),
      placeholder: locationI18n("maxProcessingPlaceholder"),
      defaultValue: locationConfig.max_processing,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "plugins",
      label: locationI18n("plugins"),
      placeholder: locationI18n("pluginsPlaceholder"),
      defaultValue: locationConfig.plugins || [],
      span: 6,
      category: ExFormItemCategory.SORT_CHECKBOXS,
      options: plugins,
    },
    {
      name: "remark",
      label: locationI18n("remark"),
      placeholder: "",
      defaultValue: locationConfig.remark,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];
  let defaultShow = 7;
  if (currentLocation === newLocation) {
    defaultShow++;
    items.unshift({
      name: "name",
      label: locationI18n("name"),
      placeholder: locationI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const schema = z.object({
    client_max_body_size: newZodBytes().optional(),
  });
  const onRemove = async () => {
    return remove("location", currentLocation).then(() => {
      handleSelectLocation(newLocation);
    });
  };

  return (
    <div className="grow overflow-auto p-4">
      <h2 className="h-8 mb-1">{formatLabel(currentLocation)}</h2>
      <ExForm
        category="location"
        key={currentLocation}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onRemove={currentLocation === newLocation ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentLocation;
          if (name === newLocation) {
            name = value["name"] as string;
          }
          omitEmptyArray(value);
          await update("location", name, value);
          handleSelectLocation(name);
        }}
      />
    </div>
  );
}
