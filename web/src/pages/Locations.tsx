import { MainHeader } from "@/components/header";
import { LoadingPage } from "@/components/loading";
import { MainSidebar } from "@/components/sidebar-nav";
import { useI18n } from "@/i18n";
import useConfigState, { Location } from "@/states/config";
import React from "react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ExForm,
  ExFormItem,
  ExFormItemCategory,
  getBooleanOptions,
  getStringOptions,
} from "@/components/ex-form";
import { pascal } from "radash";

import { z } from "zod";

function getLocationConfig(name: string, locations?: Record<string, Location>) {
  if (!locations) {
    return {} as Location;
  }
  return (locations[name] || {}) as Location;
}

export default function Locations() {
  const locationCurrentKey = "locations.current";
  const locationI18n = useI18n("location");
  const [config, initialized, update] = useConfigState((state) => [
    state.data,
    state.initialized,
    state.update,
  ]);

  const newLocation = "*";
  const locations = Object.keys(config.locations || {});
  locations.sort();
  locations.unshift(newLocation);
  const [currentLocation, setCurrentLocation] = React.useState(
    localStorage.getItem(locationCurrentKey) || locations[0],
  );

  if (!initialized) {
    return <LoadingPage />;
  }

  const triggers = locations.map((item) => {
    let label: string;
    if (item === newLocation) {
      label = "New";
    } else {
      label = item;
    }
    return (
      <TabsTrigger key={item} value={item} className="px-6">
        {label}
      </TabsTrigger>
    );
  });

  const upstreams = Object.keys(config.upstreams || {});

  const handleSelectLocation = (name: string) => {
    localStorage.setItem(locationCurrentKey, name);
    setCurrentLocation(name);
  };

  const tabs = (
    <Tabs value={currentLocation} onValueChange={handleSelectLocation}>
      <TabsList className="grid grid-flow-col auto-cols-max">
        {triggers}
      </TabsList>
    </Tabs>
  );

  const plugins = getStringOptions([
    "pingap:stats",
    "pingap:compression",
    "pingap:requestId",
    "pingap:ping",
  ]);

  const currentPlugins = config.plugins || {};
  Object.keys(currentPlugins).forEach((name) => {
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
      placehodler: locationI18n("hostPlaceholder"),
      defaultValue: locationConfig.host,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "path",
      label: locationI18n("path"),
      placehodler: locationI18n("pathPlaceholder"),
      defaultValue: locationConfig.path,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "upstream",
      label: locationI18n("upstream"),
      placehodler: locationI18n("upstreamPlaceholder"),
      defaultValue: locationConfig.upstream,
      span: 2,
      category: ExFormItemCategory.SELECT,
      options: getStringOptions(upstreams, true),
    },
    {
      name: "rewrite",
      label: locationI18n("rewrite"),
      placehodler: locationI18n("rewritePlaceholder"),
      defaultValue: locationConfig.rewrite,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "proxy_set_headers",
      label: locationI18n("proxySetHeaders"),
      placehodler: locationI18n("proxySetHeadersPlaceholder"),
      defaultValue: locationConfig.proxy_set_headers,
      span: 2,
      category: ExFormItemCategory.KV_LIST,
    },
    {
      name: "proxy_add_headers",
      label: locationI18n("proxyAddHeaders"),
      placehodler: locationI18n("proxyAddHeadersPlaceholder"),
      defaultValue: locationConfig.proxy_add_headers,
      span: 2,
      category: ExFormItemCategory.KV_LIST,
    },
    {
      name: "weight",
      label: locationI18n("weight"),
      placehodler: locationI18n("weightPlaceholder"),
      defaultValue: locationConfig.weight,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "client_max_body_size",
      label: locationI18n("clientMaxBodySize"),
      placehodler: locationI18n("clientMaxBodySizePlaceholder"),
      defaultValue: locationConfig.client_max_body_size,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },

    {
      name: "plugins",
      label: locationI18n("plugins"),
      placehodler: locationI18n("pluginsPlaceholder"),
      defaultValue: locationConfig.plugins || [],
      span: 4,
      category: ExFormItemCategory.MULTI_SELECT,
      options: plugins,
    },
    {
      name: "remark",
      label: locationI18n("remark"),
      placehodler: "",
      defaultValue: locationConfig.remark,
      span: 4,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];

  const schema = z.object({});

  return (
    <>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          {tabs}
          <div className="p-2" />
          <ExForm
            key={currentLocation}
            items={items}
            schema={schema}
            // defaultShow={6}
            onSave={async (value) => {
              let name = currentLocation;
              if (name === newLocation) {
                name = value["name"] as string;
              }
              await update("location", name, value);
              handleSelectLocation(name);
            }}
          />
        </div>
      </div>
    </>
  );
}
