import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";
import { LoadingPage } from "@/components/loading";
import useConfigState, { Server } from "@/states/config";
import {
  ExForm,
  ExFormItem,
  ExFormItemCategory,
  getBooleanOptions,
  getStringOptions,
} from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import React from "react";

import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

function getServerConfig(name: string, servers?: Record<string, Server>) {
  if (!servers) {
    return {} as Server;
  }
  return (servers[name] || {}) as Server;
}

export default function Servers() {
  const serverI18n = useI18n("server");
  const [config, initialized, update] = useConfigState((state) => [
    state.data,
    state.initialized,
    state.update,
  ]);

  const newServer = "E377u9kZXe";
  const servers = Object.keys(config.servers || {});
  servers.sort();
  servers.unshift(newServer);

  const [currentServer, setCurrentServer] = React.useState(servers[0]);
  const [serverConfig, setServerConfig] = React.useState(
    getServerConfig(servers[0], config.servers),
  );
  if (!initialized) {
    return <LoadingPage />;
  }

  const triggers = servers.map((item) => {
    let label: string;
    if (item === newServer) {
      label = "New";
    } else {
      label = item;
    }
    return (
      <TabsTrigger key={item} value={item}>
        {label}
      </TabsTrigger>
    );
  });

  const tabs = (
    <Tabs
      defaultValue={currentServer}
      onValueChange={(value) => {
        setCurrentServer(value);
        setServerConfig(getServerConfig(value, config.servers));
      }}
    >
      <TabsList className="grid w-full grid-cols-2">{triggers}</TabsList>
    </Tabs>
  );
  const items: ExFormItem[] = [
    {
      name: "addr",
      label: serverI18n("addr"),
      placehodler: serverI18n("addrPlaceholder"),
      defaultValue: serverConfig.addr,
      span: 2,
      category: ExFormItemCategory.TEXT,
    },
  ];

  const schema = z.object({
    addr: z.string(),
  });

  return (
    <div>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          {tabs}
          <ExForm
            key={currentServer}
            items={items}
            schema={schema}
            defaultShow={9}
            onSave={async (value) => update("pingap", "basic", value)}
          />
        </div>
      </div>
    </div>
  );
}
