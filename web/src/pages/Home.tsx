import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";
import useConfigState from "@/states/config";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Menu } from "lucide-react";
import { Link } from "react-router-dom";
import {
  CERTIFICATES,
  LOCATIONS,
  PLUGINS,
  SERVERS,
  UPSTREMAS,
} from "@/routers";
import { LoadingPage } from "@/components/loading";
import useBasicState from "@/states/basic";
import { useI18n } from "@/i18n";
import { listify } from "radash";

interface Summary {
  name: string;
  value: string;
}

export default function Home() {
  const homeI18n = useI18n("home");
  const [config, initialized] = useConfigState((state) => [
    state.data,
    state.initialized,
  ]);
  const [basicInfo] = useBasicState((state) => [state.data]);
  if (!initialized) {
    return <LoadingPage />;
  }

  let serverDescription = "";
  const serverSummary: Summary[] = [];
  if (config.servers) {
    const serverCount = Object.keys(config.servers).length;
    serverDescription =
      serverCount > 1 ? `${serverCount} Servers` : `${serverCount} Server`;
    listify(config.servers, (name, value) => {
      serverSummary.push({
        name,
        value: value.addr,
      });
    });
  }
  let locationDescription = "";
  const locationSummary: Summary[] = [];
  if (config.locations) {
    const locationCount = Object.keys(config.locations).length;
    locationDescription =
      locationCount > 1
        ? `${locationCount} Locations`
        : `${locationCount} Location`;
    listify(config.locations, (name, value) => {
      const tmpArr: string[] = [];
      if (value.host) {
        tmpArr.push(`Host: ${value.host}`);
      }
      if (value.path) {
        tmpArr.push(`Path: ${value.path}`);
      }
      locationSummary.push({
        name,
        value: tmpArr.join(" "),
      });
    });
  }

  let upstreamDescription = "";
  const upstreamSummary: Summary[] = [];
  if (config.upstreams) {
    const upstreamCount = Object.keys(config.upstreams).length;
    upstreamDescription =
      upstreamCount > 1
        ? `${upstreamCount} Upstreams`
        : `${upstreamCount} Upstream`;
    listify(config.upstreams, (name, value) => {
      upstreamSummary.push({
        name,
        value: value.addrs.join(","),
      });
    });
  }

  let pluginDescription = "";
  if (config.plugins) {
    const pluginCount = Object.keys(config.plugins).length;
    pluginDescription =
      pluginCount > 1 ? `${pluginCount} Plugins` : `${pluginCount} Plugin`;
  }

  let certificateDescription = "";
  if (config.certificates) {
    const certificateCount = Object.keys(config.certificates).length;
    certificateDescription =
      certificateCount > 1
        ? `${certificateCount} Certificates`
        : `${certificateCount} Certificate`;
  }

  const items = [
    {
      title: "Server",
      path: SERVERS,
      description: serverDescription,
      summary: serverSummary,
    },
    {
      title: "Location",
      path: LOCATIONS,
      description: locationDescription,
      summary: locationSummary,
    },
    {
      title: "Upstream",
      path: UPSTREMAS,
      description: upstreamDescription,
      summary: upstreamSummary,
    },
    {
      title: "Plugin",
      path: PLUGINS,
      description: pluginDescription,
      summary: [],
    },
    {
      title: "Certificate",
      path: CERTIFICATES,
      description: certificateDescription,
      summary: [],
    },
  ];
  const cards = items.map((item) => {
    return (
      <Card key={item.title}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 relative">
          <CardTitle className="text-sm font-medium ">{item.title}</CardTitle>
          <Link to={item.path} className="absolute top-3 right-3">
            <Menu className="w-5 h-5" />
          </Link>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{item.description}</div>
          {item.summary.length !== 0 && (
            <ul className="text-sm">
              {item.summary.map((item) => {
                return (
                  <li key={item.name} className="break-all mt-2">
                    <span className="text-muted-foreground">{item.name}:</span>{" "}
                    {item.value}
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>
    );
  });
  const basicInfos = [
    {
      name: "pid",
      value: basicInfo.pid,
    },
    {
      name: "threads",
      value: basicInfo.threads,
    },
    {
      name: "memory",
      value: basicInfo.memory,
    },
    {
      name: "startTime",
      value: new Date(basicInfo.start_time * 1000).toLocaleString(),
    },
    {
      name: "arch",
      value: basicInfo.arch,
    },
    {
      name: "user",
      value: basicInfo.user,
    },
    {
      name: "group",
      value: basicInfo.group,
    },
    {
      name: "configHash",
      value: basicInfo.config_hash,
    },

    {
      name: "rustc",
      value: basicInfo.rustc_version,
    },
  ];

  return (
    <div>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          <h3>{homeI18n("dashboard")}</h3>
          <Card className="my-4">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 col-span-2">
              <CardTitle className="text-sm font-medium ">
                {homeI18n("basic")}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 grid-cols-2">
                {basicInfos.map((item) => {
                  return (
                    <p key={item.name} className="text-xs">
                      <span className="text-muted-foreground mr-2">
                        {homeI18n(item.name)}:
                      </span>
                      {item.value || "--"}
                    </p>
                  );
                })}
              </div>
            </CardContent>
          </Card>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {cards}
          </div>
        </div>
      </div>
    </div>
  );
}