import useConfigState, { getLocationWeight } from "@/states/config";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FilePlus2 } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { useAsync } from "react-async-hook";
import React from "react";
import { useShallow } from "zustand/react/shallow";

interface Summary {
  name: string;
  value: string;
  link: string;
}

export default function Home() {
  const homeI18n = useI18n("home");
  const [config, initialized, getCertificateInfos] = useConfigState(
    useShallow((state) => [
      state.data,
      state.initialized,
      state.getCertificateInfos,
    ]),
  );
  const [basicInfo] = useBasicState(useShallow((state) => [state.data]));
  const [validity, setValidity] = React.useState({} as Record<string, string>);
  useAsync(async () => {
    try {
      const infos = await getCertificateInfos();
      const formatDate = (value: number) => {
        const date = new Date(value * 1000);
        let month = `${date.getMonth() + 1}`;
        if (month.length === 1) {
          month = `0${month}`;
        }
        let day = `${date.getDate()}`;
        if (day.length === 1) {
          day = `0${day}`;
        }
        return `${date.getFullYear()}-${month}-${day}`;
      };
      const results = {} as Record<string, string>;
      Object.keys(infos).forEach((name) => {
        const data = infos[name];
        if (data) {
          results[name] =
            formatDate(data.not_before) +
            ` ${homeI18n("to")} ` +
            formatDate(data.not_after);
        }
      });
      setValidity(results);
    } catch (err) {
      console.error(err);
    }
  }, []);
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
        link: `${SERVERS}?name=${name}`,
        value: value.addr,
      });
    });
  }
  serverSummary.sort((item1, item2) => {
    return item1.name.localeCompare(item2.name);
  });

  let locationDescription = "";
  const locationSummary: Summary[] = [];
  if (config.locations) {
    const locationCount = Object.keys(config.locations).length;
    locationDescription =
      locationCount > 1
        ? `${locationCount} Locations`
        : `${locationCount} Location`;
    const locationSummaryWeight: Record<string, number> = {};
    listify(config.locations, (name, value) => {
      const weight = getLocationWeight(value);
      locationSummaryWeight[name] = weight;
      const tmpArr: string[] = [];
      if (value.host) {
        tmpArr.push(`host: ${value.host}`);
      }
      tmpArr.push(`path: ${value.path || "/"}`);
      locationSummary.push({
        name,
        link: `${LOCATIONS}?name=${name}`,
        value: tmpArr.join(" "),
      });
    });
    locationSummary.sort((item1, item2) => {
      const weight1 = locationSummaryWeight[item1.name] || 0;
      const weight2 = locationSummaryWeight[item2.name] || 0;
      return weight2 - weight1;
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
      let desc = value.addrs.map((addr) => {
        const tmpArr = addr.split(" ");
        return tmpArr[0];
      }).join(",");
      const healthy = basicInfo.upstream_healthy_status[name];
      if (healthy) {
        desc += ` (${healthy[0]}/${healthy[1]})`;
      }
      upstreamSummary.push({
        name,
        link: `${UPSTREMAS}?name=${name}`,
        value: desc,
      });
    });
  }
  upstreamSummary.sort((item1, item2) => {
    return item1.name.localeCompare(item2.name);
  });

  let pluginDescription = "";
  const pluginSummary: Summary[] = [];
  if (config.plugins) {
    const pluginCount = Object.keys(config.plugins).length;
    pluginDescription =
      pluginCount > 1 ? `${pluginCount} Plugins` : `${pluginCount} Plugin`;
    listify(config.plugins, (name, value) => {
      pluginSummary.push({
        name,
        link: `${PLUGINS}?name=${name}`,
        value: value.category as string,
      });
    });
    pluginSummary.sort((item1, item2) =>
      item1.value.localeCompare(item2.value),
    );
  }
  pluginSummary.sort((item1, item2) => {
    return item1.name.localeCompare(item2.name);
  });

  let certificateDescription = "";
  const certificateSummary: Summary[] = [];
  if (config.certificates) {
    const certificateCount = Object.keys(config.certificates).length;
    certificateDescription =
      certificateCount > 1
        ? `${certificateCount} Certificates`
        : `${certificateCount} Certificate`;
    listify(config.certificates, (name, value) => {
      let date = validity[name] || "";
      if (date) {
        date = ` (${date})`;
      }
      certificateSummary.push({
        name,
        link: `${CERTIFICATES}?name=${name}`,
        value: (value.domains || "") + date,
      });
    });
  }
  certificateSummary.sort((item1, item2) => {
    return item1.name.localeCompare(item2.name);
  });

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
      summary: pluginSummary,
    },
    {
      title: "Certificate",
      path: CERTIFICATES,
      description: certificateDescription,
      summary: certificateSummary,
    },
  ];
  const cards = items.map((item) => {
    return (
      <Card key={item.title}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 relative">
          <CardTitle className="text-sm font-medium ">{item.title}</CardTitle>
          <Link to={item.path} className="absolute top-3 right-3">
            <Button variant="ghost" size="icon">
              <FilePlus2 className="w-5 h-5" />
            </Button>
          </Link>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{item.description}</div>
          {item.summary.length !== 0 && (
            <ul className="text-sm">
              {item.summary.map((item) => {
                return (
                  <li key={item.name} className="break-all mt-2">
                    <Link className="mr-1" to={item.link}>
                      <Button variant="link" size={null}>
                        [{item.name}]
                      </Button>
                    </Link>
                    <span className="text-muted-foreground">{item.value}</span>
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
      name: "startTime",
      value: new Date(basicInfo.start_time * 1000).toLocaleString(),
    },
    {
      name: "threads",
      value: basicInfo.threads,
    },
    {
      name: "machineCpu",
      value: `${basicInfo.cpus} / ${basicInfo.physical_cpus}`,
    },
    {
      name: "memory",
      value: basicInfo.memory,
    },
    {
      name: "machineMemory",
      value: `${basicInfo.used_memory} / ${basicInfo.total_memory}`,
    },
    {
      name: "processing",
      value: basicInfo.processing.toLocaleString(),
    },
    {
      name: "accepted",
      value: basicInfo.accepted.toLocaleString(),
    },
    {
      name: "tcpCount",
      value: basicInfo.tcp_count.toLocaleString(),
    },
    {
      name: "tcp6Count",
      value: basicInfo.tcp6_count.toLocaleString(),
    },
    {
      name: "fdCount",
      value: basicInfo.fd_count.toLocaleString(),
    },
    {
      name: "arch",
      value: basicInfo.arch,
    },
    {
      name: "kernel",
      value: basicInfo.kernel,
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
      name: "enabledFull",
      value: basicInfo.enabled_full ? homeI18n("yes") : homeI18n("no"),
    },
    {
      name: "rustc",
      value: basicInfo.rustc_version,
    },
    {
      name: "configHash",
      value: basicInfo.config_hash,
    },
  ];

  return (
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
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">{cards}</div>
    </div>
  );
}
