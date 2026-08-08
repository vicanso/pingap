import { LoadingPage } from "@/components/loading";
import { useI18n } from "@/i18n";
import useConfigState, { getLocationWeight, Location } from "@/states/config";
import useBasicState from "@/states/basic";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { sortIntoSections } from "@/components/ex-form-sections";
import { z } from "zod";
import {
  ExFormItemCategory,
  newBooleanOptions,
  newStringOptions,
} from "@/constants";
import { newZodBytes, omitEmptyArrayString } from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import History from "@/pages/History";
import { EntityBadge } from "@/components/config-entity-badge";
import { PageShell } from "@/components/page-shell";
import { ConfigEntityList, EntityText } from "@/components/config-entity-list";
import { LOCATIONS } from "@/routers";

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

  const [config, initialized, update, remove, getIncludeOptions, version] =
    useConfigState(
      useShallow((state) => [
        state.data,
        state.initialized,
        state.update,
        state.remove,
        state.getIncludeOptions,
        state.version,
      ]),
    );

  const [basicInfo, basicInitialized] = useBasicState(
    useShallow((state) => [state.data, state.initialized]),
  );

  const sec = {
    match: locationI18n("sectionMatch"),
    upstream: locationI18n("sectionUpstream"),
    headers: locationI18n("sectionHeaders"),
    limit: locationI18n("sectionLimit"),
    plugins: locationI18n("sectionPlugins"),
  };

  const newLocation = "*";
  const locations = Object.keys(config.locations || {});
  locations.sort();
  // No `name` in the url means the category overview, `*` means the create form.
  const currentLocation = searchParams.get("name") || "";

  if (!initialized || !basicInitialized) {
    return <LoadingPage />;
  }

  if (!currentLocation) {
    return (
      <ConfigEntityList<Location>
        title={locationI18n("title")}
        summary={locationI18n("summary", { count: locations.length })}
        nameLabel={locationI18n("name")}
        addLabel={locationI18n("add")}
        emptyText={locationI18n("empty")}
        basePath={LOCATIONS}
        newValue={newLocation}
        names={locations}
        values={config.locations || {}}
        columns={[
          {
            key: "host",
            label: locationI18n("host"),
            render: (value) => <EntityText value={value?.host} />,
          },
          {
            key: "path",
            label: locationI18n("path"),
            render: (value) => <EntityText value={value?.path} />,
          },
          {
            key: "upstream",
            label: locationI18n("upstream"),
            render: (value) => <EntityText value={value?.upstream} />,
          },
          {
            key: "weight",
            label: locationI18n("weight"),
            render: (value) => (
              <EntityText
                value={value ? getLocationWeight(value) : undefined}
              />
            ),
          },
          {
            key: "plugins",
            label: locationI18n("plugins"),
            render: (value) => (
              <EntityText value={(value?.plugins || []).join(", ")} />
            ),
          },
        ]}
      />
    );
  }

  const upstreams = Object.keys(config.upstreams || {});

  const handleSelectLocation = (name: string) => {
    searchParams.set("name", name);
    setSearchParams(searchParams);
  };

  const backToList = () => {
    searchParams.delete("name");
    setSearchParams(searchParams);
  };

  const plugins = newStringOptions(
    (basicInfo.supported_plugins || []).sort(),
    false,
  );

  const currentPlugins = config.plugins || {};
  Object.keys(currentPlugins)
    .sort()
    .forEach((name) => {
      const item = currentPlugins[name];
      plugins.push({
        label: `${name}(${item.category || ""})`,
        option: name,
        value: name,
      });
    });

  const locationConfig = getLocationConfig(currentLocation, config.locations);

  const items: ExFormItem[] = [
    {
      name: "host",
      section: sec.match,
      label: locationI18n("host"),
      placeholder: locationI18n("hostPlaceholder"),
      defaultValue: locationConfig.host,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "path",
      section: sec.match,
      label: locationI18n("path"),
      placeholder: locationI18n("pathPlaceholder"),
      defaultValue: locationConfig.path,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "upstream",
      section: sec.upstream,
      label: locationI18n("upstream"),
      placeholder: locationI18n("upstreamPlaceholder"),
      defaultValue: locationConfig.upstream,
      span: 3,
      category: ExFormItemCategory.INPUT_SELECT,
      options: newStringOptions(upstreams, false, true),
    },
    {
      name: "rewrite",
      section: sec.match,
      label: locationI18n("rewrite"),
      placeholder: locationI18n("rewritePlaceholder"),
      defaultValue: locationConfig.rewrite,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "proxy_set_headers",
      section: sec.headers,
      label: locationI18n("proxySetHeaders"),
      placeholder: locationI18n("proxySetHeadersPlaceholder"),
      defaultValue: locationConfig.proxy_set_headers,
      span: 3,
      category: ExFormItemCategory.KV_LIST,
    },
    {
      name: "proxy_add_headers",
      section: sec.headers,
      label: locationI18n("proxyAddHeaders"),
      placeholder: locationI18n("proxyAddHeadersPlaceholder"),
      defaultValue: locationConfig.proxy_add_headers,
      span: 3,
      category: ExFormItemCategory.KV_LIST,
    },
    {
      name: "max_retries",
      section: sec.upstream,
      label: locationI18n("maxRetries"),
      placeholder: locationI18n("maxRetriesPlaceholder"),
      defaultValue: locationConfig.max_retries,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "max_retry_window",
      section: sec.upstream,
      label: locationI18n("maxRetryWindow"),
      placeholder: locationI18n("maxRetryWindowPlaceholder"),
      defaultValue: locationConfig.max_retry_window,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "enable_reverse_proxy_headers",
      section: sec.upstream,
      label: locationI18n("enableReverseProxyHeaders"),
      placeholder: "",
      defaultValue: locationConfig.enable_reverse_proxy_headers,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "includes",
      section: sec.plugins,
      label: i18n("includes"),
      placeholder: i18n("includesPlaceholder"),
      defaultValue: locationConfig.includes,
      span: 3,
      category: ExFormItemCategory.MULTI_SELECT,
      options: newStringOptions(getIncludeOptions(), false),
    },
    {
      name: "grpc_web",
      section: sec.plugins,
      label: locationI18n("grpcWeb"),
      placeholder: "",
      defaultValue: locationConfig.grpc_web,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "weight",
      section: sec.match,
      label: locationI18n("weight"),
      placeholder: locationI18n("weightPlaceholder"),
      defaultValue: locationConfig.weight,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "client_max_body_size",
      section: sec.limit,
      label: locationI18n("clientMaxBodySize"),
      placeholder: locationI18n("clientMaxBodySizePlaceholder"),
      defaultValue: locationConfig.client_max_body_size,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "max_processing",
      section: sec.limit,
      label: locationI18n("maxProcessing"),
      placeholder: locationI18n("maxProcessingPlaceholder"),
      defaultValue: locationConfig.max_processing,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "plugins",
      section: sec.plugins,
      label: locationI18n("plugins"),
      placeholder: locationI18n("pluginsPlaceholder"),
      defaultValue: locationConfig.plugins || [],
      span: 6,
      category: ExFormItemCategory.SORT_CHECKBOXS,
      options: plugins,
    },
    {
      name: "remark",
      section: sec.match,
      label: locationI18n("remark"),
      placeholder: "",
      defaultValue: locationConfig.remark,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];
  if (currentLocation === newLocation) {
    items.unshift({
      name: "name",
      section: sec.match,
      label: locationI18n("name"),
      placeholder: locationI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const defaultShow = sortIntoSections(
    items,
    [sec.match, sec.upstream, sec.headers, sec.limit, sec.plugins],
    [sec.match, sec.upstream],
  );

  const schema = z.object({
    client_max_body_size: newZodBytes().optional(),
  });
  const onRemove = async () => {
    return remove("location", currentLocation).then(() => {
      backToList();
    });
  };

  return (
    <PageShell
      title={locationI18n("title")}
      description={locationI18n("description")}
      width="narrow"
      backTo={LOCATIONS}
      backLabel={i18n("backToList")}
      badge={
        <EntityBadge
          name={currentLocation}
          isNew={currentLocation === newLocation}
        />
      }
      actions={
        currentLocation !== newLocation ? (
          <History
            category="location"
            name={currentLocation}
            onRestore={async (data) => {
              await update("location", currentLocation, data);
            }}
          />
        ) : undefined
      }
    >
      <ExForm
        category="location"
        key={`${currentLocation}-${version}`}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onRemove={currentLocation === newLocation ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentLocation;
          if (name === newLocation) {
            name = value["name"] as string;
          }
          omitEmptyArrayString(value);
          await update("location", name, value);
          handleSelectLocation(name);
        }}
      />
    </PageShell>
  );
}
