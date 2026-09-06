import { LoadingPage } from "@/components/loading";
import useConfigState from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import React from "react";
import {
  ExFormItemCategory,
  newStringOptions,
  PluginCategory,
  getPluginSteps,
} from "@/constants";
import { PLUGIN_FIELDS } from "@/plugin-fields";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import useBasicState from "@/states/basic";
import { omitEmptyArrayString } from "@/helpers/util";
import History from "@/pages/History";
import { EntityBadge } from "@/components/config-entity-badge";
import { PageShell } from "@/components/page-shell";
import {
  ConfigEntityList,
  EntityText,
  type ConfigEntityColumn,
} from "@/components/config-entity-list";
import { ConfigEntitySummary } from "@/components/config-entity-summary";
import { sortIntoSections } from "@/components/ex-form-sections";
import { PLUGINS } from "@/routers";

function getPluginConfig(
  name: string,
  plugins?: Record<string, Record<string, unknown>>,
) {
  if (!plugins) {
    return {} as Record<string, unknown>;
  }
  return (plugins[name] || {}) as Record<string, unknown>;
}

export default function Plugins() {
  const pluginI18n = useI18n("plugin");
  const i18n = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, update, remove, version] = useConfigState(
    useShallow((state) => [
      state.data,
      state.initialized,
      state.update,
      state.remove,
      state.version,
    ]),
  );

  const [basicInfo] = useBasicState(useShallow((state) => [state.data]));

  const newPlugin = "*";
  const plugins = Object.keys(config.plugins || {});
  plugins.sort();

  // No `name` in the url means the category overview, `*` means the create form.
  const currentPlugin = searchParams.get("name") || "";
  const pluginConfig = getPluginConfig(currentPlugin, config.plugins);
  const [currentCategory, setCurrentCategory] = React.useState(
    (pluginConfig.category as string) || "",
  );

  if (!initialized) {
    return <LoadingPage />;
  }

  if (!currentPlugin) {
    const pluginValues = config.plugins || {};
    // Only show optional columns when at least one row has a value — otherwise
    // a cache plugin with no step/remark paints a row of empty dashes.
    const hasStep = plugins.some((name) => Boolean(pluginValues[name]?.step));
    const hasRemark = plugins.some((name) =>
      Boolean(pluginValues[name]?.remark),
    );
    const columns: ConfigEntityColumn<Record<string, unknown>>[] = [
      {
        key: "category",
        label: pluginI18n("category"),
        render: (value) => <EntityText value={value?.category as string} />,
      },
    ];
    if (hasStep) {
      columns.push({
        key: "step",
        label: pluginI18n("step"),
        render: (value) => <EntityText value={value?.step as string} />,
      });
    }
    if (hasRemark) {
      columns.push({
        key: "remark",
        label: pluginI18n("remark"),
        render: (value) => <EntityText value={value?.remark as string} />,
      });
    }
    return (
      <ConfigEntityList<Record<string, unknown>>
        title={pluginI18n("title")}
        summary={pluginI18n("summary", { count: plugins.length })}
        nameLabel={pluginI18n("name")}
        addLabel={pluginI18n("add")}
        emptyText={pluginI18n("empty")}
        basePath={PLUGINS}
        newValue={newPlugin}
        names={plugins}
        values={pluginValues}
        columns={columns}
      />
    );
  }

  const handleSelectPlugin = (name: string) => {
    const conf = getPluginConfig(name, config.plugins);
    setCurrentCategory(conf.category as string);
    searchParams.set("name", name);
    setSearchParams(searchParams);
  };

  const backToList = () => {
    searchParams.delete("name");
    setSearchParams(searchParams);
  };

  const sec = {
    basic: pluginI18n("sectionBasic"),
    options: pluginI18n("sectionOptions"),
  };
  const items: ExFormItem[] = [];
  if (currentPlugin === newPlugin) {
    items.unshift(
      {
        name: "category",
        section: sec.basic,
        label: pluginI18n("category"),
        placeholder: "",
        defaultValue: currentCategory,
        category: ExFormItemCategory.RADIOS,
        span: 6,
        options: newStringOptions(basicInfo.supported_plugins, true),
      },
      {
        name: "_name_",
        section: sec.basic,
        label: pluginI18n("name"),
        placeholder: pluginI18n("namePlaceholder"),
        defaultValue: "",
        span: 6,
        category: ExFormItemCategory.TEXT,
      },
    );
  } else {
    items.unshift({
      name: "category",
      section: sec.basic,
      label: pluginI18n("category"),
      placeholder: "",
      defaultValue: pluginConfig.category as string,
      category: ExFormItemCategory.LABEL,
      span: 6,
    });
  }
  // `currentCategory` exists only so the create form can react to the category
  // radio. For a saved plugin the category is whatever its config says — letting
  // the state win here made a plugin reached by url or by a list row render the
  // fields of whichever category was picked last.
  const category =
    currentPlugin === newPlugin
      ? currentCategory
      : (pluginConfig.category as string);
  if (category) {
    const options = getPluginSteps(category);
    if (options.length > 1) {
      items.push({
        name: "step",
        section: sec.basic,
        label: pluginI18n("step"),
        placeholder: "",
        defaultValue: (pluginConfig.step as string) || options[0].value,
        category: ExFormItemCategory.RADIOS,
        options,
        span: 6,
      });
    }
  }
  // Per-category fields live in plugin-fields.ts; every builder is pure, so
  // the page only needs to look one up and append what it returns.
  const buildFields = PLUGIN_FIELDS[category as PluginCategory];
  if (buildFields) {
    items.push(
      ...buildFields(pluginConfig, pluginI18n).map((field) => ({
        ...field,
        section: field.section ?? sec.options,
      })),
    );
  }
  if (category) {
    items.push({
      name: "remark",
      section: sec.options,
      label: pluginI18n("remark"),
      placeholder: "",
      defaultValue: pluginConfig.remark as string,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    });
  }

  const defaultShow = sortIntoSections(
    items,
    [sec.basic, sec.options],
    [sec.basic],
  );

  const schema = z.object({
    step: z.string().optional(),
  });
  let key = `${currentPlugin}-${version}`;
  if (currentPlugin == newPlugin) {
    key = `new-plugin-${category}-${version}`;
  }
  const onRemove = async () => {
    return remove("plugin", currentPlugin).then(() => {
      backToList();
    });
  };

  return (
    <PageShell
      eyebrow="plugins"
      title={pluginI18n("title")}
      description={pluginI18n("description")}
      width="narrow"
      backTo={PLUGINS}
      backLabel={i18n("backToList")}
      badge={
        <EntityBadge name={currentPlugin} isNew={currentPlugin === newPlugin} />
      }
      actions={
        currentPlugin !== newPlugin ? (
          <History
            category="plugin"
            name={currentPlugin}
            onRestore={async (data) => {
              await update("plugin", currentPlugin, data);
            }}
          />
        ) : undefined
      }
    >
      {currentPlugin !== newPlugin && (
        <ConfigEntitySummary
          fields={[
            {
              label: pluginI18n("category"),
              value: (pluginConfig.category as string) || "—",
            },
            {
              label: pluginI18n("name"),
              value: currentPlugin,
              mono: true,
            },
          ]}
        />
      )}
      <ExForm
        category="plugin"
        key={key}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onValueChange={(value) => {
          const category = value.category as string;
          if (category && category !== currentCategory) {
            setCurrentCategory(category);
          }
        }}
        onRemove={currentPlugin === newPlugin ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentPlugin;
          if (name === newPlugin) {
            name = value["_name_"] as string;
          }
          delete value["_name_"];
          omitEmptyArrayString(value);
          await update("plugin", name, value);
          handleSelectPlugin(name);
        }}
      />
    </PageShell>
  );
}
