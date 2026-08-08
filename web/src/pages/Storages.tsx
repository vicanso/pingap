import { LoadingPage } from "@/components/loading";
import useConfigState, { Storage } from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import { ExFormItemCategory, newStringOptions } from "@/constants";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import History from "@/pages/History";
import { EntityBadge } from "@/components/config-entity-badge";
import { PageShell } from "@/components/page-shell";
import { ConfigEntityList, EntityText } from "@/components/config-entity-list";
import { STORAGES } from "@/routers";

function getStorageConfig(name: string, storages?: Record<string, Storage>) {
  if (!storages) {
    return {} as Storage;
  }
  return (storages[name] || {}) as Storage;
}

export default function Storages() {
  const storageI18n = useI18n("storage");
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

  const newStorage = "*";
  const storages = Object.keys(config.storages || {});
  storages.sort();

  // No `name` in the url means the category overview, `*` means the create form.
  const currentStorage = searchParams.get("name") || "";

  if (!initialized) {
    return <LoadingPage />;
  }

  if (!currentStorage) {
    return (
      <ConfigEntityList<Storage>
        title={storageI18n("title")}
        summary={storageI18n("summary", { count: storages.length })}
        nameLabel={storageI18n("name")}
        addLabel={storageI18n("add")}
        emptyText={storageI18n("empty")}
        basePath={STORAGES}
        newValue={newStorage}
        names={storages}
        values={config.storages || {}}
        columns={[
          {
            key: "category",
            label: storageI18n("category"),
            render: (value) => <EntityText value={value?.category} />,
          },
          {
            key: "remark",
            label: storageI18n("remark"),
            render: (value) => <EntityText value={value?.remark} />,
          },
        ]}
      />
    );
  }

  const handleSelectStorage = (name: string) => {
    searchParams.set("name", name);
    setSearchParams(searchParams);
  };

  const backToList = () => {
    searchParams.delete("name");
    setSearchParams(searchParams);
  };

  const storageConfig = getStorageConfig(currentStorage, config.storages);

  const items: ExFormItem[] = [
    {
      name: "category",
      label: storageI18n("category"),
      placeholder: storageI18n("categoryPlaceholder"),
      defaultValue: storageConfig.category,
      category: ExFormItemCategory.SELECT,
      span: 3,
      options: newStringOptions(["config", "secret"], true),
    },
    {
      name: "secret",
      label: storageI18n("secret"),
      placeholder: storageI18n("secretPlaceholder"),
      defaultValue: storageConfig.secret,
      category: ExFormItemCategory.TEXT,
      span: 3,
    },
    {
      name: "value",
      label: storageI18n("value"),
      placeholder: "",
      defaultValue: storageConfig.value,
      rows: 5,
      span: 6,
      notTrim: true,
      category: ExFormItemCategory.TEXTAREA,
    },
    {
      name: "remark",
      label: storageI18n("remark"),
      placeholder: "",
      defaultValue: storageConfig.remark,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
  ];
  if (currentStorage === newStorage) {
    items.unshift({
      name: "name",
      label: storageI18n("name"),
      placeholder: storageI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const schema = z.object({
    category: z.string(),
  });

  const onRemove = async () => {
    return remove("storage", currentStorage).then(() => {
      backToList();
    });
  };

  return (
    <PageShell
      title={storageI18n("title")}
      description={storageI18n("description")}
      width="narrow"
      backTo={STORAGES}
      backLabel={i18n("backToList")}
      badge={
        <EntityBadge
          name={currentStorage}
          isNew={currentStorage === newStorage}
        />
      }
      actions={
        currentStorage !== newStorage ? (
          <History
            category="storage"
            name={currentStorage}
            onRestore={async (data) => {
              await update("storage", currentStorage, data);
            }}
          />
        ) : undefined
      }
    >
      <ExForm
        category="storage"
        key={`${currentStorage}-${version}`}
        items={items}
        schema={schema}
        onRemove={currentStorage === newStorage ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentStorage;
          if (name === newStorage) {
            name = value["name"] as string;
          }
          await update("storage", name, value);
          handleSelectStorage(name);
        }}
      />
    </PageShell>
  );
}
