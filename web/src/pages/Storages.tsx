import { LoadingPage } from "@/components/loading";
import useConfigState, { Storage } from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import React from "react";
import { ExFormItemCategory, newStringOptions } from "@/constants";
import { useSearchParams } from "react-router-dom";
import { useEffect } from "react";
import { formatLabel } from "@/helpers/html";
import { useShallow } from "zustand/react/shallow";

function getStorageConfig(name: string, storages?: Record<string, Storage>) {
  if (!storages) {
    return {} as Storage;
  }
  return (storages[name] || {}) as Storage;
}

export default function Storages() {
  const storageI18n = useI18n("storage");
  const [searchParams, setSearchParams] = useSearchParams();
  const [config, initialized, update, remove] = useConfigState(
    useShallow((state) => [
      state.data,
      state.initialized,
      state.update,
      state.remove,
    ]),
  );

  const newStorage = "*";
  const storages = Object.keys(config.storages || {});
  storages.sort();
  storages.unshift(newStorage);

  const [currentStorage, setCurrentStorage] = React.useState(
    searchParams.get("name") || newStorage,
  );

  useEffect(() => {
    setCurrentStorage(searchParams.get("name") || newStorage);
  }, [searchParams]);

  if (!initialized) {
    return <LoadingPage />;
  }

  const handleSelectStorage = (name: string) => {
    setCurrentStorage(name);
    if (name === newStorage) {
      searchParams.delete("name");
    } else {
      searchParams.set("name", name);
    }
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
      handleSelectStorage(newStorage);
    });
  };

  return (
    <div className="grow overflow-auto p-4">
      <h2 className="h-8 mb-1">{formatLabel(currentStorage)}</h2>
      <ExForm
        category="storage"
        key={currentStorage}
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
    </div>
  );
}
