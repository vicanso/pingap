import { LoadingPage } from "@/components/loading";
import useConfigState, { Storage } from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";
import { ExFormItemCategory, newStringOptions } from "@/constants";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import History from "@/pages/History";

function getStorageConfig(name: string, storages?: Record<string, Storage>) {
  if (!storages) {
    return {} as Storage;
  }
  return (storages[name] || {}) as Storage;
}

export default function Storages() {
  const storageI18n = useI18n("storage");
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
  storages.unshift(newStorage);

  const currentStorage = searchParams.get("name") || newStorage;

  if (!initialized) {
    return <LoadingPage />;
  }

  const handleSelectStorage = (name: string) => {
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

  const selectItems = storages.map((storage) => {
    let name = storage;
    if (name === newStorage) {
      name = "new";
    }
    return (
      <SelectItem key={storage} value={storage}>
        {name}
      </SelectItem>
    );
  });

  return (
    <div className="grow overflow-auto p-4">
      <div className="flex flex-row items-center gap-2 mb-2">
        <Label>{storageI18n("storage")}:</Label>
        <Select
          value={currentStorage}
          onValueChange={(value) => {
            if (value === newStorage) {
              searchParams.delete("name");
            } else {
              searchParams.set("name", value);
            }
            setSearchParams(searchParams);
          }}
        >
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder={storageI18n("storagePlaceholder")} />
          </SelectTrigger>
          <SelectContent>{selectItems}</SelectContent>
        </Select>
        {currentStorage !== newStorage && (
          <History
            category="storage"
            name={currentStorage}
            onRestore={async (data) => {
              await update("storage", currentStorage, data);
            }}
          />
        )}
      </div>
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
    </div>
  );
}
