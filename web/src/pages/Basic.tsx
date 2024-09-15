import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";
import { Loading } from "@/components/loading";
import useConfigState from "@/states/config";
import {
  ExForm,
  ExFormItem,
  ExFormItemCategory,
  getBooleanOptions,
} from "@/components/ex-form";
import { z } from "zod";
import { useI18n } from "@/i18n";

export default function Basic() {
  const basicI18n = useI18n("basic");
  const [config, initialized] = useConfigState((state) => [
    state.data,
    state.initialized,
  ]);
  const basic = config.basic;

  const items: ExFormItem[] = [
    {
      name: "name",
      label: basicI18n("name"),
      placehodler: basicI18n("namePlaceholder"),
      defaultValue: basic.name,
      span: 4,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "threads",
      label: basicI18n("threads"),
      placehodler: basicI18n("threadsPlaceholder"),
      defaultValue: basic.threads,
      span: 2,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "work_stealing",
      label: basicI18n("workStealing"),
      placehodler: "",
      defaultValue: basic.work_stealing || null,
      span: 2,
      category: ExFormItemCategory.RADIOS,
      options: getBooleanOptions(),
    },
  ];
  const schema = z.object({
    threads: z.number().optional(),
  });
  return (
    <div>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          {!initialized && <Loading />}
          {initialized && <ExForm items={items} schema={schema} />}
        </div>
      </div>
    </div>
  );
}
