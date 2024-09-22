import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";
import useConfigState from "@/states/config";
import { useAsync } from "react-async-hook";
import { useToast } from "@/hooks/use-toast";
import { formatError } from "@/helpers/util";
import { useTranslation } from "react-i18next";

export default function Home() {
  const { toast } = useToast();
  const { t } = useTranslation();

  const [toml, fetchToml] = useConfigState((state) => [
    state.toml,
    state.fetchToml,
  ]);
  useAsync(async () => {
    try {
      await fetchToml();
    } catch (err) {
      toast({
        title: t("fetchTomlFailTitle"),
        description: formatError(err),
      });
    }
  }, []);
  return (
    <div>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          <h1 className="font-semibold">{t("tomlTitle")}</h1>
          <div className="text-xs font-medium">{t("tomlDescription")}</div>
          <pre className="mt-4 text-xs text-muted-foreground">{toml}</pre>
        </div>
      </div>
    </div>
  );
}
