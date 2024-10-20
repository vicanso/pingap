import { MainSidebar } from "@/components/sidebar-nav";
import useConfigState from "@/states/config";
import { formatError } from "@/helpers/util";
import { useAsync } from "react-async-hook";
import { ScrollRestoration } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { useTranslation } from "react-i18next";

export default function Config() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [fetchToml, toml] = useConfigState((state) => [
    state.fetchToml,
    state.toml,
  ]);
  useAsync(async () => {
    try {
      await fetchToml();
    } catch (err) {
      toast({
        title: t("fetchFail"),
        description: formatError(err),
      });
    }
  }, []);
  return (
    <>
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          <pre>{toml}</pre>
        </div>
      </div>
      <ScrollRestoration />
    </>
  );
}
