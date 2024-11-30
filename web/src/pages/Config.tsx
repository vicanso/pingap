import useConfigState from "@/states/config";
import { formatError } from "@/helpers/util";
import { useAsync } from "react-async-hook";
import { useToast } from "@/hooks/use-toast";
import { useTranslation } from "react-i18next";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useShallow } from "zustand/react/shallow";

export default function Config() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [fetchToml, fullToml, originalToml] = useConfigState(
    useShallow((state) => [
      state.fetchToml,
      state.fullToml,
      state.originalToml,
    ]),
  );
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
  const different = fullToml != originalToml;
  return (
    <div className="grow lg:border-l overflow-auto p-4">
      <Tabs defaultValue="original">
        {different && (
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="original">{t("original")}</TabsTrigger>
            <TabsTrigger value="full">{t("full")}</TabsTrigger>
          </TabsList>
        )}
        <TabsContent value="full">
          <Card className="p-4">
            <pre>{fullToml}</pre>
          </Card>
        </TabsContent>
        <TabsContent value="original">
          <Card className="p-4">
            <pre>{originalToml}</pre>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
