import useBasicState from "@/states/basic";
import useConfigState, { History } from "@/states/config";
import { useShallow } from "zustand/react/shallow";
import { useI18n } from "@/i18n";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import React from "react";
import { toast } from "sonner";
import { formatError } from "@/helpers/util";
import { LoadingPage } from "@/components/loading";
import {
  Item,
  ItemContent,
  ItemHeader,
  ItemFooter,
} from "@/components/ui/item";
import { ScrollArea } from "@/components/ui/scroll-area";
import { History as HistoryIcon } from "lucide-react";

export default function HistoryPage(props: {
  category: string;
  name: string;
  onRestore: (data: Record<string, unknown>) => Promise<void>;
}) {
  const [getHistory] = useConfigState(
    useShallow((state) => [state.getHistory]),
  );
  const [basicInfo] = useBasicState(useShallow((state) => [state.data]));
  const [fetching, setFetching] = React.useState(false);
  const [history, setHistory] = React.useState<History[]>([]);
  const [open, setOpen] = React.useState(false);
  const fetchHistory = async () => {
    if (fetching) {
      return;
    }
    setFetching(true);
    setHistory([]);
    try {
      const data = await getHistory(props.category, props.name);
      setHistory(data);
    } catch (err) {
      toast(formatError(err));
    } finally {
      setFetching(false);
    }
  };
  const historyI18n = useI18n("history");
  if (!basicInfo.support_history) {
    return <></>;
  }
  const handleRestore = async (data: Record<string, unknown>) => {
    try {
      await props.onRestore(data);
      toast.success(historyI18n("restoreSuccess"));
      setOpen(false);
    } catch (err) {
      toast.error(formatError(err));
    }
  };
  const items = history.map((item) => {
    const date = new Date(item.created_at * 1000).toLocaleString();
    return (
      <Item key={item.created_at} variant="outline">
        <ItemHeader>{date}</ItemHeader>
        <ItemContent>
          <pre className="overflow-x-auto max-w-full text-xs text-muted-foreground whitespace-pre-wrap break-words">
            {JSON.stringify(item.data, null, 2)}
          </pre>
        </ItemContent>
        <ItemFooter>
          <Button
            variant="outline"
            size="sm"
            className="w-full cursor-pointer"
            onClick={() => {
              handleRestore(item.data);
            }}
          >
            {historyI18n("restore")}
          </Button>
        </ItemFooter>
      </Item>
    );
  });
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          className="cursor-pointer ml-2"
          onClick={() => {
            fetchHistory();
          }}
        >
          <HistoryIcon />
        </Button>
      </SheetTrigger>
      <SheetContent>
        <ScrollArea>
          <SheetHeader>
            <SheetTitle>{historyI18n("title")}</SheetTitle>
            <SheetDescription>{historyI18n("description")}</SheetDescription>
          </SheetHeader>
          <div className="grid flex-1 auto-rows-min gap-6 px-4">
            {fetching && <LoadingPage />}
            {!fetching && items.length === 0 && (
              <div className="text-muted-foreground">
                {historyI18n("noHistory")}
              </div>
            )}
            {!fetching && items}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
