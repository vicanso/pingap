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
import { Loading } from "@/components/loading";
import {
  Item,
  ItemContent,
  ItemHeader,
  ItemFooter,
} from "@/components/ui/item";
import { History as HistoryIcon, Inbox } from "lucide-react";

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
      <Item key={item.created_at} variant="outline" className="bg-card">
        <ItemHeader className="text-[13px] font-medium">{date}</ItemHeader>
        <ItemContent>
          <pre className="max-h-48 max-w-full overflow-auto break-words whitespace-pre-wrap rounded-md bg-muted/40 p-2.5 font-mono text-[11px] leading-relaxed text-muted-foreground">
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
          className="size-8 cursor-pointer text-muted-foreground hover:text-foreground"
          title={historyI18n("title")}
          aria-label={historyI18n("title")}
          onClick={() => {
            fetchHistory();
          }}
        >
          <HistoryIcon className="size-4" />
        </Button>
      </SheetTrigger>
      <SheetContent className="flex flex-col !p-0">
        <div className="shrink-0 border-b border-border/80 px-6 py-5">
          <SheetHeader>
            <SheetTitle>{historyI18n("title")}</SheetTitle>
            <SheetDescription>{historyI18n("description")}</SheetDescription>
          </SheetHeader>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
          <div className="grid auto-rows-min gap-4 pb-4">
            {fetching && <Loading className="mt-2" />}
            {!fetching && items.length === 0 && (
              <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border/80 bg-muted/20 px-4 py-12 text-center">
                <div className="mb-3 flex size-10 items-center justify-center rounded-xl bg-muted text-muted-foreground">
                  <Inbox className="size-5" strokeWidth={1.8} />
                </div>
                <p className="text-sm text-muted-foreground">
                  {historyI18n("noHistory")}
                </p>
              </div>
            )}
            {!fetching && items}
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
