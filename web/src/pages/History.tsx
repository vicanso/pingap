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
import {
  Check,
  ClipboardCopy,
  History as HistoryIcon,
  Inbox,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

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
  const [copiedAt, setCopiedAt] = React.useState<number | null>(null);
  const copyTimerRef = React.useRef<number | null>(null);
  React.useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);
  const { t } = useTranslation();
  const historyI18n = useI18n("history");
  if (!basicInfo.support_history) {
    return <></>;
  }
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
  const handleRestore = async (data: Record<string, unknown>) => {
    try {
      await props.onRestore(data);
      toast.success(historyI18n("restoreSuccess"));
      setOpen(false);
    } catch (err) {
      toast.error(formatError(err));
    }
  };
  const handleCopyJson = async (createdAt: number, jsonText: string) => {
    try {
      await navigator.clipboard.writeText(jsonText);
      setCopiedAt(createdAt);
      toast.success(historyI18n("copiedJson"));
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedAt(null);
      }, 1500);
    } catch (err) {
      toast.error(formatError(err));
    }
  };
  const items = history.map((item, index) => {
    const date = new Date(item.created_at * 1000).toLocaleString();
    const jsonText = JSON.stringify(item.data, null, 2);
    const isCopied = copiedAt === item.created_at;
    return (
      <Item key={item.created_at} variant="outline" className="bg-card">
        <ItemHeader className="flex items-center justify-between gap-2 text-[13px] font-medium">
          <div className="flex items-center gap-2">
            <span>{date}</span>
            {index === 0 && (
              <span className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[11px] font-medium text-primary">
                {historyI18n("latest")}
              </span>
            )}
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="size-7 cursor-pointer text-muted-foreground hover:text-foreground"
            aria-label={historyI18n("copyJson")}
            title={historyI18n("copyJson")}
            onClick={() => handleCopyJson(item.created_at, jsonText)}
          >
            {isCopied ? (
              <Check className="size-3.5 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <ClipboardCopy className="size-3.5" />
            )}
          </Button>
        </ItemHeader>
        <ItemContent>
          <pre className="max-h-48 max-w-full overflow-auto break-words whitespace-pre-wrap rounded-md bg-muted/40 p-2.5 font-mono text-[11px] leading-relaxed text-muted-foreground">
            {jsonText}
          </pre>
        </ItemContent>
        {!basicInfo.read_only && (
          <ItemFooter>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full cursor-pointer"
                >
                  {historyI18n("restore")}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    {historyI18n("restoreConfirmTitle")}
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    {historyI18n("restoreConfirmDescription")}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel className="cursor-pointer">
                    {t("cancel")}
                  </AlertDialogCancel>
                  <AlertDialogAction
                    className="cursor-pointer"
                    onClick={() => {
                      handleRestore(item.data);
                    }}
                  >
                    {t("confirm")}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </ItemFooter>
        )}
      </Item>
    );
  });
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <TooltipProvider delayDuration={200}>
        <Tooltip>
          <TooltipTrigger asChild>
            <SheetTrigger asChild>
              <Button
                variant="outline"
                size="icon"
                className="size-8 cursor-pointer text-muted-foreground hover:text-foreground"
                aria-label={historyI18n("title")}
                onClick={() => {
                  fetchHistory();
                }}
              >
                <HistoryIcon className="size-4" />
              </Button>
            </SheetTrigger>
          </TooltipTrigger>
          <TooltipContent side="bottom">{historyI18n("title")}</TooltipContent>
        </Tooltip>
      </TooltipProvider>
      <SheetContent className="flex flex-col !p-0">
        <div className="shrink-0 border-b border-border px-6 py-5">
          <SheetHeader>
            <SheetTitle>{historyI18n("title")}</SheetTitle>
            <SheetDescription>{historyI18n("description")}</SheetDescription>
          </SheetHeader>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
          <div className="grid auto-rows-min gap-4 pb-4">
            {fetching && <Loading className="mt-2" />}
            {!fetching && items.length === 0 && (
              <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-card/50 px-4 py-12 text-center">
                <div className="mb-3 flex size-10 items-center justify-center rounded-md bg-muted text-muted-foreground">
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
