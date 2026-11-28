import * as React from "react";
import { ChevronDown, ChevronUp, Search, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface SortCheckboxsProps extends React.HTMLAttributes<HTMLDivElement> {
  defaultValue?: string[];
  onValueChange: (values: string[]) => void;
  className?: string;
  options: {
    label: string;
    value: string;
  }[];
}

export const SortCheckboxs = React.forwardRef<
  HTMLDivElement,
  SortCheckboxsProps
>(({ defaultValue = [], options, className, onValueChange, ...props }, ref) => {
  const { t } = useTranslation();
  const [selectedItems, setSelectedItems] = React.useState(defaultValue);
  const [filter, setFilter] = React.useState("");

  const labelByValue = React.useMemo(() => {
    const map = new Map<string, string>();
    options.forEach((opt) => map.set(opt.value, opt.label));
    return map;
  }, [options]);

  const keyword = filter.trim().toLowerCase();
  const visibleOptions = React.useMemo(() => {
    if (!keyword) {
      return options;
    }
    return options.filter(
      (opt) =>
        opt.label.toLowerCase().includes(keyword) ||
        opt.value.toLowerCase().includes(keyword),
    );
  }, [options, keyword]);

  const handleSelect = (value: string, checked: boolean) => {
    const next = checked
      ? selectedItems.includes(value)
        ? selectedItems
        : [...selectedItems, value]
      : selectedItems.filter((item) => item !== value);
    setSelectedItems(next);
    onValueChange(next);
  };

  const handleMove = (index: number, delta: -1 | 1) => {
    const target = index + delta;
    if (target < 0 || target >= selectedItems.length) {
      return;
    }
    const next = selectedItems.slice();
    const tmp = next[target];
    next[target] = next[index];
    next[index] = tmp;
    setSelectedItems(next);
    onValueChange(next);
  };

  return (
    <div
      className={cn("grid items-start gap-3 sm:grid-cols-2", className)}
      ref={ref}
      {...props}
    >
      <div className="overflow-hidden rounded-lg border border-border bg-card">
        <div className="border-b border-border px-3 py-2">
          <span className="region-label text-xs">
            {t("formControls.availableOptions")}
          </span>
        </div>
        {options.length > 8 && (
          <div className="relative border-b border-border px-2 py-1.5">
            <Search className="pointer-events-none absolute left-4 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="text"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              enterKeyHint="search"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder={t("formControls.filterOptions", {
                defaultValue: "Filter options…",
              })}
              className="h-8 pl-7 pr-7 text-base sm:text-xs"
            />
            {filter && (
              <button
                type="button"
                onClick={() => setFilter("")}
                aria-label={t("multiSelect.clear")}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 cursor-pointer rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="size-3.5" />
              </button>
            )}
          </div>
        )}
        <div className="max-h-64 space-y-0.5 overflow-y-auto overscroll-contain p-1.5">
          {visibleOptions.length === 0 ? (
            <p className="px-2 py-4 text-center text-xs text-muted-foreground">
              {t("listFilterEmpty")}
            </p>
          ) : (
            visibleOptions.map((item) => {
              const id = `sort-opt-${item.value}`;
              const checked = selectedItems.includes(item.value);
              return (
                <label
                  key={item.value}
                  htmlFor={id}
                  className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-[13px] transition-colors hover:bg-accent/50"
                >
                  <Checkbox
                    id={id}
                    checked={checked}
                    onCheckedChange={(state) =>
                      handleSelect(item.value, state === true)
                    }
                  />
                  <span className="truncate font-medium">{item.label}</span>
                </label>
              );
            })
          )}
        </div>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-card">
        <div className="flex items-center justify-between border-b border-border px-3 py-2">
          <span className="region-label text-xs">
            {t("formControls.selectedOrder")}
          </span>
          <span className="figure text-xs text-muted-foreground">
            {selectedItems.length}
          </span>
        </div>
        {selectedItems.length === 0 ? (
          <p className="px-3 py-6 text-center text-xs text-muted-foreground">
            {t("formControls.emptySelected")}
          </p>
        ) : (
          <div className="max-h-64 divide-y divide-border/50 overflow-y-auto overscroll-contain">
            {selectedItems.map((value, index) => (
              <div
                key={value}
                className="flex items-center gap-2 px-2.5 py-1.5 text-[13px]"
              >
                <span className="figure w-4 shrink-0 text-xs text-muted-foreground">
                  {index + 1}.
                </span>
                <span className="machine min-w-0 flex-1 truncate">
                  {labelByValue.get(value) || value}
                </span>
                <div className="flex shrink-0 items-center gap-0.5">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    disabled={index === 0}
                    aria-label={t("formControls.moveUp")}
                    className="size-7 cursor-pointer text-muted-foreground hover:text-foreground disabled:opacity-30"
                    onClick={() => handleMove(index, -1)}
                  >
                    <ChevronUp className="size-3.5" />
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    disabled={index === selectedItems.length - 1}
                    aria-label={t("formControls.moveDown")}
                    className="size-7 cursor-pointer text-muted-foreground hover:text-foreground disabled:opacity-30"
                    onClick={() => handleMove(index, 1)}
                  >
                    <ChevronDown className="size-3.5" />
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    aria-label={t("formControls.removeItem")}
                    className="size-7 cursor-pointer text-muted-foreground hover:text-destructive"
                    onClick={() => handleSelect(value, false)}
                  >
                    <X className="size-3.5" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
});

SortCheckboxs.displayName = "SortCheckboxs";
