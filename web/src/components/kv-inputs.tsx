import * as React from "react";
import { Plus, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { random } from "@/helpers/util";

interface KvInputsProps extends React.HTMLAttributes<HTMLDivElement> {
  defaultValue?: string[];
  separator?: string;
  onValueChange: (values: string[]) => void;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
  className?: string;
  cols?: number[];
}

interface KvRow {
  id: string;
  key: string;
  value: string;
}

function buildKvRows(defaultValue: string[], separator: string): KvRow[] {
  const arr = defaultValue.map((item) => {
    // Split at the first separator only. A value may contain the separator
    // itself (a header value such as http://host), and cutting it there
    // would drop the rest of the value the next time the list is saved.
    const index = item.indexOf(separator);
    return {
      id: random(),
      key: index === -1 ? item : item.slice(0, index),
      value: index === -1 ? "" : item.slice(index + separator.length),
    };
  });
  if (arr.length === 0) {
    arr.push({ id: random(), key: "", value: "" });
  }
  return arr;
}

export const KvInputs = React.forwardRef<HTMLDivElement, KvInputsProps>(
  (
    {
      defaultValue = [],
      separator = ":",
      keyPlaceholder = "Input key",
      valuePlaceholder = "Input value",
      className,
      onValueChange,
      cols = [2, 2],
      ...props
    },
    ref,
  ) => {
    const { t } = useTranslation();
    const [inputs, setInputs] = React.useState(() =>
      buildKvRows(defaultValue, separator),
    );

    const emit = (rows: KvRow[]) => {
      const values: string[] = [];
      rows.forEach((item) => {
        const k = item.key.trim();
        const v = item.value.trim();
        if (k || v) {
          values.push(`${k}${separator}${v}`.trim());
        }
      });
      onValueChange(values);
    };

    const updateKeyValue = (
      index: number,
      rawValue: string,
      isKey: boolean,
    ) => {
      const next = inputs.map((row, idx) => {
        if (idx !== index) {
          return row;
        }
        return isKey ? { ...row, key: rawValue } : { ...row, value: rawValue };
      });
      setInputs(next);
      emit(next);
    };

    const addRow = () => {
      setInputs((prev) => [...prev, { id: random(), key: "", value: "" }]);
    };

    const removeRow = (index: number) => {
      if (inputs.length === 1) {
        const cleared = [{ ...inputs[0], key: "", value: "" }];
        setInputs(cleared);
        emit(cleared);
        return;
      }
      const next = inputs.filter((_, idx) => idx !== index);
      setInputs(next);
      emit(next);
    };

    const wideKey = (cols[0] ?? 2) > (cols[1] ?? 2);
    const trimmedSep = separator.trim();

    return (
      <div className={cn("space-y-2", className)} ref={ref} {...props}>
        {inputs.map((item, index) => (
          <div key={item.id} className="flex items-center gap-2">
            <div className={wideKey ? "min-w-0 flex-[3]" : "min-w-0 flex-1"}>
              <Input
                type="text"
                className="machine"
                placeholder={keyPlaceholder}
                value={item.key}
                onChange={(e) => updateKeyValue(index, e.target.value, true)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addRow();
                  }
                }}
              />
            </div>
            {trimmedSep && (
              <span className="machine shrink-0 text-xs text-muted-foreground select-none">
                {trimmedSep}
              </span>
            )}
            <div className="min-w-0 flex-1">
              <Input
                type="text"
                className="machine"
                placeholder={valuePlaceholder}
                value={item.value}
                onChange={(e) => updateKeyValue(index, e.target.value, false)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addRow();
                  }
                }}
              />
            </div>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-label={t("formControls.removeItem")}
              className="size-9 shrink-0 cursor-pointer text-muted-foreground hover:text-destructive"
              onClick={() => removeRow(index)}
            >
              <X className="size-4" />
            </Button>
          </div>
        ))}
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-8 cursor-pointer gap-1.5 text-xs"
          onClick={addRow}
        >
          <Plus className="size-3.5" />
          {t("formControls.addItem")}
        </Button>
      </div>
    );
  },
);

KvInputs.displayName = "KvInputs";
