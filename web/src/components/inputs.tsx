import * as React from "react";
import { Plus, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { random } from "@/helpers/util";

interface InputsProps extends React.HTMLAttributes<HTMLDivElement> {
  defaultValue?: string[];
  onValueChange: (values: string[]) => void;
  placeholder?: string;
  className?: string;
}

function buildRows(defaultValue: string[]) {
  const arr = defaultValue.map((item) => ({
    id: random(),
    value: item || "",
  }));
  if (arr.length === 0) {
    arr.push({ id: random(), value: "" });
  }
  return arr;
}

export const Inputs = React.forwardRef<HTMLDivElement, InputsProps>(
  (
    { defaultValue = [], placeholder, className, onValueChange, ...props },
    ref,
  ) => {
    const { t } = useTranslation();
    const [inputs, setInputs] = React.useState(() => buildRows(defaultValue));

    const emit = (rows: { id: string; value: string }[]) => {
      const values: string[] = [];
      rows.forEach((item) => {
        const value = item.value.trim();
        if (value) {
          values.push(value);
        }
      });
      onValueChange(values);
    };

    const updateValue = (index: number, value: string) => {
      const next = inputs.map((row, idx) =>
        idx === index ? { ...row, value } : row,
      );
      setInputs(next);
      emit(next);
    };

    const addRow = () => {
      setInputs((prev) => [...prev, { id: random(), value: "" }]);
    };

    const removeRow = (index: number) => {
      if (inputs.length === 1) {
        const cleared = [{ ...inputs[0], value: "" }];
        setInputs(cleared);
        emit(cleared);
        return;
      }
      const next = inputs.filter((_, idx) => idx !== index);
      setInputs(next);
      emit(next);
    };

    return (
      <div className={cn("space-y-2", className)} ref={ref} {...props}>
        {inputs.map((item, index) => (
          <div key={item.id} className="flex items-center gap-2">
            <Input
              type="text"
              value={item.value}
              placeholder={placeholder}
              className="machine flex-1"
              onChange={(e) => updateValue(index, e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addRow();
                }
              }}
            />
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

Inputs.displayName = "Inputs";
