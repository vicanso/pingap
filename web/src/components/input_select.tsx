import * as React from "react";
import { List, PencilLine } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ExFormOption } from "@/constants";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface InputSelectProps extends React.HTMLAttributes<HTMLDivElement> {
  defaultValue?: string;
  name: string;
  selectPlaceholder: string;
  inputPlaceholder: string;
  onValueChange: (values: string) => void;
  options: ExFormOption[] | undefined;
}

export const InputSelect = React.forwardRef<HTMLDivElement, InputSelectProps>(
  (
    {
      defaultValue = "",
      onValueChange,
      options,
      selectPlaceholder,
      inputPlaceholder,
      name,
      className,
      ...props
    },
    ref,
  ) => {
    const { t } = useTranslation();
    const initialInOptions =
      !defaultValue ||
      Boolean(options?.some((option) => option.value == defaultValue));
    const [isInputMode, setIsInputMode] = React.useState(!initialInOptions);
    const [currentValue, setCurrentValue] = React.useState(defaultValue || "");

    const toggleLabel = isInputMode
      ? t("formControls.presetSelectTips")
      : t("formControls.customInputTips");

    return (
      <div
        className={cn("flex items-center gap-2", className)}
        ref={ref}
        {...props}
      >
        <div className="min-w-0 flex-1">
          {isInputMode ? (
            <Input
              type="text"
              className="machine"
              value={currentValue}
              onChange={(e) => {
                const next = e.target.value;
                setCurrentValue(next);
                onValueChange(next);
              }}
              placeholder={inputPlaceholder}
            />
          ) : (
            <Select
              value={currentValue}
              onValueChange={(option) => {
                const next = option === "none" ? "" : option;
                setCurrentValue(next);
                onValueChange(next);
              }}
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder={selectPlaceholder} />
              </SelectTrigger>
              <SelectContent>
                {options?.map((opt) => (
                  <SelectItem key={`${name}-${opt.value}`} value={opt.option}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              variant={isInputMode ? "secondary" : "outline"}
              size="icon"
              aria-label={toggleLabel}
              className="size-9 shrink-0 cursor-pointer"
              onClick={() => setIsInputMode((prev) => !prev)}
            >
              {isInputMode ? (
                <List className="size-4" />
              ) : (
                <PencilLine className="size-4" />
              )}
            </Button>
          </TooltipTrigger>
          <TooltipContent side="top">{toggleLabel}</TooltipContent>
        </Tooltip>
      </div>
    );
  },
);

InputSelect.displayName = "InputSelect";
