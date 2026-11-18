import * as React from "react";
import { ChevronDown, X, XIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import { Separator } from "@/components/ui/separator";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";

interface MultiSelectProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  options: {
    label: string;
    value: string;
    icon?: React.ComponentType<{ className?: string }>;
  }[];
  onValueChange: (value: string[]) => void;
  defaultValue?: string[];
  placeholder?: string;
  maxCount?: number;
  modalPopover?: boolean;
  className?: string;
}

export const MultiSelect = React.forwardRef<
  HTMLButtonElement,
  MultiSelectProps
>(
  (
    {
      options,
      onValueChange,
      defaultValue = [],
      placeholder = "Select options",
      maxCount = 3,
      modalPopover = false,
      className,
      ...props
    },
    ref,
  ) => {
    const { t } = useTranslation();
    const [selectedValues, setSelectedValues] =
      React.useState<string[]>(defaultValue);
    const [isPopoverOpen, setIsPopoverOpen] = React.useState(false);

    const handleInputKeyDown = (
      event: React.KeyboardEvent<HTMLInputElement>,
    ) => {
      if (event.key === "Enter") {
        setIsPopoverOpen(true);
      } else if (event.key === "Backspace" && !event.currentTarget.value) {
        const newSelectedValues = [...selectedValues];
        newSelectedValues.pop();
        setSelectedValues(newSelectedValues);
        onValueChange(newSelectedValues);
      }
    };

    const toggleOption = (option: string) => {
      const newSelectedValues = selectedValues.includes(option)
        ? selectedValues.filter((value) => value !== option)
        : [...selectedValues, option];
      setSelectedValues(newSelectedValues);
      onValueChange(newSelectedValues);
    };

    const handleClear = () => {
      setSelectedValues([]);
      onValueChange([]);
    };

    const clearExtraOptions = () => {
      const newSelectedValues = selectedValues.slice(0, maxCount);
      setSelectedValues(newSelectedValues);
      onValueChange(newSelectedValues);
    };

    const toggleAll = () => {
      if (selectedValues.length === options.length) {
        handleClear();
      } else {
        const allValues = options.map((option) => option.value);
        setSelectedValues(allValues);
        onValueChange(allValues);
      }
    };

    return (
      <Popover
        open={isPopoverOpen}
        onOpenChange={setIsPopoverOpen}
        modal={modalPopover}
      >
        <PopoverTrigger asChild>
          <button
            ref={ref}
            type="button"
            {...props}
            onClick={() => setIsPopoverOpen((prev) => !prev)}
            className={cn(
              "flex min-h-9 h-auto w-full cursor-pointer items-center justify-between rounded-md border border-input bg-input-surface px-2.5 py-1 text-left text-sm font-normal shadow-none transition-[color,box-shadow] outline-none",
              "hover:bg-input-surface hover:border-foreground/30 focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/35",
              className,
            )}
          >
            {selectedValues.length > 0 ? (
              <div className="flex w-full items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-1">
                  {selectedValues.slice(0, maxCount).map((value) => {
                    const option = options.find((o) => o.value === value);
                    const IconComponent = option?.icon;
                    return (
                      <span
                        key={value}
                        className="inline-flex items-center gap-1 rounded border border-border/80 bg-secondary px-1.5 py-0.5 text-xs font-normal text-secondary-foreground"
                      >
                        {IconComponent && (
                          <IconComponent className="size-3 shrink-0" />
                        )}
                        <span className="max-w-[180px] truncate">
                          {option?.label || value}
                        </span>
                        <span
                          role="button"
                          tabIndex={-1}
                          aria-label={t("formControls.removeItem")}
                          className="cursor-pointer rounded-sm text-muted-foreground hover:text-foreground"
                          onClick={(event) => {
                            event.stopPropagation();
                            toggleOption(value);
                          }}
                        >
                          <X className="size-3" />
                        </span>
                      </span>
                    );
                  })}
                  {selectedValues.length > maxCount && (
                    <span className="inline-flex items-center gap-1 rounded border border-border bg-muted px-1.5 py-0.5 text-xs font-medium text-muted-foreground">
                      <span className="figure">
                        {t("multiSelect.moreCount", {
                          count: selectedValues.length - maxCount,
                        })}
                      </span>
                      <span
                        role="button"
                        tabIndex={-1}
                        aria-label={t("multiSelect.clear")}
                        className="cursor-pointer rounded-sm hover:text-foreground"
                        onClick={(event) => {
                          event.stopPropagation();
                          clearExtraOptions();
                        }}
                      >
                        <X className="size-3" />
                      </span>
                    </span>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <span
                    role="button"
                    tabIndex={-1}
                    aria-label={t("multiSelect.clear")}
                    className="cursor-pointer rounded p-0.5 text-muted-foreground hover:text-foreground"
                    onClick={(event) => {
                      event.stopPropagation();
                      handleClear();
                    }}
                  >
                    <XIcon className="size-3.5" />
                  </span>
                  <Separator orientation="vertical" className="h-4" />
                  <ChevronDown className="size-4 text-muted-foreground" />
                </div>
              </div>
            ) : (
              <div className="flex w-full items-center justify-between gap-2">
                <span className="truncate px-0.5 text-sm text-muted-foreground">
                  {placeholder}
                </span>
                <ChevronDown className="size-4 shrink-0 text-muted-foreground" />
              </div>
            )}
          </button>
        </PopoverTrigger>
        <PopoverContent
          className="w-[var(--radix-popover-trigger-width)] min-w-[220px] p-0"
          align="start"
          onEscapeKeyDown={() => setIsPopoverOpen(false)}
        >
          <Command>
            <CommandInput
              placeholder={t("multiSelect.searchPlaceholder")}
              onKeyDown={handleInputKeyDown}
            />
            <CommandList>
              <CommandEmpty>{t("multiSelect.empty")}</CommandEmpty>
              <CommandGroup>
                <CommandItem
                  key="all"
                  onSelect={toggleAll}
                  className="cursor-pointer"
                >
                  <Checkbox
                    className="pointer-events-none"
                    tabIndex={-1}
                    aria-hidden
                    checked={
                      options.length > 0 &&
                      selectedValues.length === options.length
                        ? true
                        : selectedValues.length > 0
                          ? "indeterminate"
                          : false
                    }
                  />
                  <span>{t("multiSelect.selectAll")}</span>
                </CommandItem>
                {options.map((option) => {
                  const isSelected = selectedValues.includes(option.value);
                  return (
                    <CommandItem
                      key={option.value}
                      onSelect={() => toggleOption(option.value)}
                      className="cursor-pointer"
                    >
                      <Checkbox
                        className="pointer-events-none"
                        tabIndex={-1}
                        aria-hidden
                        checked={isSelected}
                      />
                      {option.icon && (
                        <option.icon className="size-4 text-muted-foreground" />
                      )}
                      <span className="truncate">{option.label}</span>
                    </CommandItem>
                  );
                })}
              </CommandGroup>
              <CommandSeparator />
              <CommandGroup>
                <div className="flex items-center justify-between">
                  {selectedValues.length > 0 && (
                    <>
                      <CommandItem
                        onSelect={handleClear}
                        className="flex-1 cursor-pointer justify-center"
                      >
                        {t("multiSelect.clear")}
                      </CommandItem>
                      <Separator orientation="vertical" className="h-5" />
                    </>
                  )}
                  <CommandItem
                    onSelect={() => setIsPopoverOpen(false)}
                    className="max-w-full flex-1 cursor-pointer justify-center"
                  >
                    {t("multiSelect.close")}
                  </CommandItem>
                </div>
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
    );
  },
);

MultiSelect.displayName = "MultiSelect";
