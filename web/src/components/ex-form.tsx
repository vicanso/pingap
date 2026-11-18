import {
  LoaderCircle,
  UnfoldVertical,
  FoldVertical,
  CircleHelp,
  RotateCcw,
} from "lucide-react";
import { PluginCategoryPicker } from "@/components/plugin-category-picker";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Form,
  FormControl,
  FormItem,
  FormLabel,
  FormMessage,
  FormField,
} from "@/components/ui/form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { MultiSelect } from "@/components/multi-select";
import { Button } from "@/components/ui/button";
import React from "react";
import { useTranslation } from "react-i18next";
import { formatError } from "@/helpers/util";
import { KvInputs } from "@/components/kv-inputs";
import { SortCheckboxs } from "@/components/sort-checkboxs";
import { ExFormOption, ExFormItemCategory } from "@/constants";
import { Inputs } from "@/components/inputs";
import { CombinedAuths } from "@/components/combined-auths";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { InputSelect } from "./input_select";
import { useIsMobile } from "@/hooks/use-mobile";
import useBasicState from "@/states/basic";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useBlocker } from "react-router-dom";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

function getOption(
  value: string | number | boolean | null | undefined,
  options?: ExFormOption[],
) {
  const found = options?.find((item) => {
    if (item.value == value) {
      return true;
    }
    return false;
  });
  if (!found) {
    return "";
  }
  return found.option;
}
function getOptionValue(option: string, options?: ExFormOption[]) {
  const found = options?.find((item) => {
    if (item.option == option) {
      return true;
    }
    return false;
  });
  if (!found) {
    return null;
  }
  return found.value;
}

export interface ExFormItem {
  name: string;
  label: string;
  placeholder: string;
  category: ExFormItemCategory;
  readOnly?: boolean;
  width?: number;
  options?: ExFormOption[];
  span: number;
  rows?: number;
  cols?: number[];
  separator?: string;
  notTrim?: boolean;
  nullAsEmpty?: boolean;
  /** Optional group title; rendered as a full-width section header when it changes. */
  section?: string;
  /** Short help shown as a ? tooltip on the label. */
  tips?: string;
  defaultValue: string[] | string | number | boolean | null | undefined;
}

function FieldLabel({ label, tips }: { label: string; tips?: string }) {
  if (!tips) {
    return <FormLabel>{label}</FormLabel>;
  }
  // Keep the help control outside <FormLabel> so it is not folded into the
  // input's accessible name ("Threads Help").
  return (
    <div className="flex items-center gap-1.5">
      <FormLabel className="!mt-0">{label}</FormLabel>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            className="inline-flex size-4 shrink-0 cursor-help items-center justify-center rounded-sm text-muted-foreground outline-none transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
            aria-label="Help"
            onClick={(e) => e.preventDefault()}
          >
            <CircleHelp className="size-3.5" strokeWidth={1.8} />
          </button>
        </TooltipTrigger>
        <TooltipContent
          side="top"
          className="max-w-xs border border-border bg-popover text-xs leading-relaxed text-popover-foreground shadow-md"
        >
          {tips}
        </TooltipContent>
      </Tooltip>
    </div>
  );
}

export type FormContextValue = {
  onSave(data: Record<string, unknown>): Promise<void>;
  onValueChange(data: Record<string, unknown>): void;
  onRemove(): Promise<void>;
};

interface ExFormProps {
  category?: string;
  schema: z.ZodSchema<Record<string, unknown>>;
  items: ExFormItem[];
  defaultShow?: number;
  onlyModified?: boolean;
  allowSave?: boolean;
  cols?: number;
  onSave?: FormContextValue["onSave"];
  onValueChange?: FormContextValue["onValueChange"];
  onRemove?: FormContextValue["onRemove"];
}

export function ExForm({
  category = "",
  schema,
  items,
  defaultShow = 0,
  onlyModified,
  allowSave = false,
  onSave,
  onRemove,
  onValueChange,
  cols = 6,
}: ExFormProps) {
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  // An account that may not change anything has no use for the buttons
  // that do.
  const readOnly = useBasicState((state) => state.data.read_only);
  // One column on phones so span-3/6 fields don't squeeze into unreadably
  // narrow halves of a still-six-column grid.
  const effectiveCols = isMobile ? 1 : cols;
  const maxCount = items.length;
  let showCountDefaultValue = defaultShow;
  let showAllKey = "";
  if (category) {
    showAllKey = `${category}.showAll`;
  }
  if (showAllKey && localStorage.getItem(showAllKey)) {
    showCountDefaultValue = maxCount;
  }

  const [showCount, setShowCount] = React.useState(showCountDefaultValue);
  const [processing, setProcessing] = React.useState(false);
  const [updatedValues, setUpdatedValues] = React.useState(
    {} as Record<string, unknown>,
  );
  const [updatedCount, setUpdatedCount] = React.useState(0);
  const [resetNonce, setResetNonce] = React.useState(0);
  const defaultValues: Record<string, unknown> = {};
  const originalValues: Record<string, unknown> = {};
  items.forEach((item) => {
    let { defaultValue } = item;
    originalValues[item.name] = defaultValue;
    if (defaultValue == null) {
      switch (item.category) {
        case ExFormItemCategory.NUMBER:
        case ExFormItemCategory.TEXTAREA:
        case ExFormItemCategory.TEXT: {
          defaultValue = "";
          break;
        }
      }
    } else {
      switch (item.category) {
        case ExFormItemCategory.NUMBER: {
          defaultValue = defaultValue.toString();
          break;
        }
      }
    }
    defaultValues[item.name] = defaultValue;
  });
  const setUpdated = (key: string, value: unknown) => {
    // Functional update: rapid edits (typing) must not race on a stale
    // `updatedValues` closure or the dirty count / leave-guard goes wrong.
    setUpdatedValues((prev) => {
      const values = { ...prev };
      if (Object.is(originalValues[key], value)) {
        delete values[key];
      } else {
        values[key] = value;
      }
      setUpdatedCount(Object.keys(values).length);
      onValueChange?.(values);
      return values;
    });
  };
  const form = useForm({
    // @ts-expect-error - zodResolver has complex type constraints that are difficult to satisfy with dynamic schemas
    resolver: zodResolver(schema as z.ZodSchema<Record<string, unknown>>),
    defaultValues,
  });
  const dirty = updatedCount > 0;
  // Saving and removing navigate on their way out (to the saved entity, or back
  // to the list). Those redirects run before the dirty count is cleared, so the
  // guard has to know to stand down for them. A ref, because useBlocker reads it
  // at navigation time rather than at render time.
  const leavingOnPurpose = React.useRef(false);

  // Closing the tab or reloading: the browser shows its own confirmation.
  React.useEffect(() => {
    if (!dirty) {
      return;
    }
    const confirmClose = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", confirmClose);
    return () => window.removeEventListener("beforeunload", confirmClose);
  }, [dirty]);

  // Navigating inside the app: react-router hands us the decision.
  const blocker = useBlocker(
    ({ currentLocation, nextLocation }) =>
      dirty &&
      !leavingOnPurpose.current &&
      currentLocation.pathname + currentLocation.search !==
        nextLocation.pathname + nextLocation.search,
  );

  // 2. Define a submit handler.
  async function onSubmit() {
    if (!onSave || processing) {
      return;
    }
    let data = Object.assign({}, updatedValues);
    if (!onlyModified) {
      data = Object.assign({}, originalValues, updatedValues);
    }
    setProcessing(true);
    leavingOnPurpose.current = true;
    try {
      await onSave(data);
      setUpdatedCount(0);
      toast(t("saveSuccessTitle"), {
        description: t("saveSuccessDescription"),
      });
    } catch (err) {
      toast(t("saveConfigFail"), {
        description: formatError(err),
      });
    } finally {
      leavingOnPurpose.current = false;
      setProcessing(false);
    }
  }

  async function handleRemove() {
    if (!onRemove || processing) {
      return;
    }
    setProcessing(true);
    leavingOnPurpose.current = true;
    try {
      await onRemove();
      toast(t("removeSuccessTitle"), {
        description: t("removeSuccessDescription"),
      });
    } catch (err) {
      toast(t("removeFailTitle"), {
        description: formatError(err),
      });
    } finally {
      leavingOnPurpose.current = false;
      setProcessing(false);
    }
  }

  const sectionGroups: {
    title?: string;
    fields: React.JSX.Element[];
  }[] = [];
  let currentSectionTitle: string | undefined;

  items.map((item, index) => {
    if (defaultShow > 0) {
      if (index > showCount - 1) {
        return;
      }
    }

    let group = sectionGroups[sectionGroups.length - 1];
    if (!group || (item.section && item.section !== currentSectionTitle)) {
      if (item.section) {
        currentSectionTitle = item.section;
      }
      group = {
        title: item.section || currentSectionTitle,
        fields: [],
      };
      sectionGroups.push(group);
    }

    let fieldClass = "";
    if (item.span) {
      fieldClass = `col-span-${isMobile ? 1 : item.span}`;
    }
    const field = (
      <div key={item.name} className={fieldClass}>
        <FormField
          name={item.name}
          control={form.control}
          render={({ field }) => {
            switch (item.category) {
              case ExFormItemCategory.PLUGIN_CATEGORY: {
                const selectedValue =
                  (field.value as string | undefined) ??
                  (item.defaultValue as string) ??
                  "";
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <PluginCategoryPicker
                        options={item.options || []}
                        disabled={item.readOnly || false}
                        value={selectedValue}
                        onChange={(value) => {
                          form.setValue(item.name, value);
                          setUpdated(item.name, value);
                        }}
                      />
                    </FormControl>
                  </FormItem>
                );
              }
              case ExFormItemCategory.RADIOS: {
                const rawValue =
                  field.value !== undefined ? field.value : item.defaultValue;
                const selectedOption =
                  getOption(
                    rawValue as string | number | boolean | null | undefined,
                    item.options,
                  ) || "";
                const radios = item.options?.map(
                  (opt: ExFormOption, index: number) => {
                    const id = `${item.name}-${index}`;
                    const checked = selectedOption === opt.option;
                    return (
                      <Label
                        key={id}
                        htmlFor={id}
                        className={cn(
                          "inline-flex cursor-pointer items-center gap-2 rounded-md border px-3 py-1.5 text-[13px] font-normal transition-colors",
                          checked
                            ? "border-primary/60 bg-primary/[0.06] font-medium text-foreground"
                            : "border-border bg-card text-muted-foreground hover:border-foreground/25 hover:text-foreground",
                          item.readOnly && "pointer-events-none opacity-60",
                        )}
                      >
                        <RadioGroupItem value={opt.option} id={id} />
                        <span>{opt.label}</span>
                      </Label>
                    );
                  },
                );
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <RadioGroup
                        disabled={item.readOnly || false}
                        value={selectedOption}
                        className="flex flex-wrap items-center gap-2 pt-1.5"
                        onValueChange={(option) => {
                          const value = getOptionValue(option, item.options);
                          form.setValue(item.name, value);
                          setUpdated(item.name, value);
                        }}
                      >
                        {radios}
                      </RadioGroup>
                    </FormControl>
                  </FormItem>
                );
              }
              case ExFormItemCategory.MULTI_SELECT: {
                const options = item.options?.map((opt) => {
                  return {
                    value: opt.option,
                    label: opt.label,
                  };
                });

                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <MultiSelect
                        defaultValue={(item.defaultValue || []) as string[]}
                        options={options || []}
                        onValueChange={(values) => {
                          setUpdated(item.name, values);
                        }}
                        placeholder={item.placeholder}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              case ExFormItemCategory.SELECT: {
                const options = item.options?.map((opt) => {
                  return (
                    <SelectItem
                      key={`${item.name}-${opt.value}`}
                      value={opt.option}
                    >
                      {opt.label}
                    </SelectItem>
                  );
                });
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <Select
                        defaultValue={(item.defaultValue || "") as string}
                        onValueChange={(option) => {
                          const value = getOptionValue(option, item.options);
                          form.setValue(item.name, value);
                          setUpdated(item.name, value);
                        }}
                      >
                        <SelectTrigger className="w-full">
                          <SelectValue placeholder={item.placeholder} />
                        </SelectTrigger>
                        <SelectContent>{options}</SelectContent>
                      </Select>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              case ExFormItemCategory.INPUT_SELECT: {
                const placeholders = item.placeholder.split(" : ");
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <InputSelect
                        defaultValue={item.defaultValue as string}
                        name={item.name}
                        selectPlaceholder={placeholders[0]}
                        inputPlaceholder={placeholders[1]}
                        onValueChange={(option) => {
                          form.setValue(item.name, option);
                          setUpdated(item.name, option);
                        }}
                        options={item.options}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              case ExFormItemCategory.TEXTAREA: {
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <Textarea
                        placeholder={item.placeholder}
                        rows={item.rows}
                        readOnly={item.readOnly}
                        defaultValue={(item.defaultValue as string) || ""}
                        onChange={(e) => {
                          let value: string | null = e.target.value;
                          if (!item.notTrim) {
                            value = value.trim();
                          }
                          if (item.nullAsEmpty && !value) {
                            value = null;
                          }
                          setUpdated(item.name, value);
                        }}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              case ExFormItemCategory.NUMBER: {
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <Input
                        placeholder={item.placeholder}
                        readOnly={item.readOnly}
                        type="number"
                        value={field.value as string}
                        onChange={(e) => {
                          field.onChange(e);
                          const value = e.target.value || "";
                          if (!value) {
                            setUpdated(item.name, null);
                          } else {
                            setUpdated(item.name, Number(value));
                          }
                        }}
                        onBlur={field.onBlur}
                        name={field.name}
                        ref={field.ref}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              case ExFormItemCategory.KV_LIST: {
                const placeholders = item.placeholder.split(" : ");
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <KvInputs
                        cols={item.cols}
                        separator={item.separator}
                        defaultValue={(item.defaultValue || []) as string[]}
                        keyPlaceholder={placeholders[0]}
                        valuePlaceholder={placeholders[1]}
                        onValueChange={(values) => {
                          setUpdated(item.name, values);
                          form.setValue(item.name, values);
                        }}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              case ExFormItemCategory.TEXTS: {
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <Inputs
                        defaultValue={(item.defaultValue || []) as string[]}
                        placeholder={item.placeholder}
                        onValueChange={(values) => {
                          setUpdated(item.name, values);
                        }}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              case ExFormItemCategory.SORT_CHECKBOXS: {
                const options = item.options?.map((item) => {
                  return {
                    label: item.label,
                    value: item.value as string,
                  };
                });
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <SortCheckboxs
                        options={options || []}
                        defaultValue={(item.defaultValue || []) as string[]}
                        onValueChange={(values) => {
                          setUpdated(item.name, values);
                        }}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              case ExFormItemCategory.LABEL: {
                const text =
                  item.defaultValue !== undefined &&
                  item.defaultValue !== null &&
                  item.defaultValue !== ""
                    ? String(item.defaultValue)
                    : "—";
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <div className="machine flex min-h-9 items-center rounded-md border border-border bg-muted/40 px-3 py-1.5 text-[13px] text-foreground">
                      {text}
                    </div>
                  </FormItem>
                );
              }
              case ExFormItemCategory.COMBINED_AUTHS: {
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <CombinedAuths
                        defaultValue={item.defaultValue as []}
                        onValueChange={(value) => {
                          setUpdated(item.name, value);
                        }}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
              default: {
                return (
                  <FormItem>
                    <FieldLabel label={item.label} tips={item.tips} />
                    <FormControl>
                      <Input
                        type={item.category}
                        placeholder={item.placeholder}
                        readOnly={item.readOnly}
                        value={field.value as string}
                        onChange={(e) => {
                          field.onChange(e);
                          let value = e.target.value || "";
                          if (!item.notTrim) {
                            value = value.trim();
                          }
                          setUpdated(item.name, value);
                        }}
                        onBlur={field.onBlur}
                        name={field.name}
                        ref={field.ref}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }
            }
          }}
        ></FormField>
      </div>
    );

    sectionGroups[sectionGroups.length - 1]?.fields.push(field);
  });

  let showButton: React.JSX.Element | null = null;
  if (defaultShow > 0 && defaultShow < maxCount) {
    const expanded = showCount > defaultShow;
    const tips = expanded ? t("lessSettings") : t("moreSettings");
    showButton = (
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="cursor-pointer text-muted-foreground hover:text-foreground"
        title={tips}
        onClick={(e) => {
          if (expanded) {
            localStorage.removeItem(showAllKey);
            setShowCount(defaultShow);
          } else {
            setShowCount(maxCount);
            localStorage.setItem(showAllKey, "all");
          }
          e.preventDefault();
        }}
      >
        {expanded ? (
          <FoldVertical className="h-4 w-4" />
        ) : (
          <UnfoldVertical className="h-4 w-4" />
        )}
        <span className="ml-1.5">{tips}</span>
      </Button>
    );
  }

  return (
    <TooltipProvider delayDuration={200}>
      <Form {...form}>
        {/* 因为col-span是动态生成，因此先引入，否则tailwind并未编译该类 */}
        <span className="col-span-1 col-span-2 col-span-3 col-span-4 col-span-5 col-span-6 col-span-full" />
        <form
          // Built inside the handler, not during render: onSubmit now touches a
          // ref, and calling handleSubmit() while rendering would read it there.
          onSubmit={(e) => form.handleSubmit(onSubmit)(e)}
          className="relative space-y-0"
        >
          <div key={resetNonce} className="space-y-4">
            {/*
            The template is inline, not `grid-cols-${cols}`: that class is built
            at runtime so tailwind never emits a rule for it, leaving the grid
            with no explicit columns. Spans then created implicit columns of
            uneven width, and `col-span-full` (grid-column: 1/-1) resolved
            against the empty explicit grid, so section headers spanned one
            column instead of the row.
          */}
            {sectionGroups.map((group, groupIdx) => (
              <section
                key={group.title || `section-${groupIdx}`}
                className="overflow-hidden rounded-lg border border-border bg-card"
              >
                {group.title && (
                  <div className="border-b border-border bg-surface-subtle px-5 py-3">
                    <h3 className="region-label">{group.title}</h3>
                  </div>
                )}
                <div
                  className="grid gap-x-8 gap-y-5 p-5 sm:p-6"
                  style={{
                    gridTemplateColumns: `repeat(${effectiveCols}, minmax(0, 1fr))`,
                  }}
                >
                  {group.fields}
                </div>
              </section>
            ))}
          </div>

          {(onSave || onRemove || showButton) && (
            <div
              className={cn(
                "sticky bottom-2 z-10 mt-4 flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card/90 px-4 py-2.5 backdrop-blur-md sm:gap-3",
                // Keep the bar clear of the home indicator on notched phones.
                "pb-[max(0.625rem,env(safe-area-inset-bottom))]",
                updatedCount > 0 &&
                  "border-primary/45 shadow-sm ring-1 ring-primary/20",
              )}
            >
              {updatedCount > 0 && !readOnly && (
                <div className="machine inline-flex items-center rounded-full border border-primary/30 bg-primary/12 px-2.5 py-0.5 text-[11.5px] font-medium text-primary">
                  {updatedCount} {t("modified") || "modified"}
                </div>
              )}
              {readOnly && (onSave || onRemove) && (
                <span className="text-sm text-muted-foreground">
                  {t("readOnlyTips")}
                </span>
              )}
              {onSave && !readOnly && updatedCount > 0 && (
                <Button
                  type="button"
                  variant="outline"
                  className="cursor-pointer"
                  disabled={processing}
                  onClick={() => {
                    form.reset(defaultValues);
                    setUpdatedValues({});
                    setUpdatedCount(0);
                    setResetNonce((prev) => prev + 1);
                    onValueChange?.({});
                  }}
                >
                  <RotateCcw className="mr-1.5 size-3.5" />
                  {t("formControls.reset")}
                </Button>
              )}
              {onSave && !readOnly && (
                <Button
                  className="min-w-[120px] cursor-pointer"
                  type="submit"
                  disabled={updatedCount === 0 && !allowSave}
                >
                  {processing && (
                    <LoaderCircle className="mr-2 h-4 w-4 inline animate-spin" />
                  )}
                  {t("save")}
                  {updatedCount > 0 && (
                    <span className="ml-1.5 rounded bg-primary-foreground/20 px-1.5 text-xs">
                      {updatedCount}
                    </span>
                  )}
                </Button>
              )}
              {onRemove && !readOnly && (
                <Popover>
                  <PopoverTrigger asChild>
                    <Button
                      variant="outline"
                      type="button"
                      className="min-w-[100px] cursor-pointer text-destructive hover:bg-destructive/10 hover:text-destructive"
                    >
                      {processing && (
                        <LoaderCircle className="mr-2 h-4 w-4 inline animate-spin" />
                      )}
                      {t("remove")}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-64" align="start">
                    <div className="grid gap-3">
                      <div className="space-y-1">
                        <h4 className="font-medium leading-none">
                          {t("removeConfirm")}
                        </h4>
                        <p className="text-sm text-muted-foreground">
                          {t("removeTips")}
                        </p>
                      </div>
                      <Button
                        size="sm"
                        variant="destructive"
                        className="cursor-pointer"
                        onClick={async () => {
                          await handleRemove();
                        }}
                      >
                        {t("confirm")}
                      </Button>
                    </div>
                  </PopoverContent>
                </Popover>
              )}
              {showButton && <div className="ml-auto">{showButton}</div>}
            </div>
          )}
        </form>

        <AlertDialog
          open={blocker.state === "blocked"}
          onOpenChange={(open) => {
            if (!open) {
              blocker.reset?.();
            }
          }}
        >
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("unsavedTitle")}</AlertDialogTitle>
              <AlertDialogDescription>
                {t("unsavedDescription")}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel
                className="cursor-pointer"
                onClick={() => blocker.reset?.()}
              >
                {t("cancel")}
              </AlertDialogCancel>
              <AlertDialogAction
                className="cursor-pointer"
                onClick={() => blocker.proceed?.()}
              >
                {t("leave")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </Form>
    </TooltipProvider>
  );
}
