import { LoaderCircle, UnfoldVertical, FoldVertical } from "lucide-react";
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
  defaultValue: string[] | string | number | boolean | null | undefined;
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
  onSave,
  onRemove,
  onValueChange,
  cols = 6,
}: ExFormProps) {
  const { t } = useTranslation();
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
    const values = Object.assign({}, updatedValues);
    if (originalValues[key] == value) {
      delete values[key];
    } else {
      values[key] = value;
    }
    setUpdatedCount(Object.keys(values).length);
    setUpdatedValues(values);
    if (onValueChange) {
      onValueChange(values);
    }
  };
  const form = useForm({
    // @ts-expect-error - zodResolver has complex type constraints that are difficult to satisfy with dynamic schemas
    resolver: zodResolver(schema as z.ZodSchema<Record<string, unknown>>),
    defaultValues,
  });
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
      setProcessing(false);
    }
  }

  async function handleRemove() {
    if (!onRemove || processing) {
      return;
    }
    setProcessing(true);
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
      setProcessing(false);
    }
  }

  const fields: React.JSX.Element[] = [];
  let lastSection: string | undefined;

  items.map((item, index) => {
    if (defaultShow > 0) {
      if (index > showCount - 1) {
        return;
      }
    }

    if (item.section && item.section !== lastSection) {
      lastSection = item.section;
      fields.push(
        <div
          key={`section-${item.section}`}
          className={cn(
            "col-span-full",
            fields.length > 0 && "mt-2 border-t border-border/60 pt-5",
          )}
        >
          <h3 className="text-sm font-semibold tracking-tight text-foreground">
            {item.section}
          </h3>
        </div>,
      );
    }

    let fieldClass = "";
    if (item.span) {
      fieldClass = `col-span-${item.span}`;
    }
    const field = (
      <div key={item.name} className={fieldClass}>
        <FormField
          name={item.name}
          control={form.control}
          render={({ field }) => {
            switch (item.category) {
              case ExFormItemCategory.RADIOS: {
                const radios = item.options?.map(
                  (opt: ExFormOption, index: number) => {
                    const id = `${item.name}-${index}`;
                    return (
                      <div className="flex items-center mr-4" key={id}>
                        <RadioGroupItem value={opt.option} id={id} />
                        <Label className="pl-2 cursor-pointer" htmlFor={id}>
                          {opt.label}
                        </Label>
                      </div>
                    );
                  },
                );
                return (
                  <FormItem>
                    <FormLabel>{item.label}</FormLabel>
                    <FormControl>
                      <RadioGroup
                        disabled={item.readOnly || false}
                        defaultValue={getOption(
                          item.defaultValue as string,
                          item.options,
                        )}
                        className="flex flex-wrap items-start pt-2"
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
                    <FormLabel>{item.label}</FormLabel>
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
                    <FormLabel>{item.label}</FormLabel>
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
                    <FormLabel>{item.label}</FormLabel>
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
                    <FormLabel>{item.label}</FormLabel>
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
                    <FormLabel>{item.label}</FormLabel>
                    <FormControl>
                      <Input
                        placeholder={item.placeholder}
                        readOnly={item.readOnly}
                        type="number"
                        value={field.value as string}
                        onInput={(e) => {
                          const value =
                            (e.target as HTMLInputElement).value || "";
                          if (!value) {
                            setUpdated(item.name, null);
                          } else {
                            setUpdated(item.name, Number(value));
                          }
                        }}
                        onChange={field.onChange}
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
                    <FormLabel>{item.label}</FormLabel>
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
                    <FormLabel>{item.label}</FormLabel>
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
                    <FormLabel>{item.label}</FormLabel>
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
                return (
                  <FormItem>
                    <FormLabel>
                      {item.label}: {item.defaultValue}
                    </FormLabel>
                  </FormItem>
                );
              }
              case ExFormItemCategory.COMBINED_AUTHS: {
                return (
                  <FormItem>
                    <FormLabel>{item.label}</FormLabel>
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
                    <FormLabel>{item.label}</FormLabel>
                    <FormControl>
                      <Input
                        type={item.category}
                        placeholder={item.placeholder}
                        readOnly={item.readOnly}
                        value={field.value as string}
                        onInput={(e) => {
                          let value =
                            (e.target as HTMLInputElement).value || "";
                          if (!item.notTrim) {
                            value = value.trim();
                          }
                          setUpdated(item.name, value);
                        }}
                        onChange={field.onChange}
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

    fields.push(field);
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
    <Form {...form}>
      {/* 因为col-span是动态生成，因此先引入，否则tailwind并未编译该类 */}
      <span className="col-span-1 col-span-2 col-span-3 col-span-4 col-span-5 col-span-6 col-span-full" />
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="relative space-y-0"
      >
        <div className="rounded-xl border border-border/80 bg-card p-5 shadow-none sm:p-6">
          {updatedCount > 0 && (
            <div className="mb-4 text-xs font-medium text-primary">
              {updatedCount} {t("modified") || "modified"}
            </div>
          )}
          {/*
            The template is inline, not `grid-cols-${cols}`: that class is built
            at runtime so tailwind never emits a rule for it, leaving the grid
            with no explicit columns. Spans then created implicit columns of
            uneven width, and `col-span-full` (grid-column: 1/-1) resolved
            against the empty explicit grid, so section headers spanned one
            column instead of the row.
          */}
          <div
            className="grid gap-x-8 gap-y-5"
            style={{
              gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`,
            }}
          >
            {fields}
          </div>
        </div>

        {(onSave || onRemove || showButton) && (
          <div
            className={cn(
              "sticky bottom-0 z-10 mt-4 flex flex-wrap items-center gap-3 rounded-xl border border-border/80 bg-card/95 p-3 shadow-none backdrop-blur supports-backdrop-filter:bg-card/80",
              updatedCount > 0 && "border-primary/30 ring-1 ring-primary/15",
            )}
          >
            {onSave && (
              <Button
                className="min-w-[120px] cursor-pointer"
                type="submit"
                disabled={updatedCount === 0}
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
            {onRemove && (
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
    </Form>
  );
}
