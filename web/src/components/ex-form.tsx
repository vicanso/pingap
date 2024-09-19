import { LoaderCircle, ChevronsDown, ChevronsUp } from "lucide-react";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
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
import { pascal } from "radash";
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

export enum ExFormItemCategory {
  TEXT = "text",
  CHECKBOX = "checkbox",
  TEXTAREA = "textarea",
  SELECT = "select",
  MULTI_SELECT = "multiSelect",
  RADIOS = "radios",
  NUMBER = "number",
  DATETIME = "datetime",
  EDITOR = "editor",
  TEXTS = "texts",
  JSON = "json",
  KV_LIST = "kvList",
  SORT_CHECKBOXS = "sortCheckboxs",
}

interface ExFormOption {
  label: string;
  option: string;
  value: string | number | boolean | null;
}

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

export function newBooleanOptions() {
  const options: ExFormOption[] = [
    {
      label: "Yes",
      option: "yes",
      value: true,
    },
    {
      label: "No",
      option: "no",
      value: false,
    },
    {
      label: "None",
      option: "none",
      value: null,
    },
  ];
  return options;
}

export function newStringOptions(values: string[], withNone = false) {
  const options: ExFormOption[] = values.map((value) => {
    return {
      label: pascal(value),
      option: value,
      value: value,
    };
  });
  if (withNone) {
    options.unshift({
      label: "None",
      option: "none",
      value: "",
    });
  }
  return options;
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
  defaultValue: string[] | string | number | boolean | null | undefined;
}

type FormContextValue = {
  onSave(data: Record<string, unknown>): Promise<void>;
};

interface ExFormProps {
  schema: z.Schema;
  items: ExFormItem[];
  defaultShow?: number;
  onlyModified?: boolean;
  onSave?: FormContextValue["onSave"];
}

export function ExForm({
  schema,
  items,
  defaultShow = 0,
  onlyModified,
  onSave,
}: ExFormProps) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [showCount, setShowCount] = React.useState(defaultShow);
  const [processing, setProcessing] = React.useState(false);
  const [updatedValues, setUpdatedValues] = React.useState(
    {} as Record<string, unknown>,
  );
  const [updatedCount, setUpdatedCount] = React.useState(0);
  const defaultValues: Record<string, unknown> = {};
  const originalValues: Record<string, unknown> = {};
  // const updatedValues: Record<string, unknown> = {};
  items.forEach((item) => {
    let { defaultValue } = item;
    originalValues[item.name] = defaultValue;
    if (defaultValue == null) {
      switch (item.category) {
        case ExFormItemCategory.NUMBER:
        case ExFormItemCategory.TEXT: {
          defaultValue = "";
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
  };
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
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
    } catch (err) {
      toast({
        title: "Save Fail",
        description: formatError(err),
      });
    } finally {
      setProcessing(false);
    }
  }
  const fields: JSX.Element[] = [];
  const maxCount = items.length;

  items.map((item, index) => {
    if (defaultShow > 0) {
      if (index > showCount - 1) {
        return;
      }
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
                      <div
                        className="flex items-center space-x-2 mr-4"
                        key={id}
                      >
                        <RadioGroupItem value={opt.option} id={id} />
                        <Label htmlFor={id}>{opt.label}</Label>
                      </div>
                    );
                  },
                );
                return (
                  <FormItem>
                    <FormLabel>{item.label}</FormLabel>
                    <FormControl>
                      <RadioGroup
                        defaultValue={getOption(
                          item.defaultValue as string,
                          item.options,
                        )}
                        className="flex items-stretch pt-2"
                        onValueChange={(option) => {
                          setUpdated(
                            item.name,
                            getOptionValue(option, item.options),
                          );
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
                          setUpdated(
                            item.name,
                            getOptionValue(option, item.options),
                          );
                        }}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder={item.placeholder} />
                        </SelectTrigger>
                        <SelectContent>{options}</SelectContent>
                      </Select>
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
                        onChange={(e) => {
                          setUpdated(item.name, e.target.value.trim());
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
                        onInput={(e) => {
                          const value = e.target.value || "";
                          if (!value) {
                            setUpdated(item.name, null);
                          } else {
                            setUpdated(item.name, Number(value));
                          }
                        }}
                        {...field}
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
                        defaultValue={(item.defaultValue || []) as string[]}
                        keyPlaceholder={placeholders[0]}
                        valuePlaceholder={placeholders[1]}
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
              default: {
                return (
                  <FormItem>
                    <FormLabel>{item.label}</FormLabel>
                    <FormControl>
                      <Input
                        type={item.category}
                        placeholder={item.placeholder}
                        readOnly={item.readOnly}
                        onInput={(e) => {
                          const value = e.target.value as string;
                          setUpdated(item.name, value.trim());
                        }}
                        {...field}
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

  if (defaultShow > 0 && defaultShow < maxCount) {
    let tips = t("moreSettings");
    let icon = <ChevronsDown className="mr-2" />;
    if (showCount > defaultShow) {
      tips = t("lessSettings");
      icon = <ChevronsUp className="mr-2" />;
    }

    fields.push(
      <Separator
        key="show-hide"
        className="col-span-6 flex justify-center my-4"
      >
        <Button
          variant="ghost"
          onClick={(e) => {
            if (showCount > defaultShow) {
              setShowCount(defaultShow);
            } else {
              setShowCount(maxCount);
            }
            e.preventDefault();
          }}
          style={{
            marginTop: "-18px",
          }}
        >
          {icon}
          {tips}
        </Button>
      </Separator>,
    );
  }

  return (
    <Form {...form}>
      {/* 因为col-span是动态生成，因此先引入，否则tailwind并未编译该类 */}
      <span className="col-span-1 col-span-2 col-span-3 col-span-4 col-span-5 col-span-6" />
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
        <div className="grid grid-cols-6 gap-4">{fields}</div>
        {onSave && (
          <Button
            type="submit"
            className="w-full"
            disabled={updatedCount === 0}
          >
            {processing && (
              <LoaderCircle className="mr-2 h-4 w-4 inline animate-spin" />
            )}
            {t("save")}
          </Button>
        )}
      </form>
    </Form>
  );
}
