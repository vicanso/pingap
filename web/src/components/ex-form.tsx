import { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";

import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import * as _ from "radash";

export enum ExFormItemCategory {
  TEXT = "text",
  CHECKBOX = "checkbox",
  RADIOS = "radios",
  NUMBER = "number",
  DATETIME = "datetime",
  EDITOR = "editor",
  TEXTS = "texts",
  JSON = "json",
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

export function getBooleanOptions() {
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

export interface ExFormItem {
  name: string;
  label: string;
  placehodler: string;
  category: ExFormItemCategory;
  readOnly?: boolean;
  width?: number;
  options?: ExFormOption[];
  span: number;
  defaultValue: string | number | boolean | null | undefined;
}

interface ExFormProps {
  schema: z.Schema;
  items: ExFormItem[];
}

export function ExForm({ schema, items }: ExFormProps) {
  const defaultValues: Record<string, unknown> = {};
  items.forEach((item) => {
    let { defaultValue } = item;
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
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues,
  });
  // 2. Define a submit handler.
  function onSubmit(values: z.infer<typeof schema>) {
    // Do something with the form values.
    // ✅ This will be type-safe and validated.
    console.log(values);
  }

  const fields = items.map((item) => {
    let fieldClass = "";
    if (item.span) {
      fieldClass = `col-span-${item.span}`;
    }
    return (
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
                          item.defaultValue,
                          item.options,
                        )}
                        className="flex items-stretch pt-2"
                        onValueChange={(option) => {
                          // TODO
                          console.dir(getOptionValue(option, item.options));
                        }}
                      >
                        {radios}
                      </RadioGroup>
                    </FormControl>
                  </FormItem>
                );
              }
              default: {
                return (
                  <FormItem>
                    <FormLabel>{item.label}</FormLabel>
                    <FormControl>
                      <Input
                        placeholder={item.placehodler}
                        readOnly={item.readOnly}
                        type={item.category}
                        onInput={(e) => {
                          console.dir(e.target.value as string);
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
  });

  return (
    <Form {...form}>
      {/* 因为col-span是动态生成，因此先引入，否则tailwind并未编译该类 */}
      <span className="col-span-1 col-span-2 col-span-3 col-span-4" />
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
        <div className="grid grid-cols-4 gap-4">{fields}</div>
      </form>
    </Form>
  );
}
