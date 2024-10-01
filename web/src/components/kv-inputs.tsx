import * as React from "react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { X, Plus } from "lucide-react";
import { random } from "@/helpers/util";

interface KvInputsProps extends React.InputHTMLAttributes<HTMLInputElement> {
  defaultValue?: string[];
  separator?: string;
  onValueChange: (values: string[]) => void;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
  className?: string;
  cols?: number[];
}

export const KvInputs = React.forwardRef<HTMLInputElement, KvInputsProps>(
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
    const arr = defaultValue.map((item) => {
      const tmpArr = item.split(separator);
      return {
        id: random(),
        key: tmpArr[0] || "",
        value: tmpArr[1] || "",
      };
    });
    if (arr.length === 0) {
      arr.push({
        id: random(),
        key: "",
        value: "",
      });
    }
    const [inputs, setInputs] = React.useState(arr);
    const updateKeyValue = (index: number, value: string, isKey: boolean) => {
      const arr = inputs.slice(0);
      if (isKey) {
        arr[index].key = value.trim();
      } else {
        arr[index].value = value.trim();
      }
      setInputs(arr);
      const values: string[] = [];
      arr.forEach((item) => {
        const { key, value } = item;
        if (key || value) {
          values.push(`${key}${separator}${value}`.trim());
        }
      });
      onValueChange(values);
    };
    const updateKey = (index: number, value: string) => {
      updateKeyValue(index, value, true);
    };
    const updateValue = (index: number, value: string) => {
      updateKeyValue(index, value, false);
    };
    const items = inputs.map((item, index) => {
      const { id, key, value } = item;
      const last = index === inputs.length - 1;
      let mbClass = "mb-4";
      if (last) {
        mbClass = "";
      }
      const col1 = "col-span-" + (cols[0] || 2);
      const col2 = "col-span-" + (cols[1] || 2);

      return (
        <div key={id} className={cn("grid grid-cols-4 gap-4", mbClass)}>
          <Input
            type="text"
            className={col1}
            placeholder={keyPlaceholder}
            defaultValue={key}
            onChange={(e) => {
              updateKey(index, e.target.value);
            }}
          />
          <div className={cn("relative", col2)}>
            <span
              className="absolute pt-1"
              style={{
                marginLeft: "-10px",
              }}
            >
              {separator}
            </span>
            <Input
              type="text"
              defaultValue={value}
              placeholder={valuePlaceholder}
              className="pr-8"
              onChange={(e) => {
                updateValue(index, e.target.value);
              }}
            />
            {last && (
              <Plus
                onClick={(e) => {
                  e.preventDefault();
                  const arr = inputs.slice(0);
                  arr.push({
                    id: random(),
                    key: "",
                    value: "",
                  });
                  setInputs(arr);
                }}
                className="absolute right-2 top-2 h-5 w-5 text-muted-foreground cursor-pointer"
              />
            )}
            {!last && (
              <X
                onClick={(e) => {
                  e.preventDefault();
                  const arr = inputs.slice(0);
                  arr.splice(index, 1);
                  setInputs(arr);
                }}
                className="absolute right-2 top-2 h-5 w-5 text-muted-foreground cursor-pointer"
              />
            )}
          </div>
        </div>
      );
    });
    return (
      <div className={cn(className)} ref={ref} {...props}>
        {items}
      </div>
    );
  },
);

KvInputs.displayName = "KvInputs";
