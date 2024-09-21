import * as React from "react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { X, Plus } from "lucide-react";
import { random } from "@/helpers/util";

interface InputsProps extends React.InputHTMLAttributes<HTMLInputElement> {
  defaultValue?: string[];
  onValueChange: (values: string[]) => void;
  placeholder?: string;
  className?: string;
}

export const Inputs = React.forwardRef<HTMLInputElement, InputsProps>(
  (
    { defaultValue = [], placeholder, className, onValueChange, ...props },
    ref,
  ) => {
    const arr = defaultValue.map((item) => {
      return {
        id: random(),
        value: item || "",
      };
    });
    if (arr.length === 0) {
      arr.push({
        id: random(),
        value: "",
      });
    }
    const [inputs, setInputs] = React.useState(arr);
    const updateValue = (index: number, value: string) => {
      const arr = inputs.slice(0);
      arr[index].value = value;
      setInputs(arr);
      const values: string[] = [];
      arr.forEach((item) => {
        const value = item.value.trim();
        if (value) {
          values.push(value);
        }
      });
      onValueChange(values);
    };

    const items = inputs.map((item, index) => {
      const { id, value } = item;
      const last = index === inputs.length - 1;
      let mbClass = "mb-4";
      if (last) {
        mbClass = "";
      }

      return (
        <div key={id} className={cn("relative", mbClass)}>
          <Input
            type="text"
            defaultValue={value}
            placeholder={placeholder}
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
      );
    });
    return (
      <div className={cn(className)} ref={ref} {...props}>
        {items}
      </div>
    );
  },
);

Inputs.displayName = "Inputs";
