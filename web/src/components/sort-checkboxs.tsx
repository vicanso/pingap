import * as React from "react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { ChevronUp, ChevronDown } from "lucide-react";
import { random } from "@/helpers/util";
import { Checkbox } from "@/components/ui/checkbox";

interface SortCheckboxsProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  defaultValue?: string[];
  onValueChange: (values: string[]) => void;
  className?: string;
  options: {
    label: string;
    value: string;
  }[];
}

export const SortCheckboxs = React.forwardRef<
  HTMLInputElement,
  SortCheckboxsProps
>(({ defaultValue = [], options, className, onValueChange, ...props }, ref) => {
  const [selectedItems, setSelectedItems] = React.useState(defaultValue);
  const handleSelect = (value: string, checked: boolean) => {
    const arr = selectedItems.slice(0);
    if (checked) {
      arr.push(value);
    } else {
      const index = arr.indexOf(value);
      arr.splice(index, 1);
    }
    setSelectedItems(arr);
    onValueChange(arr);
  };
  const handleForward = (index: number) => {
    if (index === 0) {
      return;
    }
    const arr = selectedItems.slice(0);
    const prev = arr[index - 1];
    arr[index - 1] = arr[index];
    arr[index] = prev;
    setSelectedItems(arr);
    onValueChange(arr);
  };
  const selectors = options.map((item, index) => {
    const lastClass = index == options.length - 1 ? "" : "mb-2";
    return (
      <div
        key={`option-${item.value}`}
        className={cn("flex items-center space-x-2", lastClass)}
      >
        <Checkbox
          id={item.value}
          defaultChecked={selectedItems.includes(item.value)}
          onCheckedChange={(checked) => {
            handleSelect(item.value, checked as boolean);
          }}
        />
        <label
          htmlFor={item.value}
          className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
        >
          {item.label}
        </label>
      </div>
    );
  });
  const sorts = selectedItems.map((item, index) => {
    const lastClass = index === selectedItems.length - 1 ? "" : "mb-2";
    return (
      <div
        key={`sort-${item}`}
        className={cn("flex items-center space-x-2", lastClass)}
      >
        <ChevronUp
          className="w-5 h-5 cursor-pointer"
          onClick={(e) => {
            e.preventDefault();
            handleForward(index);
          }}
        />
        <label
          htmlFor={item}
          className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
        >
          {item}
        </label>
      </div>
    );
  });

  return (
    <div className={cn(className)} ref={ref} {...props}>
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-1">{selectors}</div>
        <div className="col-span-1">{sorts}</div>
      </div>
    </div>
  );
});

SortCheckboxs.displayName = "SortCheckboxs";
