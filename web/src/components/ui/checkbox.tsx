import * as React from "react";
import { CheckIcon, MinusIcon } from "lucide-react";
import { Checkbox as CheckboxPrimitive } from "radix-ui";

import { cn } from "@/lib/utils";

function Checkbox({
  className,
  ...props
}: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      data-slot="checkbox"
      className={cn(
        "peer size-4 shrink-0 rounded-[4px] border border-input shadow-xs transition-shadow outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-destructive/20 data-[state=checked]:border-primary data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground data-[state=indeterminate]:border-primary data-[state=indeterminate]:bg-primary data-[state=indeterminate]:text-primary-foreground dark:bg-input/30 dark:aria-invalid:ring-destructive/40 dark:data-[state=checked]:bg-primary dark:data-[state=indeterminate]:bg-primary",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator
        data-slot="checkbox-indicator"
        className="group/indicator grid place-content-center text-current transition-none"
      >
        {/*
          `text-current` is load-bearing, not decoration. Menu wrappers (cmdk's
          CommandItem, DropdownMenuItem) repaint every unclassed descendant svg
          with `[&_svg:not([class*='text-'])]:text-muted-foreground`, and that
          direct rule beats the colour this checkbox merely inherits down — a
          grey tick on a `bg-primary` box, 1.1:1, effectively invisible. Naming
          a `text-` utility here takes the icon out of that `:not()` selector.
        */}
        <CheckIcon className="size-3.5 text-current group-data-[state=indeterminate]/indicator:hidden" />
        {/* Partial selection, e.g. a "select all" row with some rows ticked. */}
        <MinusIcon className="hidden size-3.5 text-current group-data-[state=indeterminate]/indicator:block" />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

export { Checkbox };
