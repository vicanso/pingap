import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export interface ConfigEntityOption {
  value: string;
  label: string;
}

interface ConfigEntityHeaderProps {
  title: string;
  description?: string;
  label: string;
  value: string;
  placeholder?: string;
  options: ConfigEntityOption[];
  onChange: (value: string) => void;
  isNew?: boolean;
  actions?: ReactNode;
  className?: string;
}

/**
 * Shared header for config entity pages (server / location / upstream / …):
 * page title, entity picker, optional history and badges.
 */
export function ConfigEntityHeader({
  title,
  description,
  label,
  value,
  placeholder,
  options,
  onChange,
  isNew,
  actions,
  className,
}: ConfigEntityHeaderProps) {
  return (
    <div
      className={cn(
        "mb-4 flex flex-col gap-3 rounded-xl border bg-card/60 p-4 shadow-sm backdrop-blur-sm sm:flex-row sm:items-center sm:justify-between",
        className,
      )}
    >
      <div className="min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
          {isNew ? (
            <Badge
              variant="outline"
              className="border-primary/30 bg-primary/10 text-primary"
            >
              new
            </Badge>
          ) : (
            value && (
              <Badge variant="secondary" className="font-mono text-xs">
                {value}
              </Badge>
            )
          )}
        </div>
        {description && (
          <p className="text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Label className="text-muted-foreground whitespace-nowrap">
          {label}
        </Label>
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger className="w-[200px] cursor-pointer bg-background">
            <SelectValue placeholder={placeholder} />
          </SelectTrigger>
          <SelectContent>
            {options.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {actions}
      </div>
    </div>
  );
}
