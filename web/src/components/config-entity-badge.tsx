import { Badge } from "@/components/ui/badge";

interface EntityBadgeProps {
  /** Entity name; empty while creating. */
  name: string;
  isNew?: boolean;
}

/** Marks which entity a config form is editing, or that it is creating one. */
export function EntityBadge({ name, isNew }: EntityBadgeProps) {
  if (isNew) {
    return (
      <Badge
        variant="outline"
        className="rounded-full border-primary/30 bg-primary/10 px-2 py-0 text-[11px] font-medium text-primary"
      >
        new
      </Badge>
    );
  }
  if (!name) {
    return null;
  }
  return (
    <Badge
      variant="secondary"
      className="rounded-full px-2 py-0 font-mono text-[11px] font-normal"
    >
      {name}
    </Badge>
  );
}
