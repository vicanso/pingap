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
        className="border-primary/30 bg-primary/10 text-primary"
      >
        new
      </Badge>
    );
  }
  if (!name) {
    return null;
  }
  return (
    <Badge variant="secondary" className="font-mono text-xs">
      {name}
    </Badge>
  );
}
