import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";

interface LoadingProps extends React.HTMLAttributes<HTMLDivElement> {
  tips?: string;
}

export function Loading({ className, tips }: LoadingProps) {
  return (
    <div className={cn("w-full space-y-4", className)}>
      <div className="flex items-center justify-between gap-4">
        <div className="space-y-2">
          <Skeleton className="h-7 w-40" />
          <Skeleton className="h-4 w-64" />
        </div>
        <Skeleton className="h-9 w-28 rounded-md" />
      </div>
      <div className="rounded-xl border border-border/80 p-4 space-y-3">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-3/4" />
        <div className="grid gap-3 sm:grid-cols-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      </div>
      {tips && (
        <p className="text-center text-sm text-muted-foreground">{tips}</p>
      )}
    </div>
  );
}

export function LoadingPage() {
  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-auto">
      <div className="mx-auto w-full max-w-[1400px] px-4 py-6 md:px-6">
        <Loading />
      </div>
    </div>
  );
}
