import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { MainSidebar } from "@/components/sidebar-nav";

interface LoadingProps extends React.HTMLAttributes<HTMLDivElement> {
  tips?: string;
}
export function Loading({ className, tips }: LoadingProps) {
  return (
    <div
      className={cn(
        "flex justify-center items-center space-x-4 mt-10",
        className,
      )}
    >
      <Skeleton className="h-12 w-12 rounded-full" />
      <div className="space-y-2">
        <Skeleton className="h-4 w-[250px]" />
        <Skeleton className="h-4 w-[200px]" />
      </div>
      {tips && <p>{tips}</p>}
    </div>
  );
}

export function LoadingPage() {
  return (
    <div className="flex">
      <MainSidebar className="h-screen flex-none w-[230px]" />
      <div className="grow lg:border-l overflow-auto p-4">
        <Loading />
      </div>
    </div>
  );
}
