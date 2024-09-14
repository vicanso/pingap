import { cn } from "@/lib/utils";
import { LoaderCircle } from "lucide-react";

interface LoadingProps extends React.HTMLAttributes<HTMLDivElement> {
  tips?: string;
}
export function Loading({ className, tips }: LoadingProps) {
  return (
    <div className={cn("text-center m-4", className)}>
      <p className="text-sm leading-[32px]">
        <LoaderCircle className="mr-2 h-4 w-4 inline animate-spin" />
        {tips || "Loading..."}
      </p>
    </div>
  );
}
