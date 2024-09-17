import { cn } from "@/lib/utils";
import { LoaderCircle } from "lucide-react";
import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";

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

export function LoadingPage() {
  return (
    <div>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          <Loading />
        </div>
      </div>
    </div>
  );
}
