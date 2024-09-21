import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";

export default function Home() {
  return (
    <div>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto">HOME</div>
      </div>
    </div>
  );
}
