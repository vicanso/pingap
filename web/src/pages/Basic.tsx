import { MainHeader } from "@/components/header";
import { MainSidebar } from "@/components/sidebar-nav";
import { Loading } from "@/components/loading";

export default function Basic() {
  return (
    <div>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto">
          <Loading />
        </div>
      </div>
    </div>
  );
}
