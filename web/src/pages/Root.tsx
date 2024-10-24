import { MainSidebar } from "@/components/sidebar-nav";
import { Outlet } from "react-router-dom";

export default function Root() {
  return (
    <div className="flex">
      <MainSidebar className="h-screen flex-none w-[230px]" />
      <Outlet />
    </div>
  );
}
