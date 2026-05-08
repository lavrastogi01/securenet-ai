import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";

const DashboardLayout = () => {
  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <main className="ml-60 min-h-screen">
        <Outlet />
      </main>
    </div>
  );
};

export default DashboardLayout;
