import { BrowserRouter, NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import Lab from "./pages/Lab";
import Runs from "./pages/Runs";
import RunDetail from "./pages/RunDetail";
import Audit from "./pages/Audit";
import NewScan from "./pages/NewScan";
import ScanLive from "./pages/ScanLive";
import Walkthrough from "./pages/Walkthrough";
import Settings from "./pages/Settings";

const navClass = ({ isActive }: { isActive: boolean }) => (isActive ? "active" : "");

export default function App() {
  return (
    <BrowserRouter>
      <div className="layout">
        <nav className="sidebar">
          <h1>PownForge</h1>
          <NavLink to="/" end className={navClass}>
            Dashboard
          </NavLink>
          <NavLink to="/targets" className={navClass}>
            Targets
          </NavLink>
          <NavLink to="/lab" className={navClass}>
            Lab
          </NavLink>
          <NavLink to="/runs" className={navClass}>
            Runs
          </NavLink>
          <NavLink to="/audit" className={navClass}>
            Audit
          </NavLink>
          <NavLink to="/scan/new" className={navClass}>
            New Scan
          </NavLink>
          <NavLink to="/walkthrough/new" className={navClass}>
            Walkthrough
          </NavLink>
          <NavLink to="/settings" className={navClass}>
            Settings
          </NavLink>
        </nav>
        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/lab" element={<Lab />} />
            <Route path="/runs" element={<Runs />} />
            <Route path="/runs/:runId" element={<RunDetail />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/scan/new" element={<NewScan />} />
            <Route path="/scans/:jobId/live" element={<ScanLive />} />
            <Route path="/walkthrough/new" element={<Walkthrough />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
