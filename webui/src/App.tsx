import { BrowserRouter, NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import Lab from "./pages/Lab";
import Runs from "./pages/Runs";
import RunDetail from "./pages/RunDetail";
import Audit from "./pages/Audit";
import NewScan from "./pages/NewScan";
import ScanLive from "./pages/ScanLive";
import Playbooks from "./pages/Playbooks";
import PlaybookLive from "./pages/PlaybookLive";
import AttackSessions from "./pages/AttackSessions";
import Primitives from "./pages/Primitives";
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
          <NavLink to="/playbooks" className={navClass}>
            Playbooks
          </NavLink>
          <NavLink to="/attack-sessions" className={navClass}>
            Attack Session
          </NavLink>
          <NavLink to="/primitives" className={navClass}>
            Primitives
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
            <Route path="/playbooks" element={<Playbooks />} />
            <Route path="/playbooks/runs/:jobId/live" element={<PlaybookLive />} />
            <Route path="/attack-sessions" element={<AttackSessions />} />
            <Route path="/primitives" element={<Primitives />} />
            <Route path="/walkthrough/new" element={<Walkthrough />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
