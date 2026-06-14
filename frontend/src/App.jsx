import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute';
import useAuthStore from './store/authStore';
import AdminBootstrapTrainPage from './portals/admin/pages/AdminBootstrapTrainPage';
// Infrastructure Component Frameworks
import AdminPortal from './portals/admin/AdminPortal';
import AdminDashboardPage from './portals/admin/pages/AdminDashboardPage';
import AdminUsersPage from './portals/admin/pages/AdminUsersPage';
import AdminClientsPage from './portals/admin/pages/AdminClientsPage';
import AdminQueriesPage from './portals/admin/pages/AdminQueriesPage';
import AdminPermissionsPage from './portals/admin/pages/AdminPermissionsPage';
import AdminAuditLogPage from './portals/admin/pages/AdminAuditLogPage';
import AdminHealthPage from './portals/admin/pages/AdminHealthPage';
import AdminPaymentsPage from './portals/admin/pages/AdminPaymentsPage';

// Shared Reusable Tool Interfaces
import RetrainModelsPage from './portals/shared/RetrainModelsPage';
import Layer1RulesPage from './portals/shared/Layer1RulesPage';
import GraylogManagementPage from './portals/shared/GraylogManagementPage';

// Pre-existing Operations Paneling
import AnalystPortal from './portals/analyst/AnalystPortal';
import DashboardPage from './portals/analyst/pages/DashboardPage';
import AnalystEventsPage from './portals/analyst/pages/AnalystEventsPage';
import AnalystAnomaliesPage from './portals/analyst/pages/AnalystAnomaliesPage'; // Bug 2 fix
import AuditLogPage from './portals/analyst/pages/AuditLogPage';                 // Bug 1 fix
import IssuesPage from './portals/analyst/pages/IssuesPage';
import ThreatIntelPage from './portals/analyst/pages/ThreatIntelPage';

import SettingsPage from './portals/client/pages/SettingsPage';
import ClientPortal from './portals/client/ClientPortal';
import EventsPage from './portals/client/pages/EventsPage';
import AnomaliesPage from './portals/client/pages/AnomaliesPage';
import DownloadsPage from './portals/client/pages/DownloadsPage'; // Bug 5 fix
import PaymentsPage from './portals/client/pages/PaymentsPage';

// Auth Views
import Login from './pages/Login';
import ForgotPassword from './pages/ForgotPassword';       // Bug 4 fix
import ResetPassword from './pages/ResetPassword';         // Bug 4 fix
import ForceChangePassword from './pages/ForceChangePassword'; // Bug 4 fix

export default function App() {
  const bootstrap = useAuthStore((state) => state.bootstrap);
  const isInitialized = useAuthStore((state) => state.isInitialized);

  useEffect(() => {
    bootstrap();
  }, [bootstrap]);

  if (!isInitialized) {
    return (
      <div style={{
        background: '#0a0b0d',
        color: '#8b90a8',
        fontFamily: "'IBM Plex Mono', monospace",
        padding: '40px',
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '13px',
        letterSpacing: '1px'
      }}>
        <span style={{ color: '#e5434b', marginRight: '8px' }}>⚡</span>
        RESYNCING SECURE INFRASTRUCTURE HANDSHAKE VECTOR...
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        {/* =========================================================
            STANDALONE AUTHENTICATION GATEWAY NODES
           ========================================================= */}
        <Route path="/login" element={<Login />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />         {/* Bug 4 fix */}
        <Route path="/reset-password" element={<ResetPassword />} />           {/* Bug 4 fix */}
        <Route path="/force-change-password" element={<ForceChangePassword />} /> {/* Bug 4 fix */}

        {/* =========================================================
            PLATFORM SUPERADMIN ROUTING SCHEMATIC BOUNDS
           ========================================================= */}
        <Route path="/admin" element={<ProtectedRoute allowedRoles={['superadmin']}><AdminPortal /></ProtectedRoute>}>
          <Route index element={<Navigate to="dashboard" replace />} />
          <Route path="dashboard" element={<AdminDashboardPage />} />
          <Route path="users" element={<AdminUsersPage />} />
          <Route path="clients" element={<AdminClientsPage />} />
          <Route path="queries" element={<AdminQueriesPage />} />
          <Route path="permissions" element={<AdminPermissionsPage />} />
          <Route path="audit-log" element={<AdminAuditLogPage />} />
          <Route path="bootstrap-train" element={<AdminBootstrapTrainPage />} />
          <Route path="health" element={<AdminHealthPage />} />
          <Route path="payments" element={<AdminPaymentsPage />} />

          <Route path="retrain" element={<RetrainModelsPage accentColor="var(--red)" />} />
          <Route path="rules" element={<Layer1RulesPage accentColor="var(--red)" />} />
          <Route path="graylog" element={<GraylogManagementPage accentColor="var(--red)" />} />

          <Route path="events" element={<AnalystEventsPage />} />
          <Route path="anomalies" element={<AnalystAnomaliesPage />} /> {/* Bug 2 fix */}
          <Route path="threat-intel" element={<ThreatIntelPage />} />
        </Route>

        {/* =========================================================
            SOC ANALYST SYSTEM COMPARTMENT BOUNDS
           ========================================================= */}
        <Route path="/analyst" element={<ProtectedRoute allowedRoles={['analyst', 'superadmin']}><AnalystPortal /></ProtectedRoute>}>
          <Route index element={<Navigate to="dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="events" element={<AnalystEventsPage />} />
          <Route path="anomalies" element={<AnalystAnomaliesPage />} /> {/* Bug 2 fix */}
          <Route path="issues" element={<IssuesPage />} />
          <Route path="threat-intel" element={<ThreatIntelPage />} />
          <Route path="audit-log" element={<AuditLogPage />} />         {/* Bug 1 fix */}

          <Route path="retrain" element={<RetrainModelsPage accentColor="var(--amber)" />} />
          <Route path="rules" element={<Layer1RulesPage accentColor="var(--amber)" />} />
          <Route path="graylog" element={<GraylogManagementPage accentColor="var(--amber)" />} />
        </Route>

        {/* =========================================================
            ISOLATED TENANT CLIENT GATE OPERATIONS
           ========================================================= */}
        <Route path="/client" element={<ProtectedRoute allowedRoles={['client']}><ClientPortal /></ProtectedRoute>}>
          <Route path="settings" element={<SettingsPage />} />
          <Route index element={<Navigate to="events" replace />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="anomalies" element={<AnomaliesPage />} />
          <Route path="downloads" element={<DownloadsPage />} /> {/* Bug 5 fix */}
          <Route path="payments" element={<PaymentsPage />} />
        </Route>

        {/* Global Fallback Catchall */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
