import React from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import PortalShell from '../../components/PortalShell';
import useAuthStore from '../../store/authStore';

export default function AdminPortal() {
  const { user } = useAuthStore();

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const adminNavigation = [
    {
      title: 'MONITOR CORE',
      items: [
        { label: 'Platform Core Overview', to: '/admin/dashboard', icon: '⬡' },
        { label: 'Security Events Hub', to: '/admin/events', icon: '◎' },
        { label: 'Anomalies Registry', to: '/admin/anomalies', icon: '⚑' },
        { label: 'Threat Intelligence Matrix', to: '/admin/threat-intel', icon: '☣' }
      ]
    },
    {
      title: 'MANAGE INFRASTRUCTURE',
      items: [
        { label: 'Identity Access Records', to: '/admin/users', icon: '👤' },
        { label: 'Tenant Space Profiles', to: '/admin/clients', icon: '🏢' },
        { label: 'Telemetry Search Criteria', to: '/admin/queries', icon: '🔍' },
        { label: 'Workforce Capability Grants', to: '/admin/permissions', icon: '🔐' }
      ]
    },
    {
      title: 'PLATFORM OPERATIONS',
      items: [
        { label: 'Initial Model Bootstrap', to: '/admin/bootstrap-train', icon: '⬡' },
        { label: 'Isolation Forest Pipeline', to: '/admin/retrain', icon: '⚙' },
        { label: 'Layer 1 Filter Engine', to: '/admin/rules', icon: '⊕' },
        { label: 'Ingest Cluster Console', to: '/admin/graylog', icon: '≡' },
        { label: 'Daemon Runtime Health', to: '/admin/health', icon: '🩺' },
        { label: 'Safaricom Daraja Billing', to: '/admin/payments', icon: '💸' }
      ]
    }
  ];

  return (
    <PortalShell
      nav={adminNavigation}
      roleLabel="PLATFORM SUPERADMIN"
      accentColor="var(--red)"
    >
      <Outlet />
    </PortalShell>
  );
}