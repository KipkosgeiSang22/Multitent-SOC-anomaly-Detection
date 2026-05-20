import React, { useState, useEffect, useCallback } from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import PortalShell from '../../components/PortalShell';
import api from '../../api/axios';
import useAuthStore from '../../store/authStore'; 

export default function AnalystPortal() {
  const { user, accessToken } = useAuthStore();
  const [openIssuesCount, setOpenIssuesCount] = useState(0);

  // 🔑 Memoize the stats sync function to prevent recreating it on every render pass
  const executeStatsSync = useCallback(async () => {
    if (!user || !accessToken) return;
    try {
      const res = await api.get('/analyst/dashboard-stats');
      setOpenIssuesCount(res.data?.open_issues || 0);
    } catch (err) {
      console.warn("Internal metric telemetry heartbeat standby:", err.message);
    }
  }, [user, accessToken]);

  useEffect(() => {
    if (!user || !accessToken) return;

    executeStatsSync();
    const heartbeat = setInterval(executeStatsSync, 60000);
    return () => clearInterval(heartbeat);
  }, [user, accessToken, executeStatsSync]);

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const analystNavigation = [
    {
      title: 'MONITOR CORE',
      items: [
        { label: 'Operations Overview', to: '/analyst/dashboard', icon: '⬡' },
        { label: 'Security Events Hub', to: '/analyst/events', icon: '◎' },
        { label: 'Anomalies Registry', to: '/analyst/anomalies', icon: '⚑' },
        { label: 'Client Escalation Tickets', to: '/analyst/issues', icon: '⚐' }
      ]
    },
    {
      title: 'ELEVATED SYSTEM MATRIX',
      items: [
        { label: 'Isolation Forest Retrain', to: '/analyst/retrain', icon: '⚙' },
        { label: 'Layer 1 Filter Compiler', to: '/analyst/rules', icon: '⊕' },
        { label: 'SIEM Cluster Architecture', to: '/analyst/graylog', icon: '≡' },
        { label: 'Threat Intelligence Matrix', to: '/analyst/threat-intel', icon: '☣' },
        { label: 'Audit Log Ledger Tracking', to: '/analyst/audit-log', icon: '⟳' }
      ]
    }
  ];

  return (
    <PortalShell
      nav={analystNavigation}
      roleLabel="SOC ENG ANALYST"
      accentColor="var(--amber)"
      navBadges={{ '/analyst/issues': openIssuesCount }}
    >
      {/* 🔑 Explicitly pass an isolated, stable object down to break the re-render cascading loop */}
      <Outlet context={{ role: 'analyst', openIssuesCount }} />
    </PortalShell>
  );
}