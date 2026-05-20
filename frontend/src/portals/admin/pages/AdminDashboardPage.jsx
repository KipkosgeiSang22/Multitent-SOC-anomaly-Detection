import React, { useState, useEffect } from 'react';
import api from '../../../api/axios';
import styles from './AdminDashboardPage.module.css';

export default function AdminDashboardPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get('/admin/platform-stats')
      .then(res => setStats(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className={styles.loader}>PROBING PLATFORM CORE SCHEMATICS...</div>;

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>SUPERADMIN COMPREHENSIVE NETWORK INFRASTRUCTURE</h2>
        <p className={styles.subtitle}>Aggregated analytics spanning global tenant layers and orchestration execution health.</p>
      </header>

      <div className={styles.statsGrid}>
        {[
          { label: 'GLOBAL REGISTERED TENANTS', val: stats?.total_clients },
          { label: 'ACTIVE DISPOSITION NODES', val: stats?.active_clients, color: 'var(--green)' },
          { label: 'CRYPTOGRAPHIC USER ENTITIES', val: stats?.total_users },
          { label: 'INGESTED TELEMETRY EVENTS', val: stats?.total_events },
          { label: 'ANOMALY LAYER ALERTS FIRED', val: stats?.total_anomalies, color: 'var(--red)' },
          { label: 'PENDING UNACKNOWLEDGED FLAGS', val: stats?.unacknowledged_anomalies, color: 'var(--amber)' }
        ].map((c, idx) => (
          <div key={idx} className={styles.statCard}>
            <div className={styles.cardLabel}>{c.label}</div>
            <div className={styles.cardVal} style={{ color: c.color || 'var(--text-primary)' }}>{c.val ?? '0'}</div>
          </div>
        ))}
      </div>

      <section className={styles.schedulerSection}>
        <h3>STANDALONE PROCESS DAEMON ROUTER AGENTS</h3>
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr><th>DAEMON EXECUTABLE NODE</th><th>LAST BEAT TIME (EAT)</th><th>STATUS CODE</th><th>COMPUTATION TIME</th></tr>
            </thead>
            <tbody>
              {stats?.scheduler_status?.map((s, idx) => (
                <tr key={idx}>
                  <td className={styles.mono}><strong>{s.process_name}</strong></td>
                  <td className={styles.mono}>{s.last_run_at || 'NEVER'}</td>
                  <td>
                    <span className={`${styles.statusBadge} ${s.last_run_status === 'success' ? styles.ok : styles.fault}`}>
                      {s.last_run_status?.toUpperCase() || 'UNKNOWN'}
                    </span>
                  </td>
                  <td className={styles.mono}>{s.duration_seconds?.toFixed(2)}s</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}