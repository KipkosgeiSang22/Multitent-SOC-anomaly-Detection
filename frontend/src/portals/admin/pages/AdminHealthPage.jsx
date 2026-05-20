import React, { useState, useEffect } from 'react';
import api from '../../../api/axios';
import styles from './AdminHealthPage.module.css';

export default function AdminHealthPage() {
  const [daemonData, setDaemonData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get('/admin/platform-stats')
      .then(res => setDaemonData(res.data?.scheduler_status || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>STANDALONE SCHEDULER SYSTEM PROCESS INTERROGATOR</h2>
        <p className={styles.subtitle}>Granular runtime debugging interface targeting core automated operational daemons.</p>
      </header>

      {loading ? <div className={styles.loader}>PROBING FOR SYSTEM VOLTAGE...</div> : (
        <div className={styles.grid}>
          {daemonData.map((d, idx) => (
            <div key={idx} className={`${styles.card} ${d.last_run_status !== 'success' ? styles.cardFault : ''}`}>
              <div className={styles.cardHeader}>
                <span className={styles.processName}>{d.process_name}</span>
                <span className={`${styles.badge} ${d.last_run_status === 'success' ? styles.ok : styles.error}`}>
                  {d.last_run_status?.toUpperCase() || 'OFFLINE'}
                </span>
              </div>
              
              <div className={styles.metaRow}>
                <span>LAST TRANSACTION EXECUTION BEAT:</span>
                <strong className={styles.mono}>{d.last_run_at || 'NEVER RECORDED'}</strong>
              </div>
              <div className={styles.metaRow}>
                <span>COMPUTATION WALL TIME DUR:</span>
                <strong className={styles.mono}>{d.duration_seconds?.toFixed(3)} seconds</strong>
              </div>
              <div className={styles.metaRow}>
                <span>TENANTS CYCLE PROCESSING NODES:</span>
                <strong>{d.clients_processed}</strong>
              </div>

              {d.last_error && (
                <div className={styles.errorStack}>
                  <h5>⚠️ CRITICAL DESTRUCTIVE STACKTRACE TRACE RECORDED</h5>
                  <pre>{d.last_error}</pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}