import React, { useState, useEffect } from 'react';
import api from '../../../api/axios';
import styles from './AdminAuditLogPage.module.css';

export default function AdminAuditLogPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);

  // Filtering Form Bounds
  const [userId, setUserId] = useState('');
  const [clientId, setClientId] = useState('');
  const [eventType, setEventType] = useState('');

  useEffect(() => {
    fetchLogs();
  }, [page, eventType]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await api.get('/admin/audit-log', {
        params: {
          user_id: userId || undefined,
          client_id: clientId || undefined,
          event_type: eventType || undefined,
          limit: 25,
          offset: (page - 1) * 25
        }
      });
      setLogs(res.data);
    } catch {}
    finally { setLoading(false); } // Bug 3 fix: was setLoading(true)
  };

  const handleDownload = async () => {
    try {
      const res = await api.get('/admin/audit-log/download', { responseType: 'blob' });
      const blob = new Blob([res.data], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = `PLATFORM_AUDIT_LOG_SNAPSHOT_${new Date().toISOString().split('T')[0]}.xlsx`;
      link.click();
    } catch { alert('Download failure.'); }
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>GLOBAL SYSTEMS AUDIT LOG TRACKING CORE</h2>
        <p className={styles.subtitle}>Unfiltered programmatic history tracing atomic transactions across user layers.</p>
        <button onClick={handleDownload} className={styles.dlBtn}>DOWNLOAD FULL EXCEL MATRIX REPORT</button>
      </header>

      <div className={styles.filterBar}>
        <input type="text" placeholder="User ID Index" value={userId} onChange={e => setUserId(e.target.value)} />
        <input type="text" placeholder="Tenant Client ID" value={clientId} onChange={e => setClientId(e.target.value)} />
        <input type="text" placeholder="EVENT_TYPE_STRING" value={eventType} onChange={e => setEventType(e.target.value)} className={styles.mono} />
        <button onClick={() => { setPage(1); fetchLogs(); }}>QUERY TARGET LOG BOUNDS</button>
      </div>

      {loading ? (
        <div className={styles.loader}>LOADING AUDIT RECORDS...</div>
      ) : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>TIMESTAMP (EAT)</th>
                <th>ACTOR IDENTITY</th>
                <th>ROLE WEIGHT</th>
                <th>VECTOR DISPOSITION TYPE</th>
                <th>DETAILS TRANSLATION RUN JSONB</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(l => (
                <tr key={l.id}>
                  <td className={styles.mono}>{l.performed_at}</td>
                  <td className={styles.mono}>ID Node: {l.user_id}</td>
                  <td><span className={styles.roleBadge}>{l.role}</span></td>
                  <td><span className={styles.eventBadge}>{l.event_type}</span></td>
                  <td><pre className={styles.json}>{JSON.stringify(l.details, null, 2)}</pre></td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr><td colSpan="5" className={styles.empty}>No audit records found for the current filter criteria.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className={styles.pagination}>
        <button disabled={page === 1} onClick={() => setPage(p => p - 1)}>PREVIOUS</button>
        <span>PAGE TRACK NODE CONTAINER: {page}</span>
        <button disabled={logs.length < 25} onClick={() => setPage(p => p + 1)}>NEXT OFFSET VIEW</button>
      </div>
    </div>
  );
}
