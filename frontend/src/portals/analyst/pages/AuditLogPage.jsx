import { useState, useEffect, useCallback } from "react";
import api from "../../../api/axios";
import styles from "./AuditLogPage.module.css";

const EVENT_COLORS = {
  CLIENT_LOGIN: "blue", ANALYST_LOGIN: "blue", SUPERADMIN_LOGIN: "blue",
  LOGIN_FAILED: "red", LOGOUT: "gray",
  EVENT_CONFIRMED: "green", EVENT_ISSUE_RAISED: "amber",
  ANOMALY_ACKNOWLEDGED: "purple",
  FILE_DOWNLOADED: "teal",
  MODEL_RETRAINED: "purple", MODEL_ROLLED_BACK: "amber",
  LAYER1_RULE_CREATED: "teal", LAYER1_RULE_UPDATED: "teal", LAYER1_RULE_DELETED: "red",
};

function eventColor(type) {
  return EVENT_COLORS[type] || "gray";
}

export default function AuditLogPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get("/analyst/audit-log", {
        params: { limit: PAGE_SIZE, offset: page * PAGE_SIZE }
      });
      setLogs(res.data ?? []);
    } catch {
      setError("Failed to load audit log.");
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>AUDIT LOG</h1>
        <p className={styles.sub}>Filtered — superadmin actions excluded</p>
      </div>

      {error && <p className={styles.errorMsg}>{error}</p>}

      {loading ? <p className={styles.loading}>Loading…</p> : logs.length === 0 ? (
        <p className={styles.empty}>No audit log entries found.</p>
      ) : (
        <>
          <div className={styles.tableWrapper}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>Role</th>
                  <th>Event</th>
                  <th>Client</th>
                  <th>IP</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id} className={styles.row} onClick={() => setSelected(log)}>
                    <td className={styles.mono}>{new Date(log.performed_at).toLocaleString()}</td>
                    <td className={styles.username}>{log.username || log.user_id}</td>
                    <td><span className={`${styles.roleBadge} ${styles[`role_${log.role}`]}`}>{log.role}</span></td>
                    <td>
                      <span className={`${styles.eventBadge} ${styles[`event_${eventColor(log.event_type)}`]}`}>
                        {log.event_type}
                      </span>
                    </td>
                    <td className={styles.clientCell}>{log.client_id ?? "—"}</td>
                    <td className={styles.mono}>{log.ip_address}</td>
                    <td className={styles.detailsPreview}>
                      {log.details ? Object.keys(log.details).slice(0, 2).map(k => `${k}: ${log.details[k]}`).join(" · ") : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className={styles.pagination}>
            <button className={styles.pageBtn} onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
              ← Prev
            </button>
            <span className={styles.pageNum}>Page {page + 1}</span>
            <button className={styles.pageBtn} onClick={() => setPage(p => p + 1)} disabled={logs.length < PAGE_SIZE}>
              Next →
            </button>
          </div>
        </>
      )}

      {selected && (
        <div className={styles.modalBackdrop} onClick={() => setSelected(null)}>
          <div className={styles.modal} onClick={e => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <span className={styles.modalTitle}>Audit Entry #{selected.id}</span>
              <button className={styles.modalClose} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div className={styles.detailGrid}>
              {[
                ["Time", new Date(selected.performed_at).toLocaleString()],
                ["User ID", selected.user_id],
                ["Username", selected.username || "—"],
                ["Role", selected.role],
                ["Event", selected.event_type],
                ["Client ID", selected.client_id ?? "—"],
                ["Target ID", selected.target_id ?? "—"],
                ["IP Address", selected.ip_address],
                ["User Agent", selected.user_agent],
              ].map(([k, v]) => (
                <div key={k} className={styles.detailRow}>
                  <span className={styles.detailKey}>{k}</span>
                  <span className={styles.detailVal}>{v}</span>
                </div>
              ))}
            </div>
            {selected.details && (
              <div className={styles.detailsBlock}>
                <p className={styles.sectionLabel}>DETAILS</p>
                <pre className={styles.detailsJson}>{JSON.stringify(selected.details, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
