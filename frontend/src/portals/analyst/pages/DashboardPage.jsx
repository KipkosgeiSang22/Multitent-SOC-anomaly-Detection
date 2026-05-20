import { useState, useEffect } from "react";
import api from "../../../api/axios";
import styles from "./DashboardPage.module.css";

const STATUS_ICONS = {
  success: "✓",
  failed: "✗",
};

function StatCard({ label, value, sub }) {
  return (
    <div className={styles.statCard}>
      <p className={styles.statLabel}>{label}</p>
      <p className={styles.statValue}>{value ?? "—"}</p>
      {sub && <p className={styles.statSub}>{sub}</p>}
    </div>
  );
}

function SchedulerCard({ row }) {
  const ok = row.last_run_status === "success";
  return (
    <div className={`${styles.schedulerCard} ${ok ? styles.schedOk : styles.schedFail}`}>
      <div className={styles.schedHeader}>
        <span className={styles.schedName}>{row.process_name}</span>
        <span className={`${styles.schedBadge} ${ok ? styles.badgeOk : styles.badgeFail}`}>
          {STATUS_ICONS[row.last_run_status] ?? "?"} {row.last_run_status}
        </span>
      </div>
      <div className={styles.schedMeta}>
        <span>Last run: {row.last_run_at ? new Date(row.last_run_at).toLocaleString() : "never"}</span>
        {row.duration_seconds != null && (
          <span>{row.duration_seconds.toFixed(1)}s</span>
        )}
      </div>
      {row.events_inserted != null && (
        <p className={styles.schedDetail}>{row.events_inserted} events inserted · {row.anomalies_detected ?? 0} anomalies</p>
      )}
      {row.last_error && (
        <p className={styles.schedError}>{row.last_error}</p>
      )}
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await api.get("/analyst/dashboard-stats");
        setStats(res.data);
      } catch {
        setError("Failed to load dashboard stats.");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <div className={styles.page}><p className={styles.loading}>Loading…</p></div>;
  if (error) return <div className={styles.page}><p className={styles.errorMsg}>{error}</p></div>;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>ANALYST DASHBOARD</h1>
        <span className={styles.live}>● LIVE</span>
      </div>

      <div className={styles.statsGrid}>
        <StatCard label="ACTIVE CLIENTS" value={stats.total_clients} />
        <StatCard label="EVENTS TODAY" value={stats.total_events_today?.toLocaleString()} />
        <StatCard label="UNACKNOWLEDGED ANOMALIES" value={stats.unacknowledged_anomalies} />
        <StatCard label="OPEN ISSUES" value={stats.open_issues} />
      </div>

      <h2 className={styles.sectionTitle}>SCHEDULER STATUS</h2>
      <div className={styles.schedulerGrid}>
        {stats.scheduler_status?.length === 0 && (
          <p className={styles.empty}>No scheduler runs recorded yet.</p>
        )}
        {stats.scheduler_status?.map((row) => (
          <SchedulerCard key={row.process_name} row={row} />
        ))}
      </div>
    </div>
  );
}
