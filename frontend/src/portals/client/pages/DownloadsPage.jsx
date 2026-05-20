import { useState, useEffect } from "react";
import api from "../../../api/axios";
import styles from "./DownloadsPage.module.css";

const PERIODS = [
  { value: "24h", label: "Last 24 Hours" },
  { value: "7d",  label: "Last 7 Days"   },
  { value: "30d", label: "Last 30 Days"  },
];

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function DownloadsPage() {
  const [queries, setQueries] = useState([]);
  const [periods, setPeriods] = useState({});   // { query_name: "7d" }
  const [loading, setLoading] = useState({});    // { query_name: bool }
  const [fetchError, setFetchError] = useState(null);

  useEffect(() => {
    async function init() {
      try {
        const res = await api.get("/client/queries");
        const qs = res.data ?? [];
        setQueries(qs);
        // default period per query
        const defaults = {};
        qs.forEach((q) => { defaults[q.query_name] = "7d"; });
        setPeriods(defaults);
      } catch {
        setFetchError("Failed to load available reports.");
      }
    }
    init();
  }, []);

  async function handleDownload(queryName) {
    const period = periods[queryName] ?? "7d";
    setLoading((prev) => ({ ...prev, [queryName]: true }));
    try {
      const res = await api.get(
        `/client/events/download?query_name=${encodeURIComponent(queryName)}&period=${period}`,
        { responseType: "blob" }
      );
      const filename = `${queryName.replace(/\s+/g, "_")}_${period}.xlsx`;
      triggerDownload(res.data, filename);
    } catch {
      alert(`Download failed for "${queryName}".`);
    } finally {
      setLoading((prev) => ({ ...prev, [queryName]: false }));
    }
  }

  function handlePeriodChange(queryName, value) {
    setPeriods((prev) => ({ ...prev, [queryName]: value }));
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Download Reports</h1>
        <p className={styles.subtitle}>
          Export your security event data as formatted Excel reports.
        </p>
      </div>

      {fetchError && <div className={styles.errorMsg}>{fetchError}</div>}

      {queries.length === 0 && !fetchError && (
        <div className={styles.empty}>No reports available.</div>
      )}

      <div className={styles.grid}>
        {queries.map((q) => (
          <div key={q.query_name} className={styles.card}>
            <div className={styles.cardHeader}>
              <span className={styles.cardIcon}>⬇</span>
              <span className={styles.cardTitle}>{q.query_name}</span>
            </div>

            <div className={styles.periodRow}>
              <label className={styles.periodLabel}>Period</label>
              <select
                className={styles.periodSelect}
                value={periods[q.query_name] ?? "7d"}
                onChange={(e) => handlePeriodChange(q.query_name, e.target.value)}
              >
                {PERIODS.map((p) => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
            </div>

            <button
              className={styles.btnDownload}
              onClick={() => handleDownload(q.query_name)}
              disabled={loading[q.query_name]}
            >
              {loading[q.query_name] ? (
                <>
                  <span className={styles.spinner} />
                  Preparing…
                </>
              ) : (
                "Export Excel"
              )}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
