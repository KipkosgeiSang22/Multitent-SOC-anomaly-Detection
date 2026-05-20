import { useState, useEffect, useRef } from "react";
import api from "../../../api/axios";
import styles from "./AnalystAnomaliesPage.module.css";

const CATEGORIES = [
  "AuthenticationEvents",
  "AccountManagementEvents",
  "ProcessCreationEvents",
];

const CATEGORY_SHORT = {
  AuthenticationEvents: "Auth",
  AccountManagementEvents: "Account Mgmt",
  ProcessCreationEvents: "Process",
};

const PERIODS = [
  { value: "last_24h", label: "24h" },
  { value: "last_7d",  label: "7d"  },
  { value: "last_30d", label: "30d" },
];

function scoreColor(score) {
  if (score == null) return styles.scoreNone;
  if (score < -0.3)  return styles.scoreCritical;
  if (score < -0.1)  return styles.scoreHigh;
  return styles.scoreMed;
}

export default function AnalystAnomaliesPage() {
  const [anomalies,  setAnomalies]  = useState([]);
  const [clients,    setClients]    = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [ackLoading, setAckLoading] = useState(null);
  const [ackModal,   setAckModal]   = useState(null);
  const [ackNotes,   setAckNotes]   = useState("");

  const [filters, setFilters] = useState({
    client_id:    "",
    category:     "",
    layer:        "",
    period:       "last_7d",
    acknowledged: "",
  });

  // Use a ref so the fetch function is always current without being a dependency
  const filtersRef = useRef(filters);
  useEffect(() => { filtersRef.current = filters; }, [filters]);

  // Single stable fetch function — reads from ref, never a stale closure
  const fetchAnomalies = async (overrideFilters) => {
    const f = overrideFilters ?? filtersRef.current;
    setLoading(true);
    setError(null);
    try {
      const params = { period: f.period };
      if (f.client_id)       params.client_id  = f.client_id;
      if (f.category)        params.category   = f.category;
      if (f.layer)           params.layer      = f.layer;
      if (f.acknowledged !== "") {
        params.acknowledged = f.acknowledged === "true";
      }
      const res = await api.get("/analyst/anomalies", { params });
      setAnomalies(res.data ?? []);
    } catch {
      setError("Failed to load anomalies.");
    } finally {
      setLoading(false);
    }
  };

  // Fetch once on mount
  useEffect(() => {
    fetchAnomalies();
    api.get("/analyst/clients")
      .then(r => setClients(r.data ?? []))
      .catch(() => {});
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch whenever a filter changes — but only after mount (skip initial render)
  const isMounted = useRef(false);
  useEffect(() => {
    if (!isMounted.current) { isMounted.current = true; return; }
    fetchAnomalies(filters);
  }, [filters]); // eslint-disable-line react-hooks/exhaustive-deps

  function set(k, v) {
    setFilters(f => ({ ...f, [k]: v }));
  }

  async function acknowledge() {
    if (!ackModal) return;
    setAckLoading(ackModal.id);
    try {
      await api.post("/analyst/anomalies/acknowledge", {
        anomaly_id: ackModal.id,
        notes: ackNotes || null,
      });
      setAnomalies(prev =>
        prev.map(a =>
          a.id === ackModal.id
            ? { ...a, acknowledged_by: 1, acknowledged_at: new Date().toISOString() }
            : a
        )
      );
      setAckModal(null);
      setAckNotes("");
    } catch {
      alert("Acknowledge failed.");
    } finally {
      setAckLoading(null);
    }
  }

  const unacked = anomalies.filter(a => !a.acknowledged_by).length;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>ANOMALIES</h1>
          {unacked > 0 && (
            <span className={styles.unackedBadge}>{unacked} unacknowledged</span>
          )}
        </div>
      </div>

      <div className={styles.filters}>
        <select
          className={styles.select}
          value={filters.client_id}
          onChange={e => set("client_id", e.target.value)}
        >
          <option value="">All Clients</option>
          {clients.map(c => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
        </select>

        <select
          className={styles.select}
          value={filters.category}
          onChange={e => set("category", e.target.value)}
        >
          <option value="">All Categories</option>
          {CATEGORIES.map(c => (
            <option key={c} value={c}>{CATEGORY_SHORT[c]}</option>
          ))}
        </select>

        <select
          className={styles.select}
          value={filters.layer}
          onChange={e => set("layer", e.target.value)}
        >
          <option value="">All Layers</option>
          <option value="1">L1 Rules</option>
          <option value="2">L2 ML</option>
        </select>

        {PERIODS.map(p => (
          <button
            key={p.value}
            className={`${styles.periodBtn} ${filters.period === p.value ? styles.periodActive : ""}`}
            onClick={() => set("period", p.value)}
          >
            {p.label}
          </button>
        ))}

        <select
          className={styles.select}
          value={filters.acknowledged}
          onChange={e => set("acknowledged", e.target.value)}
        >
          <option value="">All</option>
          <option value="false">Unacknowledged</option>
          <option value="true">Acknowledged</option>
        </select>
      </div>

      <p className={styles.count}>{anomalies.length} anomalies</p>
      {error && <p className={styles.errorMsg}>{error}</p>}

      {loading ? (
        <p className={styles.loading}>Loading…</p>
      ) : anomalies.length === 0 ? (
        <p className={styles.empty}>No anomalies match the selected filters.</p>
      ) : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Detected</th>
                <th>Client</th>
                <th>Category</th>
                <th>Layer</th>
                <th>Type</th>
                <th>Score</th>
                <th>Details</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {anomalies.map(a => (
                <tr
                  key={a.id}
                  className={`${styles.row} ${a.acknowledged_by ? styles.acked : styles.unacked}`}
                >
                  <td className={styles.mono}>
                    {new Date(a.detected_at).toLocaleString()}
                  </td>
                  <td>
                    <span className={styles.clientTag}>{a.client_name}</span>
                  </td>
                  <td>
                    <span className={styles.catTag}>
                      {CATEGORY_SHORT[a.category] ?? a.category}
                    </span>
                  </td>
                  <td>
                    <span className={`${styles.layerBadge} ${a.layer === 1 ? styles.layer1 : styles.layer2}`}>
                      L{a.layer}
                    </span>
                  </td>
                  <td className={styles.typeCell}>{a.anomaly_type}</td>
                  <td>
                    {a.anomaly_score != null ? (
                      <span className={`${styles.score} ${scoreColor(a.anomaly_score)}`}>
                        {a.anomaly_score.toFixed(3)}
                      </span>
                    ) : (
                      <span className={styles.muted}>—</span>
                    )}
                  </td>
                  <td>
                    <DetailsCell details={a.details} />
                  </td>
                  <td>
                    {a.acknowledged_by ? (
                      <span className={styles.ackedBadge}>✓ Acked</span>
                    ) : (
                      <span className={styles.pendingBadge}>Pending</span>
                    )}
                  </td>
                  <td>
                    {!a.acknowledged_by && (
                      <button
                        className={styles.ackBtn}
                        disabled={ackLoading === a.id}
                        onClick={() => { setAckModal(a); setAckNotes(""); }}
                      >
                        Acknowledge
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {ackModal && (
        <div className={styles.modalBackdrop} onClick={() => setAckModal(null)}>
          <div className={styles.modal} onClick={e => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <span className={styles.modalTitle}>Acknowledge Anomaly</span>
              <button className={styles.modalClose} onClick={() => setAckModal(null)}>✕</button>
            </div>
            <p className={styles.modalMeta}>
              {CATEGORY_SHORT[ackModal.category]} · Layer {ackModal.layer} · {ackModal.anomaly_type}
            </p>
            <p className={styles.modalMeta}>
              {ackModal.client_name} · Score: {ackModal.anomaly_score?.toFixed(3) ?? "—"}
            </p>
            <textarea
              className={styles.notesInput}
              placeholder="Optional notes…"
              value={ackNotes}
              onChange={e => setAckNotes(e.target.value)}
              rows={3}
            />
            <div className={styles.modalActions}>
              <button className={styles.cancelBtn} onClick={() => setAckModal(null)}>
                Cancel
              </button>
              <button
                className={styles.confirmBtn}
                onClick={acknowledge}
                disabled={ackLoading === ackModal.id}
              >
                {ackLoading === ackModal.id ? "…" : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailsCell({ details }) {
  const [expanded, setExpanded] = useState(false);
  if (!details) return <span style={{ color: "rgba(255,255,255,0.2)" }}>—</span>;
  const keys = Object.keys(details);
  if (keys.length === 0) return <span style={{ color: "rgba(255,255,255,0.2)" }}>—</span>;
  const preview = keys.slice(0, 2).map(k => `${k}: ${details[k]}`).join(" · ");
  return (
    <div>
      <span style={{ fontSize: "11px", color: "#64748b" }}>{preview}</span>
      {keys.length > 2 && (
        <button
          style={{
            fontSize: "10px", color: "#06b6d4", background: "none",
            border: "none", cursor: "pointer", padding: "0 4px",
          }}
          onClick={() => setExpanded(v => !v)}
        >
          {expanded ? "less" : `+${keys.length - 2}`}
        </button>
      )}
      {expanded && (
        <pre style={{
          fontSize: "10px", color: "#64748b", margin: "4px 0 0",
          whiteSpace: "pre-wrap", wordBreak: "break-all",
        }}>
          {JSON.stringify(details, null, 2)}
        </pre>
      )}
    </div>
  );
}
