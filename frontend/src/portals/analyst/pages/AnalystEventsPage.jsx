import { useState, useEffect, useCallback } from "react";
import { useOutletContext } from "react-router-dom"; 
import api from "../../../api/axios";
import styles from "./AnalystEventsPage.module.css";

// ── helpers ───────────────────────────────────────────────────────────────────

function getFieldKeys(events) {
  const keys = new Set();
  events.forEach(e => {
    if (e.fields && typeof e.fields === "object")
      Object.keys(e.fields).forEach(k => keys.add(k));
  });
  return Array.from(keys);
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ── sub-components ────────────────────────────────────────────────────────────

function ClientGrid({ clients, onSelect }) {
  return (
    <div className={styles.clientGrid}>
      {clients.map(c => (
        <button key={c.id} className={styles.clientCard} onClick={() => onSelect(c)}>
          <span className={styles.clientCardIcon}>🏢</span>
          <span className={styles.clientCardName}>{c.name}</span>
          <span className={styles.clientCardArrow}>→</span>
        </button>
      ))}
    </div>
  );
}

function TabBar({ queries, activeTab, onTabClick }) {
  return (
    <div className={styles.tabBar}>
      {queries.map(q => (
        <button
          key={q.query_name}
          className={`${styles.tab} ${activeTab === q.query_name ? styles.tabActive : ""}`}
          onClick={() => onTabClick(q.query_name)}
        >
          <span className={styles.tabLabel}>{q.query_name}</span>
        </button>
      ))}
    </div>
  );
}

function PeriodFilter({ period, custom, onChange, onCustomChange }) {
  return (
    <div className={styles.periodFilter}>
      {["last_24h", "last_7d", "last_30d"].map(p => (
        <button
          key={p}
          className={`${styles.periodBtn} ${period === p ? styles.periodActive : ""}`}
          onClick={() => onChange(p)}
        >
          {p === "last_24h" ? "24 Hours" : p === "last_7d" ? "7 Days" : "30 Days"}
        </button>
      ))}
      <button
        className={`${styles.periodBtn} ${period === "custom" ? styles.periodActive : ""}`}
        onClick={() => onChange("custom")}
      >Custom</button>
      {period === "custom" && (
        <div className={styles.customRange}>
          <input type="datetime-local" className={styles.dateInput}
            value={custom.start || ""} onChange={e => onCustomChange("start", e.target.value)} />
          <span className={styles.dateSep}>→</span>
          <input type="datetime-local" className={styles.dateInput}
            value={custom.end || ""} onChange={e => onCustomChange("end", e.target.value)} />
        </div>
      )}
    </div>
  );
}

function EventRow({ event, fieldKeys }) {
  const isConfirmed = !!event.confirmed_by;
  const hasIssue    = !!event.issue_text;

  return (
    <tr className={`${styles.eventRow} ${isConfirmed ? styles.confirmedRow : ""} ${hasIssue ? styles.issueRow : ""}`}>
      {/* Time */}
      <td className={styles.timeCell}>
        {event.time_summary ? (
          <span className={styles.timeSummary}>
            {event.time_summary.split("|").map((t, i) => (
              <span key={i} className={styles.timeStamp}>{t.trim()}</span>
            ))}
          </span>
        ) : (
          <span className={styles.timeSummary}>{event.timestamp}</span>
        )}
      </td>

      {/* Dynamic JSONB fields */}
      {fieldKeys.map(k => (
        <td key={k} className={styles.fieldCell}>{event.fields?.[k] ?? "—"}</td>
      ))}

      {/* Status — read-only for analysts */}
      <td className={styles.statusCell}>
        {isConfirmed && (
          <div className={styles.confirmedBadge}>
            <span className={styles.checkIcon}>✓</span>
            <span className={styles.confirmedMeta}>
              {event.confirmed_by_username}<br />
              <small>{event.confirmed_at}</small>
            </span>
          </div>
        )}
        {hasIssue && (
          <div className={styles.issueBadge}>
            <span className={styles.flagIcon}>⚑</span>
            <span className={styles.issueText}>{event.issue_text}</span>
          </div>
        )}
        {!isConfirmed && !hasIssue && (
          <span className={styles.unconfirmedBadge}>Unconfirmed</span>
        )}
      </td>
    </tr>
  );
}

// ── main component ────────────────────────────────────────────────────────────

export default function AnalystEventsPage() {
const ctx = useOutletContext() ?? {};
const [period, setPeriod] = useState("last_7d");
const [custom, setCustomState] = useState({ start: "", end: "" });

const setCustom = (field, val) => {
  setCustomState(prev => ({ ...prev, [field]: val }));
};

  const [clients,         setClients]         = useState([]);
  const [selectedClient,  setSelectedClient]  = useState(null);
  const [queries,         setQueries]         = useState([]);
  const [activeTab,       setActiveTab]       = useState(null);
  const [events,          setEvents]          = useState([]);
  const [fieldKeys,       setFieldKeys]       = useState([]);
  const [loading,         setLoading]         = useState(false);
  const [error,           setError]           = useState(null);
  const [downloading,     setDownloading]     = useState(false);

  // Load client list
  useEffect(() => {
    api.get("/analyst/clients")
      .then(r => setClients(r.data ?? []))
      .catch(() => {});
  }, []);

  // When client is selected, load its queries
  useEffect(() => {
    if (!selectedClient) { setQueries([]); setActiveTab(null); setEvents([]); return; }
    api.get(`/analyst/clients/${selectedClient.id}/queries`)
      .then(r => {
        const qs = r.data ?? [];
        setQueries(qs);
        if (qs.length > 0) setActiveTab(qs[0].query_name);
      })
      .catch(() => setQueries([]));
  }, [selectedClient]);

  // Load events when tab / period / client changes
  const fetchEvents = useCallback(async () => {
    if (!selectedClient || !activeTab) return;
    setLoading(true); setError(null);
    try {
      const params = { client_id: selectedClient.id, query_name: activeTab, period };
      if (period === "custom" && custom.start && custom.end) {
        params.start = custom.start;
        params.end   = custom.end;
      }

      const res = await api.get("/analyst/events", { params });
      const data = res.data ?? [];
      setEvents(data);
      setFieldKeys(getFieldKeys(data));
    } catch { setError("Failed to load events."); }
    finally  { setLoading(false); }
    // 🔑 FIXED: Tracking primitive strings stops infinite background loop blinking
  }, [selectedClient?.id, activeTab, period, custom?.start, custom?.end]);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);

  async function handleDownload() {
    setDownloading(true);
    try {
      const dlParams = { client_id: selectedClient.id, query_name: activeTab, period };
      if (period === "custom" && custom.start && custom.end) {
        dlParams.start = custom.start;
        dlParams.end   = custom.end;
      }
      const res = await api.get("/analyst/events/download", {
        params: dlParams,
        responseType: "blob",
      });
      triggerDownload(res.data, `${selectedClient.name}_${activeTab}_${period}.xlsx`.replace(/\s+/g, "_"));
    } catch { alert("Download failed."); }
    finally  { setDownloading(false); }
  }

  // ── No client selected — show picker ────────────────────────────────────
  if (!selectedClient) {
    return (
      <div className={styles.page}>
        <div className={styles.header}>
          <h1 className={styles.title}>Security Events</h1>
        </div>
        <p className={styles.pickPrompt}>Select a client to view their events</p>
        {clients.length === 0
          ? <p className={styles.empty}>No clients found.</p>
          : <ClientGrid clients={clients} onSelect={setSelectedClient} />
        }
      </div>
    );
  }

  // ── Client selected — tab view ────────────────────────────────────────────
  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <button className={styles.backBtn} onClick={() => setSelectedClient(null)}>
            ← All Clients
          </button>
          <h1 className={styles.title}>
            Security Events
            <span className={styles.clientBadge}>{selectedClient.name}</span>
          </h1>
        </div>
        {activeTab && (
          <button className={styles.btnDownload} onClick={handleDownload} disabled={downloading}>
            {downloading ? "Preparing…" : "↓ Download Excel"}
          </button>
        )}
      </div>

      {queries.length > 0
        ? <TabBar queries={queries} activeTab={activeTab} onTabClick={setActiveTab} />
        : <div className={styles.empty}>No query tabs configured for this client.</div>
      }

      <PeriodFilter period={period} custom={custom}
        onChange={setPeriod}
        onCustomChange={(f, v) => setCustom(f, v)} />

      {error && <div className={styles.errorMsg}>{error}</div>}

      {loading ? (
        <div className={styles.loadingState}>
          <span className={styles.spinner} />
          <span>Loading events…</span>
        </div>
      ) : events.length === 0 && !error ? (
        <div className={styles.empty}>No events found for this period.</div>
      ) : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.th}>Time</th>
                {fieldKeys.map(k => <th key={k} className={styles.th}>{k}</th>)}
                <th className={styles.th}>Status</th>
              </tr>
            </thead>
            <tbody>
              {events.map(event => (
                <EventRow key={event.id} event={event}
                  fieldKeys={fieldKeys} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}