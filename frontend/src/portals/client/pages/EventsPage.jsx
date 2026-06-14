import { useState, useEffect, useCallback } from "react";
import api from "../../../api/axios";
import styles from "./EventsPage.module.css";

// ── helpers ──────────────────────────────────────────────────────────────────

function formatPeriodParam(period, custom) {
  if (period === "custom" && custom.start && custom.end) {
    return `custom&start=${custom.start}&end=${custom.end}`;
  }
  return period;
}

function getFieldKeys(events) {
  const keys = new Set();
  events.forEach((e) => {
    if (e.fields && typeof e.fields === "object") {
      Object.keys(e.fields).forEach((k) => keys.add(k));
    }
  });
  return Array.from(keys);
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ── TabBar ────────────────────────────────────────────────────────────────────

function TabBar({ queries, activeTab, badges, onTabClick }) {
  return (
    <div className={styles.tabBar}>
      {queries.map((q) => {
        const count = badges[q.query_name] ?? 0;
        const isActive = activeTab === q.query_name;
        return (
          <button
            key={q.query_name}
            className={`${styles.tab} ${isActive ? styles.tabActive : ""}`}
            onClick={() => onTabClick(q.query_name)}
          >
            <span className={styles.tabLabel}>{q.query_name}</span>
            {count > 0 && (
              <span className={styles.badge}>{count > 99 ? "99+" : count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

// ── PeriodFilter ──────────────────────────────────────────────────────────────

function PeriodFilter({ period, custom, onChange, onCustomChange }) {
  return (
    <div className={styles.periodFilter}>
      {["last_24h", "last_7d", "last_30d"].map((p) => (
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
      >
        Custom
      </button>
      {period === "custom" && (
        <div className={styles.customRange}>
          <input
            type="datetime-local"
            className={styles.dateInput}
            value={custom.start}
            onChange={(e) => onCustomChange("start", e.target.value)}
          />
          <span className={styles.dateSep}>→</span>
          <input
            type="datetime-local"
            className={styles.dateInput}
            value={custom.end}
            onChange={(e) => onCustomChange("end", e.target.value)}
          />
        </div>
      )}
    </div>
  );
}

// ── IssueThread ───────────────────────────────────────────────────────────────

function IssueThread({ eventId, onClose, onThreadLoaded, onRepliesSeen }) {
  const [thread, setThread] = useState(null);
  const [loading, setLoading] = useState(true);
  const [newText, setNewText] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const loadThread = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get(`/client/events/${eventId}/issues`);
      const data = res.data ?? [];
      setThread(data);

      const openCount = data.filter((i) => !i.resolved_at).length;
      const resolvedCount = data.filter((i) => !!i.resolved_at).length;
      const unreadCount = data.filter(
        (i) => i.analyst_comment && !i.reply_seen_at
      ).length;

      onThreadLoaded?.({ openCount, resolvedCount, unreadCount });

      if (unreadCount > 0) {
        await api.post("/client/issues/mark-seen", { event_id: eventId });
        onRepliesSeen?.();
      }
    } catch {
      setError("Failed to load thread.");
    } finally {
      setLoading(false);
    }
  }, [eventId, onThreadLoaded, onRepliesSeen]);

  useEffect(() => {
    loadThread();
  }, [loadThread]);

  async function handleSubmit() {
    if (!newText.trim()) return;
    setSubmitting(true);
    try {
      await api.post("/client/events/raise-issue", {
        event_id: eventId,
        issue_text: newText.trim(),
      });
      setNewText("");
      await loadThread();
    } catch {
      alert("Failed to raise issue.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className={styles.threadPanel}>
      <div className={styles.threadHeader}>
        <span className={styles.threadTitle}>ISSUE THREAD</span>
        <button className={styles.threadClose} onClick={onClose}>✕</button>
      </div>

      {error && (
        <p style={{ color: "#ef4444", fontSize: 12, margin: "0 0 0.5rem" }}>{error}</p>
      )}

      <div className={styles.threadMessages}>
        {loading ? (
          <p style={{ color: "#64748b", fontSize: 12 }}>Loading…</p>
        ) : !thread || thread.length === 0 ? (
          <p style={{ color: "#64748b", fontSize: 12 }}>No issues yet. Add one below.</p>
        ) : (
          thread.map((issue) => {
            const isUnread = !!issue.analyst_comment && !issue.reply_seen_at;
            return (
              <div
                key={issue.id}
                className={`${styles.msgBubble} ${issue.resolved_at ? styles.msgBubbleResolved : ""}`}
              >
                <div className={styles.msgHeader}>
                  <span className={styles.msgAuthor}>{issue.raised_by_username ?? "You"}</span>
                  <span className={styles.msgTime}>{fmtTime(issue.created_at)}</span>
                  {issue.resolved_at && (
                    <span className={styles.resolvedBadge}>✓ Resolved</span>
                  )}
                </div>
                <p className={styles.msgBody}>{issue.issue_text}</p>

                {issue.analyst_comment && (
                  <div className={`${styles.analystReply} ${isUnread ? styles.analystReplyUnread : ""}`}>
                    <div className={styles.analystReplyHeader}>
                      <span className={styles.analystTag}>ANALYST</span>
                      <span className={styles.analystAuthor}>
                        {issue.resolved_by_username ?? "Analyst"}
                      </span>
                      <span className={styles.msgTime}>{fmtTime(issue.resolved_at)}</span>
                      {isUnread && <span className={styles.newReplyBadge}>NEW</span>}
                    </div>
                    <p className={styles.analystReplyBody}>{issue.analyst_comment}</p>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      <div className={styles.threadAddIssue}>
        <textarea
          className={styles.issueTextarea}
          placeholder="Describe an issue you've identified…"
          rows={2}
          value={newText}
          onChange={(e) => setNewText(e.target.value)}
        />
        <div className={styles.issueActions} style={{ marginTop: "0.4rem" }}>
          <button
            className={styles.btnSubmitIssue}
            disabled={submitting || !newText.trim()}
            onClick={handleSubmit}
          >
            {submitting ? "Submitting…" : "Add to Thread"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── FlagButton ────────────────────────────────────────────────────────────────

function FlagButton({ openCount, resolvedCount, unreadCount, onClick }) {
  if (unreadCount > 0) {
    return (
      <button
        className={styles.flagReplied}
        onClick={onClick}
        title={`${unreadCount} new analyst repl${unreadCount === 1 ? "y" : "ies"} — click to view`}
      >
        ⚑{" "}
        <span className={styles.flagReplyCount}>
          {unreadCount} analyst repl{unreadCount === 1 ? "y" : "ies"}
        </span>
      </button>
    );
  }
  if (openCount > 0) {
    return (
      <button
        className={styles.flagOpen}
        onClick={onClick}
        title={`${openCount} open issue${openCount === 1 ? "" : "s"}`}
      >
        ⚑ <span className={styles.flagCount}>{openCount} open</span>
      </button>
    );
  }
  if (resolvedCount > 0) {
    return (
      <button className={styles.flagResolved} onClick={onClick} title="All issues resolved">
        ⚑ <span className={styles.flagResolvedText}>resolved</span>
      </button>
    );
  }
  return null;
}

// ── EventRow ──────────────────────────────────────────────────────────────────

function EventRow({ event, fieldKeys, onConfirm, onRepliesSeen }) {
  const [confirmLoading, setConfirmLoading] = useState(false);
  const [showThread, setShowThread] = useState(false);

  const [openCount, setOpenCount] = useState(event.open_issue_count ?? 0);
  const [resolvedCount, setResolvedCount] = useState(event.resolved_issue_count ?? 0);
  const [unreadCount, setUnreadCount] = useState(event.unread_reply_count ?? 0);

  const isConfirmed = !!event.confirmed_by;
  const hasAnyIssue = openCount > 0 || resolvedCount > 0;

  function handleFlagClick() {
    setShowThread((v) => !v);
  }

  async function handleConfirm() {
    setConfirmLoading(true);
    try {
      await onConfirm(event.id);
    } finally {
      setConfirmLoading(false);
    }
  }

  function handleThreadLoaded({ openCount: o, resolvedCount: r }) {
    setOpenCount(o);
    setResolvedCount(r);
  }

  function handleRepliesSeen() {
    setUnreadCount(0);
    onRepliesSeen?.();
  }

  const threadButtonLabel = showThread
    ? "Close Thread"
    : hasAnyIssue || unreadCount > 0
    ? "View Thread"
    : "Raise Issue";

  return (
    <>
      <tr
        className={[
          styles.eventRow,
          isConfirmed ? styles.confirmedRow : "",
          hasAnyIssue ? styles.issueRow : "",
          unreadCount > 0 ? styles.unreadReplyRow : "",
        ]
          .filter(Boolean)
          .join(" ")}
      >
        {/* Time */}
        <td className={styles.timeCell} data-label="Time">
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
        {fieldKeys.map((k) => (
          <td key={k} className={styles.fieldCell} data-label={k}>
            {event.fields?.[k] ?? "—"}
          </td>
        ))}

        {/* Status */}
        <td className={styles.statusCell} data-label="Status">
          {isConfirmed && (
            <div className={styles.confirmedBadge}>
              <span className={styles.checkIcon}>✓</span>
              <span className={styles.confirmedMeta}>
                {event.confirmed_by_username}
                <br />
                <small>{fmtTime(event.confirmed_at)}</small>
              </span>
            </div>
          )}

          {(hasAnyIssue || unreadCount > 0) && (
            <div className={styles.issueBadge} style={{ marginTop: isConfirmed ? "0.35rem" : 0 }}>
              <FlagButton
                openCount={openCount}
                resolvedCount={resolvedCount}
                unreadCount={unreadCount}
                onClick={handleFlagClick}
              />
            </div>
          )}

          {unreadCount > 0 && (
            <div className={styles.replyNotice} onClick={handleFlagClick}>
              💬 Analyst replied — click to view
            </div>
          )}
        </td>

        {/* Actions */}
        <td className={styles.actionsCell} data-label="Actions">
          {!isConfirmed && (
            <button className={styles.btnConfirm} onClick={handleConfirm} disabled={confirmLoading}>
              {confirmLoading ? "…" : "Confirm"}
            </button>
          )}
          <button className={styles.btnRaiseIssue} onClick={handleFlagClick}>
            {threadButtonLabel}
          </button>
        </td>
      </tr>

      {/* Inline thread panel */}
      {showThread && (
        <tr className={styles.issueInputRow}>
          <td colSpan={3 + fieldKeys.length} style={{ padding: 0 }}>
            <IssueThread
              eventId={event.id}
              onClose={() => setShowThread(false)}
              onThreadLoaded={handleThreadLoaded}
              onRepliesSeen={handleRepliesSeen}
            />
          </td>
        </tr>
      )}
    </>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function EventsPage() {
  const [queries, setQueries] = useState([]);
  const [badges, setBadges] = useState({});
  const [activeTab, setActiveTab] = useState(null);
  const [events, setEvents] = useState([]);
  const [fieldKeys, setFieldKeys] = useState([]);
  const [period, setPeriod] = useState("last_7d");
  const [custom, setCustom] = useState({ start: "", end: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [downloadLoading, setDownloadLoading] = useState(false);

  useEffect(() => {
    async function init() {
      try {
        const qRes = await api.get("/client/queries");
        const qs = qRes.data;
        setQueries(qs);
        const badgeMap = {};
        qs.forEach((q) => { badgeMap[q.query_name] = q.unviewed_count ?? 0; });
        setBadges(badgeMap);
        if (qs.length > 0) setActiveTab(qs[0].query_name);
      } catch {
        setError("Failed to load queries.");
      }
    }
    init();
  }, []);

  const fetchEvents = useCallback(async () => {
    if (!activeTab) return;
    setLoading(true);
    setError(null);
    try {
      const periodParam = formatPeriodParam(period, custom);
      const res = await api.get(
        `/client/events?query_name=${encodeURIComponent(activeTab)}&period=${periodParam}`
      );
      const data = res.data ?? [];
      setEvents(data);
      setFieldKeys(getFieldKeys(data));
    } catch {
      setError("Failed to load events.");
    } finally {
      setLoading(false);
    }
  }, [activeTab, period, custom]);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);

  async function handleTabClick(queryName) {
    setActiveTab(queryName);
    setBadges((prev) => ({ ...prev, [queryName]: 0 }));
  }

  async function handleConfirm(eventId) {
    try {
      await api.post("/client/events/confirm", { event_id: eventId });
      setEvents((prev) =>
        prev.map((e) =>
          e.id === eventId
            ? { ...e, confirmed_by: true, confirmed_at: new Date().toISOString() }
            : e
        )
      );
    } catch {
      alert("Failed to confirm event.");
    }
  }

  async function notifyRepliesSeen() {
    window.dispatchEvent(new Event("soc:replies-seen"));
    try {
      const res = await api.get("/client/issues/unread-by-event");
      const unreadMap = res.data ?? {};
      setEvents((prev) =>
        prev.map((e) => ({
          ...e,
          unread_reply_count: unreadMap[e.id] ?? 0,
        }))
      );
    } catch {
      // non-critical
    }
  }

  async function handleDownload() {
    setDownloadLoading(true);
    try {
      const periodParam = formatPeriodParam(period, custom);
      const res = await api.get(
        `/client/events/download?query_name=${encodeURIComponent(activeTab)}&period=${periodParam}`,
        { responseType: "blob" }
      );
      const filename = `events_${activeTab}_${period}.xlsx`.replace(/\s+/g, "_");
      triggerDownload(res.data, filename);
    } catch {
      alert("Download failed.");
    } finally {
      setDownloadLoading(false);
    }
  }

  function handleCustomChange(field, value) {
    setCustom((prev) => ({ ...prev, [field]: value }));
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Security Events</h1>
        {activeTab && (
          <button
            className={styles.btnDownload}
            onClick={handleDownload}
            disabled={downloadLoading}
          >
            {downloadLoading ? "Preparing…" : "↓ Download Excel"}
          </button>
        )}
      </div>

      {queries.length > 0 ? (
        <TabBar queries={queries} activeTab={activeTab} badges={badges} onTabClick={handleTabClick} />
      ) : (
        !error && <div className={styles.empty}>No query tabs configured.</div>
      )}

      <PeriodFilter
        period={period}
        custom={custom}
        onChange={setPeriod}
        onCustomChange={handleCustomChange}
      />

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
                {fieldKeys.map((k) => (
                  <th key={k} className={styles.th}>{k}</th>
                ))}
                <th className={styles.th}>Status</th>
                <th className={styles.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <EventRow
                  key={event.id}
                  event={event}
                  fieldKeys={fieldKeys}
                  onConfirm={handleConfirm}
                  onRepliesSeen={notifyRepliesSeen}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}