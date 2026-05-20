import { useState, useEffect, useCallback } from "react";
import api from "../../../api/axios";
import styles from "./IssuesPage.module.css";

// ── helpers ───────────────────────────────────────────────────────────────────

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function groupByEvent(issues) {
  const map = new Map();
  for (const issue of issues) {
    if (!map.has(issue.event_id)) {
      map.set(issue.event_id, []);
    }
    map.get(issue.event_id).push(issue);
  }
  return Array.from(map.entries()).map(([event_id, items]) => ({
    event_id,
    client_id: items[0].client_id,
    items,
    openCount: items.filter(i => !i.resolved_at).length,
    resolvedCount: items.filter(i => !!i.resolved_at).length,
    firstIssue: items[0],
    latest: items[items.length - 1],
  }));
}

// ── MessageBubble ─────────────────────────────────────────────────────────────

function MessageBubble({ issue, onResolve, onDelete, onUpdateComment, isAnalyst }) {
  // resolve UI state: "idle" | "confirm" | "with-comment"
  const [resolveMode,       setResolveMode]       = useState("idle");
  const [resolveComment,    setResolveComment]    = useState("");
  const [resolveLoading,    setResolveLoading]    = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteLoading,     setDeleteLoading]     = useState(false);
  const [showEditForm,      setShowEditForm]      = useState(false);
  const [editComment,       setEditComment]       = useState("");
  const [editLoading,       setEditLoading]       = useState(false);

  const isResolved = !!issue.resolved_at;

  // Resolve without a comment — one-click via checkbox-style button
  async function handleResolveQuick() {
    setResolveLoading(true);
    await onResolve(issue.id, null);
    setResolveLoading(false);
    setResolveMode("idle");
  }

  // Resolve with a comment
  async function handleResolveWithComment() {
    setResolveLoading(true);
    await onResolve(issue.id, resolveComment.trim() || null);
    setResolveLoading(false);
    setResolveMode("idle");
    setResolveComment("");
  }

  async function handleDelete() {
    setDeleteLoading(true);
    await onDelete(issue.id);
    setDeleteLoading(false);
    setShowDeleteConfirm(false);
  }

  function openEditForm() {
    setEditComment(issue.analyst_comment ?? "");
    setShowEditForm(true);
  }

  async function handleConfirmEdit() {
    setEditLoading(true);
    await onUpdateComment(issue.id, editComment.trim() || null);
    setEditLoading(false);
    setShowEditForm(false);
  }

  return (
    <div className={`${styles.message} ${isResolved ? styles.messageResolved : styles.messageOpen}`}>
      <div className={styles.msgHeader}>
        <span className={styles.msgAuthor}>{issue.raised_by_username ?? `uid:${issue.raised_by}`}</span>
        <span className={styles.msgTime}>{fmtTime(issue.created_at)}</span>
        {isResolved && <span className={styles.resolvedBadge}>✓ Resolved</span>}
      </div>
      <p className={styles.msgBody}>{issue.issue_text}</p>

      {/* Analyst resolution reply */}
      {isResolved && (
        <div className={styles.analystReply}>
          <div className={styles.analystReplyHeader}>
            <span className={styles.analystTag}>ANALYST</span>
            <span className={styles.msgAuthor} style={{ color: "#06b6d4" }}>
              {issue.resolved_by_username ?? `uid:${issue.resolved_by}`}
            </span>
            <span className={styles.msgTime}>{fmtTime(issue.resolved_at)}</span>
          </div>

          {showEditForm ? (
            <div className={styles.resolveForm}>
              <textarea
                className={styles.resolveTextarea}
                rows={3}
                value={editComment}
                onChange={e => setEditComment(e.target.value)}
                placeholder="Add or update reply (optional)…"
                autoFocus
              />
              <div className={styles.resolveFormActions}>
                <button
                  className={styles.btnResolve}
                  disabled={editLoading}
                  onClick={handleConfirmEdit}
                >
                  {editLoading ? "Saving…" : "Save Changes"}
                </button>
                <button className={styles.btnCancel} onClick={() => setShowEditForm(false)}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <>
              <p className={styles.analystReplyBody}>
                {issue.analyst_comment
                  ? issue.analyst_comment
                  : <em style={{ opacity: 0.4 }}>Resolved without comment.</em>}
              </p>
              {isAnalyst && (
                <button className={styles.btnEditComment} onClick={openEditForm}>
                  ✎ {issue.analyst_comment ? "Edit Reply" : "Add Reply"}
                </button>
              )}
            </>
          )}
        </div>
      )}

      {/* Actions — analyst only, unresolved issues */}
      {isAnalyst && !isResolved && (
        <div className={styles.msgActions}>

          {resolveMode === "idle" && (
            <>
              {/* Quick resolve — no comment required */}
              <button
                className={styles.btnResolveSmall}
                disabled={resolveLoading}
                onClick={() => setResolveMode("confirm")}
              >
                ✓ Mark Resolved
              </button>
              {/* Resolve with a reply */}
              <button
                className={styles.btnReplyResolve}
                onClick={() => setResolveMode("with-comment")}
              >
                ✎ Reply &amp; Resolve
              </button>
            </>
          )}

          {/* Inline quick-confirm (no comment) */}
          {resolveMode === "confirm" && (
            <div className={styles.quickConfirm}>
              <span className={styles.quickConfirmLabel}>Mark as resolved?</span>
              <button
                className={styles.btnResolve}
                disabled={resolveLoading}
                onClick={handleResolveQuick}
              >
                {resolveLoading ? "Resolving…" : "Confirm"}
              </button>
              <button className={styles.btnCancel} onClick={() => setResolveMode("idle")}>
                Cancel
              </button>
            </div>
          )}

          {/* Resolve with optional comment */}
          {resolveMode === "with-comment" && (
            <div className={styles.resolveForm}>
              <textarea
                className={styles.resolveTextarea}
                placeholder="Optional reply to the client…"
                rows={2}
                value={resolveComment}
                onChange={e => setResolveComment(e.target.value)}
                autoFocus
              />
              <div className={styles.resolveFormActions}>
                <button
                  className={styles.btnResolve}
                  disabled={resolveLoading}
                  onClick={handleResolveWithComment}
                >
                  {resolveLoading ? "Saving…" : "Resolve"}
                </button>
                <button
                  className={styles.btnCancel}
                  onClick={() => { setResolveMode("idle"); setResolveComment(""); }}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Delete action — analyst only, resolved issues */}
      {isAnalyst && isResolved && (
        <div className={styles.msgActions}>
          {!showDeleteConfirm && (
            <button className={styles.btnDeleteSmall} onClick={() => setShowDeleteConfirm(true)}>
              Delete Forever
            </button>
          )}
          {showDeleteConfirm && (
            <div className={styles.deleteConfirm}>
              <span>Permanently delete?</span>
              <button className={styles.btnDeleteForever} disabled={deleteLoading} onClick={handleDelete}>
                {deleteLoading ? "Deleting…" : "Delete Forever"}
              </button>
              <button className={styles.btnCancel} onClick={() => setShowDeleteConfirm(false)}>
                Cancel
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── ThreadPanel ───────────────────────────────────────────────────────────────

function ThreadPanel({ eventId, onClose, onThreadUpdated }) {
  const [thread, setThread] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showResolved, setShowResolved] = useState(false);
  const [error, setError] = useState(null);

  const loadThread = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get(`/analyst/events/${eventId}/issues`);
      setThread(res.data ?? []);
    } catch {
      setError("Failed to load thread.");
    } finally {
      setLoading(false);
    }
  }, [eventId]);

  useEffect(() => { loadThread(); }, [loadThread]);

  async function handleUpdateComment(issueId, comment) {
    try {
      await api.patch(`/analyst/issues/${issueId}/comment`, {
        issue_id: issueId,
        analyst_comment: comment,   // null is fine — backend accepts it
      });
      await loadThread();
      onThreadUpdated();
    } catch (e) {
      alert(e?.response?.data?.detail ?? "Failed to update comment.");
    }
  }

  async function handleResolve(issueId, comment) {
    try {
      await api.post("/analyst/issues/resolve", {
        issue_id: issueId,
        analyst_comment: comment,   // null = resolved without comment
      });
      await loadThread();
      onThreadUpdated();
    } catch (e) {
      alert(e?.response?.data?.detail ?? "Failed to resolve issue.");
    }
  }

  async function handleDelete(issueId) {
    try {
      await api.post("/analyst/issues/delete", { issue_id: issueId });
      await loadThread();
      onThreadUpdated();
    } catch {
      alert("Failed to delete issue.");
    }
  }

  const resolvedCount = thread.filter(i => !!i.resolved_at).length;
  const visible = showResolved ? thread : thread.filter(i => !i.resolved_at);

  return (
    <div className={styles.threadPanel}>
      <div className={styles.threadHeader}>
        <span className={styles.threadTitle}>ISSUE THREAD — EVENT #{eventId}</span>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {resolvedCount > 0 && (
            <button
              className={styles.toggleResolved}
              onClick={() => setShowResolved(v => !v)}
            >
              {showResolved ? "Hide Resolved" : `Show Resolved (${resolvedCount})`}
            </button>
          )}
          <button className={styles.threadClose} onClick={onClose}>✕</button>
        </div>
      </div>

      {error && <p style={{ color: "#ef4444", fontSize: 12, padding: "0.5rem 0" }}>{error}</p>}

      <div className={styles.threadMessages}>
        {loading ? (
          <p className={styles.loading}>Loading thread…</p>
        ) : visible.length === 0 ? (
          <p className={styles.empty}>
            {showResolved || resolvedCount === 0 ? "No issues in this thread." : "All issues resolved."}
          </p>
        ) : (
          visible.map(issue => (
            <MessageBubble
              key={issue.id}
              issue={issue}
              isAnalyst={true}
              onResolve={handleResolve}
              onDelete={handleDelete}
              onUpdateComment={handleUpdateComment}
            />
          ))
        )}
      </div>
    </div>
  );
}

// ── EventCard ─────────────────────────────────────────────────────────────────

function EventCard({ group, isSelected, onClick }) {
  const allResolved = group.openCount === 0 && group.resolvedCount > 0;
  const hasOpen = group.openCount > 0;

  return (
    <div
      className={`${styles.card} ${allResolved ? styles.cardAllResolved : ""} ${isSelected ? styles.cardSelected : ""}`}
      onClick={onClick}
    >
      <div className={styles.cardTop}>
        <span className={styles.clientTag}>Client {group.client_id}</span>
        <span className={styles.countTag}>{group.items.length} issue{group.items.length !== 1 ? "s" : ""}</span>
        {allResolved
          ? <span className={styles.resolvedTag}>✓ All Resolved</span>
          : hasOpen
            ? <span className={styles.openTag}>⚑ {group.openCount} open</span>
            : <span className={styles.partialTag}>{group.openCount} open / {group.resolvedCount} resolved</span>
        }
        <span className={styles.time}>{fmtTime(group.firstIssue.created_at)}</span>
      </div>
      <p className={styles.issueText}>
        {group.firstIssue.issue_text.length > 120
          ? group.firstIssue.issue_text.slice(0, 120) + "…"
          : group.firstIssue.issue_text}
      </p>
      <div className={styles.cardMeta}>
        <span className={styles.raisedBy}>
          {group.firstIssue.raised_by_username ?? `uid:${group.firstIssue.raised_by}`}
        </span>
        <span className={styles.eventId}>Event #{group.event_id}</span>
      </div>
    </div>
  );
}

// ── IssuesPage ────────────────────────────────────────────────────────────────

export default function IssuesPage() {
  const [issues, setIssues] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showResolved, setShowResolved] = useState(false);
  const [selectedEventId, setSelectedEventId] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get(`/analyst/issues?show_resolved=${showResolved}`);
      setIssues(res.data ?? []);
    } catch {
      setError("Failed to load issues.");
    } finally {
      setLoading(false);
    }
  }, [showResolved]);

  useEffect(() => { load(); }, [load]);

  const groups = groupByEvent(issues);
  const openCount = issues.filter(i => !i.resolved_at).length;

  function handleCardClick(eventId) {
    setSelectedEventId(prev => (prev === eventId ? null : eventId));
  }

  return (
    <div className={styles.page}>
      {/* Header */}
      <div className={styles.header}>
        <h1 className={styles.title}>
          ISSUES
          {openCount > 0 && <span className={styles.badge}>{openCount}</span>}
        </h1>
        <button
          className={`${styles.toggleBtn} ${showResolved ? styles.toggleActive : ""}`}
          onClick={() => { setShowResolved(v => !v); setSelectedEventId(null); }}
        >
          {showResolved ? "Showing All" : "Show Resolved"}
        </button>
      </div>

      {error && <p className={styles.errorMsg}>{error}</p>}

      {loading ? (
        <p className={styles.loading}>Loading…</p>
      ) : groups.length === 0 ? (
        <p className={styles.empty}>
          {showResolved ? "No issues found." : "No open issues. All clear."}
        </p>
      ) : (
        <div className={`${styles.layout} ${selectedEventId ? "" : styles.layoutFull}`}>
          {/* Card list */}
          <div className={styles.cardList}>
            {groups.map(group => (
              <EventCard
                key={group.event_id}
                group={group}
                isSelected={selectedEventId === group.event_id}
                onClick={() => handleCardClick(group.event_id)}
              />
            ))}
          </div>

          {/* Thread panel */}
          {selectedEventId && (
            <ThreadPanel
              eventId={selectedEventId}
              onClose={() => setSelectedEventId(null)}
              onThreadUpdated={load}
            />
          )}
        </div>
      )}
    </div>
  );
}
