import React, { useState, useEffect, useCallback, useRef } from 'react';
import api from '../../../api/axios';
import styles from './AdminBootstrapTrainPage.module.css';

const CATEGORIES = [
  {
    id: 'AuthenticationEvents',
    label: 'Authentication Events',
    description: 'EventIDs 4624, 4625, 4634, 4648, 4672 — logins, failures, privilege use',
    icon: '🔑',
  },
  {
    id: 'AccountManagementEvents',
    label: 'Account Management Events',
    description: 'EventIDs 4720–4781 — user creation, deletion, group changes',
    icon: '👤',
  },
  {
    id: 'ProcessCreationEvents',
    label: 'Process Creation Events',
    description: 'EventIDs 4688, 4689 — process start and stop events',
    icon: '⚙',
  },
];

const STATUS_COLORS = {
  complete: 'var(--green)',
  partial:  'var(--amber)',
  failed:   'var(--red)',
  skipped:  'var(--text-muted)',
  running:  'var(--blue)',
  queued:   'var(--text-secondary)',
  pending:  'var(--text-muted)',
};

const STATUS_ICONS = {
  complete: '✓',
  partial:  '~',
  failed:   '✗',
  skipped:  '—',
  running:  '⟳',
  queued:   '…',
  pending:  '·',
};

function ProgressBar({ value, max, color }) {
  const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return (
    <div className={styles.progressTrack}>
      <div
        className={styles.progressFill}
        style={{ width: `${pct}%`, background: color || 'var(--blue)' }}
      />
      <span className={styles.progressLabel}>{value} / {max}</span>
    </div>
  );
}

function ReadinessCard({ cat, selected, onToggle }) {
  const pct = Math.min(100, Math.round((cat.event_count / cat.min_required) * 100));
  const color = cat.ready
    ? 'var(--green)'
    : pct > 60
      ? 'var(--amber)'
      : 'var(--red)';

  const def = CATEGORIES.find(c => c.id === cat.category) || {};

  return (
    <div
      className={`${styles.catCard} ${selected ? styles.catCardSelected : ''} ${!cat.ready ? styles.catCardDisabled : ''}`}
      onClick={() => cat.ready && onToggle(cat.category)}
      title={!cat.ready ? `Need ${cat.min_required - cat.event_count} more events` : ''}
    >
      <div className={styles.catCardHeader}>
        <span className={styles.catIcon}>{def.icon || '⬡'}</span>
        <div className={styles.catMeta}>
          <span className={styles.catName}>{def.label || cat.category}</span>
          <span className={styles.catDesc}>{def.description}</span>
        </div>
        <div className={`${styles.catCheckbox} ${selected ? styles.catCheckboxOn : ''}`}>
          {selected ? '✓' : ''}
        </div>
      </div>

      <div className={styles.catStats}>
        <div className={styles.catStatRow}>
          <span>Events collected</span>
          <span style={{ color }}>{cat.event_count.toLocaleString()}</span>
        </div>
        <div className={styles.catStatRow}>
          <span>Minimum required</span>
          <span className={styles.muted}>{cat.min_required}</span>
        </div>
      </div>

      <ProgressBar value={cat.event_count} max={cat.min_required} color={color} />

      <div className={styles.catFooter}>
        {cat.model_exists ? (
          <span className={styles.badgeExisting}>
            ◎ Model exists — retrain will replace
            {cat.trained_at && ` (${new Date(cat.trained_at).toLocaleDateString('en-GB')})`}
          </span>
        ) : (
          <span className={styles.badgeNew}>⬡ No model yet — first training</span>
        )}
        <span className={`${styles.readyBadge}`} style={{ color }}>
          {cat.ready ? '● Ready' : '○ Not ready'}
        </span>
      </div>
    </div>
  );
}

function ResultRow({ result }) {
  const color = STATUS_COLORS[result.status] || 'var(--text-secondary)';
  const icon  = STATUS_ICONS[result.status]  || '?';
  const def   = CATEGORIES.find(c => c.id === result.category) || {};
  return (
    <div className={styles.resultRow}>
      <span className={styles.resultIcon} style={{ color }}>{icon}</span>
      <span className={styles.resultCat}>{def.label || result.category}</span>
      <span className={styles.resultMsg} style={{ color }}>{result.message}</span>
      {result.rows > 0 && (
        <span className={styles.resultRows}>{result.rows.toLocaleString()} rows</span>
      )}
    </div>
  );
}

export default function AdminBootstrapTrainPage() {
  const [clients, setClients]           = useState([]);
  const [selectedClient, setSelectedClient] = useState('');
  const [readiness, setReadiness]       = useState(null);
  const [loadingReadiness, setLoadingReadiness] = useState(false);

  const [selectedCats, setSelectedCats] = useState([]);
  const [contamination, setContamination] = useState(0.05);
  const [notes, setNotes]               = useState('');
  const [submitting, setSubmitting]     = useState(false);

  const [jobId, setJobId]               = useState(null);
  const [jobStatus, setJobStatus]       = useState(null);
  const pollRef                         = useRef(null);

  // Load clients on mount
  useEffect(() => {
    api.get('/admin/clients')
      .then(res => {
        const active = (res.data || []).filter(c => c.active !== false);
        setClients(active);
        if (active.length > 0) setSelectedClient(String(active[0].id));
      })
      .catch(() => {});
  }, []);

  // Load readiness when client changes
  useEffect(() => {
    if (!selectedClient) return;
    setReadiness(null);
    setSelectedCats([]);
    setJobId(null);
    setJobStatus(null);
    setLoadingReadiness(true);

    api.get(`/admin/bootstrap-train/readiness/${selectedClient}`)
      .then(res => setReadiness(res.data))
      .catch(() => setReadiness(null))
      .finally(() => setLoadingReadiness(false));
  }, [selectedClient]);

  // Poll job status
  const startPolling = useCallback((id) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await api.get(`/admin/bootstrap-train/status/${id}`);
        setJobStatus(res.data);
        if (!['queued', 'running'].includes(res.data.status)) {
          clearInterval(pollRef.current);
          pollRef.current = null;
          // Refresh readiness after completion
          api.get(`/admin/bootstrap-train/readiness/${selectedClient}`)
            .then(r => setReadiness(r.data))
            .catch(() => {});
        }
      } catch {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    }, 2000);
  }, [selectedClient]);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const toggleCategory = (id) => {
    setSelectedCats(prev =>
      prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id]
    );
  };

  const handleTrain = async () => {
    if (!selectedCats.length) return;
    setSubmitting(true);
    setJobStatus(null);
    try {
      const res = await api.post(`/admin/bootstrap-train/start/${selectedClient}`, {
        categories: selectedCats,
        contamination,
        notes: notes.trim() || undefined,
      });
      setJobId(res.data.job_id);
      setJobStatus(res.data);
      startPolling(res.data.job_id);
    } catch (err) {
      const msg = err.response?.data?.detail || 'Training request failed.';
      setJobStatus({ status: 'failed', message: msg });
    } finally {
      setSubmitting(false);
    }
  };

  const isTraining = jobStatus && ['queued', 'running'].includes(jobStatus.status);
  const readyCats  = (readiness?.categories || []).filter(c => c.ready);
  const clientName = clients.find(c => String(c.id) === selectedClient)?.name || '—';

  return (
    <div className={styles.page}>

      {/* ── Header ── */}
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Initial Model Bootstrap</h1>
          <p className={styles.subtitle}>
            Train Isolation Forest models from the first events collected after client onboarding.
            Run this once per client after a few days of log collection.
          </p>
        </div>
        <div className={styles.headerBadge}>SUPERADMIN ONLY</div>
      </div>

      {/* ── Client selector ── */}
      <div className={styles.section}>
        <label className={styles.label}>Select Client</label>
        <select
          className={styles.select}
          value={selectedClient}
          onChange={e => setSelectedClient(e.target.value)}
          disabled={isTraining}
        >
          {clients.map(c => (
            <option key={c.id} value={String(c.id)}>
              {c.name} (id: {c.id})
            </option>
          ))}
        </select>
      </div>

      {/* ── Readiness grid ── */}
      {loadingReadiness && (
        <div className={styles.loading}>
          <span className={styles.spinner} />
          Checking data readiness…
        </div>
      )}

      {readiness && !loadingReadiness && (
        <>
          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <span className={styles.label}>ML Category Readiness — {clientName}</span>
              <span className={styles.muted}>
                {readyCats.length}/{readiness.categories.length} categories ready
              </span>
            </div>
            <div className={styles.catGrid}>
              {readiness.categories.map(cat => (
                <ReadinessCard
                  key={cat.category}
                  cat={cat}
                  selected={selectedCats.includes(cat.category)}
                  onToggle={toggleCategory}
                />
              ))}
            </div>
            {readyCats.length === 0 && (
              <div className={styles.emptyHint}>
                No categories have enough data yet. Let the log collector run for a few
                days, then return here.
              </div>
            )}
          </div>

          {/* ── Training config ── */}
          {selectedCats.length > 0 && (
            <div className={styles.section}>
              <span className={styles.label}>Training Configuration</span>
              <div className={styles.configGrid}>
                <div className={styles.configField}>
                  <label className={styles.configLabel}>
                    Contamination
                    <span className={styles.configHint}>
                      Expected anomaly fraction (0.01 – 0.20).
                      Lower = fewer false positives. Start at 0.05.
                    </span>
                  </label>
                  <div className={styles.sliderRow}>
                    <input
                      type="range"
                      min="0.01" max="0.20" step="0.01"
                      value={contamination}
                      onChange={e => setContamination(parseFloat(e.target.value))}
                      className={styles.slider}
                      disabled={isTraining}
                    />
                    <span className={styles.sliderValue}>{(contamination * 100).toFixed(0)}%</span>
                  </div>
                </div>

                <div className={styles.configField}>
                  <label className={styles.configLabel}>
                    Notes
                    <span className={styles.configHint}>Optional — stored in ml_models.notes</span>
                  </label>
                  <input
                    type="text"
                    className={styles.input}
                    value={notes}
                    onChange={e => setNotes(e.target.value)}
                    placeholder="e.g. Initial training after 7-day data collection"
                    disabled={isTraining}
                  />
                </div>
              </div>
            </div>
          )}

          {/* ── Train button ── */}
          {selectedCats.length > 0 && (
            <div className={styles.section}>
              <div className={styles.trainSummary}>
                <span>
                  Training <strong>{selectedCats.length}</strong> categor{selectedCats.length === 1 ? 'y' : 'ies'}
                  {' '}for <strong>{clientName}</strong>
                </span>
                <button
                  className={styles.trainBtn}
                  onClick={handleTrain}
                  disabled={submitting || isTraining}
                >
                  {isTraining
                    ? <><span className={styles.spinner} /> Training…</>
                    : submitting
                      ? <><span className={styles.spinner} /> Starting…</>
                      : '⬡ Train Models'
                  }
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* ── Job status ── */}
      {jobStatus && (
        <div className={styles.section}>
          <div className={styles.statusBox}>
            <div className={styles.statusHeader}>
              <span className={styles.label}>Training Job</span>
              <span
                className={styles.statusBadge}
                style={{ color: STATUS_COLORS[jobStatus.status] || 'var(--text-secondary)' }}
              >
                {STATUS_ICONS[jobStatus.status]} {jobStatus.status.toUpperCase()}
              </span>
            </div>

            {jobId && (
              <div className={styles.jobId}>
                Job ID: <code>{jobId}</code>
              </div>
            )}

            {jobStatus.message && (
              <div className={styles.statusMsg}>{jobStatus.message}</div>
            )}

            {isTraining && (
              <div className={styles.pulse}>
                <span className={styles.spinner} />
                <span>Running in background — checking every 2 seconds…</span>
              </div>
            )}

            {jobStatus.results && jobStatus.results.length > 0 && (
              <div className={styles.results}>
                <div className={styles.resultsTitle}>Category Results</div>
                {jobStatus.results.map(r => (
                  <ResultRow key={r.category} result={r} />
                ))}
              </div>
            )}

            {jobStatus.started_at && (
              <div className={styles.timings}>
                <span>Started: {new Date(jobStatus.started_at).toLocaleTimeString()}</span>
                {jobStatus.finished_at && (
                  <span>Finished: {new Date(jobStatus.finished_at).toLocaleTimeString()}</span>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
