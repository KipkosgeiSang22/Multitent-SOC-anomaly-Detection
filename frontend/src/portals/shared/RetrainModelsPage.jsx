import React, { useState, useEffect } from 'react';
import api from '../../api/axios';
import styles from './RetrainModelsPage.module.css';

export default function RetrainModelsPage({ accentColor = 'var(--amber)' }) {
  const [clients, setClients] = useState([]);
  const [selectedClient, setSelectedClient] = useState('');
  const [category, setCategory] = useState('AuthenticationEvents');
  const [period, setPeriod] = useState({ start: '', end: '' });
  
  const [loading, setLoading] = useState(false);
  const [hasAccess, setHasAccess] = useState(null);
  const [rows, setRows] = useState([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const [exclusions, setExclusions] = useState([]);
  const [inclusions, setInclusions] = useState([]);
  const [notes, setNotes] = useState('');

  const [jobStatus, setJobStatus] = useState(null);
  const [polling, setPolling] = useState(false);

  useEffect(() => {
    // Bootstrap client list
    api.get('/analyst/clients')
      .then(res => {
        setClients(res.data);
        if (res.data.length > 0) setSelectedClient(res.data[0].id);
      })
      .catch(() => setHasAccess(false));
  }, []);

  const fetchPreview = async (targetPage = 1) => {
    if (!selectedClient || !period.start || !period.end) return;
    setLoading(true);
    try {
      const res = await api.get(`/retrain/preview/${selectedClient}/${category}`, {
        params: {
          period_start: period.start,
          period_end: period.end,
          page: targetPage,
          page_size: 15
        }
      });
      setRows(res.data.rows || []);
      setTotalPages(Math.ceil((res.data.total || 0) / 15));
      setPage(targetPage);
      setHasAccess(true);
    } catch (err) {
      if (err.response?.status === 403) {
        setHasAccess(false);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleToggleRow = (id, type) => {
    if (type === 'exclude') {
      setExclusions(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
    } else {
      setInclusions(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
    }
  };

  const handleStartRetrain = async () => {
    try {
      setPolling(true);
      setJobStatus({ status: 'PENDING', message: 'Spawning background engine execution context...' });
      const res = await api.post('/retrain/start', {
        client_id: parseInt(selectedClient),
        category,
        period_start: period.start,
        period_end: period.end,
        exclude_ids: exclusions,
        include_ids: inclusions,
        notes
      });
      pollJobStatus(res.data.job_id);
    } catch (err) {
      setJobStatus({ status: 'FAILED', message: err.response?.data?.detail || 'Execution trigger error' });
      setPolling(false);
    }
  };

  const pollJobStatus = (jobId) => {
    const interval = setInterval(async () => {
      try {
        const res = await api.get(`/retrain/status/${jobId}`);
        setJobStatus(res.data);
        if (res.data.status === 'complete' || res.data.status === 'failed') {
          clearInterval(interval);
          setPolling(false);
        }
      } catch {
        clearInterval(interval);
        setPolling(false);
      }
    }, 2000);
  };

  const handleRollback = async () => {
    if (!window.confirm('Are you absolutely sure you want to roll back to the previous model iteration?')) return;
    try {
      const res = await api.post(`/retrain/rollback/${selectedClient}/${category}`);
      alert(`Rollback successful: ${res.data.message}`);
    } catch (err) {
      alert(err.response?.data?.detail || 'Rollback failed.');
    }
  };

  if (hasAccess === false) {
    return (
      <div className={styles.lockedContainer}>
        <div className={styles.lockBox}>
          <span className={styles.lockIcon}>⚡</span>
          <h3>SECURITY ACCESS DENIED</h3>
          <p>Your current session profile lacks the permission scope: <code>can_retrain_models</code>.</p>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container} style={{ '--accent': accentColor }}>
      <header className={styles.header}>
        <h2>MODEL PIPELINE RETRAINING MATRIX</h2>
        <p className={styles.subtitle}>Optimize Isolation Forests dynamically through Human-in-the-Loop error verification.</p>
      </header>

      <section className={styles.controlPanel}>
        <div className={styles.formGrid}>
          <div className={styles.field}>
            <label>TARGET CLIENT SECURE IDENTITY</label>
            <select value={selectedClient} onChange={e => setSelectedClient(e.target.value)}>
              {clients.map(c => <option key={c.id} value={c.id}>{c.name} [ID: {c.id}]</option>)}
            </select>
          </div>
          <div className={styles.field}>
            <label>MATHEMATICAL ENGINE CATEGORY</label>
            <select value={category} onChange={e => setCategory(e.target.value)}>
              <option value="AuthenticationEvents">AuthenticationEvents</option>
              <option value="AccountManagementEvents">AccountManagementEvents</option>
              <option value="ProcessCreationEvents">ProcessCreationEvents</option>
            </select>
          </div>
          <div className={styles.field}>
            <label>LOOKBACK TIME RANGE START (EAT)</label>
            <input type="datetime-local" value={period.start} onChange={e => setPeriod(prev => ({ ...prev, start: e.target.value }))} />
          </div>
          <div className={styles.field}>
            <label>LOOKBACK TIME RANGE END (EAT)</label>
            <input type="datetime-local" value={period.end} onChange={e => setPeriod(prev => ({ ...prev, end: e.target.value }))} />
          </div>
        </div>

        <div className={styles.actionRow}>
          <button className={styles.primaryButton} onClick={() => fetchPreview(1)} disabled={loading || !period.start || !period.end}>
            {loading ? 'ANALYZING...' : 'PULL FEATURE SNAPSHOT DATA'}
          </button>
          <button className={styles.rollbackButton} onClick={handleRollback} disabled={!selectedClient}>
            ROLLBACK TO PREVIOUS MODEL VERSION (.bak)
          </button>
        </div>
      </section>

      {rows.length > 0 && (
        <section className={styles.tableSection}>
          <div className={styles.tableWrapper}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>SCORE</th>
                  <th>LAYER</th>
                  <th>TYPE IDENTIFIER</th>
                  <th style={{ color: 'var(--red)' }}>EXCLUDE (TRUE +)</th>
                  <th style={{ color: 'var(--green)' }}>INCLUDE (FALSE +)</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(row => (
                  <tr key={row.id}>
                    <td className={styles.mono}>{row.timestamp}</td>
                    <td className={styles.mono} style={{ color: row.anomaly_score < 0 ? 'var(--red)' : 'var(--text-secondary)' }}>
                      {row.anomaly_score?.toFixed(4)}
                    </td>
                    <td>L{row.layer}</td>
                    <td><span className={styles.badge}>{row.anomaly_type}</span></td>
                    <td>
                      <input 
                        type="checkbox" 
                        checked={exclusions.includes(row.id)} 
                        onChange={() => handleToggleRow(row.id, 'exclude')}
                        disabled={inclusions.includes(row.id)}
                      />
                    </td>
                    <td>
                      <input 
                        type="checkbox" 
                        checked={inclusions.includes(row.id)} 
                        onChange={() => handleToggleRow(row.id, 'include')}
                        disabled={exclusions.includes(row.id)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          <div className={styles.pagination}>
            <button disabled={page === 1} onClick={() => fetchPreview(page - 1)}>PREV</button>
            <span>PAGE {page} OF {totalPages}</span>
            <button disabled={page === totalPages} onClick={() => fetchPreview(page + 1)}>NEXT</button>
          </div>

          <div className={styles.executionBox}>
            <h3>COMMIT ITERATION TRAIN RUN</h3>
            <textarea 
              placeholder="Provide operational engineering notes justifying this model tuning mutation run..." 
              value={notes} 
              onChange={e => setNotes(e.target.value)}
              className={styles.notesTextarea}
            />
            <button className={styles.commitButton} onClick={handleStartRetrain} disabled={polling}>
              {polling ? 'ENGINE TUNING RUNNING...' : 'EXECUTE ISOLATION FOREST GRADIENT COMPILATION'}
            </button>
          </div>
        </section>
      )}

      {jobStatus && (
        <div className={styles.statusModal}>
          <div className={styles.modalContent}>
            <h3>PIPELINE COMPILATION RE-ENGINEERING TRACKER</h3>
            <div className={styles.statusRow}>
              <span className={styles.statusLabel}>JOB ID:</span>
              <span className={styles.statusVal}>{jobStatus.job_id || 'N/A'}</span>
            </div>
            <div className={styles.statusRow}>
              <span className={styles.statusLabel}>STATUS:</span>
              <span className={`${styles.statusVal} ${styles[jobStatus.status]}`}>{jobStatus.status?.toUpperCase()}</span>
            </div>
            <p className={styles.statusMessage}>{jobStatus.message || jobStatus.last_error}</p>
            {jobStatus.training_rows && <p className={styles.metrics}>Processed Matrix Nodes: <strong>{jobStatus.training_rows}</strong> items.</p>}
            {!polling && <button onClick={() => setJobStatus(null)} className={styles.closeModalBtn}>ACKNOWLEDGE DISMISS</button>}
          </div>
        </div>
      )}
    </div>
  );
}