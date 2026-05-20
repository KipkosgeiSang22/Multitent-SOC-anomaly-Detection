import React, { useState, useEffect } from 'react';
import api from '../../api/axios';
import styles from './Layer1RulesPage.module.css';

export default function Layer1RulesPage({ accentColor = 'var(--amber)' }) {
  const [clients, setClients] = useState([]);
  const [selectedClient, setSelectedClient] = useState('');
  const [rules, setRules] = useState([]);
  const [hasAccess, setHasAccess] = useState(null);
  const [loading, setLoading] = useState(false);

  // Modal Controls
  const [modalOpen, setModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [testResult, setTestResult] = useState(null);

  // Form State Architecture
  const [ruleName, setRuleName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('AuthenticationEvents');
  const [severity, setSeverity] = useState('medium');
  const [condition, setCondition] = useState({
    field: 'EventID',
    operator: 'eq',
    values: '',
    aggregation: 'null',
    threshold: 1,
    window_minutes: 5,
    group_by: ''
  });

  useEffect(() => {
    api.get('/analyst/clients')
      .then(res => {
        setClients(res.data);
        if (res.data.length > 0) {
          setSelectedClient(res.data[0].id);
        }
      })
      .catch(() => setHasAccess(false));
  }, []);

  useEffect(() => {
    if (selectedClient) fetchRules();
  }, [selectedClient]);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const res = await api.get(`/rules/${selectedClient}`);
      setRules(res.data);
      setHasAccess(true);
    } catch (err) {
      if (err.response?.status === 403) setHasAccess(false);
    } finally {
      setLoading(false);
    }
  };

  const handleSeedRules = async () => {
    if (!window.confirm('Seed standard security structural default profiles to this client matrix partition?')) return;
    try {
      await api.post(`/rules/seed/${selectedClient}`);
      fetchRules();
    } catch (err) {
      alert(err.response?.data?.detail || 'Seeding error');
    }
  };

  const handleToggle = async (ruleId) => {
    try {
      await api.post(`/rules/${ruleId}/toggle`);
      setRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled: !r.enabled } : r));
    } catch (err) {
      alert('Toggle operation rejected.');
    }
  };

  const handleOpenCreate = () => {
    setEditingRule(null);
    setRuleName('');
    setDescription('');
    setCategory('AuthenticationEvents');
    setSeverity('medium');
    setCondition({ field: 'EventID', operator: 'eq', values: '', aggregation: 'null', threshold: 1, window_minutes: 5, group_by: '' });
    setModalOpen(true);
  };

  const handleOpenEdit = (rule) => {
    setEditingRule(rule);
    setRuleName(rule.rule_name);
    setDescription(rule.description);
    setCategory(rule.category);
    setSeverity(rule.severity);
    const cond = rule.conditions || {};
    setCondition({
      field: cond.field || 'EventID',
      operator: cond.operator || 'eq',
      values: Array.isArray(cond.values) ? cond.values.join(', ') : '',
      aggregation: cond.aggregation || 'null',
      threshold: cond.threshold || 1,
      window_minutes: cond.window_minutes || 5,
      group_by: cond.group_by || ''
    });
    setModalOpen(true);
  };

  const handleSave = async (e) => {
    e.preventDefault();
    const payload = {
      client_id: parseInt(selectedClient),
      rule_name: ruleName,
      description,
      category,
      severity,
      conditions: {
        ...condition,
        threshold: parseInt(condition.threshold),
        window_minutes: parseInt(condition.window_minutes),
        values: condition.values.split(',').map(v => v.trim()).map(v => isNaN(v) || v === '' ? v : parseInt(v)),
        aggregation: condition.aggregation === 'null' ? null : condition.aggregation
      },
      enabled: editingRule ? editingRule.enabled : true
    };

    try {
      if (editingRule) {
        await api.patch(`/rules/${editingRule.id}`, payload);
      } else {
        await api.post('/rules', payload);
      }
      setModalOpen(false);
      fetchRules();
    } catch (err) {
      alert(err.response?.data?.detail || 'Error saving rule processing parameters.');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Purge this Layer 1 engine filter permanently?')) return;
    try {
      await api.delete(`/rules/${id}`);
      fetchRules();
    } catch (err) {
      alert('Purge rejection.');
    }
  };

  const handleTestRule = async (id) => {
    try {
      const res = await api.post(`/rules/${id}/test`);
      setTestResult(res.data);
    } catch (err) {
      alert('Simulation processing engine fault.');
    }
  };

  if (hasAccess === false) {
    return (
      <div className={styles.lockedContainer}>
        <div className={styles.lockBox}>
          <span className={styles.lockIcon}>🔒</span>
          <h3>ACCESS PRIVILEGES INSUFFICIENT</h3>
          <p>Your authorization model doesn't map to: <code>can_edit_layer1_rules</code>.</p>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container} style={{ '--accent': accentColor }}>
      <header className={styles.header}>
        <div className={styles.headerLeft}>
          <h2>LAYER 1 STRUCTURAL RULE COMPILER</h2>
          <p className={styles.subtitle}>Maintain synchronous, high-throughput, edge-processing boolean filters per tenant partition.</p>
        </div>
        <div className={styles.headerRight}>
          <button className={styles.seedButton} onClick={handleSeedRules} disabled={!selectedClient}>SEED SCHEMATIC DEFAULT MATRIX</button>
          <button className={styles.createButton} onClick={handleOpenCreate} disabled={!selectedClient}>+ DEFINE STRUCTURAL FILTER</button>
        </div>
      </header>

      <div className={styles.selectorBar}>
        <label>ACTIVE LOGICAL CLIENT MATRIX SCOPE:</label>
        <select value={selectedClient} onChange={e => setSelectedClient(e.target.value)}>
          {clients.map(c => <option key={c.id} value={c.id}>{c.name} (ID: {c.id})</option>)}
        </select>
      </div>

      {loading ? <div className={styles.loader}>PROBING SECURE STORAGE SCHEMAS...</div> : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>RULE DESIGNATION</th>
                <th>PIPELINE CATEGORY</th>
                <th>SEVERITY WEIGHT</th>
                <th>STATUS</th>
                <th style={{ textAlignment: 'right' }}>ENGINE ACTION TARGETS</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(r => (
                <tr key={r.id} className={!r.enabled ? styles.rowDisabled : ''}>
                  <td>
                    <div className={styles.ruleName}>{r.rule_name}</div>
                    <div className={styles.ruleDesc}>{r.description}</div>
                  </td>
                  <td><span className={styles.monoBadge}>{r.category}</span></td>
                  <td><span className={`${styles.sevBadge} ${styles[r.severity]}`}>{r.severity?.toUpperCase()}</span></td>
                  <td>
                    <label className={styles.switch}>
                      <input type="checkbox" checked={r.enabled} onChange={() => handleToggle(r.id)} />
                      <span className={styles.slider} />
                    </label>
                  </td>
                  <td>
                    <div className={styles.actionsCell}>
                      <button className={styles.btnTest} onClick={() => handleTestRule(r.id)}>SIMULATE 24H</button>
                      <button className={styles.btnEdit} onClick={() => handleOpenEdit(r)}>EDIT</button>
                      <button className={styles.btnDelete} onClick={() => handleDelete(r.id)}>PURGE</button>
                    </div>
                  </td>
                </tr>
              ))}
              {rules.length === 0 && <tr><td colSpan="5" className={styles.empty}>Zero logical records deployed within this tenant block.</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {/* Form Dialog Modal */}
      {modalOpen && (
        <div className={styles.modalOverlay}>
          <form className={styles.modalContent} onSubmit={handleSave}>
            <h3>{editingRule ? 'MUTATE PARSING CONFIGURATION' : 'COMPILE NEW BALANCING FILTER'}</h3>
            
            <div className={styles.formGroup}>
              <label>RULE TITLE</label>
              <input type="text" value={ruleName} onChange={e => setRuleName(e.target.value)} required placeholder="BRUTE_FORCE_AUTHENTICATION_ATTEMPT" className={styles.monoInput}/>
            </div>

            <div className={styles.formGroup}>
              <label>OPERATIONAL STRUCTURAL DESCRIPTION</label>
              <input type="text" value={description} onChange={e => setDescription(e.target.value)} required placeholder="Triggers upon execution detection matching low-frequency parameters." />
            </div>

            <div className={styles.formRow}>
              <div className={styles.formGroup}>
                <label>PIPELINE BINDING</label>
                <select value={category} onChange={e => setCategory(e.target.value)}>
                  <option value="AuthenticationEvents">AuthenticationEvents</option>
                  <option value="AccountManagementEvents">AccountManagementEvents</option>
                  <option value="ProcessCreationEvents">ProcessCreationEvents</option>
                </select>
              </div>
              <div className={styles.formGroup}>
                <label>CRITICALITY SEVERITY RATIO</label>
                <select value={severity} onChange={e => setSeverity(e.target.value)}>
                  <option value="low">LOW</option>
                  <option value="medium">MEDIUM</option>
                  <option value="high">HIGH</option>
                  <option value="critical">CRITICAL</option>
                </select>
              </div>
            </div>

            <fieldset className={styles.fieldset}>
              <legend>JSONB CONDITIONAL MAP ARCHITECTURE</legend>
              
              <div className={styles.formRow}>
                <div className={styles.formGroup}>
                  <label>JSON OBJECT FIELD TARGET</label>
                  <input type="text" value={condition.field} onChange={e => setCondition(p => ({...p, field: e.target.value}))} required />
                </div>
                <div className={styles.formGroup}>
                  <label>EVALUATION OPERATOR</label>
                  <select value={condition.operator} onChange={e => setCondition(p => ({...p, operator: e.target.value}))}>
                    <option value="eq">EQUALS (==)</option>
                    <option value="in">SET CONTAINMENT (IN)</option>
                    <option value="not_in">SET EXCLUSION (NOT IN)</option>
                    <option value="contains">SUBSTRING MATCH (CONTAINS)</option>
                    <option value="gt">GREATER THAN (&gt;)</option>
                    <option value="lt">LESS THAN (&lt;)</option>
                  </select>
                </div>
              </div>

              <div className={styles.formGroup}>
                <label>OPERATIONAL COMPILING VALUES (Comma separated strings/ints)</label>
                <input type="text" value={condition.values} onChange={e => setCondition(p => ({...p, values: e.target.value}))} required placeholder="4625, 4624, Administrator" />
              </div>

              <div className={styles.formRow}>
                <div className={styles.formGroup}>
                  <label>AGGREGATION MATH TYPE</label>
                  <select value={condition.aggregation} onChange={e => setCondition(p => ({...p, aggregation: e.target.value}))}>
                    <option value="null">NONE (STATELESS MATCH)</option>
                    <option value="count">MATHEMATICAL COUNT</option>
                    <option value="distinct_count">DISTINCT NODE COUNT</option>
                  </select>
                </div>
                <div className={styles.formGroup}>
                  <label>THRESHOLD COEFFICIENT</label>
                  <input type="number" value={condition.threshold} onChange={e => setCondition(p => ({...p, threshold: e.target.value}))} required min="1" />
                </div>
              </div>

              <div className={styles.formRow}>
                <div className={styles.formGroup}>
                  <label>SLIDING TIME WINDOW (MINUTES)</label>
                  <input type="number" value={condition.window_minutes} onChange={e => setCondition(p => ({...p, window_minutes: e.target.value}))} required min="1" />
                </div>
                <div className={styles.formGroup}>
                  <label>STATE GROUP KEY DESERIALIZATION FIELD</label>
                  <input type="text" value={condition.group_by} onChange={e => setCondition(p => ({...p, group_by: e.target.value}))} placeholder="IpAddress" />
                </div>
              </div>
            </fieldset>

            <div className={styles.modalActions}>
              <button type="button" onClick={() => setModalOpen(false)} className={styles.btnCancel}>ABORT INTERPOLATION</button>
              <button type="submit" className={styles.btnSubmit}>WRITE PRODUCTION MEMORY LOGIC</button>
            </div>
          </form>
        </div>
      )}

      {/* Test Simulation Dry Run Results Display Modal */}
      {testResult && (
        <div className={styles.modalOverlay}>
          <div className={styles.modalContent} style={{ maxWidth: '700px' }}>
            <h3>DIAGNOSTIC BACKTEST DRY-RUN RESOLUTION</h3>
            <div className={styles.testSummaryGrid}>
              <div>Scanned Frames: <strong>{testResult.total_events_scanned}</strong></div>
              <div>Matched Detections: <strong style={{ color: testResult.matched_count > 0 ? 'var(--red)' : 'var(--green)' }}>{testResult.matched_count}</strong></div>
            </div>
            
            <h4>SAMPLED COMPLIANCE LOG EXAMPLES (MAX 10)</h4>
            <div className={styles.codeBlockWrapper}>
              {testResult.matched_events?.length > 0 ? (
                <pre>{JSON.stringify(testResult.matched_events, null, 2)}</pre>
              ) : (
                <div className={styles.cleanFeedback}>Simulation parameters clear. Zero active alerts raised under historical state matrix.</div>
              )}
            </div>
            <button onClick={() => setTestResult(null)} className={styles.btnDismissTest}>CLOSE FEEDBACK TRACK</button>
          </div>
        </div>
      )}
    </div>
  );
}