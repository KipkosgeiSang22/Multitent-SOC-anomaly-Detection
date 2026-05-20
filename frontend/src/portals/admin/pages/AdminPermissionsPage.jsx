import React, { useState, useEffect } from 'react';
import api from '../../../api/axios';
import styles from './AdminPermissionsPage.module.css';

export default function AdminPermissionsPage() {
  const [permissions, setPermissions] = useState([]);
  const [analysts, setAnalysts] = useState([]);
  const [targetAnalystId, setTargetAnalystId] = useState('');
  const [loading, setLoading] = useState(false);

  // Form Struct State
  const [modalOpen, setModalOpen] = useState(false);
  const [grantAnalystId, setGrantAnalystId] = useState('');
  const [canRetrain, setCanRetrain] = useState(false);
  const [canRules, setCanRules] = useState(false);
  const [canGraylog, setCanGraylog] = useState(false);
  const [scopeText, setScopeText] = useState('ALL');
  const [reason, setReason] = useState('');

  useEffect(() => {
    fetchActivePermissions();
    // Fetch analysts list for onboarding dropdown selectors
    api.get('/admin/users?role=analyst').then(res => {
      setAnalysts(res.data);
      if (res.data.length > 0) setGrantAnalystId(res.data[0].id);
    });
  }, [targetAnalystId]);

  const fetchActivePermissions = async () => {
    setLoading(true);
    try {
      const res = await api.get('/admin/permissions', {
        params: { analyst_id: targetAnalystId || undefined }
      });
      setPermissions(res.data);
    } catch {}
    finally { setLoading(false); }
  };

  const handleGrant = async (e) => {
    e.preventDefault();
    let computedScope = ['ALL'];
    if (scopeText.trim() !== 'ALL') {
      computedScope = scopeText.split(',').map(x => parseInt(x.trim())).filter(x => !isNaN(x));
    }

    const payload = {
      analyst_id: parseInt(grantAnalystId), can_retrain_models: canRetrain,
      can_edit_layer1_rules: canRules, can_manage_graylog: canGraylog,
      client_scope: computedScope, reason
    };

    try {
      await api.post('/admin/permissions/grant', payload);
      setModalOpen(false);
      clearForm();
      fetchActivePermissions();
    } catch { alert('Security assertion framework rejected privilege expansion mapping.'); }
  };

  const handleRevoke = async (id) => {
    if (!window.confirm('Revoke elevated capability context? Authorization gates switch down immediately.')) return;
    try {
      await api.post(`/admin/permissions/${id}/revoke`);
      fetchActivePermissions();
    } catch { alert('Revocation failure.'); }
  };

  const clearForm = () => {
    setCanRetrain(false); setCanRules(false); setCanGraylog(false); setScopeText('ALL'); setReason('');
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>ELEVATED ANALYST OPERATION CAPABILITY GRANTS</h2>
        <p className={styles.subtitle}>Audit active cryptographic capabilities, expand user operation rights, and log structural authorization justifications.</p>
        <button onClick={() => setModalOpen(true)} className={styles.createBtn} disabled={analysts.length === 0}>+ GRANT ELEVATED PRIVILEGE STRAT</button>
      </header>

      <div className={styles.filterBar}>
        <label>FILTER ACTIVE DEPLOYED SCOPES BY ANALYST NODE:</label>
        <select value={targetAnalystId} onChange={e => setTargetAnalystId(e.target.value)}>
          <option value="">ALL REGISTERED ANALYSTS</option>
          {analysts.map(a => <option key={a.id} value={a.id}>{a.username} (Node: {a.id})</option>)}
        </select>
      </div>

      {loading ? <div className={styles.loader}>PROBING KERNEL MEMORY POLICIES...</div> : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr><th>ANALYST RECORD</th><th>RETRAIN CAP</th><th>RULES CAP</th><th>SIEM MGMT CAP</th><th>TENANT SPACE BOUND SCOPE</th><th>JUSTIFICATION FRAME REASON</th><th>REVOCATION</th></tr>
            </thead>
            <tbody>
              {permissions.map(p => (
                <tr key={p.id} className={p.revoked_at ? styles.revokedRow : ''}>
                  <td className={styles.mono}><strong>{p.analyst_username || `Node: ${p.analyst_id}`}</strong></td>
                  <td><span className={p.can_retrain_models ? styles.yes : styles.no}>{p.can_retrain_models ? 'GRANTED' : 'DENIED'}</span></td>
                  <td><span className={p.can_edit_layer1_rules ? styles.yes : styles.no}>{p.can_edit_layer1_rules ? 'GRANTED' : 'DENIED'}</span></td>
                  <td><span className={p.can_manage_graylog ? styles.yes : styles.no}>{p.can_manage_graylog ? 'GRANTED' : 'DENIED'}</span></td>
                  <td className={styles.mono}>{JSON.stringify(p.client_scope)}</td>
                  <td className={styles.reasonCell}>{p.reason}</td>
                  <td>
                    {!p.revoked_at ? (
                      <button onClick={() => handleRevoke(p.id)} className={styles.revBtn}>REVOKE ACCESS</button>
                    ) : (
                      <span className={styles.mutedText}>Revoked Beat: {p.revoked_at}</span>
                    )}
                  </td>
                </tr>
              ))}
              {permissions.length === 0 && <tr><td colSpan="7" className={styles.empty}>Zero active mapping adjustments logged.</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {modalOpen && (
        <div className={styles.overlay}>
          <form className={styles.modal} onSubmit={handleGrant}>
            <h3>EXPAND OPERATIONAL PROFILE BOUND MATRIX</h3>
            
            <div className={styles.field}>
              <label>TARGET ANALYST SELECTION INDEX ID</label>
              <select value={grantAnalystId} onChange={e => setGrantAnalystId(e.target.value)}>
                {analysts.map(a => <option key={a.id} value={a.id}>{a.username} [ID: {a.id}]</option>)}
              </select>
            </div>

            <fieldset className={styles.fieldset}>
              <legend>CAPABILITY PROPERTY BITMAP</legend>
              <div className={styles.checkLine}><label><input type="checkbox" checked={canRetrain} onChange={e => setCanRetrain(e.target.checked)} /> <code>can_retrain_models</code></label></div>
              <div className={styles.checkLine}><label><input type="checkbox" checked={canRules} onChange={e => setCanRules(e.target.checked)} /> <code>can_edit_layer1_rules</code></label></div>
              <div className={styles.checkLine}><label><input type="checkbox" checked={canGraylog} onChange={e => setCanGraylog(e.target.checked)} /> <code>can_manage_graylog</code></label></div>
            </fieldset>

            <div className={styles.field}>
              <label>TENANT BOUND COHERENCE SCOPE (Free Text: "ALL" or Comma-separated client IDs)</label>
              <input type="text" value={scopeText} onChange={e => setScopeText(e.target.value)} required placeholder="ALL or 1,3,7" className={styles.monoInput} />
            </div>

            <div className={styles.field}>
              <label>COMPREHENSIVE AUTHORIZATION SYSTEM JUSTIFICATION</label>
              <input type="text" value={reason} onChange={e => setReason(e.target.value)} required placeholder="Required for Q2 cluster node maintenance windows tracking adjustments." />
            </div>

            <div className={styles.modalActions}>
              <button type="button" onClick={() => setModalOpen(false)}>ABORT EXPANSION</button>
              <button type="submit" className={styles.commitBtn}>GRANT RIGHTS MATRIX</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}