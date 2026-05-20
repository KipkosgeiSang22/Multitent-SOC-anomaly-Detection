import React, { useState, useEffect } from 'react';
import api from '../../../api/axios';
import styles from './AdminClientsPage.module.css';

export default function AdminClientsPage() {
  const [clients, setClients] = useState([]);
  const [visibilityMap, setVisibilityMap] = useState({});
  const [loading, setLoading] = useState(false);

  // Form Struct State
  const [modalOpen, setModalOpen] = useState(false);
  const [editingClient, setEditingClient] = useState(null);
  const [name, setName] = useState('');
  const [siemType, setSiemType] = useState('graylog');
  const [siemBaseUrl, setSiemBaseUrl] = useState('');
  const [siemCredentials, setSiemCredentials] = useState('{}');
  const [subPlan, setSubPlan] = useState('Enterprise Tier');
  const [subStatus, setSubStatus] = useState('active');

  useEffect(() => {
    fetchClientsAndVisibility();
  }, []);

  const fetchClientsAndVisibility = async () => {
    setLoading(true);
    try {
      const clRes = await api.get('/admin/clients');
      setClients(clRes.data);
      
      const visRes = await api.get('/admin/visibility');
      const vMap = {};
      visRes.data.forEach(v => { vMap[v.client_id] = v.visible; });
      setVisibilityMap(vMap);
    } catch {}
    finally { setLoading(false); }
  };

  const handleOpenCreate = () => {
    setEditingClient(null);
    setName(''); setSiemType('graylog'); setSiemBaseUrl(''); setSiemCredentials('{}');
    setSubPlan('Enterprise Tier'); setSubStatus('active');
    setModalOpen(true);
  };

  const handleOpenEdit = (c) => {
    setEditingClient(c);
    setName(c.name);
    setSiemType(c.siem_type);
    setSiemBaseUrl(c.siem_base_url || '');
    setSiemCredentials('{}'); // Protect structural layout visibility in plain memory read
    setSubPlan(c.subscription_plan || 'Enterprise Tier');
    setSubStatus(c.subscription_status || 'active');
    setModalOpen(true);
  };

  const handleSave = async (e) => {
    e.preventDefault();
    let parsedCreds = {};
    try { parsedCreds = JSON.parse(siemCredentials); } catch { alert('SIEM Credentials must structure as syntactically sound JSON.'); return; }

    const payload = {
      name, siem_type: siemType, siem_base_url: siemBaseUrl,
      siem_credentials: parsedCreds, subscription_plan: subPlan, subscription_status: subStatus
    };

    try {
      if (editingClient) {
        await api.patch(`/admin/clients/${editingClient.id}`, payload);
      } else {
        await api.post('/admin/clients', { ...payload, active: true });
      }
      setModalOpen(false);
      fetchClientsAndVisibility();
    } catch { alert('Persistence pipeline block encountered.'); }
  };

  const handleToggleVisibility = async (clientId, currentVal) => {
    try {
      await api.post('/admin/visibility/toggle', { client_id: clientId, visible: !currentVal });
      setVisibilityMap(p => ({ ...p, [clientId]: !currentVal }));
    } catch { alert('Visibility state change rejected.'); }
  };

  const handleDeactivate = async (id) => {
    if (!window.confirm('Deactivate tenant partition space? Active user mapping blocks will isolate.')) return;
    try {
      await api.post(`/admin/clients/${id}/deactivate`);
      fetchClientsAndVisibility();
    } catch { alert('Command pipeline execution fault.'); }
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>GLOBAL TENANT COMPARTMENT MANAGEMENT MATRIX</h2>
        <p className={styles.subtitle}>Onboard corporate tenant nodes, adjust billing bounds, and change anomaly display filters.</p>
        <button onClick={handleOpenCreate} className={styles.createBtn}>+ SPIN UP TENANT SEGMENT</button>
      </header>

      {loading ? <div className={styles.loader}>MAP STRUCT COHERENCE VERIFICATION RUNNING...</div> : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr><th>TENANT LABEL DESIGNATION</th><th>INGESTION SYSTEM ENGINE</th><th>ENDPOINT SUITE URI</th><th>BILLING MATRIX LOCK</th><th>ANOMALY ENGINE VISIBILITY</th><th>ORCHESTRATION ACTIONS</th></tr>
            </thead>
            <tbody>
              {clients.map(c => (
                <tr key={c.id}>
                  <td><strong>{c.name}</strong> <span className={styles.idSub}>[ID: {c.id}]</span></td>
                  <td><span className={styles.monoBadge}>{c.siem_type?.toUpperCase()}</span></td>
                  <td className={styles.mono}>{c.siem_base_url || 'N/A'}</td>
                  <td><span className={styles.planBadge}>{c.subscription_plan} ({c.subscription_status})</span></td>
                  <td>
                    <label className={styles.toggleRow}>
                      <input type="checkbox" checked={!!visibilityMap[c.id]} onChange={() => handleToggleVisibility(c.id, !!visibilityMap[c.id])} />
                      <span className={styles.slider} />
                    </label>
                  </td>
                  <td>
                    <div className={styles.actions}>
                      <button onClick={() => handleOpenEdit(c)}>CONFIG</button>
                      <button onClick={() => handleDeactivate(c.id)} className={styles.deactBtn}>SUSPEND TIER</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {modalOpen && (
        <div className={styles.overlay}>
          <form className={styles.modal} onSubmit={handleSave}>
            <h3>{editingClient ? 'MUTATE PARSED CONFIG PARAMETERS' : 'INITIALIZE REAL ESTATE SEGMENT NODE'}</h3>
            <div className={styles.field}><label>CORPORATE LABEL ORCHESTRATION</label><input type="text" value={name} onChange={e => setName(e.target.value)} required /></div>
            
            <div className={styles.row}>
              <div className={styles.field}>
                <label>INGEST VECTOR CAPABILITY</label>
                <select value={siemType} onChange={e => setSiemType(e.target.value)}>
                  <option value="graylog">GRAYLOG DEPLOYMENT</option>
                  <option value="elastic">ELASTICSTACK NODE</option>
                  <option value="wazuh">WAZUH ENDPOINT AGENT</option>
                  <option value="splunk">SPLUNK INSTANCE</option>
                </select>
              </div>
              <div className={styles.field}><label>ENDPOINT BASE ROUTE URL</label><input type="text" value={siemBaseUrl} onChange={e => setSiemBaseUrl(e.target.value)} required placeholder="https://siem.tenant.internal:9000" /></div>
            </div>

            <div className={styles.field}>
              <label>SIEM SECURE DATA INGEST BLOCK (JSON STRUCTURE)</label>
              <span className={styles.warningNote}>⚠️ WARNING: Structural mutations undergo one-way Fernet encryption before filesystem ingestion block persistence.</span>
              <textarea value={siemCredentials} onChange={e => setSiemCredentials(e.target.value)} className={styles.textarea} required />
            </div>

            <div className={styles.row}>
              <div className={styles.field}><label>SUBSCRIPTION SPECIFICATION PROFILE</label><input type="text" value={subPlan} onChange={e => setSubPlan(e.target.value)} required /></div>
              <div className={styles.field}>
                <label>SUBSCRIPTION ENFORCEMENT DISPOSITION</label>
                <select value={subStatus} onChange={e => setSubStatus(e.target.value)}>
                  <option value="active">ACTIVE SYSTEM REGISTRATION</option>
                  <option value="suspended">SUSPENDED PARSED TERMINAL</option>
                  <option value="trial">SANDBOX EVALUATION SPACE</option>
                </select>
              </div>
            </div>

            <div className={styles.modalActions}>
              <button type="button" onClick={() => setModalOpen(false)}>ABORT PROFILE REWRITE</button>
              <button type="submit" className={styles.commitBtn}>PERSIST SECTOR STRUCT</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}