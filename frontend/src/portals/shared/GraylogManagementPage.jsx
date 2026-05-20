import React, { useState, useEffect } from 'react';
import api from '../../api/axios';
import styles from './GraylogManagementPage.module.css';

export default function GraylogManagementPage({ accentColor = 'var(--amber)' }) {
  const [clients, setClients] = useState([]);
  const [selectedClient, setSelectedClient] = useState('');
  const [activeTab, setActiveTab] = useState('health');
  const [hasAccess, setHasAccess] = useState(null);
  const [loading, setLoading] = useState(false);

  // Structural Framework Payload Arrays
  const [healthData, setHealthData] = useState(null);
  const [inputs, setInputs] = useState([]);
  const [users, setUsers] = useState([]);
  const [dashboards, setDashboards] = useState([]);
  const [streams, setStreams] = useState([]);
  const [auditLog, setAuditLog] = useState([]);

  // High Stakes Context Execution Multi-Step Modal State
  const [intentModal, setIntentModal] = useState(null); // { action, target, token }
  const [confirmPassword, setConfirmPassword] = useState('');
  
  // Entity Form Ingestion State
  const [createUserOpen, setCreateUserOpen] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', password: '', email: '', full_name: '', roles: 'Reader' });
  const [createDashOpen, setCreateDashOpen] = useState(false);
  const [newDash, setNewDash] = useState({ title: '', description: '' });

  useEffect(() => {
    api.get('/analyst/clients')
      .then(res => {
        setClients(res.data);
        if (res.data.length > 0) setSelectedClient(res.data[0].id);
      })
      .catch(() => setHasAccess(false));
  }, []);

  useEffect(() => {
    if (selectedClient) executeDataRefresh();
  }, [selectedClient, activeTab]);

  const executeDataRefresh = async () => {
    setLoading(true);
    try {
      const url = `/graylog/${selectedClient}/${activeTab}`;
      const res = await api.get(url);
      setHasAccess(true);
      
      if (activeTab === 'health') setHealthData(res.data.data || res.data);
      if (activeTab === 'inputs') setInputs(res.data.data || []);
      if (activeTab === 'users') setUsers(res.data.data || []);
      if (activeTab === 'dashboards') setDashboards(res.data.data || []);
      if (activeTab === 'streams') setStreams(res.data.data || []);
      if (activeTab === 'audit') setAuditLog(res.data || []);
    } catch (err) {
      if (err.response?.status === 403) setHasAccess(false);
    } finally {
      setLoading(false);
    }
  };

  // Intent Step-Up Verification Protocol
  const triggerIntentEscalation = async (action, target) => {
    try {
      const res = await api.post(`/graylog/${selectedClient}/confirm-intent`, {
        client_id: parseInt(selectedClient),
        action,
        target
      });
      setIntentModal({
        action,
        target,
        token: res.data.confirm_token
      });
      setConfirmPassword('');
    } catch (err) {
      alert('Failed to obtain execution step-up token.');
    }
  };

  const executeDestructiveCommit = async (e) => {
    e.preventDefault();
    try {
      if (intentModal.action === 'RESTART_INPUT') {
        await api.post(`/graylog/${selectedClient}/inputs/${intentModal.target}/restart`, {
          confirm_token: intentModal.token,
          password: confirmPassword
        });
      } else if (intentModal.action === 'DELETE_USER') {
        await api.delete(`/graylog/${selectedClient}/users/${intentModal.target}`, {
          data: { confirm_token: intentModal.token, password: confirmPassword }
        });
      }
      setIntentModal(null);
      executeDataRefresh();
    } catch (err) {
      alert(err.response?.data?.detail || 'Cryptographic operational signature mismatch.');
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      await api.post(`/graylog/${selectedClient}/users`, { ...newUser, roles: [newUser.roles] });
      setCreateUserOpen(false);
      setActiveTab('users');
      executeDataRefresh();
    } catch (err) {
      alert('Creation execution fault.');
    }
  };

  const handleCreateDashboard = async (e) => {
    e.preventDefault();
    try {
      await api.post(`/graylog/${selectedClient}/dashboards`, newDash);
      setCreateDashOpen(false);
      setActiveTab('dashboards');
      executeDataRefresh();
    } catch (err) {
      alert('Dashboard generation error.');
    }
  };

  if (hasAccess === false) {
    return (
      <div className={styles.lockedContainer}>
        <div className={styles.lockBox}>
          <span className={styles.lockIcon}>☢️</span>
          <h3>CLUSTER COHERENCE PRIVILEGE LOCKED</h3>
          <p>Your identity claims lack operational access to: <code>can_manage_graylog</code>.</p>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container} style={{ '--accent': accentColor }}>
      <header className={styles.header}>
        <h2>SIEM INGESTION CLUSTER ARCHITECTURE CONSOLE</h2>
        <p className={styles.subtitle}>Directly manage node load balanced ingestion paths, permissions, and stream mappings across partitions.</p>
      </header>

      <div className={styles.topBar}>
        <div className={styles.selectorField}>
          <label>TENANT ENGINE BINDING:</label>
          <select value={selectedClient} onChange={e => setSelectedClient(e.target.value)}>
            {clients.map(c => <option key={c.id} value={c.id}>{c.name} [ID: {c.id}]</option>)}
          </select>
        </div>

        <nav className={styles.navTabs}>
          {['health', 'inputs', 'users', 'dashboards', 'streams', 'audit'].map(t => (
            <button key={t} className={activeTab === t ? styles.activeTabBtn : styles.tabBtn} onClick={() => setActiveTab(t)}>
              {t.toUpperCase()}
            </button>
          ))}
        </nav>
      </div>

      <main className={styles.workplace}>
        {loading ? <div className={styles.spinner}>INTERROGATING DISTRIBUTED CLUSTER HEAD...</div> : (
          <div className={styles.resultsContent}>
            
            {/* HEALTH WORKSPACE PANEL */}
            {activeTab === 'health' && healthData && (
              <div className={styles.panelCard}>
                <h3>NODE OVERVIEW SNAPSHOT</h3>
                <pre className={styles.codeBlock}>{JSON.stringify(healthData, null, 2)}</pre>
              </div>
            )}

            {/* INPUTS WORKSPACE PANEL */}
            {activeTab === 'inputs' && (
              <div className={styles.tableWrapper}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>INPUT BLOCK ID</th><th>TITLE</th><th>INTERFACE BIND</th><th>TYPE</th><th>OPERATIONAL TARGET</th></tr>
                  </thead>
                  <tbody>
                    {inputs.map(i => (
                      <tr key={i.id}>
                        <td className={styles.mono}>{i.id}</td>
                        <td><strong>{i.title}</strong></td>
                        <td className={styles.mono}>{i.configuration?.bind_address || '0.0.0.0'}:{i.configuration?.port}</td>
                        <td><span className={styles.badge}>{i.type}</span></td>
                        <td><button onClick={() => triggerIntentEscalation('RESTART_INPUT', i.id)} className={styles.btnDangerAction}>RESTART ENGINE</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* USERS WORKSPACE PANEL */}
            {activeTab === 'users' && (
              <div>
                <button onClick={() => setCreateUserOpen(true)} className={styles.mbBtn}>+ PROVISION CLUSTER USER</button>
                <div className={styles.tableWrapper}>
                  <table className={styles.table}>
                    <thead>
                      <tr><th>USERNAME</th><th>FULL NAME</th><th>EMAIL TARGET</th><th>ROLES ASSIGNED</th><th>CRITICAL PURGE</th></tr>
                    </thead>
                    <tbody>
                      {users.map(u => (
                        <tr key={u.username}>
                          <td className={styles.mono}>{u.username}</td>
                          <td>{u.full_name}</td>
                          <td>{u.email}</td>
                          <td>{u.roles?.join(', ')}</td>
                          <td><button onClick={() => triggerIntentEscalation('DELETE_USER', u.username)} className={styles.btnDangerAction} disabled={u.username === 'admin'}>PURGE DESTRUCTIVE</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* DASHBOARDS WORKSPACE PANEL */}
            {activeTab === 'dashboards' && (
              <div>
                <button onClick={() => setCreateDashOpen(true)} className={styles.mbBtn}>+ INITIALIZE SYSTEM DASHBOARD</button>
                <div className={styles.gridContainer}>
                  {dashboards.map(d => (
                    <div key={d.id} className={styles.dashCard}>
                      <h4>{d.title}</h4>
                      <p>{d.description || 'Zero engineering documentation notes attached.'}</p>
                      <span className={styles.monoId}>ID: {d.id}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* STREAMS WORKSPACE PANEL */}
            {activeTab === 'streams' && (
              <div className={styles.tableWrapper}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>STREAM IDENTIFICATION TOKEN</th><th>TITLE</th><th>DESCRIPTION CONFIG</th><th>ROUTING DISPOSITION</th></tr>
                  </thead>
                  <tbody>
                    {streams.map(s => (
                      <tr key={s.id}>
                        <td className={styles.mono}>{s.id}</td>
                        <td><strong>{s.title}</strong></td>
                        <td>{s.description || 'No data rules structured.'}</td>
                        <td><span className={styles.monoBadge}>{s.disabled ? 'SUSPENDED' : 'LIVE ROUTING'}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* AUDIT WORKSPACE PANEL */}
            {activeTab === 'audit' && (
              <div className={styles.tableWrapper}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>TIMESTAMP</th><th>ANALYST ID</th><th>ACTION TYPE OBJECT</th></tr>
                  </thead>
                  <tbody>
                    {auditLog.map(a => (
                      <tr key={a.id}>
                        <td className={styles.mono}>{a.performed_at}</td>
                        <td className={styles.mono}>User Node: {a.analyst_id}</td>
                        <td>
                          <div className={styles.mono}>{a.action_type}</div>
                          <pre className={styles.innerCode}>{JSON.stringify(a.payload, null, 2)}</pre>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

          </div>
        )}
      </main>

      {/* SECURE STEP-UP INTERCEPT RE-AUTHENTICATION DIALOG MODAL */}
      {intentModal && (
        <div className={styles.overlay}>
          <form className={styles.intentBox} onSubmit={executeDestructiveCommit}>
            <div className={styles.alertBanner}>⚠️ HIGH-STAKES DISRUPTIVE MODAL ENFORCEMENT</div>
            <h3>SECURE CONTEXT STATE MUTATION RE-AUTH SIGNATURE</h3>
            <p>You are triggering a destructive change on the active cluster index:</p>
            <div className={styles.targetSpec}>
              <div>Action Vector: <strong>{intentModal.action}</strong></div>
              <div>Node/User ID: <code>{intentModal.target}</code></div>
            </div>
            <p className={styles.timerWarning}>This tracking validation cryptographic assertion window will expire in <strong>60 seconds</strong>.</p>
            
            <div className={styles.inputField}>
              <label>CONFIRM ROOT IDENTITY PASSWORD SECURE CREDENTIALS</label>
              <input type="password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} required placeholder="••••••••" />
            </div>

            <div className={styles.actions}>
              <button type="button" onClick={() => setIntentModal(null)} className={styles.btnAbort}>ABORT OPERATION</button>
              <button type="submit" className={styles.btnCommitDestructive}>AUTHORIZE DESTRUCTIVE ACTION</button>
            </div>
          </form>
        </div>
      )}

      {/* CREATE USER MODAL */}
      {createUserOpen && (
        <div className={styles.overlay}>
          <form className={styles.dialogBox} onSubmit={handleCreateUser}>
            <h3>PROVISION NEW CONTEXT CLUSTER USER</h3>
            <div className={styles.dgForm}>
              <input type="text" placeholder="Username" value={newUser.username} onChange={e => setNewUser(p => ({ ...p, username: e.target.value }))} required />
              <input type="password" placeholder="Password" value={newUser.password} onChange={e => setNewUser(p => ({ ...p, password: e.target.value }))} required />
              <input type="email" placeholder="Email" value={newUser.email} onChange={e => setNewUser(p => ({ ...p, email: e.target.value }))} required />
              <input type="text" placeholder="Full Name" value={newUser.full_name} onChange={e => setNewUser(p => ({ ...p, full_name: e.target.value }))} required />
              <select value={newUser.roles} onChange={e => setNewUser(p => ({ ...p, roles: e.target.value }))}>
                <option value="Reader">Reader</option>
                <option value="Administrator">Administrator</option>
              </select>
            </div>
            <div className={styles.actions}>
              <button type="button" onClick={() => setCreateUserOpen(false)} className={styles.btnAbort}>CANCEL</button>
              <button type="submit" className={styles.btnConfirm}>PROVISION ENGINE USER</button>
            </div>
          </form>
        </div>
      )}

      {/* CREATE DASHBOARD MODAL */}
      {createDashOpen && (
        <div className={styles.overlay}>
          <form className={styles.dialogBox} onSubmit={handleCreateDashboard}>
            <h3>INITIALIZE SYSTEM VIEWING MATRIX DASHBOARD</h3>
            <div className={styles.dgForm}>
              <input type="text" placeholder="Dashboard Title" value={newDash.title} onChange={e => setNewDash(p => ({ ...p, title: e.target.value }))} required />
              <input type="text" placeholder="Description Configuration Notes" value={newDash.description} onChange={e => setNewDash(p => ({ ...p, description: e.target.value }))} required />
            </div>
            <div className={styles.actions}>
              <button type="button" onClick={() => setCreateDashOpen(false)} className={styles.btnAbort}>CANCEL</button>
              <button type="submit" className={styles.btnConfirm}>GENERATE GRAPH VIEW</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}