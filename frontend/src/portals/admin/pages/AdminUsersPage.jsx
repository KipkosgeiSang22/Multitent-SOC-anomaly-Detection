import React, { useState, useEffect } from 'react';
import api from '../../../api/axios';
import styles from './AdminUsersPage.module.css';

export default function AdminUsersPage() {
  const [users, setUsers] = useState([]);
  const [clients, setClients] = useState([]);
  const [roleFilter, setRoleFilter] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);

  // Modal Control Infrastructure
  const [createModal, setCreateModal] = useState(null); // 'analyst' | 'client'
  const [editUser, setEditUser] = useState(null);
  const [tempPasswordFeedback, setTempPasswordFeedback] = useState(null);

  // Form Field State Holds
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [selectedClientId, setSelectedClientId] = useState('');
  const [isActive, setIsActive] = useState(true);
  const [forceChange, setForceChange] = useState(false);

  useEffect(() => {
    fetchUsers();
    api.get('/admin/clients').then(res => {
      setClients(res.data);
      if (res.data.length > 0) setSelectedClientId(res.data[0].id);
    });
  }, [roleFilter]);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await api.get('/admin/users', { params: { role: roleFilter || undefined } });
      setUsers(res.data);
    } catch {}
    finally { setLoading(false); }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    const endpoint = createModal === 'analyst' ? '/admin/analysts' : '/admin/client-users';
    const payload = createModal === 'analyst' 
      ? { username, email, password } 
      : { username, email, password, client_id: parseInt(selectedClientId) };

    try {
      await api.post(endpoint, payload);
      setCreateModal(null);
      clearForm();
      fetchUsers();
    } catch (err) { alert(err.response?.data?.detail || 'Identity assertion failed.'); }
  };

  const handleOpenEdit = (u) => {
    setEditUser(u);
    setEmail(u.email);
    setIsActive(u.is_active);
    setForceChange(u.force_password_change);
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    try {
      await api.patch(`/admin/users/${editUser.id}`, {
        email,
        is_active: isActive,
        force_password_change: forceChange
      });
      setEditUser(null);
      fetchUsers();
    } catch { alert('Modification rejected.'); }
  };

  const handleResetPassword = async (id) => {
    if (!window.confirm('Invalidate current credentials and issue an administrator system override temp-pass string?')) return;
    try {
      const res = await api.post(`/admin/users/${id}/reset-password`);
      setTempPasswordFeedback(res.data.temp_password);
    } catch { alert('Credential compilation fault.'); }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Completely erase this identity node? Historical trace signatures in logs will freeze.')) return;
    try {
      await api.delete(`/admin/users/${id}`);
      fetchUsers();
    } catch (err) { alert(err.response?.data?.detail || 'Purge failed.'); }
  };

  const clearForm = () => {
    setUsername(''); setEmail(''); setPassword('');
  };

  const filteredUsers = users.filter(u => u.username.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>GLOBAL USER SECURITY IDENTITY ACCESS MANAGEMENT</h2>
        <p className={styles.subtitle}>Modify access scopes, lock profiles, and manage system authentication strings.</p>
      </header>

      {tempPasswordFeedback && (
        <div className={styles.criticalAlert}>
          <h3>⚠️ PLAIN TEXT TEMPORARY SECURITY STRING GENERATED</h3>
          <p>Copy this value directly. It will not be visible again:</p>
          <div className={styles.tokenBox}><code>{tempPasswordFeedback}</code></div>
          <button onClick={() => setTempPasswordFeedback(null)}>DISMISS CRITICAL LOCKOUT WARNING</button>
        </div>
      )}

      <div className={styles.actionRow}>
        <div className={styles.filters}>
          <input type="text" placeholder="Probe identity index username..." value={search} onChange={e => setSearch(e.target.value)} />
          <select value={roleFilter} onChange={e => setRoleFilter(e.target.value)}>
            <option value="">ALL ROLES</option>
            <option value="superadmin">SUPERADMIN</option>
            <option value="analyst">ANALYST</option>
            <option value="client">CLIENT USER</option>
          </select>
        </div>
        <div className={styles.buttons}>
          <button onClick={() => setCreateModal('analyst')} className={styles.btnSec}>+ PROVISION ANALYST INTERFACE</button>
          <button onClick={() => setCreateModal('client')} className={styles.btnPrimary}>+ BIND CLIENT USER</button>
        </div>
      </div>

      {loading ? <div className={styles.loader}>MAP ENUMERATION RUNNING...</div> : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr><th>ENTITY USERNAME</th><th>EMAIL PIPELINE BOUND</th><th>ROLE</th><th>STATUS CLAIMS</th><th>LAST RE-AUTH BEAT</th><th>MUTATION MANAGEMENT</th></tr>
            </thead>
            <tbody>
              {filteredUsers.map(u => (
                <tr key={u.id}>
                  <td className={styles.mono}><strong>{u.username}</strong></td>
                  <td>{u.email}</td>
                  <td><span className={styles.roleBadge}>{u.role}</span></td>
                  <td>
                    <span className={u.is_active ? styles.activeText : styles.deadText}>
                      {u.is_active ? 'ENABLED SECURE' : 'TERMINATED/LOCKED'}
                    </span>
                  </td>
                  <td className={styles.mono}>{u.last_login || 'NEVER'}</td>
                  <td>
                    <div className={styles.cellActions}>
                      <button onClick={() => handleOpenEdit(u)}>MODIFY</button>
                      <button onClick={() => handleResetPassword(u.id)} className={styles.warnBtn}>FORCED STRING OVERRIDE</button>
                      <button onClick={() => handleDelete(u.id)} className={styles.dangerBtn} disabled={u.role === 'superadmin'}>PURGE</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* CREATE USER DIALOG MODAL */}
      {createModal && (
        <div className={styles.overlay}>
          <form className={styles.modal} onSubmit={handleCreate}>
            <h3>PROVISION NEW ACCESSIBLE RECORD NODE ({createModal?.toUpperCase()})</h3>
            <div className={styles.field}><label>USERNAME INDEX ID</label><input type="text" value={username} onChange={e => setUsername(e.target.value)} required /></div>
            <div className={styles.field}><label>EMAIL CHANNEL</label><input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></div>
            <div className={styles.field}><label>INITIAL PLAIN CREDENTIAL AUTH STRING</label><input type="password" value={password} onChange={e => setPassword(e.target.value)} required /></div>
            
            {createModal === 'client' && (
              <div className={styles.field}>
                <label>TENANT DOMAIN ALLOCATION BINDING</label>
                <select value={selectedClientId} onChange={e => setSelectedClientId(e.target.value)}>
                  {clients.map(c => <option key={c.id} value={c.id}>{c.name} [ID: {c.id}]</option>)}
                </select>
              </div>
            )}

            <div className={styles.modalBtns}>
              <button type="button" onClick={() => setCreateModal(null)}>ABORT INTERPOLATION</button>
              <button type="submit" className={styles.btnPrimary}>COMMIT MEMORY RECORD</button>
            </div>
          </form>
        </div>
      )}

      {/* EDIT USER DIALOG MODAL */}
      {editUser && (
        <div className={styles.overlay}>
          <form className={styles.modal} onSubmit={handleSaveEdit}>
            <h3>MUTATE ENFORCE IDENTITY CRITERIA ({editUser.username})</h3>
            <div className={styles.field}><label>ROUTING EMAIL TARGET</label><input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></div>
            
            <div className={styles.checkGroup}>
              <label><input type="checkbox" checked={isActive} onChange={e => setIsActive(e.target.checked)} /> ACTIVE ACCESS DEPLOYED CLAIMS STATE</label>
            </div>
            <div className={styles.checkGroup}>
              <label><input type="checkbox" checked={forceChange} onChange={e => setForceChange(e.target.checked)} /> ENFORCE IMMEDIATE PASSWORD MUTATION ON NEXT BEAT</label>
            </div>

            <div className={styles.modalBtns}>
              <button type="button" onClick={() => setEditUser(null)}>ABORT</button>
              <button type="submit" className={styles.btnPrimary}>SAVE DEPLOYMENT ADJUSTMENTS</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}