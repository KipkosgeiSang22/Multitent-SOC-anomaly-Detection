import React, { useState, useEffect } from 'react';
import api from '../../../api/axios';
import styles from './AdminQueriesPage.module.css';

export default function AdminQueriesPage() {
  const [clients, setClients] = useState([]);
  const [selectedClient, setSelectedClient] = useState('');
  const [queries, setQueries] = useState([]);
  const [loading, setLoading] = useState(false);

  // Form Management Frame Holding
  const [modalOpen, setModalOpen] = useState(false);
  const [editingQuery, setEditingQuery] = useState(null);
  const [queryName, setQueryName] = useState('');
  const [graylogQuery, setGraylogQuery] = useState('');
  const [isMl, setIsMl] = useState(false);
  const [mlCategory, setMlCategory] = useState('AuthenticationEvents');
  const [displayOrder, setDisplayOrder] = useState(0);

  useEffect(() => {
    api.get('/admin/clients').then(res => {
      setClients(res.data);
      if (res.data.length > 0) setSelectedClient(res.data[0].id);
    });
  }, []);

  useEffect(() => {
    if (selectedClient) fetchQueries();
  }, [selectedClient]);

  const fetchQueries = async () => {
    setLoading(true);
    try {
      const res = await api.get(`/admin/clients/${selectedClient}/queries`);
      setQueries(res.data);
    } catch {}
    finally { setLoading(false); }
  };

  const handleOpenCreate = () => {
    setEditingQuery(null);
    setQueryName(''); setGraylogQuery(''); setIsMl(false); setMlCategory('AuthenticationEvents'); setDisplayOrder(0);
    setModalOpen(true);
  };

  const handleOpenEdit = (q) => {
    setEditingQuery(q);
    setQueryName(q.query_name);
    setGraylogQuery(q.graylog_query);
    setIsMl(q.is_ml_category);
    setMlCategory(q.ml_category || 'AuthenticationEvents');
    setDisplayOrder(q.display_order || 0);
    setModalOpen(true);
  };

  const handleSave = async (e) => {
    e.preventDefault();
    const payload = {
      client_id: parseInt(selectedClient), query_name: queryName, graylog_query: graylogQuery,
      is_ml_category: isMl, ml_category: isMl ? mlCategory : null, display_order: parseInt(displayOrder)
    };

    try {
      if (editingQuery) {
        await api.patch(`/admin/queries/${editingQuery.id}`, payload);
      } else {
        await api.post('/admin/queries', payload);
      }
      setModalOpen(false);
      fetchQueries();
    } catch { alert('Named query specification tracking block rejected.'); }
  };

  const handleDisable = async (id) => {
    if (!window.confirm('Suspend ingestion parsing runs against this target filter?')) return;
    try {
      await api.post(`/admin/queries/${id}/disable`);
      fetchQueries();
    } catch { alert('Query state mutation error.'); }
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>INGESTION CRITERIA CONFIGURATION MATRICES</h2>
        <p className={styles.subtitle}>Map core log management system query constraints directly to downstream pipeline processing blocks.</p>
        <button onClick={handleOpenCreate} className={styles.createBtn} disabled={!selectedClient}>+ LINK NAMED QUERY CONSTRAINTS</button>
      </header>

      <div className={styles.clientFilterBar}>
        <label>TARGET DATA BLOCK CONTAINER INTENT:</label>
        <select value={selectedClient} onChange={e => setSelectedClient(e.target.value)}>
          {clients.map(c => <option key={c.id} value={c.id}>{c.name} (Tenant Node: {c.id})</option>)}
        </select>
      </div>

      {loading ? <div className={styles.loader}>PARSING SCHEMATIC VALIDATION LAYERS...</div> : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr><th>QUERY STRATEGIC LABELLING</th><th>RAW STRING SEARCH EXPRESSION</th><th>ML MODEL LAYER BIND</th><th>INDEX PRIORITY</th><th>PIPELINE TARGET DISPOSITION</th></tr>
            </thead>
            <tbody>
              {queries.map(q => (
                <tr key={q.id} className={!q.enabled ? styles.disabledRow : ''}>
                  <td className={styles.mono}><strong>{q.query_name}</strong></td>
                  <td className={styles.mono}><div className={styles.truncate}>{q.graylog_query}</div></td>
                  <td>
                    {q.is_ml_category ? (
                      <span className={styles.mlBadge}>{q.ml_category}</span>
                    ) : (
                      <span className={styles.opsBadge}>Operational Visual Tab</span>
                    )}
                  </td>
                  <td className={styles.mono}>{q.display_order}</td>
                  <td>
                    <div className={styles.actions}>
                      <button onClick={() => handleOpenEdit(q)}>MUTATE</button>
                      <button onClick={() => handleDisable(q.id)} className={styles.disBtn} disabled={!q.enabled}>DISABLE RUN</button>
                    </div>
                  </td>
                </tr>
              ))}
              {queries.length === 0 && <tr><td colSpan="5" className={styles.empty}>Zero active queries parsing logs for this tenant space.</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {modalOpen && (
        <div className={styles.overlay}>
          <form className={styles.modal} onSubmit={handleSave}>
            <h3>{editingQuery ? 'MUTATE TARGET SEARCH PROPERTIES' : 'INITIALIZE SCHEMATIC INGEST VECTOR'}</h3>
            <div className={styles.field}><label>SYSTEM BIND NAME (UNIQUE ENTRY IDENTIFIER)</label><input type="text" value={queryName} onChange={e => setQueryName(e.target.value)} required placeholder="Successful_RDP_Logons" className={styles.monoInput}/></div>
            <div className={styles.field}><label>RAW SIEM INDEX QUERY CONSTRAINTS STR STRING</label><textarea value={graylogQuery} onChange={e => setGraylogQuery(e.target.value)} required placeholder="EventID:4624 AND LogonType:10" className={styles.textarea}/></div>
            
            <div className={styles.checkBlock}>
              <label><input type="checkbox" checked={isMl} onChange={e => setIsMl(e.target.checked)} /> ENGINE ROUTING BINDS TO MACHINE LEARNING MODEL ANALYZER</label>
            </div>

            {isMl && (
              <div className={styles.field}>
                <label>TARGET MATHEMATICAL VECTOR CLASSIFIER CATEGORY</label>
                <select value={mlCategory} onChange={e => setMlCategory(e.target.value)}>
                  <option value="AuthenticationEvents">AuthenticationEvents</option>
                  <option value="AccountManagementEvents">AccountManagementEvents</option>
                  <option value="ProcessCreationEvents">ProcessCreationEvents</option>
                </select>
              </div>
            )}

            <div className={styles.field}><label>VISUAL RENDERING DISPLAY SEQUENCE WEIGHT (TAB ORDER)</label><input type="number" value={displayOrder} onChange={e => setDisplayOrder(e.target.value)} required /></div>

            <div className={styles.modalActions}>
              <button type="button" onClick={() => setModalOpen(false)}>ABORT PROPERTY REWRITE</button>
              <button type="submit" className={styles.commitBtn}>PERSIST CRITERIA</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}