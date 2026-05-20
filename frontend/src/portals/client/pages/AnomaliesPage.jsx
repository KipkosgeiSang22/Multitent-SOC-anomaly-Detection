import React, { useState, useEffect } from 'react';
import api from '../../../api/axios';
import styles from './AnomaliesPage.module.css';

export default function AnomaliesPage() {
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(false);
  const [period, setPeriod] = useState('7d');
  const [category, setCategory] = useState('ALL');

  useEffect(() => {
    fetchClientAnomalies();
  }, [period, category]);

  const fetchClientAnomalies = async () => {
    setLoading(true);
    try {
      const res = await api.get('/client/anomalies', {
        params: { period: period !== 'custom' ? period : undefined }
      });
      
      let dataset = res.data || [];
      if (category !== 'ALL') {
        dataset = dataset.filter(a => a.category === category);
      }
      setAnomalies(dataset);
    } catch {}
    finally { setLoading(false); }
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>DETECTED ENGINE ANOMALY SECURITY INCIDENTS</h2>
        <p className={styles.subtitle}>Statistical behavioral anomalies flagged via Layer 1 Boolean constraints and Layer 2 Isolation Forest mathematical models.</p>
      </header>

      <div className={styles.filterDeck}>
        <div className={styles.controlGroup}>
          <label>LOOKBACK RESOLUTION MATRIX:</label>
          <select value={period} onChange={e => setPeriod(e.target.value)}>
            <option value="24h">LAST 24 HOURS</option>
            <option value="7d">LAST 7 DAYS DEPLOYMENT</option>
            <option value="30d">LAST 30 DAYS TRACK</option>
          </select>
        </div>

        <div className={styles.controlGroup}>
          <label>MODEL CORRELATION GROUP:</label>
          <select value={category} onChange={e => setCategory(e.target.value)}>
            <option value="ALL">UNFILTERED GLOBAL SCHEMAS</option>
            <option value="AuthenticationEvents">AuthenticationEvents</option>
            <option value="AccountManagementEvents">AccountManagementEvents</option>
            <option value="ProcessCreationEvents">ProcessCreationEvents</option>
          </select>
        </div>
      </div>

      {loading ? <div className={styles.loader}>INTERROGATING ISOLATED DATA LABELS...</div> : (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr><th>DETECTION BEAT (EAT)</th><th>PIPELINE CATEGORY</th><th>PROCESSING LAYER</th><th>ALERT TYPING CRITERIA</th><th>METRIC COEFFICIENT DETAILS</th></tr>
            </thead>
            <tbody>
              {anomalies.map(a => (
                <tr key={a.id}>
                  <td className={styles.mono}>{a.detected_at}</td>
                  <td><span className={styles.catBadge}>{a.category}</span></td>
                  <td className={styles.mono}>Layer_0{a.layer}</td>
                  <td><span className={styles.typeBadge}>{a.anomaly_type}</span></td>
                  <td>
                    <div className={styles.detailsPayload}>
                      <pre>{JSON.stringify(a.details || {}, null, 2)}</pre>
                    </div>
                  </td>
                </tr>
              ))}
              {anomalies.length === 0 && <tr><td colSpan="5" className={styles.empty}>Your corporate perimeter maps clean. Zero statistical deviations reported.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}