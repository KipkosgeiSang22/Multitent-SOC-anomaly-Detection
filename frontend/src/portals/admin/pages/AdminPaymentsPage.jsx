import React, { useState, useEffect, useCallback } from 'react';
import api from '../../../api/axios';
import styles from './AdminPaymentsPage.module.css';

const STATUS_LABELS = {
  completed: 'COMPLETED',
  pending: 'PENDING',
  failed: 'FAILED',
  cancelled: 'CANCELLED',
};

function StatusBadge({ status }) {
  return (
    <span className={`${styles.badge} ${styles[`badge_${status}`] || styles.badge_cancelled}`}>
      {STATUS_LABELS[status] || status.toUpperCase()}
    </span>
  );
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-KE', {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  });
}

function formatPeriod(start, end) {
  if (!start && !end) return '—';
  const s = start ? new Date(start).toLocaleDateString('en-KE') : '?';
  const e = end ? new Date(end).toLocaleDateString('en-KE') : '?';
  return `${s} → ${e}`;
}

export default function AdminPaymentsPage() {
  const [payments, setPayments] = useState([]);
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Filters
  const [filterClient, setFilterClient] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

  // Initiate modal
  const [showInitModal, setShowInitModal] = useState(false);
  const [initForm, setInitForm] = useState({
    client_id: '',
    phone_number: '',
    amount: '',
    payment_type: 'subscription',
    period_start: '',
    period_end: '',
  });
  const [initLoading, setInitLoading] = useState(false);
  const [initResult, setInitResult] = useState(null); // { success, message }

  // -----------------------------------------------------------------------
  const fetchPayments = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = {};
      if (filterClient) params.client_id = filterClient;
      if (filterStatus) params.status = filterStatus;
      const res = await api.get('/admin/payments', { params });
      setPayments(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load payments.');
    } finally {
      setLoading(false);
    }
  }, [filterClient, filterStatus]);

  useEffect(() => {
    fetchPayments();
    api.get('/admin/clients').then(res => setClients(res.data)).catch(() => {});
  }, [fetchPayments]);

  // -----------------------------------------------------------------------
  // Re-fetch a single client's history to refresh rows (manual status check)
  const handleRefreshClient = async (clientId) => {
    try {
      const res = await api.get(`/payments/${clientId}/history`);
      // Merge updated rows back into local state
      setPayments(prev => {
        const updated = res.data;
        const updatedIds = new Set(updated.map(p => p.id));
        const kept = prev.filter(p => p.client_id !== clientId || !updatedIds.has(p.id));
        return [...kept, ...updated].sort(
          (a, b) => new Date(b.initiated_at) - new Date(a.initiated_at)
        );
      });
    } catch {
      // silently ignore
    }
  };

  // -----------------------------------------------------------------------
  const handleInitSubmit = async () => {
    if (!initForm.client_id || !initForm.phone_number || !initForm.amount) {
      setInitResult({ success: false, message: 'Client, phone, and amount are required.' });
      return;
    }
    setInitLoading(true);
    setInitResult(null);
    try {
      const payload = {
        client_id: parseInt(initForm.client_id),
        phone_number: initForm.phone_number,
        amount: parseInt(initForm.amount),
        payment_type: initForm.payment_type,
      };
      if (initForm.period_start) payload.period_start = initForm.period_start;
      if (initForm.period_end) payload.period_end = initForm.period_end;

      const res = await api.post('/payments/initiate', payload);
      setInitResult({ success: true, message: res.data.message });
      fetchPayments();
    } catch (err) {
      const detail = err.response?.data?.detail;
      setInitResult({ success: false, message: typeof detail === 'string' ? detail : 'STK Push failed.' });
    } finally {
      setInitLoading(false);
    }
  };

  const closeInitModal = () => {
    setShowInitModal(false);
    setInitResult(null);
    setInitForm({
      client_id: '', phone_number: '', amount: '',
      payment_type: 'subscription', period_start: '', period_end: '',
    });
  };

  // -----------------------------------------------------------------------
  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h2>M-PESA PAYMENT LEDGER</h2>
        <p className={styles.subtitle}>
          Safaricom Daraja STK Push dispatch, callback tracking, and subscription billing.
        </p>
      </header>

      {/* Toolbar */}
      <div className={styles.toolbar}>
        <div className={styles.filters}>
          <select
            className={styles.select}
            value={filterClient}
            onChange={e => setFilterClient(e.target.value)}
          >
            <option value="">All Clients</option>
            {clients.map(c => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <select
            className={styles.select}
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
          >
            <option value="">All Statuses</option>
            <option value="pending">Pending</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
          <button className={styles.btnSec} onClick={fetchPayments}>REFRESH</button>
        </div>
        <button className={styles.btnPrimary} onClick={() => setShowInitModal(true)}>
          + INITIATE M-PESA STK PUSH
        </button>
      </div>

      {/* Error */}
      {error && <div className={styles.errorBar}>{error}</div>}

      {/* Table */}
      <div className={styles.tableWrapper}>
        {loading ? (
          <div className={styles.loader}>LOADING PAYMENT DATA...</div>
        ) : (
          <table className={styles.table}>
            <thead>
              <tr>
                <th>DATE INITIATED</th>
                <th>CLIENT</th>
                <th>PHONE</th>
                <th>AMOUNT (KES)</th>
                <th>RECEIPT #</th>
                <th>TYPE</th>
                <th>STATUS</th>
                <th>PERIOD COVERED</th>
                <th>COMPLETED</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {payments.length === 0 ? (
                <tr>
                  <td colSpan={10} className={styles.emptyRow}>
                    No payment records found.
                  </td>
                </tr>
              ) : (
                payments.map(p => (
                  <tr key={p.id} className={p.status === 'completed' ? styles.rowCompleted : ''}>
                    <td className={styles.mono}>{formatDate(p.initiated_at)}</td>
                    <td>{p.client_name}</td>
                    <td className={styles.mono}>{p.phone_number || '—'}</td>
                    <td className={styles.mono}>
                      {p.amount != null ? Number(p.amount).toLocaleString('en-KE') : '—'}
                    </td>
                    <td className={styles.mono}>{p.mpesa_receipt_number || '—'}</td>
                    <td>
                      <span className={styles.typeBadge}>
                        {p.payment_type?.toUpperCase() || '—'}
                      </span>
                    </td>
                    <td><StatusBadge status={p.status} /></td>
                    <td className={styles.mono}>
                      {formatPeriod(p.period_covered_start, p.period_covered_end)}
                    </td>
                    <td className={styles.mono}>{formatDate(p.completed_at)}</td>
                    <td>
                      {p.status === 'pending' && (
                        <button
                          className={styles.checkBtn}
                          onClick={() => handleRefreshClient(p.client_id)}
                          title="Re-fetch from Daraja history to update status"
                        >
                          CHECK
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Summary strip */}
      {!loading && payments.length > 0 && (
        <div className={styles.summaryStrip}>
          <span>
            {payments.length} record{payments.length !== 1 ? 's' : ''} &nbsp;|&nbsp;
            {payments.filter(p => p.status === 'completed').length} completed &nbsp;|&nbsp;
            {payments.filter(p => p.status === 'pending').length} pending &nbsp;|&nbsp;
            KES {payments
              .filter(p => p.status === 'completed' && p.amount != null)
              .reduce((sum, p) => sum + Number(p.amount), 0)
              .toLocaleString('en-KE')} total received
          </span>
        </div>
      )}

      {/* ---------------------------------------------------------------- */}
      {/* Initiate Payment Modal                                            */}
      {/* ---------------------------------------------------------------- */}
      {showInitModal && (
        <div className={styles.overlay}>
          <div className={styles.modal}>
            <h3>INITIATE M-PESA STK PUSH</h3>

            {initResult ? (
              <div className={initResult.success ? styles.successBox : styles.errorBox}>
                {initResult.message}
              </div>
            ) : null}

            {!initResult?.success && (
              <>
                <div className={styles.field}>
                  <label>CLIENT *</label>
                  <select
                    className={styles.fieldInput}
                    value={initForm.client_id}
                    onChange={e => setInitForm(f => ({ ...f, client_id: e.target.value }))}
                  >
                    <option value="">Select client…</option>
                    {clients.map(c => (
                      <option key={c.id} value={c.id}>{c.name}</option>
                    ))}
                  </select>
                </div>

                <div className={styles.field}>
                  <label>PHONE NUMBER * <span className={styles.hint}>(Kenyan: 07XXXXXXXX or 254XXXXXXXXX)</span></label>
                  <input
                    className={styles.fieldInput}
                    type="tel"
                    placeholder="e.g. 0712345678"
                    value={initForm.phone_number}
                    onChange={e => setInitForm(f => ({ ...f, phone_number: e.target.value }))}
                  />
                </div>

                <div className={styles.field}>
                  <label>AMOUNT (KES) *</label>
                  <input
                    className={styles.fieldInput}
                    type="number"
                    min="1"
                    step="1"
                    placeholder="e.g. 5000"
                    value={initForm.amount}
                    onChange={e => setInitForm(f => ({ ...f, amount: e.target.value }))}
                  />
                </div>

                <div className={styles.field}>
                  <label>PAYMENT TYPE</label>
                  <select
                    className={styles.fieldInput}
                    value={initForm.payment_type}
                    onChange={e => setInitForm(f => ({ ...f, payment_type: e.target.value }))}
                  >
                    <option value="subscription">Subscription</option>
                    <option value="onboarding">Onboarding</option>
                  </select>
                </div>

                <div className={styles.fieldRow}>
                  <div className={styles.field}>
                    <label>PERIOD START (optional)</label>
                    <input
                      className={styles.fieldInput}
                      type="date"
                      value={initForm.period_start}
                      onChange={e => setInitForm(f => ({ ...f, period_start: e.target.value }))}
                    />
                  </div>
                  <div className={styles.field}>
                    <label>PERIOD END (optional)</label>
                    <input
                      className={styles.fieldInput}
                      type="date"
                      value={initForm.period_end}
                      onChange={e => setInitForm(f => ({ ...f, period_end: e.target.value }))}
                    />
                  </div>
                </div>
              </>
            )}

            <div className={styles.modalBtns}>
              <button className={styles.btnCancel} onClick={closeInitModal}>
                {initResult?.success ? 'CLOSE' : 'CANCEL'}
              </button>
              {!initResult?.success && (
                <button
                  className={styles.btnPrimary}
                  onClick={handleInitSubmit}
                  disabled={initLoading}
                >
                  {initLoading ? 'SENDING…' : 'SEND STK PUSH'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
