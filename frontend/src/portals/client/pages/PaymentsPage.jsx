import { useState, useEffect } from "react";
import api from "../../../api/axios";

const STATUS_COLORS = {
  completed: "#2fb87a",
  pending:   "#f5a623",
  failed:    "#e5434b",
};

const cell = {
  padding: "10px 14px",
  fontFamily: "'IBM Plex Mono', monospace",
  fontSize: "12px",
  color: "#e8eaf0",
  borderBottom: "1px solid #1a1d2e",
};

const headerCell = {
  ...cell,
  color: "#8b90a8",
  fontSize: "11px",
  letterSpacing: "0.5px",
  borderBottom: "1px solid #252838",
};

export default function PaymentsPage() {
  const [history, setHistory]   = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [paying, setPaying]     = useState(false);
  const [payMsg, setPayMsg]     = useState(null);
  const [phone, setPhone]       = useState("");
  const [payType, setPayType]   = useState("subscription");

  useEffect(() => {
    api.get("/payments/client/history")
      .then(r => setHistory(r.data ?? []))
      .catch(() => setError("Failed to load payment history."))
      .finally(() => setLoading(false));
  }, []);

  const handlePay = async (e) => {
    e.preventDefault();
    setPaying(true);
    setPayMsg(null);
    try {
      const res = await api.post("/payments/client/initiate", {
        phone_number: phone,
        payment_type: payType,
      });
      setPayMsg({ ok: true, text: res.data?.detail ?? "STK Push sent — check your phone." });
      // Refresh history after a short delay
      setTimeout(() => {
        api.get("/payments/client/history")
          .then(r => setHistory(r.data ?? []))
          .catch(() => {});
      }, 4000);
    } catch (err) {
      setPayMsg({ ok: false, text: err.response?.data?.detail ?? "Payment initiation failed." });
    } finally {
      setPaying(false);
    }
  };

  return (
    <div style={{ padding: "28px", fontFamily: "'IBM Plex Mono', monospace" }}>

      {/* ── Header ── */}
      <div style={{ marginBottom: "28px" }}>
        <h2 style={{ color: "#e8eaf0", margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>
          PAYMENTS
        </h2>
        <p style={{ color: "#8b90a8", margin: 0, fontSize: "12px" }}>
          Manage your subscription payments via M-Pesa STK Push.
        </p>
      </div>

      {/* ── Pay Now form ── */}
      <div style={{
        background: "#0f1115",
        border: "1px solid #252838",
        borderRadius: "4px",
        padding: "20px",
        marginBottom: "28px",
        maxWidth: "480px",
      }}>
        <h3 style={{ color: "#e8eaf0", margin: "0 0 16px", fontSize: "13px", letterSpacing: "0.5px" }}>
          INITIATE PAYMENT
        </h3>
        <form onSubmit={handlePay} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#8b90a8", fontSize: "11px", letterSpacing: "0.5px" }}>
              M-PESA PHONE NUMBER
            </label>
            <input
              type="tel"
              value={phone}
              onChange={e => setPhone(e.target.value)}
              required
              placeholder="254712345678"
              style={{
                background: "#0a0b0d",
                border: "1px solid #252838",
                color: "#e8eaf0",
                padding: "10px 12px",
                fontFamily: "'IBM Plex Mono', monospace",
                fontSize: "13px",
                borderRadius: "2px",
                outline: "none",
              }}
            />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#8b90a8", fontSize: "11px", letterSpacing: "0.5px" }}>
              PAYMENT TYPE
            </label>
            <select
              value={payType}
              onChange={e => setPayType(e.target.value)}
              style={{
                background: "#0a0b0d",
                border: "1px solid #252838",
                color: "#e8eaf0",
                padding: "10px 12px",
                fontFamily: "'IBM Plex Mono', monospace",
                fontSize: "13px",
                borderRadius: "2px",
                outline: "none",
              }}
            >
              <option value="subscription">Subscription Renewal</option>
              <option value="onboarding">Onboarding Fee</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={paying}
            style={{
              background: paying ? "#4a5068" : "#252838",
              color: paying ? "#8b90a8" : "#e8eaf0",
              border: "1px solid #3a3f5c",
              fontFamily: "'IBM Plex Mono', monospace",
              fontWeight: 600,
              fontSize: "12px",
              padding: "11px",
              cursor: paying ? "not-allowed" : "pointer",
              borderRadius: "2px",
              letterSpacing: "0.5px",
            }}
          >
            {paying ? "SENDING STK PUSH..." : "PAY NOW"}
          </button>
          {payMsg && (
            <div style={{
              background: payMsg.ok ? "rgba(47,184,122,0.1)" : "rgba(229,67,75,0.1)",
              border: `1px solid ${payMsg.ok ? "#2fb87a" : "#e5434b"}`,
              color: payMsg.ok ? "#2fb87a" : "#e5434b",
              padding: "10px",
              fontSize: "12px",
              borderRadius: "2px",
            }}>
              {payMsg.text}
            </div>
          )}
        </form>
      </div>

      {/* ── Payment History ── */}
      <div style={{ background: "#0f1115", border: "1px solid #252838", borderRadius: "4px" }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #252838" }}>
          <h3 style={{ color: "#e8eaf0", margin: 0, fontSize: "13px", letterSpacing: "0.5px" }}>
            PAYMENT HISTORY
          </h3>
        </div>

        {loading && (
          <div style={{ padding: "24px", color: "#8b90a8", fontSize: "12px" }}>Loading...</div>
        )}
        {error && (
          <div style={{ padding: "24px", color: "#e5434b", fontSize: "12px" }}>{error}</div>
        )}
        {!loading && !error && (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["DATE", "TYPE", "AMOUNT (KES)", "STATUS", "REFERENCE"].map(h => (
                  <th key={h} style={{ ...headerCell, textAlign: "left" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ ...cell, color: "#8b90a8", textAlign: "center" }}>
                    No payment records found.
                  </td>
                </tr>
              ) : history.map((p, i) => (
                <tr key={p.id ?? i}>
                  <td style={cell}>{p.created_at ? new Date(p.created_at).toLocaleDateString() : "—"}</td>
                  <td style={cell}>{p.payment_type ?? "—"}</td>
                  <td style={cell}>{p.amount != null ? p.amount.toLocaleString() : "—"}</td>
                  <td style={cell}>
                    <span style={{ color: STATUS_COLORS[p.status] ?? "#8b90a8" }}>
                      {(p.status ?? "unknown").toUpperCase()}
                    </span>
                  </td>
                  <td style={{ ...cell, color: "#8b90a8" }}>{p.mpesa_receipt_number ?? p.checkout_request_id ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
