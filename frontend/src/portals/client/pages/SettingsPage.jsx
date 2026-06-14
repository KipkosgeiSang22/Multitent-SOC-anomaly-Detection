import { useState } from "react";
import api from "../../../api/axios";
import QRCode from "qrcode.react";

export default function SettingsPage() {
  const [step, setStep] = useState("idle"); // idle | setup | verify | done
  const [qrUrl, setQrUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleEnable() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get("/auth/mfa-setup");
      setQrUrl(res.data.qr_code_url);
      setSecret(res.data.secret);
      setStep("setup");
    } catch {
      setError("Failed to start MFA setup.");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify() {
    if (!code.trim()) return;
    setLoading(true);
    setError(null);
    try {
      await api.post("/auth/mfa-setup/verify", { totp_code: code });
      setStep("done");
    } catch {
      setError("Invalid code. Try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: "2rem", color: "#e2e8f0", fontFamily: "IBM Plex Mono, monospace" }}>
      <h1 style={{ fontSize: "1.2rem", marginBottom: "1.5rem" }}>Security Settings</h1>

      {step === "idle" && (
        <div>
          <p style={{ color: "#94a3b8", marginBottom: "1rem" }}>
            Two-Factor Authentication adds an extra layer of security to your account.
          </p>
          <button
            onClick={handleEnable}
            disabled={loading}
            style={{
              background: "#e5434b", color: "#fff", border: "none",
              padding: "0.6rem 1.2rem", cursor: "pointer", borderRadius: "4px"
            }}
          >
            {loading ? "Loading..." : "Enable 2FA"}
          </button>
        </div>
      )}

      {step === "setup" && (
        <div>
          <p style={{ color: "#94a3b8", marginBottom: "1rem" }}>
            1. Download <strong>Google Authenticator</strong> or <strong>Authy</strong> on your phone.
          </p>
          <p style={{ color: "#94a3b8", marginBottom: "1rem" }}>
            2. Scan this QR code:
          </p>
          <div style={{ background: "#fff", display: "inline-block", padding: "1rem", marginBottom: "1rem" }}>
            <QRCode value={qrUrl} size={180} />
          </div>
          <p style={{ color: "#64748b", fontSize: "0.75rem", marginBottom: "1rem" }}>
            Can't scan? Enter this secret manually: <strong style={{ color: "#94a3b8" }}>{secret}</strong>
          </p>
          <p style={{ color: "#94a3b8", marginBottom: "0.5rem" }}>
            3. Enter the 6-digit code from the app:
          </p>
          <input
            type="text"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="000000"
            style={{
              background: "#1e2330", border: "1px solid #334155",
              color: "#e2e8f0", padding: "0.5rem 1rem",
              fontSize: "1.2rem", letterSpacing: "0.5rem",
              borderRadius: "4px", marginBottom: "1rem",
              display: "block", width: "160px"
            }}
          />
          {error && <p style={{ color: "#e5434b", marginBottom: "0.5rem" }}>{error}</p>}
          <button
            onClick={handleVerify}
            disabled={loading || code.length !== 6}
            style={{
              background: "#e5434b", color: "#fff", border: "none",
              padding: "0.6rem 1.2rem", cursor: "pointer", borderRadius: "4px"
            }}
          >
            {loading ? "Verifying..." : "Verify and Enable"}
          </button>
        </div>
      )}

      {step === "done" && (
        <div>
          <p style={{ color: "#22c55e", fontSize: "1rem" }}>
            ✓ Two-factor authentication has been enabled successfully.
          </p>
          <p style={{ color: "#94a3b8", marginTop: "0.5rem" }}>
            You will need your authenticator app on every future login.
          </p>
        </div>
      )}
    </div>
  );
}