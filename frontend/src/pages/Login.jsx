import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import useAuthStore from '../store/authStore';

// ─── Step constants ────────────────────────────────────────────────────────────
const STEP_CREDENTIALS = 'credentials';
const STEP_MFA         = 'mfa';

export default function Login() {
  const { login, verifyMfa, user, isLoading, error, clearError } = useAuthStore();

  // ── Form state ───────────────────────────────────────────────────────────────
  const [step,          setStep]          = useState(STEP_CREDENTIALS);
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [mfaCode,       setMfaCode]       = useState('');
  const [tempToken,     setTempToken]     = useState(null);

  const navigate  = useNavigate();
  const location  = useLocation();

  // ── Clear stale errors on mount ──────────────────────────────────────────────
  useEffect(() => {
    clearError();
  }, []);

  // ── Redirect after successful login ─────────────────────────────────────────
  // Fires whenever user or isLoading changes in the store.
  // If ProtectedRoute saved a deep-link destination, go there.
  // Otherwise fall back to the role's default landing page.
  useEffect(() => {
    if (user && !isLoading) {
      const from = location.state?.from?.pathname;
      if (from && from !== '/login') {
        navigate(from, { replace: true });
        return;
      }
      if (user.role === 'superadmin') navigate('/admin/dashboard',  { replace: true });
      else if (user.role === 'analyst') navigate('/analyst/dashboard', { replace: true });
      else if (user.role === 'client')  navigate('/client/events',    { replace: true });
    }
  }, [user, isLoading, navigate, location]);

  // ── Step 1: username + password ──────────────────────────────────────────────
  const handleCredentialsSubmit = async (e) => {
    e.preventDefault();//not login as default html
    try {
      const result = await login(usernameInput, passwordInput);

      if (result?.requires_mfa) {
        // Analyst or superadmin — MFA required before token is issued
        setTempToken(result.temp_token);
        setStep(STEP_MFA);
        return;
      }

      if (result?.force_password_change) {
        // Client or non-MFA user who must change password on first login
        navigate('/force-change-password', { replace: true });
        return;
      }

      // result.done — redirect handled by the useEffect above
    } catch {
      // Error already set in store — displayed in the UI below
    }
  };

  // ── Step 2: TOTP code ────────────────────────────────────────────────────────
  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    try {
      const result = await verifyMfa(tempToken, mfaCode);

      if (result?.force_password_change) {
        navigate('/force-change-password', { replace: true });
        return;
      }

      // result.done — redirect handled by the useEffect above
    } catch {
      // Error already set in store
    }
  };

  // ── Shared styles ────────────────────────────────────────────────────────────
  const inputStyle = {
    background:   '#0a0b0d',
    border:       '1px solid #252838',
    color:        '#e8eaf0',
    padding:      '10px 12px',
    fontFamily:   "'IBM Plex Mono', monospace",
    fontSize:     '14px',
    borderRadius: '2px',
    outline:      'none',
    width:        '100%',
    boxSizing:    'border-box',
  };

  const labelStyle = {
    fontFamily:    "'IBM Plex Mono', monospace",
    fontSize:      '11px',
    color:         '#8b90a8',
    letterSpacing: '0.5px',
  };

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <div style={{
      display:        'flex',
      alignItems:     'center',
      justifyContent: 'center',
      minHeight:      '100vh',
      background:     '#0a0b0d',
      fontFamily:     "'IBM Plex Sans', sans-serif",
    }}>
      <div style={{
        background:    '#0f1115',
        border:        '1px solid #252838',
        width:         '400px',
        padding:       '28px',
        borderRadius:  '4px',
        display:       'flex',
        flexDirection: 'column',
        gap:           '18px',
      }}>

        {/* ── Terminal dot decoration ── */}
        <div style={{
          display:       'flex',
          alignItems:    'center',
          gap:           '6px',
          fontFamily:    "'IBM Plex Mono', monospace",
          fontSize:      '11px',
          color:         '#4a5068',
          borderBottom:  '1px solid #252838',
          paddingBottom: '10px',
          marginBottom:  '4px',
        }}>
          <span style={{ color: '#e5434b' }}>●</span>
          <span style={{ color: '#f5a623' }}>●</span>
          <span style={{ color: '#2fb87a' }}>●</span>
          <span style={{ marginLeft: '4px' }}>
            {step === STEP_CREDENTIALS ? 'SECURE_AUTH_GATEWAY_NODE' : 'MFA_VERIFICATION_NODE'}
          </span>
        </div>

        {/* ── Title ── */}
        <h3 style={{
          fontFamily:    "'IBM Plex Mono', monospace",
          color:         '#e8eaf0',
          margin:        '0 0 4px 0',
          fontSize:      '16px',
          letterSpacing: '-0.5px',
        }}>
          {step === STEP_CREDENTIALS ? 'AUTHENTICATE IDENTITY MATRIX' : 'MFA VERIFICATION REQUIRED'}
        </h3>

        {/* ── MFA context message ── */}
        {step === STEP_MFA && (
          <p style={{
            fontFamily: "'IBM Plex Mono', monospace",
            fontSize:   '12px',
            color:      '#8b90a8',
            margin:     '0',
            lineHeight: '1.6',
          }}>
            Enter the 6-digit code from your authenticator app.
          </p>
        )}

        {/* ── Error display ── */}
        {error && (
          <div style={{
            background:  'rgba(229,67,75,0.1)',
            border:      '1px solid #e5434b',
            color:       '#e5434b',
            padding:     '10px',
            fontSize:    '13px',
            fontFamily:  "'IBM Plex Mono', monospace",
            borderRadius:'2px',
          }}>
            ❌ {error}
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            STEP 1 — Username + Password
           ══════════════════════════════════════════════════════════════════════ */}
        {step === STEP_CREDENTIALS && (
          <form onSubmit={handleCredentialsSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={labelStyle}>USERNAME</label>
              <input
                type="text"
                value={usernameInput}
                onChange={e => setUsernameInput(e.target.value)}
                required
                placeholder="username"
                autoComplete="username"
                autoFocus
                style={inputStyle}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={labelStyle}>PASSWORD</label>
              <input
                type="password"
                value={passwordInput}
                onChange={e => setPasswordInput(e.target.value)}
                required
                placeholder="••••••••"
                autoComplete="current-password"
                style={inputStyle}
              /> 
            </div>

            <SubmitButton isLoading={isLoading} label="SIGN IN" loadingLabel="AUTHENTICATING..." />

            {/* ── Forgot password link ── */}
            <div style={{ textAlign: 'center' }}>
              <Link
                to="/forgot-password"
                style={{
                  fontFamily:     "'IBM Plex Mono', monospace",
                  fontSize:       '11px',
                  color:          '#8b90a8',
                  textDecoration: 'none',
                  letterSpacing:  '0.3px',
                }}
                onMouseEnter={e => e.target.style.color = '#e8eaf0'}
                onMouseLeave={e => e.target.style.color = '#8b90a8'}
              >
                Forgot password?
              </Link>
            </div>

          </form>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            STEP 2 — MFA TOTP Code
           ══════════════════════════════════════════════════════════════════════ */}
        {step === STEP_MFA && (
          <form onSubmit={handleMfaSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={labelStyle}>AUTHENTICATOR CODE</label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={mfaCode}
                onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                required
                placeholder="000000"
                autoFocus
                autoComplete="one-time-code"
                style={{
                  ...inputStyle,
                  fontSize:      '22px',
                  letterSpacing: '8px',
                  textAlign:     'center',
                }}
              />
            </div>

            <SubmitButton isLoading={isLoading} label="VERIFY CODE" loadingLabel="VERIFYING..." />

            {/* ── Back link ── */}
            <div style={{ textAlign: 'center' }}>
              <button
                type="button"
                onClick={() => { setStep(STEP_CREDENTIALS); setMfaCode(''); clearError(); }}
                style={{
                  background:  'none',
                  border:      'none',
                  fontFamily:  "'IBM Plex Mono', monospace",
                  fontSize:    '11px',
                  color:       '#8b90a8',
                  cursor:      'pointer',
                  letterSpacing: '0.3px',
                }}
                onMouseEnter={e => e.target.style.color = '#e8eaf0'}
                onMouseLeave={e => e.target.style.color = '#8b90a8'}
              >
                ← Back to login
              </button>
            </div>

          </form>
        )}

      </div>
    </div>
  );
}

// ─── Shared submit button ──────────────────────────────────────────────────────
function SubmitButton({ isLoading, label, loadingLabel }) {
  return (
    <button
      type="submit"
      disabled={isLoading}
      style={{
        background:    isLoading ? '#4a5068' : '#252838',
        color:         isLoading ? '#8b90a8' : '#e8eaf0',
        border:        '1px solid #3a3f5c',
        fontFamily:    "'IBM Plex Mono', monospace",
        fontWeight:    '600',
        fontSize:      '12px',
        padding:       '12px',
        cursor:        isLoading ? 'not-allowed' : 'pointer',
        borderRadius:  '2px',
        letterSpacing: '0.5px',
        transition:    'background 0.2s',
        width:         '100%',
      }}
      onMouseEnter={e => { if (!isLoading) e.target.style.background = '#3a3f5c'; }}
      onMouseLeave={e => { if (!isLoading) e.target.style.background = '#252838'; }}
    >
      {isLoading ? loadingLabel : label}
    </button>
  );
}
