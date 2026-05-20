import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import useAuthStore from '../store/authStore';

export default function Login() {
  const { login, user, isLoading, error, clearError } = useAuthStore();
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (clearError) clearError();
  }, []);

  useEffect(() => {
    if (user && !isLoading) {
      // Check if ProtectedRoute passed a historic deep-link destination memory block
      const fromDestination = location.state?.from?.pathname;

      if (fromDestination && fromDestination !== '/login') {
        navigate(fromDestination, { replace: true });
      } else {
        // Fall back to standard role-based root routes if launching from fresh tabs
        if (user.role === 'superadmin') navigate('/admin/dashboard', { replace: true });
        else if (user.role === 'analyst') navigate('/analyst/dashboard', { replace: true });
        else if (user.role === 'client') navigate('/client/events', { replace: true });
      }
    }
  }, [user, isLoading, navigate, location]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await login(usernameInput, passwordInput);
    } catch (err) {
      console.error("Authentication execution failure:", err.message);
    }
  };

  return (
    <div className="login-root" style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      background: '#0a0b0d',
      fontFamily: "'IBM Plex Sans', sans-serif"
    }}>
      <form onSubmit={handleSubmit} style={{
        background: '#0f1115',
        border: '1px solid #252838',
        width: '400px',
        padding: '28px',
        borderRadius: '4px',
        display: 'flex',
        flexDirection: 'column',
        gap: '18px'
      }}>
        {/* Terminal Dot Row Header decoration */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontFamily: "'IBM Plex Mono', monospace",
          fontSize: '11px',
          color: '#4a5068',
          borderBottom: '1px solid #252838',
          paddingBottom: '10px',
          marginBottom: '4px'
        }}>
          <span style={{ color: '#e5434b' }}>●</span>
          <span style={{ color: '#f5a623' }}>●</span>
          <span style={{ color: '#2fb87a' }}>●</span>
          <span style={{ marginLeft: '4px' }}>SECURE_AUTH_GATEWAY_NODE</span>
        </div>
        
        <h3 style={{
          fontFamily: "'IBM Plex Mono', monospace",
          color: '#e8eaf0',
          margin: '0 0 4px 0',
          fontSize: '16px',
          letterSpacing: '-0.5px'
        }}>AUTHENTICATE IDENTITY MATRIX</h3>
        
        {error && (
          <div style={{
            background: 'rgba(229,67,75,0.1)',
            border: '1px solid #e5434b',
            color: '#e5434b',
            padding: '10px',
            fontSize: '13px',
            fontFamily: "'IBM Plex Mono', monospace"
          }}>
            ❌ {error}
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <label style={{
            fontFamily: "'IBM Plex Mono', monospace",
            fontSize: '11px',
            color: '#8b90a8',
            letterSpacing: '0.5px'
          }}>USER PRINCIPAL IDENTIFIER</label>
          <input 
            type="text" 
            value={usernameInput} 
            onChange={e => setUsernameInput(e.target.value)} 
            required 
            placeholder="username" 
            autoComplete="username"
            style={{
              background: '#0a0b0d',
              border: '1px solid #252838',
              color: '#e8eaf0',
              padding: '10px',
              fontFamily: "'IBM Plex Mono', monospace",
              fontSize: '14px',
              borderRadius: '2px',
              outline: 'none'
            }}
          />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <label style={{
            fontFamily: "'IBM Plex Mono', monospace",
            fontSize: '11px',
            color: '#8b90a8',
            letterSpacing: '0.5px'
          }}>CRYPTOGRAPHIC PASSKEY STRING</label>
          <input 
            type="password" 
            value={passwordInput} 
            onChange={e => setPasswordInput(e.target.value)} 
            required 
            placeholder="••••••••" 
            autoComplete="current-password"
            style={{
              background: '#0a0b0d',
              border: '1px solid #252838',
              color: '#e8eaf0',
              padding: '10px',
              fontFamily: "'IBM Plex Mono', monospace",
              fontSize: '14px',
              borderRadius: '2px',
              outline: 'none'
            }}
          />
        </div>

        <button 
          type="submit" 
          disabled={isLoading} 
          style={{
            background: isLoading ? '#4a5068' : '#252838',
            color: isLoading ? '#8b90a8' : '#e8eaf0',
            border: '1px solid #3a3f5c',
            fontFamily: "'IBM Plex Mono', monospace",
            fontWeight: '600',
            fontSize: '12px',
            padding: '12px',
            cursor: isLoading ? 'not-allowed' : 'pointer',
            marginTop: '8px',
            borderRadius: '2px',
            transition: 'background 0.2s'
          }}
          onMouseEnter={(e) => { if(!isLoading) e.target.style.background = '#3a3f5c'; }}
          onMouseLeave={(e) => { if(!isLoading) e.target.style.background = '#252838'; }}
        >
          {isLoading ? 'ESTABLISHING HANDSHAKE...' : 'EXECUTE AUTHORIZATION PROTOCOL'}
        </button>
      </form>
    </div>
  );
}