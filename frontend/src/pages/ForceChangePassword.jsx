import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import useAuthStore from '../store/authStore';
import styles from './Auth.module.css';

const ROLE_HOME = { superadmin: '/admin', analyst: '/analyst', client: '/client' };

const RULES = [
  { test: (p) => p.length >= 12,          label: 'At least 12 characters' },
  { test: (p) => /[A-Z]/.test(p),         label: 'Uppercase letter' },
  { test: (p) => /[a-z]/.test(p),         label: 'Lowercase letter' },
  { test: (p) => /[0-9]/.test(p),         label: 'Number' },
  { test: (p) => /[^A-Za-z0-9]/.test(p), label: 'Special character' },
];

export default function ForceChangePassword() {
  const { forceChangePassword, user, isLoading, logout } = useAuthStore();
  const navigate = useNavigate();

  const [password, setPassword] = useState('');
  const [confirm, setConfirm]   = useState('');
  const [error, setError]       = useState('');

  const strong = RULES.every((r) => r.test(password));
  const match  = password === confirm && confirm.length > 0;

  // Note: access control (only users with force_password_change=true can reach
  // this page) is enforced in ProtectedRoute via requireForceChange prop.
  // No extra guard needed here.

  async function handleSubmit(e) {
    e.preventDefault();
    if (!strong || !match) return;
    setError('');
    try {
      await forceChangePassword(password);
      navigate(ROLE_HOME[user?.role] || '/', { replace: true });
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className={styles.root}>
      <div className={styles.grid} aria-hidden />
      <div className={styles.panel}>
        <div className={styles.header}>
          <div className={styles.logo}>
            <span className={styles.logoIcon}>◈</span>
            <span className={styles.logoText}>SOC<span className={styles.logoAccent}>//</span>PLATFORM</span>
          </div>
        </div>

        <div className={styles.divider}>
          <span className={styles.dividerLine} />
          <span className={styles.dividerLabel}>CHANGE REQUIRED</span>
          <span className={styles.dividerLine} />
        </div>

        <div className={styles.warningBox}>
          <span className={styles.warningIcon}>⚠</span>
          <p>
            Your password has been reset by an administrator. You must set a new
            password before proceeding.
          </p>
        </div>

        <form onSubmit={handleSubmit} className={styles.form} noValidate>
          {error && (
            <div className={styles.errorBox} role="alert">
              <span>✕</span> {error}
            </div>
          )}

          <div className={styles.field}>
            <label className={styles.label} htmlFor="password">
              <span className={styles.labelPrefix}>01</span> NEW PASSWORD
            </label>
            <input
              id="password"
              className={styles.input}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={isLoading}
              placeholder="••••••••••••"
              autoFocus
            />
            {password.length > 0 && (
              <div className={styles.rules}>
                {RULES.map((r) => (
                  <div
                    key={r.label}
                    className={`${styles.rule} ${r.test(password) ? styles.rulePassed : ''}`}
                  >
                    <span>{r.test(password) ? '✓' : '·'}</span> {r.label}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="confirm">
              <span className={styles.labelPrefix}>02</span> CONFIRM PASSWORD
            </label>
            <input
              id="confirm"
              className={`${styles.input} ${confirm && !match ? styles.inputError : ''}`}
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              disabled={isLoading}
              placeholder="••••••••••••"
            />
            {confirm && !match && (
              <span className={styles.fieldError}>Passwords do not match</span>
            )}
          </div>

          <button
            type="submit"
            className={styles.btn}
            disabled={isLoading || !strong || !match}
          >
            {isLoading
              ? <span className={styles.spinner} />
              : <><span>SET NEW PASSWORD</span><span className={styles.btnArrow}>→</span></>
            }
          </button>

          <button
            type="button"
            className={styles.backBtn}
            onClick={logout}
            disabled={isLoading}
          >
            Sign out instead
          </button>
        </form>
      </div>
    </div>
  );
}
