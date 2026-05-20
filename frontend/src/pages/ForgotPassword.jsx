import { useState } from 'react';
import { Link } from 'react-router-dom';
import useAuthStore from '../store/authStore';
import styles from './Auth.module.css';

export default function ForgotPassword() {
  const { forgotPassword, isLoading } = useAuthStore();
  const [email, setEmail]     = useState('');
  const [sent, setSent]       = useState(false);
  const [error, setError]     = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    try {
      await forgotPassword(email);
      setSent(true);
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
          <span className={styles.dividerLabel}>PASSWORD RECOVERY</span>
          <span className={styles.dividerLine} />
        </div>

        {sent ? (
          <div className={styles.successBox}>
            <div className={styles.successIcon}>✓</div>
            <p className={styles.successTitle}>Recovery link sent</p>
            <p className={styles.successText}>
              If an account exists for <strong>{email}</strong>, a password
              reset link has been sent. Check your inbox.
            </p>
            <Link to="/login" className={styles.backLink}>← Return to login</Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className={styles.form} noValidate>
            <p className={styles.hint}>
              Enter your registered email address to receive a password reset link.
            </p>

            {error && (
              <div className={styles.errorBox} role="alert">
                <span>✕</span> {error}
              </div>
            )}

            <div className={styles.field}>
              <label className={styles.label} htmlFor="email">
                <span className={styles.labelPrefix}>→</span> EMAIL ADDRESS
              </label>
              <input
                id="email"
                className={styles.input}
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={isLoading}
                placeholder="user@organization.com"
                autoFocus
              />
            </div>

            <button
              type="submit"
              className={styles.btn}
              disabled={isLoading || !email}
            >
              {isLoading
                ? <span className={styles.spinner} />
                : <><span>SEND RESET LINK</span><span className={styles.btnArrow}>→</span></>
              }
            </button>

            <div className={styles.links}>
              <Link to="/login" className={styles.link}>← Back to login</Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
