import { useState, useEffect, useRef } from 'react';
import { NavLink, useNavigate, Outlet, useLocation } from 'react-router-dom';
import useAuthStore from '../store/authStore';
import styles from './PortalShell.module.css';

export default function PortalShell({ nav, roleLabel, accentColor, outletContext, navBadges = {} }) {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const sidebarRef = useRef(null);

  // Close sidebar on route change (mobile)
  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  // Close sidebar when clicking outside (mobile)
  useEffect(() => {
    function handleClickOutside(e) {
      if (sidebarOpen && sidebarRef.current && !sidebarRef.current.contains(e.target)) {
        setSidebarOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('touchstart', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('touchstart', handleClickOutside);
    };
  }, [sidebarOpen]);

  async function handleLogout() {
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <div className={styles.root}>
      {/* ── Overlay (mobile only) ─────────────────────────── */}
      {sidebarOpen && (
        <div
          className={styles.overlay}
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* ── Sidebar ──────────────────────────────────────────── */}
      <aside
        ref={sidebarRef}
        className={`${styles.sidebar} ${sidebarOpen ? styles.sidebarOpen : ''}`}
        aria-label="Sidebar navigation"
      >
        {/* Logo */}
        <div className={styles.brand}>
          <span className={styles.brandIcon} style={{ color: accentColor }}>◈</span>
          <div>
            <div className={styles.brandName}>SOC<span style={{ color: accentColor }}>//</span>PLATFORM</div>
            <div className={styles.brandRole}>{roleLabel}</div>
          </div>
          {/* Close button — mobile only */}
          <button
            className={styles.sidebarCloseBtn}
            onClick={() => setSidebarOpen(false)}
            aria-label="Close sidebar"
          >
            ✕
          </button>
        </div>

        {/* Nav */}
        <nav className={styles.nav} aria-label="Portal navigation">
          {nav.map((section, sectionIdx) => (
            <div key={`section-matrix-${section.title || sectionIdx}`} className={styles.navSection}>
              <div className={styles.navSectionTitle}>{section.title}</div>
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `${styles.navItem} ${isActive ? styles.navItemActive : ''}`
                  }
                  style={({ isActive }) =>
                    isActive ? { '--accent': accentColor } : {}
                  }
                >
                  <span className={styles.navIcon}>{item.icon}</span>
                  {item.label}
                  {navBadges[item.to] > 0 && (
                    <span className={styles.navBadge} style={{ background: accentColor }}>
                      {navBadges[item.to] > 99 ? "99+" : navBadges[item.to]}
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* User card */}
        <div className={styles.userCard}>
          <div className={styles.userAvatar} style={{ borderColor: accentColor }}>
            {user?.username?.[0]?.toUpperCase() || '?'}
          </div>
          <div className={styles.userInfo}>
            <div className={styles.userName}>{user?.username}</div>
            <div className={styles.userEmail}>{user?.email}</div>
          </div>
          <button
            className={styles.logoutBtn}
            onClick={handleLogout}
            title="Sign out"
            aria-label="Sign out"
          >
            ⏻
          </button>
        </div>
      </aside>

      {/* ── Main ─────────────────────────────────────────────── */}
      <main className={styles.main}>
        {/* Top bar */}
        <header className={styles.topbar}>
          <div className={styles.topbarLeft}>
            {/* Hamburger — mobile only */}
            <button
              className={styles.hamburger}
              onClick={() => setSidebarOpen(true)}
              aria-label="Open navigation"
              aria-expanded={sidebarOpen}
            >
              <span /><span /><span />
            </button>


          </div>
          <div className={styles.topbarRight}>
            <span className={styles.topbarTime} suppressHydrationWarning>
              {new Date().toLocaleTimeString('en-KE', {
                hour: '2-digit',
                minute: '2-digit',
                timeZoneName: 'short',
                timeZone: 'Africa/Nairobi',
              })}
            </span>
          </div>
        </header>

        {/* Page content */}
        <div className={styles.content}>
          <Outlet context={outletContext} />
        </div>
      </main>
    </div>
  );
}
