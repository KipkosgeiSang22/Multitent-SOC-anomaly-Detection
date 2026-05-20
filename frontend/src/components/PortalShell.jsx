import { NavLink, useNavigate, Outlet } from 'react-router-dom';
import useAuthStore from '../store/authStore';
import styles from './PortalShell.module.css';

export default function PortalShell({ nav, roleLabel, accentColor, outletContext, navBadges = {} }) {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <div className={styles.root}>
      {/* ── Sidebar ──────────────────────────────────────────── */}
      <aside className={styles.sidebar}>
        {/* Logo */}
        <div className={styles.brand}>
          <span className={styles.brandIcon} style={{ color: accentColor }}>◈</span>
          <div>
            <div className={styles.brandName}>SOC<span style={{ color: accentColor }}>//</span>PLATFORM</div>
            <div className={styles.brandRole}>{roleLabel}</div>
          </div>
        </div>

        {/* Nav */}
        <nav className={styles.nav} aria-label="Portal navigation">
          {nav.map((section, sectionIdx) => (
            /* 🔑 Unique identification trace added safely to section nodes */
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
            <div className={styles.statusBadge} style={{ '--accent': accentColor }}>
              <span className={styles.statusDot} />
              LIVE
            </div>
          </div>
          <div className={styles.topbarRight}>
            <span className={styles.topbarTime} suppressHydrationWarning>
              {new Date().toLocaleTimeString('en-KE', {
                hour: '2-digit',
                minute: '2-digit',
                timeZoneName: 'short',
                timeZone: 'Africa/Nairobi',
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