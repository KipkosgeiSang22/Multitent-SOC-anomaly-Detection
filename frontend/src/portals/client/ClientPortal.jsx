import { useState, useEffect } from "react";
import PortalShell from "../../components/PortalShell";
import api from "../../api/axios";

const CLIENT_NAV = [
  {
    title: "MONITORING",
    items: [
      { label: "Events",    to: "events",    icon: "◈" },
      { label: "Anomalies", to: "anomalies", icon: "⚠" },
      { label: "Downloads", to: "downloads", icon: "⬇" }
    ]
  },
  {
    title: "ACCOUNT",
    items: [
      { label: "Settings", to: "settings", icon: "⚙" }
    ]
  }
];

export default function ClientPortal() {
  const [navBadges, setNavBadges] = useState({});

  async function fetchUnreadReplies() {
    try {
      const res = await api.get("/client/issues/unread-replies");
      const count = res.data?.unread_replies ?? 0;
      setNavBadges(count > 0 ? { events: count } : {});
    } catch {
      // Silently fail — badge is non-critical
    }
  }

  useEffect(() => {
    fetchUnreadReplies();
    const interval = setInterval(fetchUnreadReplies, 60_000);
    // Instant refresh when a thread is opened and replies are marked seen
    window.addEventListener("soc:replies-seen", fetchUnreadReplies);
    return () => {
      clearInterval(interval);
      window.removeEventListener("soc:replies-seen", fetchUnreadReplies);
    };
  }, []);

  return (
    <PortalShell
      nav={CLIENT_NAV}
      accentColor="var(--blue-accent, #0070f3)"
      roleLabel="Client Portal"
      navBadges={navBadges}
    />
  );
}