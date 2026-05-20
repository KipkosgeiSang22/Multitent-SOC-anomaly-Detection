import { useState, useEffect } from "react";
import api from "../../../api/axios";
import styles from "./ThreatIntelPage.module.css";

const SEVERITY_COLOR = {
  critical: styles.sevCritical,
  high: styles.sevHigh,
  medium: styles.sevMedium,
  low: styles.sevLow,
};

export default function ThreatIntelPage() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const res = await api.get("/analyst/threat-intel");
        setItems(res.data ?? []);
      } catch {
        setError("Failed to load threat intelligence.");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const filtered = items.filter(i =>
    !search ||
    i.title?.toLowerCase().includes(search.toLowerCase()) ||
    i.source?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>THREAT INTELLIGENCE</h1>
        <input
          className={styles.search}
          placeholder="Search title or source…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {error && <p className={styles.errorMsg}>{error}</p>}

      {loading ? <p className={styles.loading}>Loading…</p> : filtered.length === 0 ? (
        <p className={styles.empty}>{search ? "No results match your search." : "No threat intelligence data yet. Run threat_intel.py to populate."}</p>
      ) : (
        <div className={styles.list}>
          {filtered.map(item => (
            <div key={item.id} className={styles.card} onClick={() => setSelected(item)}>
              <div className={styles.cardTop}>
                <span className={styles.source}>{item.source}</span>
                {item.severity && (
                  <span className={`${styles.sev} ${SEVERITY_COLOR[item.severity] || styles.sevLow}`}>
                    {item.severity}
                  </span>
                )}
                <span className={styles.pubTime}>
                  {item.published_at ? new Date(item.published_at).toLocaleDateString() : "—"}
                </span>
              </div>
              <p className={styles.cardTitle}>{item.title}</p>
              {item.summary && <p className={styles.cardSummary}>{item.summary}</p>}
              <div className={styles.cardTags}>
                {item.attack_types?.slice(0, 3).map(t => (
                  <span key={t} className={styles.tag}>{t}</span>
                ))}
                {item.affected_sectors?.slice(0, 2).map(s => (
                  <span key={s} className={`${styles.tag} ${styles.tagSector}`}>{s}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {selected && (
        <div className={styles.modalBackdrop} onClick={() => setSelected(null)}>
          <div className={styles.modal} onClick={e => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <span className={styles.modalTitle}>{selected.source}</span>
              <button className={styles.modalClose} onClick={() => setSelected(null)}>✕</button>
            </div>
            <p className={styles.modalItemTitle}>{selected.title}</p>
            {selected.summary && <p className={styles.modalSummary}>{selected.summary}</p>}
            <div className={styles.modalMeta}>
              {selected.severity && <span className={`${styles.sev} ${SEVERITY_COLOR[selected.severity] || styles.sevLow}`}>{selected.severity}</span>}
              {selected.published_at && <span className={styles.metaItem}>Published: {new Date(selected.published_at).toLocaleString()}</span>}
              {selected.url && (
                <a className={styles.link} href={selected.url} target="_blank" rel="noreferrer">
                  View source ↗
                </a>
              )}
            </div>
            {selected.iocs && Object.keys(selected.iocs).length > 0 && (
              <div className={styles.iocBlock}>
                <p className={styles.sectionLabel}>INDICATORS OF COMPROMISE</p>
                <pre className={styles.iocJson}>{JSON.stringify(selected.iocs, null, 2)}</pre>
              </div>
            )}
            {selected.attack_types?.length > 0 && (
              <div className={styles.tagsBlock}>
                <p className={styles.sectionLabel}>ATTACK TYPES</p>
                <div className={styles.cardTags}>
                  {selected.attack_types.map(t => <span key={t} className={styles.tag}>{t}</span>)}
                </div>
              </div>
            )}
            {selected.affected_sectors?.length > 0 && (
              <div className={styles.tagsBlock}>
                <p className={styles.sectionLabel}>AFFECTED SECTORS</p>
                <div className={styles.cardTags}>
                  {selected.affected_sectors.map(s => <span key={s} className={`${styles.tag} ${styles.tagSector}`}>{s}</span>)}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
