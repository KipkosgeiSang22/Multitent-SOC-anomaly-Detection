import styles from './Placeholder.module.css';

export default function Placeholder({ title, description, session }) {
  return (
    <div className={styles.root}>
      <div className={styles.badge}>SESSION {session}</div>
      <h1 className={styles.title}>{title}</h1>
      {description && <p className={styles.desc}>{description}</p>}
      <div className={styles.grid}>
        {[...Array(6)].map((_, i) => (
          <div key={i} className={styles.block} style={{ animationDelay: `${i * 0.08}s` }} />
        ))}
      </div>
    </div>
  );
}
