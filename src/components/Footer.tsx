import { Link } from 'react-router-dom'
import { CLOUDS } from '@/data/clouds'
import { curriculumStats } from '@/data/curriculum'

export function Footer() {
  const stats = curriculumStats()
  return (
    <footer className="footer">
      <div className="footer__inner">
        <div>
          <strong style={{ color: 'var(--ink)' }}>
            CloudSec Atlas — from cloud fundamentals to red team
          </strong>
          <div style={{ marginTop: '0.3rem' }}>
            {stats.topics} topics · {stats.techniques} techniques ·{' '}
            {stats.signals} detection signals · {stats.checks} verification
            steps
          </div>
        </div>
        <div style={{ display: 'flex', gap: '1.25rem', flexWrap: 'wrap' }}>
          {CLOUDS.map((c) => (
            <Link key={c.id} to={`/cloud/${c.id}`}>
              {c.name}
            </Link>
          ))}
          <Link to="/method">Method</Link>
        </div>
      </div>
    </footer>
  )
}
