import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <div className="shell" style={{ paddingBlock: '5rem' }}>
      <div className="empty">
        <b>That page is not in the atlas</b>
        The topic may not be written yet, or the link may be wrong.
        <div style={{ marginTop: '1.25rem' }}>
          <Link className="btn" to="/curriculum">
            Go to the curriculum
          </Link>
        </div>
      </div>
    </div>
  )
}
