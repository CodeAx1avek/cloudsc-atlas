import { NavLink, Link } from 'react-router-dom'
import { Search } from 'lucide-react'

const LINKS = [
  { to: '/curriculum', label: 'Curriculum' },
  { to: '/advisories', label: 'Advisories' },
  { to: '/method', label: 'Method' },
]

export function Nav({ onOpenSearch }: { onOpenSearch: () => void }) {
  return (
    <header className="nav">
      <div className="nav__inner">
        <Link to="/" className="brand">
          <BrandMark />
          <span className="brand__word">
            CloudSec <span>Atlas</span>
          </span>
        </Link>

        <nav className="nav__links">
          {LINKS.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              className={({ isActive }) =>
                isActive ? 'nav__link nav__link--active' : 'nav__link'
              }
            >
              {l.label}
            </NavLink>
          ))}
          <button
            type="button"
            className="nav__search"
            onClick={onOpenSearch}
            aria-label="Search topics"
          >
            <Search size={13} strokeWidth={2.2} />
            <span>Search</span>
            <span className="nav__key">/</span>
          </button>
        </nav>
      </div>
    </header>
  )
}

function BrandMark() {
  return (
    <svg
      className="brand__mark"
      viewBox="0 0 32 32"
      aria-hidden="true"
      focusable="false"
    >
      <rect width="32" height="32" rx="6" fill="#12161c" />
      {/* an ascending attack path: three nodes joined by two segments */}
      <path
        d="M6 24 L14 16 L20 20 L26 8"
        fill="none"
        stroke="#c72f2f"
        strokeWidth="2.2"
        strokeLinecap="square"
      />
      <circle cx="6" cy="24" r="2.6" fill="#eceef1" />
      <circle cx="14" cy="16" r="2.6" fill="#eceef1" />
      <circle cx="20" cy="20" r="2.6" fill="#eceef1" />
      <circle cx="26" cy="8" r="3.2" fill="#c72f2f" />
    </svg>
  )
}
