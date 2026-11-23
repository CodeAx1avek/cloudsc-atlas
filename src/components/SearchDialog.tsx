import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { TOPICS } from '@/data/curriculum'
import type { Topic } from '@/types'

interface IndexEntry {
  topic: Topic
  haystack: string
}

const INDEX: IndexEntry[] = TOPICS.map((topic) => {
  const parts = [
    topic.title,
    topic.summary,
    topic.track,
    topic.cloud,
    topic.stage,
    topic.mentalModel ?? '',
    topic.concept.body,
    topic.concept.keyPoints.join(' '),
    topic.attack.body,
    topic.attack.techniques.map((t) => `${t.name} ${t.what}`).join(' '),
    topic.detect.body,
    topic.detect.signals.map((s) => `${s.signal} ${s.source}`).join(' '),
    topic.fix.body,
    topic.fix.remediations.map((r) => `${r.action} ${r.detail}`).join(' '),
    topic.checklist.map((c) => c.text).join(' '),
  ]
  return { topic, haystack: parts.join(' \n ').toLowerCase() }
})

function score(entry: IndexEntry, query: string): number {
  const q = query.toLowerCase().trim()
  if (!q) return 0
  const title = entry.topic.title.toLowerCase()
  if (title === q) return 100
  if (title.startsWith(q)) return 80
  if (title.includes(q)) return 60
  if (entry.topic.summary.toLowerCase().includes(q)) return 40

  // every whitespace-separated term must appear somewhere
  const terms = q.split(/\s+/)
  if (!terms.every((t) => entry.haystack.includes(t))) return 0

  let s = 20
  for (const term of terms) {
    let from = 0
    let hits = 0
    while (hits < 5) {
      const idx = entry.haystack.indexOf(term, from)
      if (idx === -1) break
      hits++
      from = idx + term.length
    }
    s += hits * 2
  }
  return s
}

export function SearchDialog({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()

  const results = useMemo(() => {
    if (!query.trim()) return []
    return INDEX.map((entry) => ({ entry, s: score(entry, query) }))
      .filter((r) => r.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 12)
      .map((r) => r.entry.topic)
  }, [query])

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  useEffect(() => {
    setActive(0)
  }, [query])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setActive((a) => Math.min(a + 1, results.length - 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setActive((a) => Math.max(a - 1, 0))
      } else if (e.key === 'Enter' && results[active]) {
        e.preventDefault()
        navigate(`/topic/${results[active].slug}`)
        onClose()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [results, active, navigate, onClose])

  return (
    <div
      className="overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="searchbox" role="dialog" aria-label="Search topics">
        <input
          ref={inputRef}
          className="searchbox__input"
          placeholder="Search concepts, techniques, log events, IAM actions…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search query"
        />
        <div className="searchbox__results">
          {results.length === 0 ? (
            <div className="searchbox__empty">
              {query.trim()
                ? 'No topic matches that. Try a service name, a log event, or an IAM action.'
                : 'Start typing to search across every topic.'}
            </div>
          ) : (
            results.map((t, i) => (
              <a
                key={t.slug}
                href={`#/topic/${t.slug}`}
                className={
                  i === active ? 'search-result search-result--active' : 'search-result'
                }
                onClick={(e) => {
                  e.preventDefault()
                  navigate(`/topic/${t.slug}`)
                  onClose()
                }}
              >
                <div className="search-result__top">
                  <span className={`dot dot--${t.cloud}`} />
                  {t.title}
                </div>
                <div className="search-result__summary">{t.summary}</div>
              </a>
            ))
          )}
        </div>
        <div className="searchbox__foot">
          <span>↑ ↓ to move</span>
          <span>↵ to open</span>
          <span>esc to close</span>
        </div>
      </div>
    </div>
  )
}
