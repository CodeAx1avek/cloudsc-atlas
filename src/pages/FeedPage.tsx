import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { advisories } from '@/data/feed/advisories'
import { TOPIC_BY_SLUG } from '@/data/curriculum'
import { CLOUD_BY_ID } from '@/data/clouds'
import type { Cloud } from '@/types'

type CloudFilter = Cloud | 'all'
type ExploitFilter = 'all' | 'exploited' | 'bulletin'

export function FeedPage() {
  const [cloud, setCloud] = useState<CloudFilter>('all')
  const [kind, setKind] = useState<ExploitFilter>('all')
  const [mappedOnly, setMappedOnly] = useState(false)

  const filtered = useMemo(() => {
    return advisories.filter((a) => {
      if (cloud !== 'all' && a.cloud !== cloud && a.cloud !== 'all') return false
      if (kind === 'exploited' && !a.exploited) return false
      if (kind === 'bulletin' && a.exploited) return false
      if (mappedOnly && a.relatedTopics.length === 0) return false
      return true
    })
  }, [cloud, kind, mappedOnly])

  const exploitedCount = advisories.filter((a) => a.exploited).length

  return (
    <div className="shell" style={{ paddingBlock: '2.5rem 4rem' }}>
      <header className="page-head">
        <h1>Advisories</h1>
        <p>
          A live feed of what is being patched and what is being exploited, pulled
          from the CISA Known Exploited Vulnerabilities catalog and the cloud
          providers' own security bulletins. Entries link to the atlas topic that
          explains the mechanism.
        </p>
        <p className="mono" style={{ color: 'var(--ink-faint)', marginBottom: 0 }}>
          {advisories.length} entries · {exploitedCount} confirmed exploited in
          the wild
        </p>
      </header>

      <div className="feed-toolbar">
        <span className="eyebrow">cloud</span>
        {(['all', 'aws', 'azure', 'gcp'] as CloudFilter[]).map((c) => (
          <button
            key={c}
            type="button"
            className={cloud === c ? 'chip chip--on' : 'chip'}
            onClick={() => setCloud(c)}
          >
            {c === 'all' ? 'All' : CLOUD_BY_ID[c].glyph}
          </button>
        ))}

        <span className="eyebrow" style={{ marginLeft: '1rem' }}>
          source
        </span>
        {(['all', 'exploited', 'bulletin'] as ExploitFilter[]).map((k) => (
          <button
            key={k}
            type="button"
            className={kind === k ? 'chip chip--on' : 'chip'}
            onClick={() => setKind(k)}
          >
            {k === 'all' ? 'Everything' : k === 'exploited' ? 'Exploited' : 'Bulletins'}
          </button>
        ))}

        <button
          type="button"
          className={mappedOnly ? 'chip chip--on' : 'chip'}
          onClick={() => setMappedOnly((v) => !v)}
          style={{ marginLeft: 'auto' }}
        >
          Only with a topic
        </button>
      </div>

      {filtered.length === 0 ? (
        <div className="empty">
          <b>Nothing matches those filters</b>
          Try widening the cloud or the source filter.
        </div>
      ) : (
        <div>
          {filtered.map((a) => (
            <article className="adv" key={a.id}>
              <div
                className={
                  a.exploited ? 'adv__flag adv__flag--exploited' : 'adv__flag'
                }
                aria-hidden="true"
              />
              <div>
                <div className="adv__title">
                  <a href={a.url} target="_blank" rel="noreferrer">
                    {a.title}
                  </a>
                </div>
                <div className="adv__meta">
                  {a.cve ? <span className="tag">{a.cve}</span> : null}
                  <span className={`tag tag--${a.cloud === 'all' ? 'solid' : a.cloud}`}>
                    {a.cloud === 'all' ? 'multi-cloud' : CLOUD_BY_ID[a.cloud].glyph}
                  </span>
                  {a.service ? <span>{a.service}</span> : null}
                  <span>{a.vendor}</span>
                  {a.published ? <span>{a.published.slice(0, 10)}</span> : null}
                  {a.exploited ? (
                    <span className="tag tag--sev-critical">exploited</span>
                  ) : null}
                </div>
                {a.summary ? <p className="adv__summary">{a.summary}</p> : null}
                {a.relatedTopics.length ? (
                  <div
                    className="adv__meta"
                    style={{ marginTop: '0.5rem' }}
                  >
                    <span>related:</span>
                    {a.relatedTopics.map((slug) => {
                      const t = TOPIC_BY_SLUG[slug]
                      if (!t) return null
                      return (
                        <Link key={slug} to={`/topic/${slug}`} className="tag">
                          {t.title}
                        </Link>
                      )
                    })}
                  </div>
                ) : null}
              </div>
              <div className="adv__score">
                {a.cvss ? a.cvss.toFixed(1) : a.exploited ? 'KEV' : '—'}
              </div>
            </article>
          ))}
        </div>
      )}

      <p className="mono" style={{ color: 'var(--ink-faint)', marginTop: '2rem' }}>
        Refreshed by <code>npm run ingest</code>. Sources: CISA KEV catalog, AWS
        Security Bulletins, Microsoft Security Blog, Google Cloud Blog.
      </p>
    </div>
  )
}
