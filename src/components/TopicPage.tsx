import { Link, useLocation } from 'react-router-dom'
import { getTopic, TOPIC_BY_SLUG } from '@/data/curriculum'
import { CLOUD_BY_ID, STAGE_BY_ID } from '@/data/clouds'
import { Markdown } from '@/lib/markdown'
import { BeatBlock } from '@/components/BeatBlock'
import { NotFoundPage } from '@/pages/NotFoundPage'
import type { Topic } from '@/types'

export function TopicPage() {
  const location = useLocation()

  // The route is /topic/* because slugs contain slashes of their own
  // (aws/redteam/iam-privilege-escalation), so the whole remaining path
  // is the slug.
  const slug = decodeURIComponent(
    location.pathname.replace(/^.*#\/topic\//, '').replace(/^\/topic\//, ''),
  )
  const topic = slug ? getTopic(slug) : undefined

  if (!topic) return <NotFoundPage />

  const cloud = CLOUD_BY_ID[topic.cloud]
  const stage = STAGE_BY_ID[topic.stage]

  const prerequisites = topic.prerequisites
    .map((s) => TOPIC_BY_SLUG[s])
    .filter(Boolean) as Topic[]
  const unlocks = topic.enables
    .map((s) => TOPIC_BY_SLUG[s])
    .filter(Boolean) as Topic[]

  return (
    <div className="shell" style={{ paddingBlock: '2.5rem 4rem' }}>
      <article>
        <header className="topic__header">
          <div className="topic__crumbs">
            <Link to="/">Atlas</Link>
            <span>/</span>
            <Link to={`/cloud/${cloud.id}`}>{cloud.name}</Link>
            <span>/</span>
            <span>{stage.name}</span>
            <span>/</span>
            <span>{topic.track}</span>
          </div>

          <h1 className="topic__title">{topic.title}</h1>
          <p className="topic__summary">{topic.summary}</p>

          <div className="topic__meta">
            <span className={`tag tag--${topic.cloud}`}>{cloud.glyph}</span>
            <span className="tag">{stage.name}</span>
            <span className="tag">{topic.track}</span>
            <span className="tag">{topic.duration}</span>
            <span className="tag">Level {topic.difficulty}</span>
          </div>
        </header>

        <div className="topic__body">
          {topic.mentalModel ? (
            <div className="model">
              <div className="model__label">Mental model</div>
              <p className="model__text">{topic.mentalModel}</p>
            </div>
          ) : null}

          <BeatBlock index={1} kind="concept" title="Concept" sub="What it is and why it exists">
            <Markdown source={topic.concept.body} />
            {topic.concept.keyPoints.length ? (
              <>
                <h4 style={{ marginBottom: 0 }}>Worth knowing by heart</h4>
                <ul className="keypoints">
                  {topic.concept.keyPoints.map((k) => (
                    <li key={k}>{k}</li>
                  ))}
                </ul>
              </>
            ) : null}
            {topic.concept.misconceptions?.length ? (
              <div className="myths">
                {topic.concept.misconceptions.map((m) => (
                  <div className="myth" key={m.claim}>
                    <div className="myth__claim">
                      <b>Not true</b>
                      <span>{m.claim}</span>
                    </div>
                    <div className="myth__truth">
                      <b>In fact</b> {m.truth}
                    </div>
                  </div>
                ))}
              </div>
            ) : null}
          </BeatBlock>

          <BeatBlock index={2} kind="attack" title="Attack" sub="How it gets abused">
            <Markdown source={topic.attack.body} />
            {topic.attack.techniques.map((t) => (
              <div className="tech" key={t.name}>
                <div className="tech__head">
                  <span className="tech__name">{t.name}</span>
                  <span className="tech__what">{t.what}</span>
                </div>
                {t.steps?.length ? (
                  <ol className="tech__steps">
                    {t.steps.map((s, i) => (
                      <li key={i}>
                        <Markdown source={s} />
                      </li>
                    ))}
                  </ol>
                ) : null}
                {t.command ? (
                  <div className="code">
                    <span className="code__label">shell</span>
                    <pre>
                      <code>{t.command}</code>
                    </pre>
                  </div>
                ) : null}
                <div className="tech__impact">
                  <b>Impact</b> — {t.impact}
                </div>
              </div>
            ))}
            {topic.attack.cases?.length ? (
              <>
                <h4 style={{ marginTop: '2rem', marginBottom: 0 }}>Seen in the wild</h4>
                <div className="cases">
                  {topic.attack.cases.map((c) => (
                    <div className="case" key={c.title}>
                      <div className="case__title">
                        {c.url ? (
                          <a href={c.url} target="_blank" rel="noreferrer">
                            {c.title}
                          </a>
                        ) : (
                          c.title
                        )}
                      </div>
                      <div className="case__source">
                        {c.source}
                        {c.year ? ` · ${c.year}` : ''}
                      </div>
                      <p className="case__impact">{c.impact}</p>
                    </div>
                  ))}
                </div>
              </>
            ) : null}
          </BeatBlock>

          <BeatBlock index={3} kind="detect" title="Detect" sub="What the signal looks like">
            <Markdown source={topic.detect.body} />
            <div className="signals" style={{ marginTop: '1.25rem' }}>
              {topic.detect.signals.map((s) => (
                <div className="signal" key={s.signal}>
                  <div className="signal__top">
                    <span className="signal__name">{s.signal}</span>
                    <span className="signal__source">{s.source}</span>
                  </div>
                  {s.query ? (
                    <div className="code">
                      <span className="code__label">query</span>
                      <pre>
                        <code>{s.query}</code>
                      </pre>
                    </div>
                  ) : null}
                  {s.note ? <p className="signal__note">{s.note}</p> : null}
                </div>
              ))}
            </div>
            {topic.detect.posture?.length ? (
              <>
                <h4 style={{ marginTop: '2rem', marginBottom: 0 }}>
                  Guardrails that reduce the blast radius
                </h4>
                <ul className="keypoints">
                  {topic.detect.posture.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              </>
            ) : null}
          </BeatBlock>

          <BeatBlock index={4} kind="fix" title="Fix" sub="What to change">
            <Markdown source={topic.fix.body} />
            <div className="fixes" style={{ marginTop: '1.25rem' }}>
              {topic.fix.remediations.map((r) => (
                <div className="fix-item" key={r.action}>
                  <div className="fix-item__head">
                    <span className={`tag tag--sev-${r.priority}`}>{r.priority}</span>
                    <span className="fix-item__action">{r.action}</span>
                  </div>
                  <p className="fix-item__detail">{r.detail}</p>
                  {r.snippet ? (
                    <div className="code">
                      <span className="code__label">
                        {r.snippetLang ?? 'config'}
                      </span>
                      <pre>
                        <code>{r.snippet}</code>
                      </pre>
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </BeatBlock>

          {topic.checklist.length ? (
            <section className="beat-block" style={{ ['--beat-hue' as string]: 'var(--ink)' }}>
              <div className="beat-block__head">
                <span className="beat-block__index">✓</span>
                <span className="beat-block__title">Verify it yourself</span>
                <span className="beat-block__sub">
                  {topic.checklist.length} steps · run in your own account
                </span>
              </div>
              <div className="beat-block__body">
                <ol className="checklist">
                  {topic.checklist.map((c) => (
                    <li key={c.id}>
                      <div>
                        <div className="checklist__text">{c.text}</div>
                        {c.command ? (
                          <div className="code">
                            <span className="code__label">shell</span>
                            <pre>
                              <code>{c.command}</code>
                            </pre>
                          </div>
                        ) : null}
                        {c.expected ? (
                          <div className="checklist__expected">
                            <strong>Expected:</strong> {c.expected}
                          </div>
                        ) : null}
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            </section>
          ) : null}
        </div>
      </article>

      {(prerequisites.length || unlocks.length) && (
        <nav className="prov-next">
          {prerequisites.length ? (
            <div>
              <div className="prov-next__title">Read before this</div>
              <div className="prov-cards">
                {prerequisites.map((p) => (
                  <Link
                    key={p.slug}
                    to={`/topic/${p.slug}`}
                    className="prov-card"
                    style={{ ['--cloud-hue' as string]: `var(--${p.cloud})` }}
                  >
                    <div className="prov-card__label">
                      {CLOUD_BY_ID[p.cloud].glyph} · {STAGE_BY_ID[p.stage].name}
                    </div>
                    <div className="prov-card__title">{p.title}</div>
                  </Link>
                ))}
              </div>
            </div>
          ) : null}

          {unlocks.length ? (
            <div style={{ marginTop: '1.5rem' }}>
              <div className="prov-next__title">This unlocks</div>
              <div className="prov-cards">
                {unlocks.map((p) => (
                  <Link
                    key={p.slug}
                    to={`/topic/${p.slug}`}
                    className="prov-card"
                    style={{ ['--cloud-hue' as string]: `var(--${p.cloud})` }}
                  >
                    <div className="prov-card__label">
                      {CLOUD_BY_ID[p.cloud].glyph} · {STAGE_BY_ID[p.stage].name}
                    </div>
                    <div className="prov-card__title">{p.title}</div>
                  </Link>
                ))}
              </div>
            </div>
          ) : null}
        </nav>
      )}

      {topic.references?.length ? (
        <section className="prose" style={{ marginTop: '3rem' }}>
          <h2>References</h2>
          <ul>
            {topic.references.map((r) => (
              <li key={r.url}>
                <a href={r.url} target="_blank" rel="noreferrer">
                  {r.label}
                </a>
              </li>
            ))}
          </ul>
          <p className="mono" style={{ color: 'var(--ink-faint)' }}>
            Last reviewed {topic.updated}
          </p>
        </section>
      ) : null}
    </div>
  )
}
