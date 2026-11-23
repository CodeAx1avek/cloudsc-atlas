import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { CLOUDS, STAGES } from '@/data/clouds'
import { curriculumStats, orderedTopics, topicsByCloud } from '@/data/curriculum'

const BEATS = [
  {
    kind: 'concept',
    name: 'Concept',
    text: 'What the mechanism is and why the platform built it this way. A model you can reuse, not a definition to memorise.',
  },
  {
    kind: 'attack',
    name: 'Attack',
    text: 'How it gets abused, with the commands that work and the blast radius of each. Ordered quiet to loud.',
  },
  {
    kind: 'detect',
    name: 'Detect',
    text: 'The signal in the audit log, as a query you can paste. Escalation shows up in the sequence, not the event.',
  },
  {
    kind: 'fix',
    name: 'Fix',
    text: 'What to change, by priority, with the policy or config that closes it. Plus a checklist to verify in your own account.',
  },
]

const HUES: Record<string, string> = {
  concept: 'var(--concept)',
  attack: 'var(--attack)',
  detect: 'var(--detect)',
  fix: 'var(--fix)',
}

export function HomePage() {
  const stats = curriculumStats()
  const ordered = orderedTopics()

  return (
    <>
      <section className="hero">
        <div className="hero__grid" />
        <div className="hero__inner">
          <h1 className="hero__title">
            From cloud fundamentals
            <br />
            to <em>red team cloud.</em>
          </h1>
          <p className="hero__lede">
            A structured path through AWS, Azure and GCP. Every concept taught the
            same four times over — what it is, how it is abused, how you catch it,
            and what you change.
          </p>
          <div className="hero__actions">
            <Link className="btn" to="/curriculum">
              Start the curriculum <ArrowRight size={15} />
            </Link>
            <Link className="btn btn--ghost" to="/method">
              How the method works
            </Link>
          </div>

          <div className="hero__stats">
            <div className="hero__stat">
              <b>{stats.topics}</b>
              <span>topics</span>
            </div>
            <div className="hero__stat">
              <b>{stats.techniques}</b>
              <span>techniques</span>
            </div>
            <div className="hero__stat">
              <b>{stats.signals}</b>
              <span>detection signals</span>
            </div>
            <div className="hero__stat">
              <b>{stats.checks}</b>
              <span>verification steps</span>
            </div>
          </div>
        </div>
      </section>

      <section className="shell section">
        <div className="section__head">
          <h2 className="section__title">Every topic, the same four times</h2>
          <span className="section__note">concept → attack → detect → fix</span>
        </div>
        <div className="beats">
          {BEATS.map((b) => (
            <div className="beat" key={b.kind} style={{ ['--beat-hue' as string]: HUES[b.kind] }}>
              <div className="beat__name">{b.name}</div>
              <p className="beat__text">{b.text}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="shell section">
        <div className="section__head">
          <h2 className="section__title">The path</h2>
          <span className="section__note">stage by stage</span>
        </div>

        <div className="pathmap">
          {STAGES.map((stage) => {
            const inStage = ordered.filter((t) => t.stage === stage.id)
            return (
              <div className="pathmap__row" key={stage.id}>
                <div className="pathmap__label">
                  <b>{stage.name}</b>
                  <span>{inStage.length} topics</span>
                </div>
                <div className="pathmap__track">
                  {inStage.map((t, i) => (
                    <span key={t.slug} style={{ display: 'contents' }}>
                      {i > 0 ? <span className="pathmap__arrow">→</span> : null}
                      <Link
                        to={`/topic/${t.slug}`}
                        className="pathnode"
                        style={{ ['--node-hue' as string]: `var(--${t.cloud})` }}
                      >
                        <span className="pathnode__cloud" />
                        {t.title}
                      </Link>
                    </span>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      </section>

      <section className="shell section">
        <div className="section__head">
          <h2 className="section__title">Three clouds, one model</h2>
          <span className="section__note">the perimeter moves — the pattern does not</span>
        </div>
        <div className="cloud-grid">
          {CLOUDS.map((c) => {
            const count = topicsByCloud(c.id).length
            return (
              <Link
                key={c.id}
                to={`/cloud/${c.id}`}
                className="cloud-card"
                style={{ ['--cloud-hue' as string]: c.hue }}
              >
                <div className="cloud-card__name">{c.name}</div>
                <p className="cloud-card__blurb">{c.blurb}</p>
                <div className="cloud-card__facts">
                  <div>
                    <span>identity</span>
                    <b>{c.identity}</b>
                  </div>
                  <div>
                    <span>audit log</span>
                    <b>{c.auditLog}</b>
                  </div>
                  <div>
                    <span>topics</span>
                    <b>{count}</b>
                  </div>
                </div>
              </Link>
            )
          })}
        </div>
      </section>

      <section className="shell section">
        <div className="section__head">
          <h2 className="section__title">What you should be able to do</h2>
          <span className="section__note">one outcome per stage</span>
        </div>
        <div className="stage-strip">
          {STAGES.map((s) => (
            <div className="stage-row" key={s.id}>
              <div className="stage-row__name">{s.name}</div>
              <p className="stage-row__outcome">{s.outcome}</p>
            </div>
          ))}
        </div>
      </section>
    </>
  )
}
