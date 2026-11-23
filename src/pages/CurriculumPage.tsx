import { Link, useParams } from 'react-router-dom'
import { CLOUDS, STAGES, STAGE_ORDER } from '@/data/clouds'
import { curriculumStats, topicsByCloud } from '@/data/curriculum'

export function CurriculumPage() {
  const stats = curriculumStats()
  return (
    <div className="shell" style={{ paddingBlock: '2.5rem 4rem' }}>
      <header className="page-head">
        <h1>The curriculum</h1>
        <p>
          Five stages, three clouds, {stats.topics} topics. Read the path straight
          through for the foundations, or jump to the cloud and stage you need.
          Every topic ends with a checklist you can run in your own account.
        </p>
      </header>

      <div className="curriculum">
        {CLOUDS.map((cloud) => {
          const cloudTopics = topicsByCloud(cloud.id)
          return (
            <div
              className="curriculum__col"
              key={cloud.id}
              style={{ ['--cloud-hue' as string]: cloud.hue }}
            >
              <div className="curriculum__head">
                <b>{cloud.name}</b>
                <span>
                  {cloudTopics.length} topic{cloudTopics.length === 1 ? '' : 's'}
                </span>
              </div>
              {cloudTopics.length === 0 ? (
                <div className="curriculum__pending">
                  <p>Not written yet.</p>
                  <span>
                    The {STAGES.length} stages for this cloud are planned and follow
                    the same four-beat structure as the rest of the atlas.
                  </span>
                </div>
              ) : null}
              {STAGE_ORDER.map((stageId) => {
                const stage = STAGES.find((s) => s.id === stageId)!
                const list = cloudTopics.filter((t) => t.stage === stageId)
                if (!list.length) return null
                return (
                  <div key={stageId}>
                    <div className="curriculum__stage">{stage.name}</div>
                    {list.map((t) => (
                      <Link
                        key={t.slug}
                        to={`/topic/${t.slug}`}
                        className="topic-link"
                      >
                        {t.title}
                        <div className="topic-link__meta">
                          {t.duration} · level {t.difficulty}
                        </div>
                      </Link>
                    ))}
                  </div>
                )
              })}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function CloudPage() {
  const { cloudId } = useParams<{ cloudId: string }>()
  const cloud = CLOUDS.find((c) => c.id === cloudId)

  if (!cloud) {
    return (
      <div className="shell" style={{ paddingBlock: '4rem' }}>
        <div className="empty">
          <b>No such cloud</b>
          Try AWS, Azure or GCP from the curriculum.
        </div>
      </div>
    )
  }

  const cloudTopics = topicsByCloud(cloud.id)

  return (
    <div className="shell" style={{ paddingBlock: '2.5rem 4rem' }}>
      <header className="page-head">
        <div className="topic__meta" style={{ marginBottom: '1rem' }}>
          <span className={`tag tag--${cloud.id}`}>{cloud.glyph}</span>
          <span className="tag">{cloud.console}</span>
          <span className="tag">{cloud.cli}</span>
        </div>
        <h1>{cloud.name}</h1>
        <p>{cloud.blurb}</p>
      </header>

      <div className="stage-strip">
        {STAGE_ORDER.map((stageId) => {
          const stage = STAGES.find((s) => s.id === stageId)!
          const list = cloudTopics.filter((t) => t.stage === stageId)
          if (!list.length) return null
          return (
            <div
              className="stage-row"
              key={stageId}
              style={{ ['--cloud-hue' as string]: cloud.hue }}
            >
              <div>
                <div className="stage-row__name">{stage.name}</div>
                <div className="topic-link__meta">
                  {list.length} topics · {stage.outcome}
                </div>
              </div>
              <div>
                {list.map((t) => (
                  <Link
                    key={t.slug}
                    to={`/topic/${t.slug}`}
                    className="topic-link"
                    style={{ padding: '0.3rem 0.5rem' }}
                  >
                    {t.title}
                  </Link>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
