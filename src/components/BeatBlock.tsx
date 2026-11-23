import type { ReactNode } from 'react'

const HUES: Record<string, string> = {
  concept: 'var(--concept)',
  attack: 'var(--attack)',
  detect: 'var(--detect)',
  fix: 'var(--fix)',
}

const WASHES: Record<string, string> = {
  concept: 'var(--concept-wash)',
  attack: 'var(--attack-wash)',
  detect: 'var(--detect-wash)',
  fix: 'var(--fix-wash)',
}

/**
 * One beat of the teaching model. The index and the hue are what make the
 * four-beat structure legible at a glance across the whole site.
 */
export function BeatBlock({
  index,
  kind,
  title,
  sub,
  children,
}: {
  index: number | string
  kind: 'concept' | 'attack' | 'detect' | 'fix'
  title: string
  sub?: string
  children: ReactNode
}) {
  return (
    <section
      className="beat-block"
      style={{
        ['--beat-hue' as string]: HUES[kind],
        ['--beat-wash' as string]: WASHES[kind],
      }}
    >
      <header className="beat-block__head">
        <span className="beat-block__index">{index}</span>
        <span className="beat-block__title">{title}</span>
        {sub ? <span className="beat-block__sub">{sub}</span> : null}
      </header>
      <div className="beat-block__body">{children}</div>
    </section>
  )
}
