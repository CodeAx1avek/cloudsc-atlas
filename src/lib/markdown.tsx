import type { ReactNode } from 'react'

/**
 * A deliberately small markdown renderer.
 *
 * The content model only needs paragraphs, bullet lists, fenced code,
 * blockquotes, bold and inline code — so the site carries no markdown
 * dependency and the output cannot drift between environments.
 */

type Block =
  | { kind: 'p'; text: string }
  | { kind: 'ul'; items: string[] }
  | { kind: 'code'; lang?: string; text: string }
  | { kind: 'quote'; text: string }

function parseBlocks(src: string): Block[] {
  const lines = src.replace(/\r\n/g, '\n').split('\n')
  const blocks: Block[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    if (!line.trim()) {
      i++
      continue
    }

    // fenced code
    if (line.trim().startsWith('```')) {
      const lang = line.trim().slice(3).trim()
      const buf: string[] = []
      i++
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        buf.push(lines[i])
        i++
      }
      i++ // closing fence
      blocks.push({ kind: 'code', lang: lang || undefined, text: buf.join('\n') })
      continue
    }

    // bullet list
    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, ''))
        i++
      }
      blocks.push({ kind: 'ul', items })
      continue
    }

    // blockquote
    if (line.trim().startsWith('>')) {
      const buf: string[] = []
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        buf.push(lines[i].replace(/^\s*>\s?/, ''))
        i++
      }
      blocks.push({ kind: 'quote', text: buf.join(' ').trim() })
      continue
    }

    // paragraph
    const buf: string[] = []
    while (
      i < lines.length &&
      lines[i].trim() &&
      !lines[i].trim().startsWith('```') &&
      !/^\s*[-*]\s+/.test(lines[i]) &&
      !lines[i].trim().startsWith('>')
    ) {
      buf.push(lines[i])
      i++
    }
    blocks.push({ kind: 'p', text: buf.join(' ') })
  }

  return blocks
}

/** Inline formatting: `code` and **bold**. */
function inline(text: string, keyPrefix: string): ReactNode[] {
  const out: ReactNode[] = []
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*)/g
  let last = 0
  let match: RegExpExecArray | null
  let n = 0

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) out.push(text.slice(last, match.index))
    const token = match[0]
    if (token.startsWith('`')) {
      out.push(<code key={`${keyPrefix}-c${n++}`}>{token.slice(1, -1)}</code>)
    } else {
      out.push(<strong key={`${keyPrefix}-b${n++}`}>{token.slice(2, -2)}</strong>)
    }
    last = match.index + token.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

export function Markdown({ source }: { source: string }) {
  const blocks = parseBlocks(source)
  return (
    <>
      {blocks.map((b, idx) => {
        const key = `b${idx}`
        if (b.kind === 'p') {
          return <p key={key}>{inline(b.text, key)}</p>
        }
        if (b.kind === 'ul') {
          return (
            <ul key={key}>
              {b.items.map((item, j) => (
                <li key={`${key}-${j}`}>{inline(item, `${key}-${j}`)}</li>
              ))}
            </ul>
          )
        }
        if (b.kind === 'quote') {
          return (
            <blockquote key={key}>
              <p>{inline(b.text, key)}</p>
            </blockquote>
          )
        }
        return (
          <div className="code" key={key}>
            {b.lang ? <span className="code__label">{b.lang}</span> : null}
            <pre>
              <code>{b.text}</code>
            </pre>
          </div>
        )
      })}
    </>
  )
}
