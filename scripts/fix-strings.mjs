#!/usr/bin/env node
/**
 * Repair escaping in the authored topic files.
 *
 * The corpus has exactly three defects, all from prose being written into
 * JavaScript string literals:
 *
 *   1. A bare backtick inside a template literal's text. It closes the
 *      template early.
 *   2. A bare apostrophe inside a single-quoted string. It closes the
 *      string early.
 *   3. A template literal whose closing backtick was omitted. It then runs
 *      on until the next unrelated backtick in the file.
 *
 * The scan is linear rather than regex-based, because a regex cannot tell
 * whether a `key:` it matched is a real property or a phrase inside prose
 * — and matching the latter is how a repair ends up escaping a delimiter
 * it should have left alone.
 *
 * The scan tracks three things:
 *   - whether we are in code, a single-quoted string, or a template
 *   - for a template, where its closing backtick is (the one followed by a
 *     structural terminator: comma, closing bracket, or end of line)
 *   - for a single-quoted string, where its closing quote is (the one
 *     followed by a structural terminator)
 *
 * Run with --check to report without writing.
 */
import { readFile, writeFile, readdir } from 'node:fs/promises'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const TOPICS = resolve(__dirname, '../src/data/topics')
const checkOnly = process.argv.includes('--check')

/** Structural characters that can follow the end of a string literal. */
const TERMINATORS = new Set([',', ']', '}', ':', ';', '\n', '\r'])

function isTerminator(src, idx) {
  let j = idx + 1
  while (j < src.length && (src[j] === ' ' || src[j] === '\t')) j++
  if (j >= src.length) return true
  return TERMINATORS.has(src[j])
}

/**
 * Find the closing delimiter of a value that opened at `open`.
 *
 * A single-quoted string cannot span a newline — if the closing quote is
 * not on the same line, the value is unterminated. Enforcing that matters:
 * without it, a stray apostrophe in prose makes the scan run on for
 * hundreds of lines and swallow every template literal in between.
 *
 * A template literal may span lines, but not past the next property at the
 * same indentation. That boundary is what catches a multi-line `body:`
 * whose closing backtick was omitted: without it, the template swallows
 * every following property until it finds some unrelated backtick, and the
 * repair then corrupts that unrelated backtick instead.
 *
 * Returns the index of the closing delimiter, or -1 if the value never
 * closes.
 */
function findEnd(src, open, delim) {
  const openLineStart = src.lastIndexOf('\n', open) + 1
  const openIndent = src.slice(openLineStart, open).match(/^[ \t]*/)[0]

  let i = open + 1
  const n = src.length
  while (i < n) {
    const ch = src[i]
    if (ch === '\\') {
      i += 2
      continue
    }
    if (ch === '\n') {
      if (delim === "'") return -1

      // A new line that starts a property at the same indentation ends the
      // template. The template's closing backtick must have come before
      // it, so if we get here without finding one, it is missing.
      const nextLineStart = i + 1
      let nextLineEnd = src.indexOf('\n', nextLineStart)
      if (nextLineEnd === -1) nextLineEnd = n
      const nextLine = src.slice(nextLineStart, nextLineEnd)
      const nextIndent = nextLine.match(/^[ \t]*/)[0]
      if (
        nextIndent === openIndent &&
        /^[ \t]*[A-Za-z_][A-Za-z0-9_]*:/.test(nextLine)
      ) {
        return -1
      }
    }
    if (ch === delim && isTerminator(src, i)) return i
    i++
  }
  return -1
}

/**
 * Escape the characters that are illegal in the given literal, inside the
 * literal's text.
 */
function escapeInner(inner, delim) {
  let out = ''
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]
    if (ch === '\\' && i + 1 < inner.length) {
      const next = inner[i + 1]
      // A backtick escaped inside a single-quoted string is unnecessary —
      // the author escaped it by reflex. Normalise it back to a bare
      // backtick, which is legal there.
      if (delim === "'" && next === '`') {
        out += '`'
        i++
        continue
      }
      out += ch + next
      i++
      continue
    }
    if (ch === delim) {
      out += '\\' + ch
      continue
    }
    out += ch
  }
  return out
}

/**
 * Scan the source linearly and repair every string literal it finds.
 */
function fixSource(src) {
  let out = ''
  let i = 0
  const n = src.length

  while (i < n) {
    const ch = src[i]

    // A quote that opens a literal.
    if (ch === "'" || ch === '`') {
      const delim = ch
      const open = i

      // Does this literal close on its own line?
      //
      // A single-quoted string always does. A template usually does too —
      // the corpus writes shell commands and policy documents as
      // single-line templates — but the long `body:` fields legitimately
      // span lines.
      //
      // The distinction that matters: if the line the literal opened on
      // already ends with a comma (a complete property), the literal was
      // meant to close on that line and its closing delimiter is missing.
      // Without this check the template runs on until the next unrelated
      // delimiter in the file and swallows every property in between.
      let lineEnd = src.indexOf('\n', open)
      if (lineEnd === -1) lineEnd = n
      const ownLine = src.slice(open, lineEnd)
      const closesOnOwnLine = ownLine.includes(delim, 1)
      const lineEndsWithComma = ownLine.trimEnd().endsWith(',')

      if (delim === '`' && !closesOnOwnLine && lineEndsWithComma) {
        // The closing backtick was omitted. Close the value here.
        const stem = ownLine.slice(1) // drop the opening delimiter
        const trailingComma = stem.endsWith(',') ? ',' : ''
        const body = trailingComma ? stem.slice(0, -1) : stem
        out += '`' + escapeInner(body, '`') + '`' + trailingComma
        i = lineEnd
        continue
      }

      const end = findEnd(src, open, delim)

      if (end === -1) {
        // Unterminated template. The closing backtick was omitted, so the
        // value runs on past the end of its own property.
        //
        // For a value that spans lines, the property ends at the line
        // before the next property at the same indentation. For a value on
        // a single line, the property ends at that line.
        if (delim === '`') {
          const openLineStart = src.lastIndexOf('\n', open) + 1
          const openIndent = src.slice(openLineStart, open).match(/^[ \t]*/)[0]

          // Find where the value should stop: the first line at the same
          // indentation that starts a property.
          let stop = lineEnd
          let scan = lineEnd
          while (scan < n) {
            const ls = scan + 1
            let le = src.indexOf('\n', ls)
            if (le === -1) le = n
            const line = src.slice(ls, le)
            const indent = line.match(/^[ \t]*/)[0]
            if (
              indent === openIndent &&
              /^[ \t]*[A-Za-z_][A-Za-z0-9_]*:/.test(line)
            ) {
              stop = scan
              break
            }
            scan = le
          }

          const stem = src.slice(open + 1, stop)
          const trailingComma = stem.endsWith(',') ? ',' : ''
          const body = trailingComma ? stem.slice(0, -1) : stem
          out += '`' + escapeInner(body, '`') + '`' + trailingComma
          i = stop
          continue
        }
        // A single-quoted string that never closes on its line. The cause is
        // an apostrophe in prose that closed the string early. The value
        // runs to the end of the line, so close it there and escape the
        // apostrophe that broke it.
        const stem = ownLine.slice(1)
        const lastQuote = stem.lastIndexOf("'")
        const body = lastQuote === -1 ? stem : stem.slice(0, lastQuote)
        const after = lastQuote === -1 ? '' : stem.slice(lastQuote + 1)
        out += "'" + escapeInner(body, "'") + "'" + after
        i = lineEnd
        continue
      }

      const inner = src.slice(open + 1, end)
      const fixed = escapeInner(inner, delim)

      // Only re-emit when something changed, so the rest of the source is
      // copied verbatim and untouched.
      out += delim + fixed + src[end]
      i = end + 1
      continue
    }

    // A double-quoted string: copy verbatim (the corpus does not use them
    // for prose, and its escapes are already valid).
    if (ch === '"') {
      out += ch
      i++
      while (i < n) {
        if (src[i] === '\\') {
          out += src[i] + (src[i + 1] ?? '')
          i += 2
          continue
        }
        if (src[i] === '"') {
          out += src[i]
          i++
          break
        }
        out += src[i]
        i++
      }
      continue
    }

    // A line comment.
    if (ch === '/' && src[i + 1] === '/') {
      let lineEnd = src.indexOf('\n', i)
      if (lineEnd === -1) lineEnd = n
      out += src.slice(i, lineEnd)
      i = lineEnd
      continue
    }

    // A block comment.
    if (ch === '/' && src[i + 1] === '*') {
      let j = i + 2
      while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++
      out += src.slice(i, Math.min(j + 2, n))
      i = j + 2
      continue
    }

    out += ch
    i++
  }

  return out
}

const files = (await readdir(TOPICS)).filter((f) => f.endsWith('.ts'))
let changed = 0
for (const f of files) {
  const p = resolve(TOPICS, f)
  const src = await readFile(p, 'utf8')
  const fixed = fixSource(src)
  if (fixed !== src) {
    changed++
    if (!checkOnly) {
      await writeFile(p, fixed, 'utf8')
      console.log(`fixed ${f}`)
    }
  }
}
console.log(`${changed} file(s) ${checkOnly ? 'would change' : 'fixed'}`)
