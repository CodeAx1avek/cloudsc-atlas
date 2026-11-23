import fs from 'node:fs'
import path from 'node:path'

const dir = process.argv[2] || '.'
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.ts'))

const KEY = /^\s*[A-Za-z_][A-Za-z0-9_]*:\s*/

for (const f of files) {
  const lines = fs.readFileSync(path.join(dir, f), 'utf8').split('\n')
  lines.forEach((l, i) => {
    if (!KEY.test(l)) return
    const t = l.trimEnd()
    // A property value line must end with a comma unless the property is
    // the last entry of an object, in which case the closing brace follows.
    if (t.endsWith(',')) return
    if (/[{[]$/.test(t)) return
    const last = t[t.length - 1]
    if (last !== "'" && last !== '"' && last !== '`') return
    console.log(`${f}:${i + 1}: ${t.slice(0, 120)}`)
  })
}
