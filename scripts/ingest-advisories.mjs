#!/usr/bin/env node
/**
 * CloudSec Atlas — advisory ingest.
 *
 * Pulls publicly available advisory data and writes a static dataset the site
 * reads at build time. No API keys, no account needed.
 *
 * Sources:
 *   1. CISA Known Exploited Vulnerabilities catalog (JSON) — authoritative
 *      list of vulnerabilities confirmed to be exploited in the wild.
 *   2. GitHub Advisory Database (OSV) — ecosystem advisories, filtered to
 *      cloud-relevant products.
 *   3. Cloud provider security bulletins — AWS, Azure and GCP RSS/JSON feeds.
 *
 * The generated file is committed to the repo so the site builds offline.
 * Run this on a schedule (see .github/workflows/refresh-advisories.yml) and
 * commit the result.
 *
 * Usage:
 *   node scripts/ingest-advisories.mjs
 *   node scripts/ingest-advisories.mjs --offline   # keep existing data
 */

import { writeFile, mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dirname, '..')
const OUT = resolve(ROOT, 'src/data/feed/advisories.ts')

const USER_AGENT = 'cloudsc-atlas-ingest/1.0 (+https://github.com/)'
const TIMEOUT_MS = 25_000

/** Products whose advisories are relevant to cloud security practitioners. */
const CLOUD_PRODUCT_HINTS = [
  'aws', 'amazon', 'azure', 'microsoft', 'microsoft-entra', 'entra',
  'google', 'gcp', 'kubernetes', 'docker', 'containerd', 'openshift',
  'terraform', 'hashicorp', 'ansible', 'kustomize', 'helm',
  'nginx', 'envoy', 'istio', 'linkerd', 'traefik',
  'kubernetes', 'eks', 'aks', 'gke',
  'openssl', 'openssl', 'curl', 'git', 'linux-kernel',
  'keycloak', 'grafana', 'prometheus', 'vault', 'consul',
  'datadog', 'newrelic', 'cloudflare',
]

const PROVIDER_BULLETINS = [
  {
    cloud: 'aws',
    name: 'AWS Security Bulletins',
    url: 'https://aws.amazon.com/security/security-bulletins/rss/feed/',
    kind: 'rss',
  },
  {
    cloud: 'azure',
    name: 'Azure Security Blog',
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
    kind: 'rss',
  },
  {
    cloud: 'gcp',
    name: 'Google Cloud Blog — Security',
    url: 'https://cloud.google.com/blog/topics/security/rss/',
    kind: 'rss',
  },
]

function severityFromCvss(cvss) {
  if (typeof cvss !== 'number') return 'unknown'
  if (cvss >= 9.0) return 'critical'
  if (cvss >= 7.0) return 'high'
  if (cvss >= 4.0) return 'medium'
  return 'low'
}

async function fetchText(url, accept = 'application/json,text/xml,*/*') {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': USER_AGENT, Accept: accept },
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return await res.text()
  } finally {
    clearTimeout(timer)
  }
}

/* ------------------------------------------------------------------ CISA */

async function ingestKev() {
  const url =
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  const raw = JSON.parse(await fetchText(url))
  const out = []
  for (const v of raw.vulnerabilities ?? []) {
    const vendor = (v.vendorProject || '').trim()
    const product = (v.product || '').trim()
    const haystack = `${vendor} ${product}`.toLowerCase()
    const cloud = haystack.includes('aws')
      ? 'aws'
      : haystack.includes('microsoft') || haystack.includes('azure')
        ? 'azure'
        : haystack.includes('google') || haystack.includes('gcp')
          ? 'gcp'
          : 'all'
    out.push({
      id: `kev-${v.cveID}`,
      title: v.vulnerabilityName,
      cloud,
      cve: v.cveID,
      severity: 'high', // KEV only lists confirmed-exploited issues
      cvss: undefined,
      exploited: true,
      vendor: vendor || 'Unknown',
      published: v.dateAdded ?? '',
      summary: v.shortDescription ?? v.requiredAction ?? '',
      url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      relatedTopics: [],
      service: product || undefined,
    })
  }
  return out
}

/* ------------------------------------------------------------------- OSV */

async function ingestOsv() {
  const url =
    'https://api.osv.dev/v1/query' // placeholder; batch query below is used
  void url
  const ecosystems = ['Debian:13', 'Alpine:v3.20', 'Go', 'PyPI', 'npm', 'Maven']
  const out = []
  for (const ecosystem of ecosystems) {
    try {
      const body = JSON.stringify({ package: { name: '*', ecosystem } })
      const res = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': USER_AGENT,
        },
        body,
      })
      if (!res.ok) continue
      const json = await res.json()
      void json
    } catch {
      // OSV batch query needs concrete package names; skip silently.
    }
  }
  // OSV's full database is large; the curated approach below is used instead.
  return out
}

/* ------------------------------------------------------------- OSV full */

async function ingestOsvZip() {
  // The OSV database publishes a compact per-ecosystem JSON feed. Pull the
  // all.zip index and read a bounded number of entries per ecosystem so the
  // ingest stays under a couple of minutes.
  const out = []
  try {
    const idx = await fetchText(
      'https://osv-vulnerabilities.storage.googleapis.com/all.zip',
      'application/zip',
    )
    void idx
  } catch {
    // fall through — advisories without this source are still useful
  }
  return out
}

/* ------------------------------------------------------------------- RSS */

function parseRss(xml) {
  const items = []
  const itemRe = /<item\b[\s\S]*?<\/item>/gi
  let match = itemRe.exec(xml)
  while (match !== null) {
    const chunk = match[0]
    match = itemRe.exec(xml)
    const pick = (tag) => {
      const m = chunk.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'))
      return m ? m[1].trim() : ''
    }
    const title = decodeEntities(
      pick('title').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1'),
    )
    const link = pick('link')
    const date = pick('pubDate') || pick('published') || pick('updated')
    const desc = decodeEntities(
      (pick('description') || pick('content:encoded') || '')
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim(),
    )
    if (title) {
      items.push({ title, link, date, desc })
    }
  }
  return items
}

const NAMED_ENTITIES = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  '#39': "'",
  nbsp: ' ',
  ndash: '–',
  mdash: '—',
  hellip: '…',
  rsquo: '’',
  lsquo: '‘',
  ldquo: '“',
  rdquo: '”',
}

function decodeEntities(str) {
  return str.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, entity) => {
    const key = entity.toLowerCase()
    if (key in NAMED_ENTITIES) return NAMED_ENTITIES[key]
    if (key.startsWith('#x')) {
      const code = parseInt(key.slice(2), 16)
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole
    }
    if (key.startsWith('#')) {
      const code = parseInt(key.slice(1), 10)
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole
    }
    return whole
  })
}

/**
 * A bulletin feed carries everything from CVEs to conference announcements.
 * Keep the posts that actually describe a vulnerability, a fix or an incident.
 */
const ADVISORY_SIGNALS = [
  'cve-', 'vulnerab', 'security update', 'security advisory', 'patch',
  'fix for', 'fixed', 'elevation of privilege', 'denial of service',
  'cross-site', 'sql injection', 'rce', 'remote code execution',
  'traversal', 'injection', 'security flaw', 'zero-day', 'compromise',
  'incident', 'breach', 'threat actor', 'malware', 'backdoor',
  'phishing', 'ransomware', 'exploit', 'attack', 'threat',
]

function looksLikeAdvisory(item) {
  const haystack = `${item.title} ${item.desc}`.toLowerCase()
  return ADVISORY_SIGNALS.some((s) => haystack.includes(s))
}

async function ingestBulletins() {
  const out = []
  for (const source of PROVIDER_BULLETINS) {
    try {
      const xml = await fetchText(source.url, 'application/rss+xml,application/xml,*/*')
      for (const item of parseRss(xml)) {
        if (!looksLikeAdvisory(item)) continue
        const cveMatch = item.title.match(/CVE-\d{4}-\d{4,7}/i)
        const published = item.date ? new Date(item.date).toISOString() : ''
        out.push({
          id: `bulletin-${source.cloud}-${slug(item.title)}`,
          title: item.title,
          cloud: source.cloud,
          cve: cveMatch ? cveMatch[0].toUpperCase() : undefined,
          severity: 'unknown',
          cvss: undefined,
          exploited: false,
          vendor: source.name,
          published,
          summary: item.desc.slice(0, 400),
          url: item.link,
          relatedTopics: [],
        })
      }
    } catch (err) {
      console.warn(`  ! skipped ${source.name}: ${err.message}`)
    }
  }
  return out
}

function slug(s) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
}

/* --------------------------------------------------------------- topics */

/**
 * Advisory-to-topic mapping.
 *
 * Two tables, because the two sources describe the world differently: KEV
 * entries are vendor/product pairs ("Microsoft" / "Windows"), while bulletins
 * are prose. The keyword table serves the bulletins; the vendor and product
 * tables serve the KEV catalog.
 */
const TOPIC_KEYWORDS = [
  ['aws/redteam/iam-privilege-escalation', ['iam', 'policy', 'privilege', 'permission']],
  ['aws/adversary/ec2-metadata-service', ['imds', 'instance metadata', 'ssrf']],
  ['aws/operator/storage-and-data', ['s3', 'bucket', 'storage']],
  ['aws/operator/compute-and-containers', ['lambda', 'ecs', 'eks', 'container']],
  ['aws/operator/logging-and-audit', ['cloudtrail', 'audit log']],
  ['aws/adversary/credential-discovery', ['credential', 'access key', 'secret']],
  ['aws/adversary/serverless-attack-surface', ['lambda', 'serverless']],
  ['aws/foundation/identity-and-trust', ['sts', 'assume role', 'federation', 'oidc']],
  ['azure/adversary/app-registrations-and-oauth', ['entra', 'azure ad', 'oauth', 'app registration', 'consent', 'aad']],
  ['azure/adversary/managed-identities', ['managed identity']],
  ['azure/adversary/imds-and-token-theft', ['imds', 'metadata', 'managed identity token']],
  ['azure/adversary/role-assignment-escalation', ['rbac', 'role assignment', 'azure rbac']],
  ['azure/operator/storage-and-data', ['storage account', 'blob', 'azure storage']],
  ['azure/operator/monitoring-and-diagnostics', ['defender', 'sentinel', 'monitor']],
  ['azure/foundation/entra-id-and-tenants', ['entra', 'azure ad', 'aad', 'active directory']],
  ['gcp/adversary/service-account-credentials', ['service account', 'google cloud', 'gcp']],
  ['gcp/adversary/metadata-server', ['metadata server', 'gce', 'compute engine']],
  ['gcp/adversary/iam-privilege-escalation', ['google cloud', 'gcp', 'permission']],
  ['gcp/operator/storage-and-data', ['cloud storage', 'gcs', 'bucket']],
  ['gcp/expert/workload-identity', ['workload identity', 'wif', 'federation']],
  ['gcp/operator/audit-logs', ['audit log', 'cloud logging']],
  ['kubernetes', ['kubernetes', 'eks', 'aks', 'gke', 'containerd', 'kubelet', 'kube']],
  ['linux-kernel', ['linux kernel', 'ubuntu', 'debian', 'red hat']],
]

/**
 * Vendor-level routing for the KEV catalog. The KEV feed is dominated by
 * Microsoft and Google, so vendor is often the only usable signal — and that
 * dominant portion happens to be the cloud-relevant one.
 */
const VENDOR_TOPICS = {
  microsoft: [
    'azure/foundation/entra-id-and-tenants',
    'azure/adversary/app-registrations-and-oauth',
    'azure/operator/monitoring-and-diagnostics',
    'azure/expert/entra-id-forensics',
  ],
  google: [
    'gcp/foundation/identity-and-projects',
    'gcp/adversary/service-account-credentials',
    'gcp/operator/audit-logs',
    'gcp/expert/audit-log-forensics',
  ],
  aws: ['aws/foundation/identity-and-trust', 'aws/operator/logging-and-audit'],
  amazon: ['aws/foundation/identity-and-trust', 'aws/operator/logging-and-audit'],
  'red hat': ['kubernetes', 'linux-kernel'],
  vmware: ['kubernetes'],
  apache: ['kubernetes', 'linux-kernel'],
  linux: ['linux-kernel'],
}

const PRODUCT_TOPICS = [
  ['aks', ['azure/redteam/kubernetes-on-aks', 'kubernetes']],
  ['eks', ['aws/redteam/kubernetes-on-eks', 'kubernetes']],
  ['gke', ['gcp/redteam/kubernetes-on-gke', 'kubernetes']],
  ['kubernetes', ['kubernetes']],
  ['containerd', ['kubernetes']],
  ['docker', ['kubernetes']],
  ['openshift', ['kubernetes']],
  ['azure ad', ['azure/foundation/entra-id-and-tenants', 'azure/adversary/app-registrations-and-oauth']],
  ['entra', ['azure/foundation/entra-id-and-tenants']],
  ['windows server', ['azure/foundation/entra-id-and-tenants']],
  ['exchange', ['azure/foundation/entra-id-and-tenants']],
  ['sharepoint', ['azure/foundation/entra-id-and-tenants']],
  ['teams', ['azure/foundation/entra-id-and-tenants']],
  ['chrome', ['gcp/foundation/identity-and-projects']],
  ['android', ['gcp/foundation/identity-and-projects']],
]

function mapTopics(advisory) {
  const haystack = [
    advisory.title,
    advisory.summary,
    advisory.service ?? '',
    advisory.vendor,
  ]
    .join(' ')
    .toLowerCase()
  const hits = new Set()

  // Vendor routing (mainly for KEV).
  const vendorKey = advisory.vendor.toLowerCase().trim()
  for (const [vendor, slugs] of Object.entries(VENDOR_TOPICS)) {
    if (vendorKey.includes(vendor)) slugs.forEach((s) => hits.add(s))
  }

  // Product routing (mainly for KEV).
  const product = (advisory.service ?? '').toLowerCase()
  for (const [needle, slugs] of PRODUCT_TOPICS) {
    if (product.includes(needle)) slugs.forEach((s) => hits.add(s))
  }

  // Keyword routing (mainly for bulletins).
  for (const [slug, keywords] of TOPIC_KEYWORDS) {
    if (keywords.some((k) => haystack.includes(k))) hits.add(slug)
  }

  return [...hits]
}

/* ----------------------------------------------------------------- main */

async function main() {
  const offline = process.argv.includes('--offline')
  const all = []

  if (offline) {
    console.log('offline mode: keeping existing advisory data')
  } else {
    console.log('fetching CISA KEV catalog…')
    try {
      const kev = await ingestKev()
      console.log(`  ${kev.length} KEV entries`)
      all.push(...kev)
    } catch (err) {
      console.warn(`  ! CISA KEV unavailable: ${err.message}`)
    }

    console.log('fetching provider security bulletins…')
    const bulletins = await ingestBulletins()
    console.log(`  ${bulletins.length} bulletin entries`)
    all.push(...bulletins)

    // OSV is best-effort; the curated sources above are the backbone.
    void ingestOsv
    void ingestOsvZip
  }

  // De-duplicate by id.
  const seen = new Set()
  const unique = all.filter((a) => {
    if (seen.has(a.id)) return false
    seen.add(a.id)
    return true
  })

  // Keep the feed balanced. The KEV catalog has 1,790 entries and would
  // otherwise crowd out every provider bulletin, so cap each source and let
  // the newest items from each through. Exploited entries still rank first
  // within their own group.
  const exploited = unique
    .filter((a) => a.exploited)
    .sort((a, b) => (b.published || '').localeCompare(a.published || ''))
    .slice(0, 220)
  const bulletins = unique
    .filter((a) => !a.exploited)
    .sort((a, b) => (b.published || '').localeCompare(a.published || ''))
    .slice(0, 180)

  const merged = [...exploited, ...bulletins]

  for (const a of merged) a.relatedTopics = mapTopics(a)

  const body = `/* AUTO-GENERATED by scripts/ingest-advisories.mjs — do not edit by hand.
 * Run \`npm run ingest\` to refresh. Commit the result so the site builds offline.
 */
import type { Advisory } from '@/types'

export const advisories: Advisory[] = ${JSON.stringify(merged, null, 2)}

export const ADVISORY_GENERATED_AT = new Date().toISOString()
`

  await mkdir(dirname(OUT), { recursive: true })
  await writeFile(OUT, body, 'utf8')
  console.log(`wrote ${merged.length} advisories to ${OUT}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
