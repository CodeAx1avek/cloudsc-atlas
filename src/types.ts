/**
 * CloudSec Atlas content model.
 *
 * Every topic follows the same four beats, in the same order:
 *
 *   Concept -> Attack -> Detect -> Fix
 *
 * The order is not decorative. It is the order a security engineer actually
 * needs: what the thing is, how it gets abused, what the signal looks like,
 * and what to change. A topic that cannot fill all four beats is not
 * finished, and the type system reflects that.
 */

export type Cloud = 'aws' | 'azure' | 'gcp'

export type Stage =
  | 'foundation'
  | 'operator'
  | 'adversary'
  | 'redteam'
  | 'expert'

export type Priority = 'critical' | 'high' | 'medium' | 'low'

/** A named offensive technique inside the attack beat. */
export interface Technique {
  name: string
  /** What the technique does, in one sentence. */
  what: string
  /** A runnable command. Kept short; multi-line steps go in `steps`. */
  command?: string
  /** Longer command sequences or worked steps. */
  steps?: string[]
  /** The blast radius if it succeeds. */
  impact: string
}

/** A real-world case that shows the technique is not theoretical. */
export interface CaseStudy {
  title: string
  /** Who reported it and where it was found. */
  source: string
  /** The consequence, stated plainly. */
  impact: string
  /** Year the report or disclosure happened. */
  year?: number
  url?: string
}

/** A detection signal: what to look for and where it lives. */
export interface Signal {
  signal: string
  /** Which log or telemetry source carries it. */
  source: string
  /** A ready-to-run query where one exists. */
  query?: string
  /** How reliable this signal is, in plain terms. */
  note?: string
}

/** A concrete remediation action. */
export interface Remediation {
  priority: Priority
  action: string
  /** Why this action, specifically, closes the gap. */
  detail: string
  /** Config or code showing the fix where it is short enough to show. */
  snippet?: string
  snippetLang?: 'bash' | 'json' | 'yaml' | 'hcl' | 'xml' | 'text'
}

/** One verification step, runnable by the reader. */
export interface Check {
  id: string
  text: string
  command?: string
  /** What a correct result looks like. */
  expected?: string
}

export interface Misconception {
  claim: string
  truth: string
}

export interface Reference {
  label: string
  url: string
}

export interface Topic {
  /** Stable path segments, e.g. "aws/identity/iam-privilege-escalation". */
  slug: string
  title: string
  cloud: Cloud
  stage: Stage
  /** The subject grouping inside a cloud, e.g. "Identity & access". */
  track: string
  /** One plain sentence. If it needs a second sentence, it is two topics. */
  summary: string
  /** Estimated reading plus hands-on time. */
  duration: string
  /** 1 = understand it, 5 = you have to have done it in a real account. */
  difficulty: 1 | 2 | 3 | 4 | 5
  /** Slugs of topics that should be read first. */
  prerequisites: string[]
  /** Slugs of topics this one unlocks. */
  enables: string[]
  /** The shortest correct model of the thing. */
  mentalModel?: string
  concept: {
    body: string
    keyPoints: string[]
    misconceptions?: Misconception[]
  }
  attack: {
    body: string
    techniques: Technique[]
    cases?: CaseStudy[]
  }
  detect: {
    body: string
    signals: Signal[]
    /** Guardrails and policy that limit the blast radius. */
    posture?: string[]
  }
  fix: {
    body: string
    remediations: Remediation[]
  }
  /** Hands-on verification steps the reader runs themselves. */
  checklist: Check[]
  references?: Reference[]
  /** ISO date the topic was last reviewed. */
  updated: string
  /** True for topics still being drafted. */
  draft?: boolean
}

/** An item in the auto-ingested advisory feed. */
export interface Advisory {
  id: string
  title: string
  /** Cloud the advisory applies to, or 'all' for cross-cloud. */
  cloud: Cloud | 'all'
  /** CVE identifier if the advisory has one. */
  cve?: string
  /** Severity as published. */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown'
  /** CVSS base score when published. */
  cvss?: number
  /** Whether this advisory is known to be exploited. */
  exploited: boolean
  /** Vendor or affected product. */
  vendor: string
  /** Published date, ISO. */
  published: string
  summary: string
  url: string
  /** Topics in the atlas this advisory is relevant to. */
  relatedTopics: string[]
  /** Which cloud service the advisory is about. */
  service?: string
}

export interface CloudMeta {
  id: Cloud
  name: string
  /** The provider's own brand hue, used as a structural signal. */
  hue: string
  /** Short identity used in the UI, e.g. the logo glyph. */
  glyph: string
  /** The identity providers that cloud sits on top of. */
  identity: string
  /** The console and CLI names for this cloud. */
  console: string
  cli: string
  /** The audit log that matters most in this cloud. */
  auditLog: string
  blurb: string
}

export interface StageMeta {
  id: Stage
  name: string
  /** The question a learner should be able to answer at this stage. */
  outcome: string
  blurb: string
}
