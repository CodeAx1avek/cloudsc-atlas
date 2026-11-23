import type { Cloud, Stage, Topic } from '@/types'
import { STAGE_ORDER } from '@/data/clouds'

/**
 * Every topic module in the atlas. Adding a topic means adding an import
 * here — the import list is the curriculum's table of contents.
 */
import { topic as awsIdentityAndTrust } from '@/data/topics/aws-foundation-identity-and-trust'
import { topic as awsNetworkBoundaries } from '@/data/topics/aws-foundation-network-boundaries'
import { topic as awsRegionsAndAvailability } from '@/data/topics/aws-foundation-regions-and-availability'
import { topic as awsStorageAndData } from '@/data/topics/aws-operator-storage-and-data'
import { topic as awsComputeAndContainers } from '@/data/topics/aws-operator-compute-and-containers'
import { topic as awsLoggingAndAudit } from '@/data/topics/aws-operator-logging-and-audit'
import { topic as awsCredentialDiscovery } from '@/data/topics/aws-adversary-credential-discovery'
import { topic as awsEc2MetadataService } from '@/data/topics/aws-adversary-ec2-metadata-service'
import { topic as awsServerlessAttackSurface } from '@/data/topics/aws-adversary-serverless-attack-surface'
import { topic as awsIamPolicyEvaluation } from '@/data/topics/aws-adversary-iam-policy-evaluation'
import { topic as awsAssumeRoleTrust } from '@/data/topics/aws-adversary-assume-role-trust'
import { topic as awsIamPrivilegeEscalation } from '@/data/topics/aws-iam-privilege-escalation'
import { topic as awsKubernetesOnEks } from '@/data/topics/aws-redteam-kubernetes-on-eks'
import { topic as awsAttackPathChaining } from '@/data/topics/aws-redteam-attack-path-chaining'
import { topic as awsOrganizationalGuardrails } from '@/data/topics/aws-expert-organizational-guardrails'
import { topic as awsCloudtrailForensics } from '@/data/topics/aws-expert-cloudtrail-forensics'
import { topic as awsMultiAccountEstate } from '@/data/topics/aws-expert-multi-account-estate'

export const TOPICS: Topic[] = [
  awsIdentityAndTrust,
  awsNetworkBoundaries,
  awsRegionsAndAvailability,
  awsStorageAndData,
  awsComputeAndContainers,
  awsLoggingAndAudit,
  awsCredentialDiscovery,
  awsEc2MetadataService,
  awsServerlessAttackSurface,
  awsIamPolicyEvaluation,
  awsAssumeRoleTrust,
  awsIamPrivilegeEscalation,
  awsKubernetesOnEks,
  awsAttackPathChaining,
  awsOrganizationalGuardrails,
  awsCloudtrailForensics,
  awsMultiAccountEstate,
]

export const TOPIC_BY_SLUG: Record<string, Topic> = Object.fromEntries(
  TOPICS.map((t) => [t.slug, t]),
)

export function getTopic(slug: string): Topic | undefined {
  return TOPIC_BY_SLUG[slug]
}

/** Topics for one cloud, in curriculum order. */
export function topicsByCloud(cloud: Cloud): Topic[] {
  return TOPICS.filter((t) => t.cloud === cloud)
}

/** Topics for one cloud at one stage. */
export function topicsByStage(cloud: Cloud, stage: Stage): Topic[] {
  return TOPICS.filter((t) => t.cloud === cloud && t.stage === stage)
}

/**
 * The recommended reading order: stage first, then cloud, then the order the
 * topics were authored in. This is the spine of the progression map.
 */
export function orderedTopics(): Topic[] {
  return [...TOPICS].sort((a, b) => {
    const s = STAGE_ORDER.indexOf(a.stage) - STAGE_ORDER.indexOf(b.stage)
    if (s !== 0) return s
    return TOPICS.indexOf(a) - TOPICS.indexOf(b)
  })
}

/** A topic and the topics it unlocks, resolved to real objects. */
export interface PathLink {
  from: Topic
  to: Topic
}

export function attackPath(): PathLink[] {
  const links: PathLink[] = []
  for (const t of TOPICS) {
    for (const slug of t.enables) {
      const target = TOPIC_BY_SLUG[slug]
      if (target) links.push({ from: t, to: target })
    }
  }
  return links
}

export interface CurriculumStats {
  topics: number
  clouds: number
  stages: number
  techniques: number
  signals: number
  remediations: number
  checks: number
}

export function curriculumStats(): CurriculumStats {
  return {
    topics: TOPICS.length,
    clouds: new Set(TOPICS.map((t) => t.cloud)).size,
    stages: STAGE_ORDER.filter((s) => TOPICS.some((t) => t.stage === s)).length,
    techniques: TOPICS.reduce((n, t) => n + t.attack.techniques.length, 0),
    signals: TOPICS.reduce((n, t) => n + t.detect.signals.length, 0),
    remediations: TOPICS.reduce((n, t) => n + t.fix.remediations.length, 0),
    checks: TOPICS.reduce((n, t) => n + t.checklist.length, 0),
  }
}
