import type { CloudMeta, StageMeta } from '@/types'

export const CLOUDS: CloudMeta[] = [
  {
    id: 'aws',
    name: 'Amazon Web Services',
    hue: '#d9700f',
    glyph: 'AWS',
    identity: 'IAM users, roles and policies',
    console: 'AWS Console',
    cli: 'aws-cli / aws-sdk',
    auditLog: 'CloudTrail',
    blurb:
      'Identity is the perimeter. Almost every AWS breach starts with a permission that was wider than the job required.',
  },
  {
    id: 'azure',
    name: 'Microsoft Azure',
    hue: '#1f6feb',
    glyph: 'Az',
    identity: 'Microsoft Entra ID tenants and managed identities',
    console: 'Azure Portal',
    cli: 'az cli / Azure CLI',
    auditLog: 'Azure Activity and Microsoft Entra sign-in logs',
    blurb:
      'The tenant is the perimeter. A single Entra ID app registration with the wrong consent turns into tenant-wide compromise.',
  },
  {
    id: 'gcp',
    name: 'Google Cloud Platform',
    hue: '#0f9d70',
    glyph: 'GCP',
    identity: 'Google Accounts, service accounts and IAM',
    console: 'Google Cloud Console',
    cli: 'gcloud',
    auditLog: 'Cloud Audit Logs',
    blurb:
      'Blast radius is bound by projects and service account keys. The classic mistake is a service account with owner on everything.',
  },
]

export const CLOUD_BY_ID: Record<string, CloudMeta> = Object.fromEntries(
  CLOUDS.map((c) => [c.id, c]),
)

export const STAGES: StageMeta[] = [
  {
    id: 'foundation',
    name: 'Foundation',
    outcome: 'I can explain how a request gets authenticated in this cloud, and where the trust boundaries are.',
    blurb:
      'Identity, regions, and the network shape. Get the vocabulary right and everything later becomes easier to reason about.',
  },
  {
    id: 'operator',
    name: 'Operator',
    outcome: 'I can build and run workloads here safely, and read the audit logs that tell me what happened.',
    blurb:
      'Deploying, storing data, and wiring services together. The stage where misconfiguration usually gets introduced.',
  },
  {
    id: 'adversary',
    name: 'Adversary',
    outcome: 'I can turn a set of credentials into a foothold and move laterally inside the account.',
    blurb:
      'Credential theft, token theft, and the first meaningful pivots. Understanding the offence starts to pay off.',
  },
  {
    id: 'redteam',
    name: 'Red team',
    outcome: 'I can chain weaknesses into a path to a crown-jewel objective, and prove it without leaving evidence I cannot explain.',
    blurb:
      'Chaining, persistence, and tradecraft. This is where separate weaknesses become one objective.',
  },
  {
    id: 'expert',
    name: 'Expert',
    outcome: 'I can design a cloud estate that is hard to attack, and detect the ones that are not.',
    blurb:
      'Guardrails, detection engineering, and the attack paths that survive every control you can write down.',
  },
]

export const STAGE_BY_ID: Record<string, StageMeta> = Object.fromEntries(
  STAGES.map((s) => [s.id, s]),
)

export const STAGE_ORDER: StageMeta['id'][] = [
  'foundation',
  'operator',
  'adversary',
  'redteam',
  'expert',
]
