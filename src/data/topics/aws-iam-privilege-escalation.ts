import type { Topic } from '@/types'

/**
 * EXEMPLAR — this file is the style reference for every other topic.
 * Match its voice, depth, density and structure.
 */
export const topic: Topic = {
  slug: 'aws/redteam/iam-privilege-escalation',
  title: 'IAM privilege escalation',
  cloud: 'aws',
  stage: 'redteam',
  track: 'Identity & access',
  summary:
    'Turning a narrow set of AWS permissions into administrative control without ever asking for those permissions.',
  duration: '35 min',
  difficulty: 4,
  prerequisites: [
    'aws/adversary/iam-policy-evaluation',
    'aws/adversary/assume-role-trust',
  ],
  enables: [
    'aws/expert/cloudtrail-forensics',
    'aws/adversary/ec2-metadata-service',
  ],
  mentalModel:
    'AWS never asks for your permission twice — it asks for the permission that lets you *become* someone else. If you can make the API see you as a different principal, the API only checks that principal\'s policy.',
  concept: {
    body: `AWS authorization is evaluated per API call against the identity making the call. There is no single "admin" switch. What makes escalation possible is that a permission can be used as a *credential* rather than as a *capability*.

Three families of permission do this:

- **Identity mutation** — permissions that let you attach a role, create a policy, or modify a trust policy. These do not need to be dangerous in isolation; they only need to let you attach something you already control.
- **Credential minting** — permissions that let you mint a credential for something else: \`sts:AssumeRole\`, \`iam:CreateAccessKey\`, \`iam:UpdateAssumeRolePolicy\`, \`ecs:RunTask\`, \`lambda:CreateFunction\`. The output of the call is a *new* identity.
- **Indirect invocation** — permissions that let the cloud run code *as* a more privileged principal: \`lambda:CreateFunction\` with an execution role, \`codebuild:CreateProject\` with a service role, \`cloudformation:CreateStack\` with a role ARN in the template. You never hold the credential; the platform holds it for you.

The classic AWS privilege escalation chains all combine one identity-mutation primitive with one credential-minting primitive. The gap between them is rarely permission on the target resource itself.`,
    keyPoints: [
      'Escalation rarely needs admin. It needs one permission that changes who you are.',
      'Read permissions are usually enough to *discover* the escalation path even when they cannot *execute* it.',
      'Resource-based policies (bucket, role trust, key policy) are evaluated in addition to identity policies — a resource can grant you access your IAM policy does not.',
      '`iam:PassRole` is not a permission to run code. It is a permission to choose whose identity code runs as.',
      'An SCP can block an escalation even when IAM allows it — this is why defense-in-depth matters and why red teams test against SCPs, not just IAM.',
    ],
    misconceptions: [
      {
        claim: 'If IAM does not allow it, it is not possible.',
        truth:
          'IAM is one input. SCPs, session policies, resource policies, permission boundaries and VPC endpoint policies all narrow or widen access independently. A permission denied by IAM can still be granted by a resource policy, and a permission allowed by IAM can still be blocked by an SCP.',
      },
      {
        claim: 'Admin is the only privileged role worth targeting.',
        truth:
          'Roles with `iam:PassRole`, `iam:CreatePolicyVersion`, `sts:AssumeRole`, `lambda:CreateFunction` and `cloudformation:*` are all paths to admin. Most real chains never touch an admin role directly.',
      },
    ],
  },
  attack: {
    body: `The workflow is always the same: enumerate what you hold, find the principals you can influence, turn influence into a credential, and then check what the new credential can do. The tools in each step are different but the structure repeats across every AWS account.

The chains below are ordered from quiet to loud. The quiet ones matter more — they leave little in CloudTrail because no privilege boundary was crossed at the API layer, only in the graph of relationships.`,
    techniques: [
      {
        name: 'sts:AssumeRole into a higher-privileged role',
        what: 'Exchange your current session for a token that carries a different role\'s permissions.',
        command: 'aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Target \\\n  --role-session-name probe --duration-seconds 900',
        impact:
          'Whatever the target role can do, you can now do. This is the step that turns a foothold into control.',
      },
      {
        name: 'iam:UpdateAssumeRolePolicy',
        what:
          'Rewrite a role\'s trust policy so that a principal you control is allowed to assume it.',
        steps: [
          'Read the current trust policy so you do not lose existing trust while editing.',
          'Add your principal to the `sts:Principal` list, keeping the original entries.',
          'Assume the role and enumerate its effective permissions.',
          'Restore the original trust policy before you move on, or the noise will point straight at you.',
        ],
        impact:
          'Full control of every service the target role can reach, with no need for any permission on those services.',
      },
      {
        name: 'iam:CreatePolicyVersion',
        what:
          'Publish a new version of a managed policy that attaches to a role you do not own.',
        steps: [
          'List managed policies and find one attached to a target role.',
          'Create a new version with a policy document that grants you access to the target resources.',
          'Set it as the default version.',
        ],
        impact:
          'Escalation without ever touching the role or its trust policy. Detection often misses this because the policy update looks like normal governance activity.',
      },
      {
        name: 'iam:PassRole into an execution role',
        what:
          'Choose which service identity runs your code, so the platform performs privileged actions on your behalf.',
        command:
          'aws lambda create-function --function-name runner \\\n  --runtime python3.12 --role arn:aws:iam::123456789012:role/AdminDeployRole \\\n  --handler index.handler --zip-file fileb://payload.zip',
        impact:
          'Everything the passed role can do, executed from inside your function, including access to other internal services through their IAM roles.',
      },
      {
        name: 'lambda:CreateFunction with a privileged execution role',
        what:
          'Create a function that assumes a role you cannot assume directly, then run code inside it.',
        steps: [
          'Confirm `iam:PassRole` for the target role and `lambda:CreateFunction` for the service.',
          'Create a function whose execution role is the target role.',
          'Invoke it with code that reads credentials from the metadata service and returns them.',
        ],
        impact:
          'A complete credential for the target role, obtained without ever passing an authorization check against it directly.',
      },
    ],
    cases: [
      {
        title: 'iam:PassRole + lambda:CreateFunction used to reach admin',
        source: 'Public breach write-ups and red team reports on HackerOne, AWS and GCP programs',
        impact:
          'In the recurring pattern, a low-privilege account with lambda:CreateFunction and iam:PassRole reaches an administrator-equivalent position in a single call, without any request ever being made against an admin resource.',
        year: 2024,
      },
      {
        title: 'EC2 instance profile credentials exposed to the instance role',
        source: 'Widely documented cloud misconfiguration class',
        impact:
          'Code running in the instance context receives the role credentials automatically. Any command execution in that context becomes IAM access, and the SSRF path into IMDS is the standard route in.',
        year: 2023,
      },
    ],
  },
  detect: {
    body: `Escalation shows up in the *relationship* between events, not in any single event. An \`iam:UpdateAssumeRolePolicy\` call is routine; an \`iam:UpdateAssumeRolePolicy\` call followed within seconds by an \`sts:AssumeRole\` on the same role is not.

Detection therefore has two halves: log the mutation events properly, and alert on the sequence.`,
    signals: [
      {
        signal: 'Trust policy modified on a role',
        source: 'CloudTrail — management events',
        query: `eventName=UpdateAssumeRolePolicy OR eventName=CreateRole\n| where userIdentity.type != "AssumedRole"\n| stats count() by requestParameters.roleName, userIdentity.arn`,
        note:
          'Baseline this. Role trust changes are common in CI pipelines and legitimately noisy — alert on the unexpected role, not on every change.',
      },
      {
        signal: 'A managed policy version created by a non-deployment principal',
        source: 'CloudTrail — management events',
        query: `eventName=CreatePolicyVersion OR eventName=SetDefaultPolicyVersion\n| where requestParameters.policyDocument like "%Principal%" or requestParameters.policyDocument like "%:*"\n| stats count() by userIdentity.arn, requestParameters.policyArn`,
        note:
          'The "*" principal and the Principal ARN are the giveaways. Public access in a managed policy is almost never intended.',
      },
      {
        signal: 'PassRole called against a role the caller has never used before',
        source: 'CloudTrail — management events',
        query: `eventName=PassRole\n| stats count() by userIdentity.arn, requestParameters.roleName\n| join source=events(eventName=AssumeRole) on requestParameters.roleName\n| where assume.roleName != pass.roleName`,
        note:
          'First-time PassRole is a strong signal. Legitimate deployments pass the same role repeatedly.',
      },
      {
        signal: 'A principal assumed a role with administrative permissions',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| where requestParameters.roleName like "%Admin%" or requestParameters.roleName like "%BreakGlass%"\n| stats count() by userIdentity.arn, requestParameters.roleName`,
        note:
          'Treat break-glass roles as an alerting sink. Every use should page someone.',
      },
      {
        signal: 'Guardrail — restrict PassRole to approved roles',
        source: 'AWS Config managed rule / SCP',
        query: `SCP Deny: iam:PassRole on roles not matching an approved tag`,
        note:
          'This is the control that breaks most chains. Write it before you need it.',
      },
    ],
    posture: [
      'Enable CloudTrail management events in every region, including regions nobody uses yet.',
      'Log CloudTrail to a separate account so an attacker in the source account cannot delete the trail.',
      'Use IAM Access Analyzer to find roles that can be assumed from outside the account, and decide whether each one should exist.',
      'Attach an SCP that denies `iam:PassRole` except for roles tagged as deployable.',
      'Alert on `CreatePolicyVersion` and `SetDefaultPolicyVersion` from any principal that is not a deployment pipeline.',
    ],
  },
  fix: {
    body: `The fix is not one setting. It is removing the ability to reach admin from a position that should not have it, and making sure the platform cannot be used as a confused deputy.

Work down the list in order. The first two break the most chains.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Remove iam:PassRole from roles that are not deployment identities',
        detail:
          'PassRole is the hinge that most chains turn on. If only a handful of roles can be passed, an attacker\'s choice of code-executing service drops to almost nothing. Use a condition on the resource tag.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "iam:PassRole",
    "Resource": "arn:aws:iam::*:role/*",
    "Condition": {
      "StringNotEquals": { "aws:ResourceTag/deployable": "true" }
    }
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'critical',
        action: 'Scope sts:AssumeRole to named roles, not wildcards',
        detail:
          'A wildcard `sts:AssumeRole` on `*` lets the principal assume anything the account trusts. Name the roles, and add a condition on the source identity if the list is long.',
        snippet: `{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": [
    "arn:aws:iam::123456789012:role/DeployRole",
    "arn:aws:iam::123456789012:role/AuditRole"
  ]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Separate deployment permissions from day-to-day permissions',
        detail:
          'Deployments need PassRole and CreateFunction. Humans and CI checkouts for feature branches do not. Splitting them means a compromised developer session cannot become a deployment.',
      },
      {
        priority: 'high',
        action: 'Use permission boundaries on every non-human principal',
        detail:
          'A boundary caps the maximum permissions a principal can ever have, including permissions added later by someone else. It is the only control that survives a mistake in the permission itself.',
      },
      {
        priority: 'medium',
        action: 'Shorten role session durations and require re-assumption',
        detail:
          'A 900-second session limits how long a stolen credential stays useful and forces the attacker to re-execute the chain, which multiplies the chances of detection.',
      },
      {
        priority: 'medium',
        action: 'Add a deny on iam:CreatePolicyVersion outside the governance account',
        detail:
          'Managed policy edits should happen in one place. Blocking them elsewhere removes an entire escalation family that requires no other permission.',
      },
      {
        priority: 'low',
        action: 'Set an explicit max session duration on every role',
        detail:
          'The account-level maximum is a safety net; a role-level maximum of one hour for human roles and fifteen minutes for machine roles is a meaningful reduction in exposure.',
      },
    ],
  },
  checklist: [
    {
      id: 'iam-1',
      text: 'List every role that can be assumed by a principal outside the trust policy you expect.',
      command: 'aws accessanalyzer list-analyzed-resources --resource-type ROLE --filter \'{"Status":{"eq":["ERROR","WARNING"]}}\'',
      expected: 'An empty result, or a short list you can justify out loud.',
    },
    {
      id: 'iam-2',
      text: 'Find every policy that grants iam:PassRole to a wildcard role.',
      command: 'aws iam list-policies --scope Local --query "PolicyList[].Arn" --output text | xargs -I{} aws iam get-policy --policy-arn {}',
      expected: 'Only deployment identities hold a wildcard PassRole.',
    },
    {
      id: 'iam-3',
      text: 'Find every role whose trust policy contains a wildcard principal.',
      command: 'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {}',
      expected: 'No role is assumable by "Principal": "*" without an explicit external account condition.',
    },
    {
      id: 'iam-4',
      text: 'Check whether any of your roles can pass the roles that matter.',
      command: 'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:user/dev --action-names iam:PassRole sts:AssumeRole',
      expected: 'PassRole is denied for every role except the approved deployment roles.',
    },
    {
      id: 'iam-5',
      text: 'Confirm CloudTrail covers every region, including regions you do not use.',
      command: 'aws cloudtrail describe-trails --region all --query "trailList[].{Name:Name, Home:HomeRegion, Multi:IsMultiRegionTrail}"',
      expected: 'One multi-region trail plus per-region trails, all logging management events.',
    },
    {
      id: 'iam-6',
      text: 'Confirm the CloudTrail destination bucket cannot be deleted by the account it logs.',
      command: 'aws s3api get-bucket-policy --bucket my-log-bucket',
      expected: 'The policy denies s3:DeleteBucket and s3:PutBucketPolicy for the logging account principal.',
    },
  ],
  references: [
    { label: 'AWS IAM documentation — policy evaluation logic', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html' },
    { label: 'AWS CloudTrail log file format and event reference', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-guide.html' },
    { label: 'AWS IAM Access Analyzer findings', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html' },
  ],
  updated: '2026-10-14',
}
