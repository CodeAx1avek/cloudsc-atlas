import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/foundation/identity-and-trust',
  title: 'Identity and trust in AWS',
  cloud: 'aws',
  stage: 'foundation',
  track: 'Identity & access',
  summary:
    'The IAM mental model: who the caller is, what policy says, and why a resource policy can grant access your IAM policy never approved.',
  duration: '30 min',
  difficulty: 2,
  prerequisites: [],
  enables: [
    'aws/foundation/network-boundaries',
    'aws/operator/storage-and-data',
    'aws/operator/logging-and-audit',
    'aws/adversary/credential-discovery',
    'aws/adversary/iam-policy-evaluation',
    'aws/adversary/assume-role-trust',
    'aws/expert/multi-account-estate',
  ],
  mentalModel:
    'Every AWS API call answers three questions in order: who is the principal, does the identity policy allow it, and does the resource policy also allow it. A resource policy can say yes on its own — that is the seam most AWS compromises walk through.',
  concept: {
    body: `AWS has one global identity service, IAM. Every API call in every region is evaluated against it. IAM is not a directory of users and passwords; it is an authorization engine that answers "may this principal perform this action on this resource, right now, in this context".

**Principals.** Four kinds show up in IAM:

- The **root user**, a single account-level identity with full access. It cannot be given permissions, it cannot be denied by IAM, and it should never make an API call.
- **IAM users**, which represent a person or a workload with a long-lived credential: an access key pair, a password, or both. There is no good reason for a human to hold one any more, but they are everywhere in legacy estates.
- **IAM roles**, which are never directly used. They are *assumed*. A role is the only way a human, a service, or a federated identity gets temporary credentials.
- **Service principals**, which are the AWS service itself (for example, the Lambda service assuming a function's execution role, or EC2 assuming an instance profile). Service principals are not identities you create, but they are actors that will act on your behalf if a policy allows it.

**Trust and authorization are two different documents.** A role has a *trust policy* (the resource policy attached to the role) that says who is allowed to call \`sts:AssumeRole\` on it. The role's *permissions* come from a completely separate set of identity policies attached to it or to the group it belongs to. Conflating the two is the single most common source of AWS security confusion. A trust policy is a resource policy and uses the \`sts:AssumeRole\` action; it never grants s3 or ec2 permissions.

**Policy types and where they sit.**

- *Identity-based policies* attach to users, groups and roles: inline in the entity, or as managed policies by ARN.
- *Resource-based policies* attach to the resource: an S3 bucket policy, a KMS key policy, an SNS topic policy, an SQS queue policy, a Lambda resource policy, a VPC endpoint policy.
- *Session policies* are passed at \`sts:AssumeRole\` time and can only narrow.
- *Permission boundaries* cap an identity's maximum permissions even if an attached policy allows more.
- *Service control policies* (SCPs) sit in AWS Organizations and cap the maximum permissions of anything in an account or organizational unit.
- *Resource control policies* (RCPs) do the same for resource data-plane access, most usefully S3.

**The evaluation result.** AWS unions all applicable Allows and intersects all applicable Denies. An explicit Deny anywhere wins, even against an explicit Allow elsewhere. Critically, the union means two policies that each allow half of what you need combine into full access — this is why "it cannot grant delete" is not a meaningful defence. A resource policy is an independent Allow source. If a bucket policy allows your principal, you do not need any Allow in your own policy at all, and no deny in your own policy will stop it unless it is an explicit Deny.

That asymmetry is the whole attack surface. Identity-based policy thinking says "does my policy allow this?" Resource-policy thinking says "does anything attached to the target say yes?" The second question is the one that finds real accounts.`,
    keyPoints: [
      'Trust policy authorizes `sts:AssumeRole` and nothing else. Role permissions live in identity policies attached to the role.',
      'An explicit Deny anywhere in the evaluation beats every Allow. An Allow is additive, so two partial Allows compose into full access.',
      'A resource-based policy is a standalone Allow source. It can grant access that your identity policy never mentions.',
      'Permission boundaries and SCPs cap permissions; they never grant them. An entity inside a boundary is limited to the intersection of its policies and the boundary.',
      'The root user is not restricted by IAM. It can only be constrained by SCPs, RCPs and account-level controls.',
      'IAM is global, but the resources it protects are regional. A role in `eu-west-1` is the same role in `us-east-1`.',
    ],
    misconceptions: [
      {
        claim: 'A role trust policy can grant the role its permissions.',
        truth:
          'It cannot. The trust policy only answers "who may call sts:AssumeRole on this role". Permissions come from identity policies attached to the role or its group.',
      },
      {
        claim: 'If my IAM policy does not allow an action, nothing can grant it.',
        truth:
          'Resource policies, session policies, permission boundaries, SCPs and RCPs are separate inputs. A resource policy can grant access your identity policy never mentions, and a session policy can narrow an identity policy that is otherwise broad.',
      },
      {
        claim: 'Roles are accounts.',
        truth:
          'A role is a set of permissions plus a trust policy, scoped to one account. It has no home region and no console home of its own; assuming it produces a session scoped to the region you called STS in.',
      },
    ],
  },
  attack: {
    body: `Most AWS account access is not obtained by cracking a password. It is obtained by reading a relationship that was left more permissive than intended and then using a documented API to exploit it.

The first phase is always the same: pull the principal inventory and the policy documents. \`aws iam list-users\`, \`aws iam list-roles\` and \`aws iam list-groups\` are cheap, fast and rarely restricted, and they hand you the map of the account's identity surface. \`aws iam list-roles\` in particular is the highest-value enumeration call in AWS because roles are where trust lives.

The second phase is reading trust. \`aws iam get-role\` returns the trust policy of a role. A role trusted by \`"Principal": {"AWS": "*"}\`, or trusted by an external account you control, or trusted by a service such as lambda.amazonaws.com with a broad principal, is a candidate for escalation.

The third phase is mutation. If you hold \`iam:CreatePolicyVersion\` or \`iam:UpdateAssumeRolePolicy\`, you can rewrite who is allowed to do what, and you never need to hold the target permission itself.

The fourth phase is the confused deputy. \`iam:PassRole\` is not a permission to run code; it is a permission to choose whose identity code runs as. Combine it with any permission that creates or runs compute and you have an escalation that never touches the target role directly.

Every one of these steps is visible in CloudTrail. The point of understanding the chain is knowing exactly which link to break.`,
    techniques: [
      {
        name: 'Enumerate principals and their attached policies',
        what: 'Build the identity map of the account in two API calls.',
        steps: [
          'List every role: `aws iam list-roles --query "Roles[].{Arn:Arn,Name:RoleName}" --output table`.',
          'For each role that looks interesting, pull the trust policy and the attached managed policies.',
          'Compare the two. A role with a narrow trust policy but a wide permission set is only as strong as its trust.',
        ],
        command:
          'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {}',
        impact:
          'A complete list of roles, their trust policies and their session durations. This is the map every later step is drawn on.',
      },
      {
        name: 'Read a role trust policy to find an assumable principal',
        what: 'Check who is allowed to call sts:AssumeRole on a target role.',
        command:
          'aws iam get-role --role-name TargetRole --query "Role.AssumeRolePolicyDocument"',
        impact:
          'If a principal you control is trusted, the role is yours. A bare `"Principal": "*"` with no condition means anyone who can reach the STS endpoint can try.',
      },
      {
        name: 'iam:CreatePolicyVersion to add yourself to a shared managed policy',
        what: 'Publish a new default version of a managed policy that other principals already have attached.',
        steps: [
          'List managed policies in scope and find one attached to a target role: `aws iam list-attached-role-policies --role-name TargetRole`.',
          'Fetch the current default version with `aws iam get-policy-version --policy-arn <arn> --version-id <id>`.',
          'Add a statement granting yourself the actions you need, then publish it as the default version.',
        ],
        impact:
          'The target role gains your permissions the moment the version becomes default. You never touched the role, its trust policy, or the resource in question.',
      },
      {
        name: 'iam:PassRole to make the cloud act as a privileged principal',
        what: 'Choose whose identity runs code, so the platform performs privileged actions on your behalf.',
        command:
          'aws lambda create-function --function-name runner \\\n  --runtime python3.12 --role arn:aws:iam::123456789012:role/DeployAdmin \\\n  --handler index.handler --zip-file fileb://payload.zip',
        impact:
          'Everything the passed role can do, executed from inside your code. The authorization check happens against the passed role, not against you.',
      },
      {
        name: 'Abuse a resource policy that grants cross-account access',
        what: 'Use a bucket, key or topic policy that names a principal you control.',
        steps: [
          'Collect resource policies: bucket policies, KMS key policies, SNS topic policies, SQS queue policies, Lambda resource policies.',
          'Check whether any of them name an account or principal that you can act as.',
          'Call the resource directly. No Allow in your own IAM policy is required.',
        ],
        impact:
          'Direct access to the resource — and often to everything reachable from it — with an identity that has no visible relationship to the account.',
      },
    ],
    cases: [
      {
        title: 'Root user credentials used to access a production account',
        source: 'Recurring pattern in published cloud incident retrospectives and breach write-ups',
        impact:
          'Root has full access and is not constrained by IAM. Because root sign-ins are rare in a healthy account, any root API activity is a high-confidence compromise signal and is frequently the first thing an attacker uses to enable everything else.',
        year: 2020,
      },
      {
        title: 'Wildcard trust on a role',
        source: 'Widely documented cloud misconfiguration class',
        impact:
          'A role trusted by `"Principal": {"AWS": "*"}` with no condition lets any AWS account attempt to assume it. Combined with a public repo or a leaked key, that is a direct path to the role\'s permissions.',
        year: 2023,
      },
    ],
  },
  detect: {
    body: `Identity attacks show up as *mismatches*: a principal doing something it never does, a policy changing hands, a session that looks like it came from somewhere unexpected.

Three fields carry most of the signal in a CloudTrail management event: \`userIdentity.type\` (IAMUser, AssumedRole, Root, IAMUserService, FederatedUser), \`userIdentity.arn\`, and \`sourceIPAddress\`. Add \`userIdentity.sessionContext.attributes.mfaAuthenticated\` to separate a human session from a programmatic one.

Log delivery matters. If your CloudTrail trail writes to CloudWatch Logs, the same fields become queryable directly. The queries below assume a trail delivering to a log group, and the same logic works in Athena against the raw S3 files.`,
    signals: [
      {
        signal: 'Root account identity used for an API call',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, sourceIPAddress, userAgent, eventSource\n| filter userIdentity.type = "Root"\n| stats count() by eventName, sourceIPAddress, userAgent`,
        note:
          'There is no legitimate reason for the root user to make API calls. Treat every one as an incident, not a configuration smell.',
      },
      {
        signal: 'A managed policy version created by an unexpected principal',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.policyArn, requestParameters.setAsDefault\n| filter eventName = "CreatePolicyVersion" or eventName = "SetDefaultPolicyVersion"\n| stats count() by userIdentity.arn, requestParameters.policyArn`,
        note:
          'Policy changes are how escalation avoids touching the target role. Baseline which principals legitimately publish policy versions.',
      },
      {
        signal: 'A trust policy rewritten',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.roleName\n| filter eventName = "UpdateAssumeRolePolicy"\n| stats count() by userIdentity.arn, requestParameters.roleName`,
        note:
          'Common in CI pipelines, which makes it noisy. Alert on the principal and the role combination, not on the event itself.',
      },
      {
        signal: 'Role assumed from an unexpected network source',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters.roleName\n| filter eventName = "AssumeRole" and errorCode = "AccessDenied"\n| stats count() by sourceIPAddress, requestParameters.roleName`,
        note:
          'Failed assumption attempts are attacker reconnaissance. A burst of AccessDenied against one role is a probing pattern, not a user error.',
      },
      {
        signal: 'Guardrail — roles assumable from outside the account',
        source: 'IAM Access Analyzer',
        query: `aws accessanalyzer list-analyzed-resources --resource-type ROLE --filter '{"Status":{"eq":["ERROR","WARNING"]}}'`,
        note:
          'Access Analyzer flags roles that grant access to principals outside the organization or account. Run it on a schedule and treat new findings as change tickets.',
      },
    ],
    posture: [
      'Enable CloudTrail management events in every region and deliver to a log archive account the workload account cannot write to.',
      'Turn on IAM Access Analyzer for the whole organization, not per account — findings are only useful if someone reviews them.',
      'Alert on `CreatePolicyVersion`, `SetDefaultPolicyVersion` and `UpdateAssumeRolePolicy` from any principal outside the identity team.',
      'Require MFA for every human session and surface `mfaAuthenticated` in your detection queries.',
      'Use a break-glass role with a hard alerting sink instead of leaving root credentials available.',
    ],
  },
  fix: {
    body: `Identity hardening in AWS is mostly subtraction. The default posture of a young account — root with access keys, a wildcard admin policy, inline policies on every user, roles trusted by anyone — is worse than any specific misconfiguration you will find later.

Work top-down. Root hygiene first, because it is the one identity no policy can constrain. Then the trust policies, because a trust policy is the most consequential document in the account and the least reviewed. Then permissions, then boundaries.

The order matters in practice: replacing root keys with an audited role means you now need a role whose trust policy is correct. Doing trust first is doing the hard thing first.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Delete the root access keys and enforce MFA on the root user',
        detail:
          'Root access keys are the classic cloud persistence mechanism: they survive password resets, work with every API, and ignore IAM. IAM Identity Center with an external IdP gives you the same administrative access with short sessions and a revocation path.',
        snippet: `aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE`,
        snippetLang: 'bash',
      },
      {
        priority: 'critical',
        action: 'Remove wildcard principals from every role trust policy',
        detail:
          'A trust policy naming `"Principal": {"AWS": "*"}` needs a condition to be safe, and the condition must be one you can enforce — `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID` or `aws:SourceIp`. Name the account instead wherever possible.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:role/DeployRole" },
    "Action": "sts:AssumeRole"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Replace the AdministratorAccess managed policy on human roles',
        detail:
          'Instead of a wildcard admin, give the human role only the actions their job needs, and give the job a permission boundary so a future over-broad attachment cannot widen it.',
        snippet: `{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": ["arn:aws:s3:::app-data", "arn:aws:s3:::app-data/*"]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Apply a permission boundary to every non-human principal',
        detail:
          'Boundaries cap the maximum permissions of machine identities — Lambda execution roles, CI deploy roles, node roles. They are the only control that survives someone attaching a permissive policy to your role later.',
      },
      {
        priority: 'high',
        action: 'Convert long-lived IAM users to IAM Identity Center role sessions',
        detail:
          'Session credentials expire, are tied to an IdP session, and can be revoked centrally. Access keys cannot be revoked without a rotation cycle that usually does not happen.',
      },
      {
        priority: 'medium',
        action: 'Scope sessions with session policies at assume time',
        detail:
          'A session policy can only narrow, so it is a safe way to hand a temporary, task-scoped set of permissions without editing the role. Use it for delegated administration and for break-glass workflows.',
      },
      {
        priority: 'medium',
        action: 'Turn on Access Analyzer and review findings on a schedule',
        detail:
          'Access Analyzer detects roles, policies and resources that grant access to principals outside your organization. It is the closest thing AWS has to a built-in trust audit.',
      },
      {
        priority: 'low',
        action: 'Set explicit MaxSessionDuration on roles that do not need long sessions',
        detail:
          'The account default is one hour for role sessions, but roles can be configured for up to twelve hours. Most workloads need fifteen minutes. Short sessions multiply the number of fresh assumptions an attacker must make, and each one is a detection opportunity.',
      },
    ],
  },
  checklist: [
    {
      id: 'idt-1',
      text: 'Confirm the root user has no access keys and MFA is enabled.',
      command:
        'aws iam list-access-keys --user-name <root-alias> && aws iam get-account-summary --query "Summary.{MFA:AccountMFAEnabled,Keys:AccessKeysPerUserQuota}"',
      expected: 'An empty key list for the root alias and AccountMFAEnabled is true.',
    },
    {
      id: 'idt-2',
      text: 'List every role in the account and check its trust policy for a wildcard principal.',
      command:
        'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {}',
      expected:
        'No role trusts "Principal": "*" without a condition, and no role trusts an external account without a documented reason.',
    },
    {
      id: 'idt-3',
      text: 'Simulate the effective permissions of a low-privilege role before you rely on it.',
      command:
        'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/DevRole --action-names s3:PutObject iam:PassRole --resource-arns arn:aws:s3:::app-data/*',
      expected:
        'The simulation returns only the actions you expect, and PassRole is absent unless the role is a deployment identity.',
    },
    {
      id: 'idt-4',
      text: 'Find every principal that can change a policy or a trust relationship.',
      command:
        'aws iam list-policies --scope Local --query "PolicyList[].Arn" --output text | xargs -I{} aws iam list-entities-for-policy --policy-arn {}',
      expected:
        'Only the identity-governance principals attach or modify policies.',
    },
    {
      id: 'idt-5',
      text: 'Check whether any local managed policy grants administrative access.',
      command:
        'aws iam list-policies --scope Local --query "PolicyList[?PolicyName==`AdministratorAccess` || PolicyName==`PowerUserAccess`].Arn"',
      expected:
        'Zero or a very short list, each with a documented owner and a compensating boundary.',
    },
    {
      id: 'idt-6',
      text: 'Confirm the account identity baseline by checking who you currently are.',
      command: 'aws sts get-caller-identity',
      expected:
        'The account matches the one you expect, and the arn is a role or user you recognise rather than something you have never seen.',
    },
  ],
  references: [
    { label: 'AWS IAM policy evaluation logic', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html' },
    { label: 'AWS IAM policy types', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_types.html' },
    { label: 'AWS IAM Identity Center', url: 'https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html' },
    { label: 'AWS IAM Access Analyzer', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html' },
  ],
  updated: '2026-11-18',
}
