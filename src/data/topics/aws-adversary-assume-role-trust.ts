import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/adversary/assume-role-trust',
  title: 'Cross-account trust and AssumeRole',
  cloud: 'aws',
  stage: 'adversary',
  track: 'Identity & access',
  summary:
    'How trust between AWS accounts is actually established, and how a single condition on a trust policy turns that trust into a path across the estate.',
  duration: '30 min',
  difficulty: 4,
  prerequisites: ['aws/foundation/identity-and-trust'],
  enables: [
    'aws/redteam/iam-privilege-escalation',
    'aws/expert/multi-account-estate',
  ],
  mentalModel:
    'A trust policy is not about what the role can do — it is about who is allowed to become the role. IAM answers the first question, the trust policy answers the second, and an attacker who controls the second has the first for free.',
  concept: {
    body: `AWS has no concept of a global administrator. Every account is its own island with its own IAM, its own root user, its own audit trail. Cross-account access is the only way between islands, and it is built on one mechanism: the role trust policy.

**A role trust policy answers one question.** Given a principal, is that principal allowed to assume this role? The evaluation is separate from, and happens before, the question of what the role's permissions policy allows. This is why a trust-policy flaw is a complete compromise on its own — you do not need the role to be permissive, only to be assumable.

The shape of a trust policy is small:

\`\`\`json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "aws:PrincipalOrgID": "o-abc123" }
    }
  }]
}
\`\`\`

Three details carry most of the risk:

- **\`Principal: { "AWS": "arn:aws:iam::ACCOUNT:root" }\`** delegates the decision to the other account. The root user of that account cannot itself assume the role, but *any principal in that account with permission to assume it* can — and that includes a role with \`sts:AssumeRole\` on a wildcard, or a federated identity that has been given it. This indirection is the single most misunderstood part of cross-account trust: naming an account root is not naming a user.

- **\`Principal: "*"\` with a condition** is the second most misunderstood. It looks dangerous and is often safe; it looks safe and is often dangerous. The correct question is not "is the principal a wildcard" but "does the condition bind it to something an attacker cannot hold". \`aws:PrincipalArn\` pinned to a specific role ARN is strong. \`aws:PrincipalOrgID\` pinned to your organisation is strong against outsiders and weak against anyone who can create a principal inside your organisation.

- **The condition on \`sts:ExternalId\`** is the third-party mechanism. The third party generates a random value, puts it in its own trust, and passes it when assuming. It works because the third party cannot be tricked into assuming a role for somebody else. It is still the standard answer for SaaS vendors and it is still widely misconfigured.

**Federation is the other door.** OIDC and SAML trust policies let an external identity provider supply the principal identity, and the \`sts:RoleSessionName\` becomes the role session name. Web identity federation — \`sts:AssumeRoleWithWebIdentity\` — is the basis for GitHub Actions, GitLab CI, and every other CI system running in AWS, and it is where a lot of real estates have quietly accumulated broad trust.

**The roles involved.** \`sts:AssumeRole\` returns a session for a role in the same or another account. \`sts:AssumeRoleWithSAML\` and \`sts:AssumeRoleWithWebIdentity\` are separate actions with separate trust policies, but the same underlying concept. The session carries the role's permissions policy, minus anything denied by an SCP in either account.`,
    keyPoints: [
      'Trust is evaluated before permissions. A role you can assume is a role you can use.',
      'Naming an account root in a trust policy delegates the decision to that account — it does not restrict it to the root user.',
      'A wildcard principal with a strong condition is safer than a specific principal with no condition.',
      'The session in the target account is what carries the permissions, and it is bounded by SCPs in the target account.',
      'sts:AssumeRoleWithWebIdentity and sts:AssumeRoleWithSAML have their own trust policies and their own misconfigurations.',
      'ExternalId exists so a third party cannot be used as a confused deputy; it is a shared secret, not an authorisation control.',
    ],
    misconceptions: [
      {
        claim: 'Specifying the root user of the other account limits who can assume the role.',
        truth:
          'The root user is a delegation, not a restriction. Any principal in that account that has sts:AssumeRole permission on the target role can use it — including roles, federated users, and CI identities you did not think of as external.',
      },
      {
        claim: 'A wildcard principal means anyone on the internet can assume the role.',
        truth:
          'The wildcard is bounded by the Condition block. What matters is whether the condition keys bind the request to something an attacker cannot produce. aws:PrincipalOrgID inside your organisation binds it to anyone who can create a principal inside your organisation — which is a much weaker guarantee than it looks.',
      },
      {
        claim: 'Assuming a role across accounts is always logged in the source account.',
        truth:
          'The sts:AssumeRole call is logged in the source account, and a separate AssumeRole event appears in the target account. If you only monitor one of them, half the event is invisible to you.',
      },
    ],
  },
  attack: {
    body: `The attack is a search. You are looking for a role in some other account that your current principal is allowed to assume, and that role is more powerful than what you already hold.

The search has three inputs: the trust policies you can read, the identity you currently hold, and the conditions you might be able to satisfy.

The conditions are where the work is. A trust policy conditioned on \`aws:PrincipalOrgID\` can be satisfied by any principal you can create in that organisation — and creating a principal is often easier than it should be. A trust policy conditioned on \`aws:PrincipalArn\` requires you to already hold that exact role, which is much harder, but a role with \`sts:AssumeRole\` on \`*\` lets you become it first.

A trust policy conditioned on \`sts:ExternalId\` requires knowing a secret that the third party generated. This is the control that actually works against a confused deputy, and it is why the "external ID" pattern shows up in every serious cross-account integration.

The final move is always the same: assume the role, enumerate what the new session can do, and look for the next trust relationship outward.`,
    techniques: [
      {
        name: 'Enumerate roles you can assume',
        what: 'Read every role trust policy in reach and find the ones your principal satisfies.',
        command:
          'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {}',
        impact:
          'A complete map of which roles in this account are reachable, and by whom. The trust policy is where the answer is.',
      },
      {
        name: 'Test whether you can actually assume a role',
        what: 'Attempt the assumption and read the error message, which tells you exactly why it failed.',
        command:
          'aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Target \\\n  --role-session-name probe --duration-seconds 900',
        impact:
          'A successful call hands you the target role\'s permissions. A failed call leaks the condition that blocked you, which is how you work out what to satisfy next.',
      },
      {
        name: 'Satisfy an aws:PrincipalOrgID condition',
        what:
          'Create a principal inside the trusted organisation and then assume the role as that principal.',
        steps: [
          'Read the trust policy and confirm it is conditioned on aws:PrincipalOrgID rather than a specific ARN.',
          'Create a role in the target organisation with sts:AssumeRole permission on the target role.',
          'Assume the target role using that new role\'s session.',
          'If you cannot create a role in that organisation, find an existing principal that can.',
        ],
        impact:
          'Cross-organisation access, because the condition was satisfied by membership rather than by identity.',
      },
      {
        name: 'Use sts:AssumeRoleWithWebIdentity',
        what:
          'Exchange a web identity token for a role session when the trust policy allows federated access.',
        command:
          'aws sts assume-role-with-web-identity --role-arn arn:aws:iam::123456789012:role/CIRole \\\n  --role-session-name ci --web-identity-token file://token.txt',
        impact:
          'If a CI trust policy is broad, a forged or stolen OIDC token becomes a role session in the account.',
      },
      {
        name: 'Pivot outward from a trusted role',
        what:
          'Once inside a role, read its own outbound trust relationships and repeat.',
        steps: [
          'From the new session, list the roles it can assume.',
          'Read those roles\' trust policies for further reachable principals.',
          'Prefer roles that are assumable from a different organisation or that carry more privilege.',
        ],
        impact:
          'One hop in the trust graph becomes three, and the estate-level blast radius is nothing like the single-account view suggests.',
      },
    ],
    cases: [
      {
        title: 'Trust policy with an AWS account principal used as a wide-open door',
        source: 'Recurring pattern across cloud bug bounty programs and public breach write-ups',
        impact:
          'A trust policy naming an account root is common in multi-account estates, and the delegation is rarely understood by the teams that wrote it. In the recurring pattern, a low-privilege role in the trusting account carries sts:AssumeRole on a wildcard and thereby reaches the target account\'s administrative role.',
      },
      {
        title: 'Over-broad CI trust policy',
        source: 'Widely documented class of CI/CD misconfiguration',
        impact:
          'A web identity trust policy that does not pin the subject claim lets any identity from the configured issuer assume the role. In the recurring pattern, that includes an account created by an attacker on the same identity provider.',
      },
    ],
  },
  detect: {
    body: `The signal is the assumption itself, and the context is what makes it interesting. Role assumption is normal in a multi-account estate; it becomes a finding when the session does something the role has never done, or when the source is somewhere new.

Two accounts log the event, and you need both. The \`sts:AssumeRole\` call appears in the source account with \`eventName = AssumeRole\`. The target account logs its own \`AssumeRole\` event, where \`userIdentity.type\` is \`AssumedRole\` and \`sessionContext.sessionIssuer.arn\` names the role that was assumed. The second view is the one that tells you who actually used the credentials.

The strongest individual signal is an assumption into a role that has not been assumed recently, or by a principal that has never assumed it before.`,
    signals: [
      {
        signal: 'Role assumed across account boundaries',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| where userIdentity.type == "AssumedRole"\n| stats count() by requestParameters.roleName, userIdentity.arn, sourceIPAddress\n| sort count desc`,
        note:
          'Baseline this. In a healthy estate a small set of roles accounts for most of the volume, and the tail is where the interesting activity is.',
      },
      {
        signal: 'A session issuer that has not assumed the role before',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| stats dc(userIdentity.arn) as callers by requestParameters.roleName\n| where callers <= 2\n| sort callers asc`,
        note:
          'A role with one or two distinct callers is a candidate for a new one appearing.',
      },
      {
        signal: 'Trust policy modified',
        source: 'CloudTrail — management events',
        query: `eventName=UpdateAssumeRolePolicy OR eventName=CreateRole\n| where requestParameters.roleName != ""\n| stats count() by userIdentity.arn, requestParameters.roleName`,
        note:
          'Trust changes are the prerequisite for the attack, so alerting here catches it before the assumption rather than after.',
      },
      {
        signal: 'ExternalId or condition used in an unexpected assumption',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| where requestParameters.externalId != ""\n| stats count() by requestParameters.roleName, requestParameters.externalId`,
        note:
          'If ExternalId is in use, the value should be stable per integration. A new value appearing means a new integrator, or a new guess.',
      },
      {
        signal: 'Guardrail — restrict who can assume roles',
        source: 'SCP / permission boundary',
        query: `SCP Deny: sts:AssumeRole on roles that are not tagged as assumable-from-tagged-principals`,
        note:
          'The most effective control. Most estates have dozens of roles and no rule about who may assume them.',
      },
    ],
    posture: [
      'Log CloudTrail to a central account so trust changes in a compromised account are still visible.',
      'Run IAM Access Analyzer across every account on a schedule and review external-access findings.',
      'Maintain an inventory of every cross-account trust relationship and the principal that satisfies it.',
      'Require MFA for every human principal, so a stolen key is not sufficient on its own.',
      'Use a distinct ExternalId per third-party integration, never shared across vendors.',
    ],
  },
  fix: {
    body: `The fix is to replace broad delegation with explicit identity wherever you can, and to make the exception cases deliberate.

Order matters. The first item breaks the most chains; the later ones are hygiene that keeps the estate navigable.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Replace account-root principals with specific role ARNs in trust policies',
        detail:
          'Naming the account root delegates the decision to that account\'s IAM, which means every principal there with sts:AssumeRole permission is in scope. Naming a specific role narrows the set to that role and its session issuer.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:role/DeployRole"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "o-abc123",
        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/DeployRole"
      }
    }
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'critical',
        action: 'Constrain sts:AssumeRole on principals that do not need it',
        detail:
          'A wildcard sts:AssumeRole on a role turns any trust relationship into a reachable path. Scope it to the specific role ARNs the principal is meant to assume.',
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
        action: 'Pin the subject claim on CI web identity trust policies',
        detail:
          'A web identity trust policy that checks only the issuer accepts any identity from that issuer, including one an attacker created. Pin the subject claim to the specific repository, project or workflow path.',
        snippet: `{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
    }
  }
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Use a distinct ExternalId for every third-party integration',
        detail:
          'ExternalId is the control that stops a third party being used as a confused deputy. It works per integration: a shared value across vendors means compromising one integration exposes all of them.',
      },
      {
        priority: 'medium',
        action: 'Require MFA in the trust condition for human principals',
        detail:
          'A condition on aws:MultiFactorAuthPresent prevents a stolen session token being used directly, and forces the attacker to satisfy MFA as well.',
        snippet: `{
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}`,
        snippetLang: 'json',
      },
      {
        priority: 'medium',
        action: 'Bound the session duration on roles that cross accounts',
        detail:
          'A role with a one-hour maximum session limits how long a stolen credential stays useful and forces the attacker to re-execute the chain, which multiplies the chances of detection.',
      },
      {
        priority: 'low',
        action: 'Enable IAM Access Analyzer and review external access findings monthly',
        detail:
          'Access Analyzer flags roles that grant access to principals outside the account. It is the only automated way to keep the trust inventory honest as the estate changes.',
      },
    ],
  },
  checklist: [
    {
      id: 'trust-1',
      text: 'List every role in the account whose trust policy names an account root rather than a specific role ARN.',
      command:
        'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {}',
      expected:
        'Every result either names a specific role ARN, or you can name the delegation you intended and why it is safe.',
    },
    {
      id: 'trust-2',
      text: 'Find every trust policy containing a wildcard principal.',
      command:
        'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {} | grep -l "\\"Principal\\": *{\\"AWS\\": *\\"\\*"',
      expected:
        'Every wildcard is paired with a condition that binds it to something an attacker cannot hold.',
    },
    {
      id: 'trust-3',
      text: 'Check whether your current principal can assume each role in the account.',
      command:
        'aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Candidate --role-session-name probe --duration-seconds 900',
      expected:
        'Only roles you expect. Any unexpected success is a finding worth writing up immediately.',
    },
    {
      id: 'trust-4',
      text: 'Find every web identity trust policy and confirm the subject claim is pinned.',
      command:
        'aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[].Arn" --output text | xargs -I{} aws iam get-open-id-connect-provider --open-id-connect-provider-arn {}',
      expected:
        'Every provider has a sub condition that names a specific repository, project or subject.',
    },
    {
      id: 'trust-5',
      text: 'Confirm AssumeRole events are captured in the target account, not only the source.',
      command:
        'aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --max-results 20',
      expected:
        'Both accounts show the assumption. Monitoring only the source account hides half the event.',
    },
    {
      id: 'trust-6',
      text: 'Review the estate-wide trust inventory.',
      command:
        'aws accessanalyzer list-analyzed-resources --resource-type ROLE --filter \'{"Status":{"eq":["ERROR","WARNING"]}}\'',
      expected:
        'A short list you can justify out loud, with a named owner for each entry.',
    },
  ],
  references: [
    { label: 'AWS IAM — role trust policy', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role.html' },
    { label: 'AWS IAM — cross-account access', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html' },
    { label: 'AWS STS — AssumeRoleWithWebIdentity', url: 'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html' },
    { label: 'AWS IAM — confused deputy and ExternalId', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html' },
  ],
  updated: '2026-11-22',
}
