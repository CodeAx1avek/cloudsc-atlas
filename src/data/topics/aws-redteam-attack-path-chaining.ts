import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/redteam/attack-path-chaining',
  title: 'Chaining cloud weaknesses into a path',
  cloud: 'aws',
  stage: 'redteam',
  track: 'Operations',
  summary:
    'Turning a list of separate findings into one path to a crown-jewel objective — and finding the link that breaks the chain.',
  duration: '35 min',
  difficulty: 5,
  prerequisites: [
    'aws/adversary/iam-policy-evaluation',
    'aws/adversary/assume-role-trust',
    'aws/redteam/iam-privilege-escalation',
  ],
  enables: ['aws/expert/cloudtrail-forensics'],
  mentalModel:
    'A vulnerability report tells you what is wrong with a thing. An attack path tells you what to do next. The difference is that a path has a direction and an endpoint — and the direction is usually the trust edge, not the vulnerability.',
  concept: {
    body: `A finding is a fact about a configuration. A path is a sequence of facts where each one gives you the ability to cause the next.

The thing that makes cloud attack paths different from traditional ones is that the graph is made of **relationships**, not of vulnerabilities. A misconfigured S3 bucket is a finding. An IAM role that can read that bucket, and a trust policy that lets you become that role, and a role that can create an EC2 instance with that role attached — that is a path. Every step is a configuration choice that someone made, and every step is individually defensible.

**The four edge types.** Almost every cloud path is built from these:

- **Credential edges.** You can obtain a credential that belongs to someone else. Metadata service, IAM Access Analyzer, a leaked key, a token in a CI log.
- **Privilege edges.** Your current credential can obtain a more powerful credential. \`iam:PassRole\`, \`sts:AssumeRole\`, \`lambda:CreateFunction\`, \`cloudformation:CreateStack\`.
- **Execution edges.** You can run code somewhere that has a different identity. \`ec2:RunInstances\`, \`ecs:RunTask\`, \`codebuild:CreateProject\`, \`sagemaker:CreateNotebookInstance\`.
- **Data edges.** You can reach a store that holds something you want, and the store's contents are the objective. A bucket, a database, a snapshot, a secret.

**Where paths break.** The defensive question is never "is this configuration safe?" but "which edge does this configuration remove?" An SCP that denies \`iam:PassRole\` removes an entire class of privilege edge, regardless of how many individual permissions are misconfigured. A VPC endpoint policy that denies a service removes the data edge. A trust policy that pins \`aws:PrincipalArn\` removes the credential edge into that role.

This is why the strongest remediation is usually not the one that fixes the individual finding but the one that severs the edge. Fixing an over-broad permission on one role is good. Denying \`iam:PassRole\` across the account breaks every path that used it.

**The graph is bigger than the account.** The edges that cross account boundaries — trust policies, resource policies, S3 bucket policies that grant access to a role in another account — are the ones people do not draw, because they require reading more than one account. In a multi-account estate this is where the real paths live.

**Chains are often short.** It is worth saying plainly: in a mature cloud account, most real paths are two or three edges long, not eight. A single over-broad role plus a single trust relationship is frequently the whole chain. Length is not the measure of severity — reachability of the objective is.`,
    keyPoints: [
      'Paths are made of trust edges, not vulnerabilities. Each edge is a configuration choice.',
      'The four edge types are credential, privilege, execution and data. Every cloud path is a sequence of them.',
      'The best remediation severs an edge for a whole class of paths rather than fixing one instance of a finding.',
      'Cross-account edges are the ones most often missing from the picture, because they need more than one account to read.',
      'Most real paths are two or three edges long. Severity comes from the objective reached, not the chain length.',
      'A finding that cannot be connected to anything else is usually lower priority than a modest finding that can.',
    ],
    misconceptions: [
      {
        claim: 'Findings should be prioritised by severity score.',
        truth:
          'CVSS describes the impact of the bug, not the reachability of your objective from it. A medium finding that opens a path to production data beats a critical finding in a dev account with nothing on the path.',
      },
      {
        claim: 'Fixing every finding eliminates the paths.',
        truth:
          'Not necessarily. A path made of four individually-permitted actions is not a set of misconfigurations to fix. Sometimes the only real fix is a guardrail that denies a whole edge type.',
      },
      {
        claim: 'The path is the same from every starting point.',
        truth:
          'It is not. The same misconfiguration is a dead end from one principal and the first step of a chain from another. Paths are directional and depend on the starting identity.',
      },
    ],
  },
  attack: {
    body: `The method is: fix a starting identity, enumerate what it can reach, and follow edges until you either reach the objective or run out of edges. Then look for a shorter path from a different starting point.

The practical trick that separates a good cloud assessment from a checklist is **starting from the objective backwards**. Most people start from the entry point — a compromised key — and enumerate forward. If you instead name the objective ("read the production customer database") and work backwards through the data edge, you find the narrow set of roles that can reach it, then work outward from those to find who can become them.

The second trick is to track **not just what is reachable but what is silent**. A path that uses only read operations — \`s3:GetObject\`, \`secretsmanager:GetSecretValue\`, \`ssm:GetParameter\` — leaves a much smaller trail than one that creates something. The read-only path is often the more valuable finding because it is more likely to be missed in review.

The third is to check whether the chain can be **shortened**. Often the long path you found is because you assumed a boundary that does not exist. If a role can create a Lambda function with any execution role, then every role that trusts that identity is one step away, not three.`,
    techniques: [
      {
        name: 'Work backwards from the objective',
        what:
          'Start from the data you want and find the smallest set of identities that can reach it.',
        steps: [
          'Name the objective precisely: which bucket, which table, which secret, which account.',
          'Use IAM Access Analyzer or a policy query to find the roles with read access to that resource.',
          'For each such role, note the identity that can assume it.',
          'Recurse outward until you reach a principal an attacker plausibly holds.',
        ],
        impact:
          'A ranked list of paths ordered by how many steps they are from a plausible entry point.',
      },
      {
        name: 'Build the permission graph',
        what:
          'Enumerate, for each identity you hold, the actions that mint or change another identity.',
        command:
          'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/Target \\\n  --action-names iam:PassRole iam:CreatePolicyVersion iam:UpdateAssumeRolePolicy \\\n  iam:AttachRolePolicy iam:CreateAccessKey lambda:CreateFunction cloudformation:CreateStack',
        impact:
          'The privilege edges, enumerated. Every action on this list is a potential edge from one identity to another.',
      },
      {
        name: 'Find the execution edges',
        what:
          'Identify the services that run code with a role you choose.',
        command:
          'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam simulate-principal-policy \\\n  --policy-source {} --action-names ec2:RunInstances ecs:RunTask lambda:CreateFunction codebuild:CreateProject sagemaker:CreateNotebookInstance',
        impact:
          'The services that let you run code as someone else. Any of them converts a low-privilege foothold into a high-privilege one.',
      },
      {
        name: 'Cross the account boundary',
        what:
          'Read the trust policies that point into other accounts and follow the chain there.',
        steps: [
          'List every role in the account and read its trust policy.',
          'Identify the roles assumable from another account.',
          'Assume one and repeat the same enumeration in the target account.',
          'Record the full chain, including which account each edge lives in.',
        ],
        impact:
          'The cross-account edges. These are the ones the account owner cannot see and the ones that most often reach production.',
      },
      {
        name: 'Prefer the read-only path',
        what:
          'Look for a chain of read actions that reaches the objective without modifying anything.',
        steps: [
          'List every read action available on the objective resource.',
          'Follow the roles that hold them back to their assumable principals.',
          'Check whether any of those reads is logged, and with what detail.',
        ],
        impact:
          'A path that leaves almost no trail. This is usually the finding that survives remediation longest.',
      },
      {
        name: 'Break the chain at the weakest edge',
        what:
          'Find the single control that, if present, would have stopped the whole path.',
        steps: [
          'Write out the chain as a sequence of edges.',
          'For each edge, ask what a guardrail denying that action would have done.',
          'Check whether that guardrail exists.',
          'The missing guardrail is the real finding, not the individual misconfiguration.',
        ],
        impact:
          'A single control that removes an entire class of paths, rather than a list of individual fixes.',
      },
    ],
    cases: [
      {
        title: 'Public bucket to cross-account role to production data',
        source: 'Recurring pattern across cloud bug bounty programs and public breach analyses',
        impact:
          'The recurring shape: a bucket is public or grants access to a wide principal, a role in the same account can read it, and that role is assumable from elsewhere. Each step is individually defensible. Together they read production data.',
      },
      {
        title: 'CI identity to deployment role to data access',
        source: 'Widely documented supply chain attack class',
        impact:
          'In the recurring pattern, a CI workflow token is over-trusted, the deployment role it assumes has iam:PassRole, and a workload role with access to a secret store is passed to a function the attacker controls. The chain runs from a source code change to production secrets.',
      },
    ],
  },
  detect: {
    body: `Chain detection is not a single rule. It is the observation that each edge in a chain is individually unremarkable, and the chain as a whole is not.

The practical approach is to build detections around the *transitions*: the moment a low-privilege identity becomes a high-privilege one. That is where the chain has its narrowest waist and where the evidence is most concentrated.

The second approach is behavioural: a role that has never read a particular secret before, or a session that touches a resource family it has never touched. In a chain, the final step is almost always the first time the identity touches that resource — because the attacker is going somewhere the identity has no business going routinely.

The third is the write-up. When you find a chain, the remediation that matters is the missing guardrail, and the evidence that supports it is the individual edge. That makes the detection work and the remediation work the same work.`,
    signals: [
      {
        signal: 'Privilege transition — an identity that mints a new credential',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole OR eventName=CreateAccessKey OR eventName=UpdateAssumeRolePolicy OR eventName=CreatePolicyVersion\n| where userIdentity.type != "AssumedRole"\n| stats count() by userIdentity.arn, eventName\n| sort count desc`,
        note:
          'The narrowest waist in most chains. A principal that normally does not assume roles suddenly doing so is worth a page.',
      },
      {
        signal: 'PassRole called against a role the caller has never used',
        source: 'CloudTrail — management events',
        query: `eventName=PassRole\n| stats dc(userIdentity.arn) as callers by requestParameters.roleName\n| where callers <= 2\n| sort callers asc`,
        note:
          'First-time PassRole is a strong signal, because most principals never pass roles at all.',
      },
      {
        signal: 'A session touching a resource family it has never touched',
        source: 'CloudTrail — data events',
        query: `eventName=GetSecretValue OR eventName=GetObject OR eventName=GetParameter\n| stats dc(userIdentity.arn) as actors by resources\n| filter actors <= 2\n| sort actors asc`,
        note:
          'In a chain, the final step is the first time that identity touches that resource. This is where the objective is actually reached.',
      },
      {
        signal: 'Role assumed across account boundaries from a new source',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| where sourceIPAddress not like "10." and sourceIPAddress not like "172.16." and sourceIPAddress not like "192.168."\n| stats count() by requestParameters.roleName, sourceIPAddress\n| sort count desc`,
        note:
          'Internal assumption from an external source address. Restrict to the roles that should never be assumed from outside.',
      },
      {
        signal: 'Guardrail — deny the edge, not the finding',
        source: 'SCP / permission boundary',
        query: `SCP Deny: iam:PassRole, iam:CreatePolicyVersion, iam:UpdateAssumeRolePolicy on non-deployment identities`,
        note:
          'A deny on the edge type breaks every chain that used it, present and future.',
      },
    ],
    posture: [
      'Build a graph of every role and what can assume it, and review it rather than the individual permissions.',
      'Alert on privilege transitions, not on individual sensitive calls.',
      'Enable CloudTrail data events for the resource types that hold the objective.',
      'Keep a written inventory of cross-account trust relationships.',
      'Review which identities could reach each crown-jewel resource, and shorten the list.',
    ],
  },
  fix: {
    body: `The remediation that matters is the one that severs an edge. Fixing individual findings along a chain leaves the chain available for the next misconfiguration.

So the first job is to identify which edge is the weakest — the one where a single denial would have stopped the whole path. Usually that is \`iam:PassRole\`, because it is the pivot between "can run code" and "can run code as someone else".

The second job is to shorten the paths that survive. Every additional edge is an opportunity for the chain to be noticed.

The third job, and the one most people skip, is to write down the chain. A written path with the missing guardrail named is the artefact that changes the estate; an itemised list of findings does not.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Deny the privilege edge that the chain pivots on',
        detail:
          'In most chains the pivot is iam:PassRole, because it converts "I can run code" into "I can run code as someone else". Denying it for non-deployment identities removes every chain that used that pivot, including chains you have not found yet.',
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
        action: 'Scope the role that holds access to the objective',
        detail:
          'The role that can read the crown-jewel resource is the node every chain terminates at. Reducing it to the specific actions and resources required removes the endpoint for every path at once.',
      },
      {
        priority: 'high',
        action: 'Remove the cross-account edge that makes the path reachable',
        detail:
          'If a chain crosses accounts through a trust policy, that trust policy is the edge. Narrow the principal from an account root to a specific role ARN, or add the aws:PrincipalArn condition.',
      },
      {
        priority: 'high',
        action: 'Put a permission boundary on the identities at the start of the chain',
        detail:
          'A boundary caps the maximum permissions a principal can ever hold, including permissions added later by someone else. It is the control that survives a mistake in the permission itself.',
      },
      {
        priority: 'medium',
        action: 'Separate deployment permissions from day-to-day permissions',
        detail:
          'Deployments need PassRole and CreateFunction. Humans and CI checkouts for feature branches do not. Splitting them means a compromised developer session cannot become a deployment.',
      },
      {
        priority: 'medium',
        action: 'Enable CloudTrail data events for the objective resources',
        detail:
          'Without data events, the final step of the chain — actually reading the data — leaves no trace. This is the control that makes chain detection possible.',
      },
      {
        priority: 'low',
        action: 'Write the path down and re-test it quarterly',
        detail:
          'Chains are built from configuration that changes constantly. A written path with a named owner and a re-test date is the only way to know it is still closed.',
      },
    ],
  },
  checklist: [
    {
      id: 'chain-1',
      text: 'Name the objective and find every identity with read access to it.',
      command:
        'aws accessanalyzer list-analyzed-resources --resource-type S3_BUCKET --filter \'{"Status":{"eq":["ERROR","WARNING"]}}\'',
      expected:
        'A short list. Each entry should have an owner who can say why that role needs the access.',
    },
    {
      id: 'chain-2',
      text: 'Enumerate every role that can reach the objective, and who can assume each one.',
      command:
        'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {}',
      expected:
        'For each role that holds the objective access, the set of principals that can assume it is small and explicable.',
    },
    {
      id: 'chain-3',
      text: 'Check whether any principal can pass the roles that matter.',
      command:
        'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/Target \\\n  --action-names iam:PassRole',
      expected:
        'Only deployment identities can pass roles. Any other answer is the pivot of a chain.',
    },
    {
      id: 'chain-4',
      text: 'Check whether a low-privilege principal can run code as a privileged one.',
      command:
        'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/LowPriv \\\n  --action-names lambda:CreateFunction ec2:RunInstances ecs:RunTask cloudformation:CreateStack',
      expected:
        'Denied for every execution action that would let the principal choose its own execution role.',
    },
    {
      id: 'chain-5',
      text: 'Find the cross-account trust edges into this account.',
      command:
        'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {} | grep -B2 -A8 "Principal"',
      expected:
        'Every external principal is a specific role ARN, not an account root, and the role is not one you would not expect.',
    },
    {
      id: 'chain-6',
      text: 'Confirm data events are on for the resource that holds the objective.',
      command:
        'aws cloudtrail describe-event-data-selectors --query "EventDataSelectors[].DataResources" --output text',
      expected:
        'The objective bucket, table or parameter store appears in the selectors, not just the management events.',
    },
    {
      id: 'chain-7',
      text: 'Re-test the whole chain from a clean account to confirm it is closed.',
      command:
        'aws sts assume-role --role-arn arn:aws:iam::123456789012:role/SecondHop --role-session-name probe --duration-seconds 900',
      expected:
        'The second hop is denied. If it succeeds, the chain is still open regardless of what the individual fixes say.',
    },
  ],
  references: [
    { label: 'AWS IAM — policy evaluation logic', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html' },
    { label: 'AWS CloudTrail — event data selectors', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events.html' },
    { label: 'AWS IAM Access Analyzer — findings', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html' },
    { label: 'MITRE ATT&CK — cloud matrix', url: 'https://attack.mitre.org/matrices/cloud/' },
  ],
  updated: '2026-11-22',
}
