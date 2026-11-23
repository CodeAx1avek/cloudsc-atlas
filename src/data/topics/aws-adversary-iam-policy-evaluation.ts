import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/adversary/iam-policy-evaluation',
  title: 'Evaluating IAM policies in practice',
  cloud: 'aws',
  stage: 'adversary',
  track: 'Identity & access',
  summary:
    'Turning a pile of JSON policy documents into a correct answer about what a principal can actually do.',
  duration: '35 min',
  difficulty: 4,
  prerequisites: [
    'aws/foundation/identity-and-trust',
    'aws/adversary/credential-discovery',
  ],
  enables: [
    'aws/adversary/assume-role-trust',
    'aws/redteam/iam-privilege-escalation',
    'aws/redteam/attack-path-chaining',
  ],
  mentalModel:
    'Effective permissions are not stored anywhere in AWS. They are recomputed on every single API call from five separate inputs, and the policy document in the console is only one of the five.',
  concept: {
    body: `AWS does not keep a permission list for a principal. When you call \`s3:GetObject\`, the service asks IAM to answer one question: is this principal allowed to perform this action on this resource? The answer is computed on the spot from five inputs, and only one of them is the identity policy you can read in the console.

**The five inputs.**

1. **Identity-based policies** — attached to users, groups, roles. Multiple policies attached to the same principal are combined. This is the only input that grants access on its own.
2. **Resource-based policies** — attached to the resource (an S3 bucket policy, a KMS key policy, a role trust policy, a Lambda resource policy). They also grant access, and they are unioned with the identity policy for that resource.
3. **Permissions boundary** — a hard ceiling on what the principal can ever hold. It intersects; it never grants.
4. **Session policy** — passed at \`sts:AssumeRole\` time via \`--policy\`. It also intersects and never grants.
5. **Service control policies** — the organizational ceiling. Also intersects, also never grants.

**The evaluation itself.** The order matters:

- If an applicable **explicit Deny** exists anywhere — identity policy, resource policy, boundary, session policy or SCP — the request is denied. Deny always wins, everywhere, with no exceptions.
- Otherwise, if an applicable **explicit Allow** exists in the identity policy *or* in the resource policy for that resource, the request is allowed.
- Otherwise it is an **implicit deny**.

So the arithmetic is: allows are unioned, denials are unioned, and one denial anywhere wins. That is why \`"Action": "*", "Resource": "*"\` in one statement does not make a principal unrestricted if a boundary or an SCP denies a single action, and why a bucket policy that allows a principal works even when the principal's IAM policy says nothing at all.

**Conditions are part of the permission, not a decoration.** A statement with \`"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}\` is only an allow for requests where that condition key resolves to that value. A condition on a key the service cannot resolve (for example \`aws:PrincipalOrgID\` on a request with no organizational principal) fails the statement — the condition is not satisfied, so there is no allow.

**\`NotAction\` and \`NotPrincipal\` invert the whole statement.** \`"Effect": "Allow", "NotAction": "iam:*"\` means "allow everything except IAM", which is a very different thing from what it looks like. These are the two most common sources of a policy that looks narrow and is not.

**The result is per-resource, not per-principal.** \`"s3:GetObject", "Resource": "*"\` is not a flat grant — it grants on every bucket in the account *and* every bucket you can reach from another account. When you evaluate, always hold the resource ARN in mind.`,
    keyPoints: [
      'Effective permissions are computed at request time from identity policy, resource policy, boundary, session policy and SCP.',
      'An explicit Deny in any applicable source wins. There is no allow that overrides it.',
      'Identity policies and resource policies are unioned; boundaries, session policies and SCPs intersect.',
      'A condition key that cannot be resolved does not fail open. The statement simply does not apply.',
      'NotAction and NotPrincipal invert a statement and are the usual cause of a policy that reads narrow but grants broadly.',
      'Service-side authorization is a further layer. An IAM Allow does not make an otherwise-forbidden action legal.',
    ],
    misconceptions: [
      {
        claim: 'If IAM allows the action, the call succeeds.',
        truth:
          'IAM is one input. An SCP, a permission boundary or a session policy can deny an action that IAM allows, and a resource policy can grant an action that IAM says nothing about. There is also a service layer — several AWS services refuse actions based on account-level settings regardless of IAM.',
      },
      {
        claim: 'The console shows the effective permissions of a role.',
        truth:
          'It shows the policy documents attached to the role. The effective set is a computed result across five sources, and only the simulator approximates it. The simulator approximates it imperfectly — it does not evaluate SCPs, and it does not apply the principal\'s permissions boundary unless you pass it in explicitly.',
      },
      {
        claim: 'A deny statement is unnecessary because allows are additive.',
        truth:
          'Explicit deny overrides every allow in every source. Deny statements are how you subtract, and they are the only way to subtract an action that another policy grants.',
      },
    ],
  },
  attack: {
    body: `Evaluating a policy is an offensive skill, not a defensive chore. The attacker\'s goal is to answer "what can this principal do?" as accurately as the service will, using read-only calls, so that the next call is chosen deliberately instead of guessed.

The workflow has three parts: collect every policy that applies, apply the evaluation rules by hand, and then confirm with the simulator — while remembering what the simulator cannot see.

**Collecting the policies.** Identity policies come from \`list-attached-*-policies\` (managed) and \`list-*-policies\` (inline). The resource policy comes from the resource's own API — \`s3api get-bucket-policy\`, \`kms get-key-policy\`, \`lambda get-policy\`, \`iam get-role\` for a role's trust policy. The boundary comes from \`iam get-role\` (the \`PermissionsBoundary\` field) or \`iam get-user\`. The session policy is only visible if you are the one who passed it to \`sts:AssumeRole\`, or if you can read the role's sessions through the STS API. The SCP comes from \`organizations list-policies --filter PolicyType=SERVICE_CONTROL_POLICY\` plus the OU attachment tree.

**Reading a role trust policy from the CLI.** \`aws iam get-role\` returns the trust policy as a URL-encoded blob. It has to be decoded before it is readable, and skipping that step is how people conclude a trust policy is empty.

**Applying the rules by hand.** For each candidate action and resource: gather the allows from the identity policy and the resource policy, gather every deny from all five sources, and check whether any deny applies. Then check the conditions on each allow — a condition on \`aws:PrincipalOrgID\` only helps if the principal actually has one, and a condition on \`aws:SourceIp\` only helps if the request comes from that address.

**Using the simulator.** \`iam:simulate-principal-policy\` is the fast path. It returns a decision per action and, in \`EvalDecisionMap\`, the specific policy statement that produced it, with \`MatchedStatements\` and \`MissingContextValues\` — the latter is how you find out that a condition never resolves.

Three limits of the simulator to hold in mind. It does not evaluate SCPs, so a simulated allow may be blocked in production by the organizational ceiling. It does not apply the principal's permissions boundary unless you pass \`--permissions-boundary-policy\`. And it evaluates the request against the context you supply, so \`aws:CurrentTime\`, \`aws:SourceIp\` and \`aws:MultiFactorAuthPresent\` have to be provided explicitly with \`--context-entry\` or the conditions are simply not satisfied.

The most common offensive use of all this is not "can I read the bucket" but "can I *become* someone else" — which is the subject of the next topic.`,
    techniques: [
      {
        name: 'Simulate a principal against a specific action and resource',
        what: 'Ask IAM for the decision and the statement that produced it, without making the real call.',
        command:
          'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/AppRole \\\n  --action-names s3:GetObject s3:PutObject \\\n  --resource-arns arn:aws:s3:::prod-bucket/reports/',
        impact:
          'A definitive answer on the identity policy and boundary, without touching the data. The response also names the policy and statement, which tells you exactly which grant to go after.',
      },
      {
        name: 'Read and decode a role trust policy',
        what: 'Recover the URL-encoded trust policy and see who is allowed to assume the role.',
        steps: [
          '`aws iam get-role --role-name Target` returns `Role.AssumeRolePolicyDocument` URL-encoded.',
          'Decode it with `urllib.parse.unquote` before reading it.',
          'Look for a bare account ARN such as `arn:aws:iam::111122223333:root`, a wildcard principal, or any condition that mentions an external id.',
        ],
        command:
          'aws iam get-role --role-name Target --query "Role.AssumeRolePolicyDocument" --output text | python3 -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))"',
        impact:
          'The trust policy is the most consequential policy in the account, because it decides who can become the role.',
      },
      {
        name: 'Find every principal that holds a permissive managed policy',
        what: 'Resolve a managed policy to the users, groups and roles it is attached to.',
        command:
          'aws iam list-entities-for-policy --policy-arn arn:aws:iam::123456789012:policy/AdminAccess',
        impact:
          'Turns one interesting policy document into a list of every principal whose blast radius includes it, which is what converts a policy finding into a prioritised finding.',
      },
      {
        name: 'Audit the attached policy set on a role',
        what: 'Enumerate managed and inline policies on a role and pull their documents.',
        steps: [
          '`aws iam list-attached-role-policies --role-name AppRole` lists the managed policies.',
          '`aws iam list-role-policies --role-name AppRole` lists the inline ones.',
          '`aws iam get-role-policy --role-name AppRole --policy-name Inline` and `aws iam get-policy-version --policy-arn <arn> --version-id <id>` give the documents.',
        ],
        command:
          'aws iam list-attached-role-policies --role-name AppRole --query "AttachedPolicies[].[PolicyName,PolicyArn]" --output table',
        impact:
          'The complete input set for the evaluation, including the policy version in effect — which is not necessarily the default version.',
      },
      {
        name: 'Find unused permissions on a role',
        what: 'Use the service last accessed data to shrink a role to what it actually calls.',
        steps: [
          '`aws iam generate-service-last-accessed-details --arn <role-arn>` starts the report.',
          '`aws iam get-service-last-accessed-details --arn <role-arn> --job-function-type service` reads it.',
          'Compare the returned service list against the allowed action list.',
        ],
        command:
          'aws iam generate-service-last-accessed-details --arn arn:aws:iam::123456789012:role/LegacyRole && aws iam get-service-last-accessed-details --arn arn:aws:iam::123456789012:role/LegacyRole --job-function-type service',
        impact:
          'A defensible, evidence-backed way to remove permissions. It also proves the role is over-scoped, which is the finding a reviewer will otherwise dismiss as theoretical.',
      },
      {
        name: 'Test a policy document before deploying it',
        what: 'Check a candidate policy for correctness and for risky constructs.',
        command:
          'aws accessanalyzer validate-policy --policy-document file://policy.json --policy-type IDENTITY_POLICY',
        impact:
          'Catches malformed conditions, unused statements and missing permissions before the policy reaches an account. It validates the document; it does not evaluate it against a principal.',
      },
    ],
    cases: [
      {
        title: 'Boundary and SCP gaps turning a narrow role into a wide one',
        source: 'Recurring pattern in published cloud assessment findings and red team write-ups',
        impact:
          'In the recurring pattern, a role was scoped to a single bucket and appeared safe in review. A permission boundary on the role granted a wider S3 prefix, and the SCP at the OU level granted a third path, so the effective permission set was the union of three documents that nobody reviewed together. The policy document was never the problem.',
        year: 2023,
      },
      {
        title: 'Wildcard condition keys turning a scoped allow into a global one',
        source: 'Public security research on IAM condition key misuse',
        impact:
          'A policy intended to restrict an action to one organisation used a condition key that does not resolve for the calling principal. The condition never matched, the statement never applied, and the allow fell through to a different, broader statement in the same document.',
        year: 2022,
      },
    ],
  },
  detect: {
    body: `Policy evaluation attacks are quiet. Nothing is modified, no credential is minted, and every call is a read. The signal is not a single event but a *shape*: a principal reading a lot of policy metadata, or a principal making a lot of calls that come back \`AccessDenied\`.

**Reads of policy metadata.** \`iam:GetPolicyVersion\`, \`iam:ListEntityPolicies\`, \`iam:ListAttachedRolePolicies\`, \`iam:GetRole\`, \`iam:ListPolicyVersions\`. Some are routine for administrators. None of them are routine for a workload role.

**Simulation calls.** \`iam:SimulatePrincipalPolicy\` and \`iam:SimulateCustomPolicy\` are logged. A principal that simulates its own permissions is either doing legitimate self-service tooling or preparing an escalation. Both are rare enough to be worth alerting on.

**Denied-call probing.** A principal issuing the same action against a series of different resources, with \`errorCode\` of \`AccessDenied\` or \`UnauthorizedOperation\`, is mapping the boundary of its own permissions. Individually each call is noise; the sequence is a capability scan.

**The absence of a signal.** Note what you cannot see: a successful read of a policy that the principal was always allowed to read produces nothing worth alerting on, and the eventual abuse may happen through a *different* principal than the one that did the evaluation. That is why the useful alerts are on the enumeration behaviour and on the first anomalous use of the discovered permission.

**Guardrails.** The defensive posture is to make evaluation expensive to do from the wrong place: restrict \`iam:Simulate*\` and \`iam:GetPolicyVersion\` with an SCP to a small set of identity administrators, and make sure the policies worth stealing are the ones that are not reachable in the first place — permission boundaries on every non-human principal, and Access Analyzer external-access findings reviewed on a schedule.`,
    signals: [
      {
        signal: 'A principal simulated its own permissions',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, sourceIPAddress\n| filter eventName = "SimulatePrincipalPolicy" or eventName = "SimulateCustomPolicy"\n| stats count() by userIdentity.arn, sourceIPAddress`,
        note:
          'Almost nobody runs this on a schedule. A workload role simulating itself is a lead, not a false positive.',
      },
      {
        signal: 'Bulk reading of policy documents',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.policyArn, requestParameters.roleName\n| filter eventName in ["GetPolicyVersion","ListPolicyVersions","ListEntitiesForPolicy","ListAttachedRolePolicies","GetRole"]\n| stats count() by userIdentity.arn, eventName`,
        note:
          'Baseline the administrators who hold these. A spike from a principal that normally only calls its own service APIs is policy reconnaissance.',
      },
      {
        signal: 'Denied-call probing across many resources',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, errorCode, userIdentity.arn, resources[].ARN\n| filter errorCode in ["AccessDenied","UnauthorizedOperation","AccessDeniedException"]\n| stats count() as denials by userIdentity.arn, eventName, resources[].ARN`,
        note:
          'One denied call is routine. The same action denied against many resources by one principal is a permission boundary scan, and the ARNs it lists are the targets it wants.',
      },
      {
        signal: 'A policy document was changed after a simulation',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.policyArn\n| filter eventName in ["CreatePolicyVersion","SetDefaultPolicyVersion","AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy"]\n| stats count() by userIdentity.arn, eventName`,
        note:
          'This is the escalation step following the evaluation step. Correlate the principal with the simulation events over the preceding hour.',
      },
      {
        signal: 'Guardrail — restrict policy evaluation APIs to identity administrators',
        source: 'AWS Organizations SCP',
        query: `SCP Deny: iam:SimulatePrincipalPolicy, iam:SimulateCustomPolicy, iam:GetPolicyVersion, iam:ListEntitiesForPolicy for principals outside the identity administration group`,
        note:
          'Self-service policy simulation is a convenience. Restricting it removes the cheapest reconnaissance tool without affecting any workload.',
      },
      {
        signal: 'External access findings on managed policies',
        source: 'IAM Access Analyzer',
        query: `aws accessanalyzer list-analyzed-resources --resource-type POLICY --filter \'{"Status":{"eq":["ERROR","WARNING"]}}\''`,
        note:
          'This is a standing check rather than an incident signal. A policy that allows access from outside the organization is a finding regardless of who reads it.',
      },
    ],
    posture: [
      'Apply a permission boundary to every non-human principal so a policy mistake is capped.',
      'Alert on `iam:Simulate*` calls; they are almost always deliberate.',
      'Review IAM Access Analyzer external access findings on a schedule, not once at launch.',
      'Keep SCPs attached at the organization root so the ceiling applies to accounts created later.',
      'Require MFA for every human principal, so a stolen key is not sufficient on its own.',
      'Log policy read calls for workload roles separately from administrator roles, so the baseline is clean.',
    ],
  },
  fix: {
    body: `Fixing a policy problem means changing the *documents*, not the console view of them. Work in this order.

**Remove wildcards.** \`"Action": "*", "Resource": "*"\` in an identity policy is almost never the requirement — it is a placeholder that survived review. Enumerate the actions the workload actually calls and the resources it actually touches. The service last accessed data is the evidence for that list.

**Scope the resource.** Replace \`"Resource": "*"\` with the ARNs, and add condition keys to narrow further: \`aws:PrincipalOrgID\` for organization-internal access, \`aws:PrincipalArn\` for a specific principal, \`aws:SourceVpce\` for a VPC endpoint, \`aws:SourceArn\` for a specific service that will call you.

**Add the missing deny.** Where a broad grant exists that must not apply to a particular principal, add an explicit Deny in a boundary or an SCP rather than trying to subtract with the allow statements. Deny is the only subtraction AWS has.

**Cap with a boundary.** The boundary is the control that survives somebody later adding a bad statement to a role. Apply one to every non-human principal.

**Validate before deploy.** Run the candidate document through Access Analyzer policy validation in the pull request, and check for the constructs that cause trouble: \`NotAction\`, \`NotPrincipal\`, conditions on keys that do not resolve, and \`"Principal": "*"\` in a resource policy.

**Then reduce what evaluation can even see.** Restrict the evaluation APIs and the policy-mutation APIs with an SCP, so that reading a policy and rewriting one are both limited to the identity team.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Replace wildcard allows with enumerated actions and scoped resources',
        detail:
          'A wildcard allow is unbounded in a way that no amount of tagging or monitoring makes safe. Enumerate the calls the workload makes and write them down.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::prod-bucket",
      "arn:aws:s3:::prod-bucket/reports/*"
    ]
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'critical',
        action: 'Apply a permission boundary to every non-human principal',
        detail:
          'The boundary intersects with every other grant and is applied at request time, so it caps the principal even if somebody later attaches a broader policy or the SCP set changes.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject", "logs:PutLogEvents"],
    "Resource": ["arn:aws:s3:::app-bucket/*", "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/app:*"]
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Audit every NotAction, NotPrincipal and wildcard Principal in the account',
        detail:
          'These three constructs invert the meaning of a statement. A NotAction allow is "everything except", and a wildcard Principal in a resource policy grants to anybody who can reach it.',
        snippet: `aws iam list-policies --scope Local --query "PolicyList[].Arn" --output text | xargs -I{} aws iam get-policy --policy-arn {}`,
      },
      {
        priority: 'high',
        action: 'Deny policy mutation and policy evaluation outside the identity team with an SCP',
        detail:
          'Reading a policy is reconnaissance; changing one is escalation. Restricting both to the identity administration group removes the pair of steps that most privilege escalation chains need.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": [
      "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
      "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
      "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
      "iam:DeleteUserPolicy", "iam:DeleteRolePolicy"
    ],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'medium',
        action: 'Add condition keys so the grant is tied to the caller',
        detail:
          'A condition on `aws:PrincipalOrgID` or `aws:PrincipalArn` narrows the grant to a known caller and survives a wildcard resource list better than an enumerated one.',
        snippet: `{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::shared-bucket/*",
  "Condition": {
    "StringEquals": { "aws:PrincipalOrgID": "o-abcd1234" }
  }
}`,
        snippetLang: 'json',
      },
      {
        priority: 'medium',
        action: 'Trim unused permissions using service last accessed data',
        detail:
          'The service last accessed report names the services a role has actually called. Removing the services it has not called shrinks the role and shrinks the blast radius of any credential leak, and gives the reviewer evidence.',
      },
      {
        priority: 'low',
        action: 'Validate candidate policies in the pipeline',
        detail:
          'Access Analyzer policy validation catches malformed conditions and unused statements before they reach an account, and it costs one API call per pull request.',
        snippet: `aws accessanalyzer validate-policy --policy-document file://policy.json --policy-type IDENTITY_POLICY`,
        snippetLang: 'bash',
      },
    ],
  },
  checklist: [
    {
      id: 'pol-1',
      text: 'Simulate a role against the actions you believe it needs.',
      command:
        'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/AppRole --action-names s3:GetObject s3:PutObject ec2:DescribeInstances',
      expected:
        'Every action you did not expect to be allowed is either denied or is one you can justify in writing.',
    },
    {
      id: 'pol-2',
      text: 'Find every principal that holds a broadly permissive managed policy.',
      command:
        'aws iam list-entities-for-policy --policy-arn arn:aws:iam::123456789012:policy/AdministratorAccess',
      expected:
        'A short, named list of principals, each with a documented reason to hold administrative permissions.',
    },
    {
      id: 'pol-3',
      text: 'Confirm which policy version is actually in effect on a managed policy.',
      command:
        'aws iam list-policy-versions --policy-arn arn:aws:iam::123456789012:policy/AppPolicy --query "Versions[].[VersionId,IsDefaultVersion]" --output table',
      expected:
        'One default version, and no version other than the default carrying a different document without a reason.',
    },
    {
      id: 'pol-4',
      text: 'Check whether any of your roles have a permission boundary.',
      command:
        'aws iam list-roles --query "Roles[?PermissionsBoundary!=null].[RoleName,PermissionsBoundary.PermissionsBoundaryArn]" --output table',
      expected:
        'Every non-human role has a boundary. A role with no boundary has no ceiling other than the SCP.',
    },
    {
      id: 'pol-5',
      text: 'Read the SCP ceiling that applies to a target account.',
      command:
        'aws organizations list-policies --filter PolicyType=SERVICE_CONTROL_POLICY --query "Policies[].[Id,Name,Description]" --output table',
      expected:
        'One ceiling policy at the root, attached to the root OU, plus documented OU-level additions.',
    },
    {
      id: 'pol-6',
      text: 'Confirm that the simulator is not the only thing standing between a role and the SCP.',
      command:
        'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/AppRole --action-names iam:PassRole iam:CreatePolicyVersion',
      expected:
        'Both are denied. A simulation allow here is a finding, because the simulator does not evaluate SCPs and the SCP may deny it anyway.',
    },
  ],
  references: [
    { label: 'AWS IAM policy evaluation logic', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html' },
    { label: 'AWS IAM policy simulator', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-policy-simulator.html' },
    { label: 'AWS IAM Access Analyzer policy validation', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html' },
    { label: 'AWS IAM service last accessed data', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-used.html' },
  ],
  updated: '2026-11-22',
}
