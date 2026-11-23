import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/expert/organizational-guardrails',
  title: 'Guardrails that actually hold',
  cloud: 'aws',
  stage: 'expert',
  track: 'Platform',
  summary:
    'The difference between a policy that stops an attack and a policy that makes an attack harder — and how to write the first kind.',
  duration: '35 min',
  difficulty: 5,
  prerequisites: [
    'aws/foundation/regions-and-availability',
    'aws/redteam/iam-privilege-escalation',
  ],
  enables: ['aws/expert/multi-account-estate'],
  mentalModel:
    'A guardrail is a limit you cannot lift. A policy is a limit you can edit. If the person who would make the mistake can also change the rule, it is a suggestion — and in AWS, the people who make mistakes are the same people who have IAM permissions.',
  concept: {
    body: `AWS has four mechanisms that can constrain permissions, and they differ enormously in how hard they are to change.

**Identity-based policy.** The policy attached to a user, role, or group. It is the ordinary mechanism, and it is editable by anyone with \`iam:PutUserPolicy\`, \`iam:AttachRolePolicy\`, or \`iam:CreatePolicyVersion\`. An attacker with those actions can grant themselves whatever they lacked.

**Resource-based policy.** The policy on the bucket, queue, function, or role trust. It grants access to principals in the same or other accounts. Editable by whoever owns the resource.

**Permission boundary.** A maximum set of permissions attached to a principal. It *intersects* with identity policies: the effective permission is the intersection of what the identity policy allows and what the boundary allows. Crucially, a boundary caps what a principal can ever have, including permissions added later by someone else. It is still editable by anyone with \`iam:PutUserPermissionsBoundary\` or \`iam:PutRolePermissionsBoundary\`.

**Service control policy (SCP).** Attached to an account, an organisational unit, or the root. An SCP also intersects. The crucial difference is *where the permission to edit it lives*: an SCP can only be edited from the management account or by a delegated administrator, and — this is the point — an SCP can deny \`iam:PutUserPolicy\`, \`iam:AttachRolePolicy\`, \`iam:CreatePolicyVersion\`, and \`iam:PutUserPermissionsBoundary\` itself. That is what makes it a guardrail rather than a policy.

**Why the distinction matters for an attacker.** Think about what an attacker does after they get a foothold. They escalate by changing an identity policy, attaching a policy, creating a new policy version, or setting a permissions boundary. If the account is protected by an SCP that denies those four actions, every one of those escalation paths is closed at once — regardless of how many individual permissions are misconfigured. The attacker is left with the permissions they already had.

**The intersection semantics have a trap.** Because an SCP denies by default on anything not explicitly allowed, and because an SCP can only restrict, the effective permission is the intersection of identity policy and every applicable SCP and boundary. A deny in any one of them wins. This means an SCP that is too broad in its allows does not matter — but an SCP that is too narrow in its *denies* removes capability that the account genuinely needs, and teams then add an exception, and the exception is where the gap reappears.

**The exception is the real estate.** Every mature AWS organisation has a set of break-glass roles and a set of SCP exceptions with expiry dates. The quality of the guardrail is the quality of its exception handling, not the quality of the SCP. An SCP with a permanent exception for "the security team" is not a guardrail for the security team.`,
    keyPoints: [
      'An SCP can deny iam:PutUserPolicy, iam:AttachRolePolicy, iam:CreatePolicyVersion and iam:PutUserPermissionsBoundary — which closes every IAM-write escalation path at once.',
      'All four mechanisms intersect. An explicit deny in any one of them wins over an allow in all the others.',
      'A permission boundary caps what a principal can ever hold, including permissions granted later by someone else.',
      'An SCP is only a guardrail if the account that holds it is outside the blast radius of the account being protected.',
      'An SCP exception with no expiry date is a permanent hole in the guardrail.',
      'Region opt-in matters: a control that is only enabled in the regions you use is not a control in the regions you have not.',
    ],
    misconceptions: [
      {
        claim: 'An SCP grants permissions.',
        truth:
          'It never does. An SCP can only allow or deny, and a deny wins. If a permission is missing after an SCP is attached, the fix is in the identity policy, not the SCP.',
      },
      {
        claim: 'A deny on iam:AttachUserPolicy would break deployments.',
        truth:
          'It would break deployments that use IAM to grant permissions at runtime. Most CI pipelines use OIDC and assume a role instead, which no SCP needs to deny. The exception list tells you which pipelines genuinely need IAM write access.',
      },
      {
        claim: 'Applying an SCP to the root protects every account.',
        truth:
          'Only if the management account itself is not in the blast radius of the compromised account. An account administrator who can reach the management account can edit the SCP that was supposed to stop them.',
      },
    ],
  },
  attack: {
    body: `An attacker in a well-guarded account cannot escalate through IAM writes — those actions are denied by SCP. So they change approach. The remaining routes are all about *execution*: run code somewhere that already has the identity you want.

This is the most important thing to understand about guardrails. An SCP that denies all the IAM-write actions does not stop an attacker who holds \`iam:PassRole\` and \`lambda:CreateFunction\`. It stops them from changing permissions. It does not stop them from *using* permissions they cannot change, by borrowing someone else's.

The second route is the guardrail's own exception. Every SCP exception is a principal that can do what the SCP denies. If the exception is a role that can be assumed broadly, the SCP is bypassed through the exception rather than around it.

The third route is scope. An SCP applies to an account or an OU. A role in an OU with no SCP, a resource in a different region where the SCP has not been applied, a service that has its own permission model — these are the places the guardrail stops existing.

The fourth is the management account itself. If the guardrails live there and the management account is reachable from a workload account, the guardrails are advisory.`,
    techniques: [
      {
        name: 'Bypass the guardrail through an execution path',
        what:
          'Use PassRole plus a code-execution service to borrow an identity the attacker cannot edit.',
        steps: [
          'Enumerate the roles that can be passed: check for iam:PassRole on a wildcard or a broad set.',
          'Find a service that runs code with a role you choose — Lambda, ECS, CodeBuild, CloudFormation, SageMaker.',
          'Create or update the workload with the target role attached.',
          'Run code in it and read the credentials from the environment.',
        ],
        impact:
          'The target role\'s permissions, without ever changing a policy. The SCP never sees this because none of these actions are IAM writes.',
      },
      {
        name: 'Find the exception that does the work',
        what:
          'Identify the principal that is exempt from the SCP deny and use it.',
        command:
          'aws organizations list-policies --filter PolicyType=SERVICE_CONTROL_POLICY',
        impact:
          'The SCP exceptions are usually implemented as a role that is exempt, and that role often has more permissions than the guardrail it is exempt from.',
      },
      {
        name: 'Work in the region where the guardrail is not applied',
        what:
          'Find a region where the account-level controls were never enabled and create resources there.',
        steps: [
          'List the regions the account has enabled, and compare with the regions where the SCP is attached.',
          'Check whether a resource can be created in a region with no trail, no Config and no SCP.',
          'Create the workload there.',
        ],
        impact:
          'An entire control surface does not exist in that region, and most alerts are region-scoped.',
      },
      {
        name: 'Reach the management account',
        what:
          'Find a path from a workload account to the account that holds the SCPs.',
        steps: [
          'Enumerate the trust relationships pointing at the management account from workload accounts.',
          'Assume a role that has access to the organisation or the SCPs.',
          'Edit the SCP to remove the deny, or attach an exempt role to the compromised OU.',
        ],
        impact:
          'Total defeat of the guardrail for every account under it.',
      },
      {
        name: 'Use a service with its own permission model',
        what:
          'Find a service that does not enforce the account IAM boundary the way you expect.',
        steps: [
          'Review the services in use and note which ones have separate resource-based permission models.',
          'Check for services that allow resource policies to grant cross-account access without an SCP being consulted.',
          'Test a cross-account access path through that service.',
        ],
        impact:
          'The SCP boundary does not apply uniformly across services, and the exceptions are not always documented.',
      },
    ],
    cases: [
      {
        title: 'iam:PassRole and code execution surviving a hardened SCP',
        source: 'Recurring pattern across cloud security research and red team write-ups',
        impact:
          'In the recurring pattern, the SCP denies every IAM write action and is considered complete. The attacker holds iam:PassRole and lambda:CreateFunction, runs a function as the administrator role, and the guardrail records nothing unusual because no policy was modified.',
      },
      {
        title: 'Guardrail bypass through a workload in a region without controls',
        source: 'Widely documented class of cloud misconfiguration',
        impact:
          'In the recurring pattern, the account has a strong SCP and a complete trail, all in one region. A second region was enabled later for a migration and carries none of it, and the activity there is invisible to the alerting.',
      },
    ],
  },
  detect: {
    body: `Detecting a guardrail failure means detecting the *absence* of a control, which is harder than detecting a control being broken. The practical signals are:

- **Configuration drift in the guardrails themselves.** The SCP set changes rarely, so any change is worth a page.
- **IAM write attempts that are denied.** These are the attempts the guardrail caught. They are the best detector of an attacker who believes the guardrail is not there.
- **Activities in regions or accounts where the guardrail does not apply.** Detected by comparing the guardrail inventory against actual resource locations.
- **Exception usage.** Every use of a break-glass role or an SCP-exempt principal should be an event, and should be rare enough that "rare" means something.

The last one is the most important operationally. A guardrail is only as good as the ability to notice it being used for something other than its purpose.`,
    signals: [
      {
        signal: 'SCP or policy changed in the organisation',
        source: 'CloudTrail — management events',
        query: `eventName=UpdatePolicy OR eventName=CreatePolicy OR eventName=DeletePolicy OR eventName=AttachPolicy OR eventName=DetachPolicy\n| where requestParameters.policyType = "SERVICE_CONTROL_POLICY"\n| stats count() by userIdentity.arn, requestParameters.policyName`,
        note:
          'SCPs change rarely. Treat every change as an incident until someone confirms the change ticket.',
      },
      {
        signal: 'Denied IAM write attempts',
        source: 'CloudTrail — management events',
        query: `errorCode="AccessDenied" and eventName in ("PutUserPolicy", "AttachUserPolicy", "AttachRolePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion", "PutUserPermissionsBoundary", "PutRolePermissionsBoundary", "UpdateAssumeRolePolicy")\n| stats count() by userIdentity.arn, eventName\n| sort count desc`,
        note:
          'This is the guardrail catching an attacker. A single denied attempt is worth investigating; a sequence is an incident.',
      },
      {
        signal: 'PassRole used outside the deployment path',
        source: 'CloudTrail — management events',
        query: `eventName=PassRole\n| stats count() by userIdentity.arn, requestParameters.roleName\n| sort count desc`,
        note:
          'The execution edge that the SCP does not cover. Every occurrence is either a deployment or a finding.',
      },
      {
        signal: 'Resources created in a region with no controls enabled',
        source: 'CloudTrail — management events',
        query: `eventSource in ("ec2.amazonaws.com", "s3.amazonaws.com", "lambda.amazonaws.com") and eventName in ("RunInstances", "CreateBucket", "CreateFunction")\n| stats count() by awsRegion\n| sort count desc`,
        note:
          'Compare against the list of regions where the trail, Config and SCPs are applied. Any region outside it is a blind spot.',
      },
      {
        signal: 'Break-glass role used',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| where requestParameters.roleName like "%BreakGlass%" or requestParameters.roleName like "%Emergency%" or requestParameters.roleName like "%Admin%"\n| stats count() by userIdentity.arn, sourceIPAddress, requestParameters.roleName`,
        note:
          'These roles should be used a handful of times a year. Every use should page someone.',
      },
      {
        signal: 'Guardrail — deny the IAM write actions everywhere',
        source: 'SCP',
        query: `SCP Deny: iam:PutUserPolicy, iam:AttachUserPolicy, iam:AttachRolePolicy, iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, iam:PutUserPermissionsBoundary, iam:PutRolePermissionsBoundary, iam:UpdateAssumeRolePolicy`,
        note:
          'The single most valuable SCP in a modern estate, because it closes every IAM-write escalation path at once.',
      },
    ],
    posture: [
      'Attach an SCP to the organisation root that denies every IAM write action to non-exempt principals.',
      'Give every SCP exception an expiry date and an owner, and review the exception list monthly.',
      'Apply the trail, Config, GuardDuty and SCPs in every region the account can use, including new ones.',
      'Enrol every account in the organisation, so new accounts inherit the root SCP automatically.',
      'Keep the management account credentials offline, and use a delegated administrator for day-to-day SCP changes.',
      'Alert on denied IAM write attempts — they are the guardrail proving its value.',
    ],
  },
  fix: {
    body: `A guardrail programme is a small number of hard denies, an explicit exception list, and a way to notice when either is used. Everything else is decoration.

Start with the single SCP that denies the IAM write actions. It closes more paths than any other control, it is one document, and it breaks nothing if your deployments use OIDC rather than IAM to grant permissions.

Then get the exceptions right, because that is where the guardrail actually lives. An exception without an owner and an expiry is not an exception, it is a second policy that nobody reviews.

Then extend coverage to every region and every new account, because a guardrail that does not apply is worse than no guardrail — it produces false confidence.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Deny the IAM write actions at the organisation root',
        detail:
          'This closes every escalation path that works by editing a policy, attaching a policy, publishing a new policy version, or setting a permission boundary. It is one document and it is the highest-value control in the estate.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyIAMWrite",
    "Effect": "Deny",
    "Action": [
      "iam:PutUserPolicy",
      "iam:PutGroupPolicy",
      "iam:PutRolePolicy",
      "iam:AttachUserPolicy",
      "iam:AttachGroupPolicy",
      "iam:AttachRolePolicy",
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:PutUserPermissionsBoundary",
      "iam:PutRolePermissionsBoundary",
      "iam:UpdateAssumeRolePolicy"
    ],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'critical',
        action: 'Give every SCP exception an owner and an expiry date',
        detail:
          'An exception that never expires is a permanent hole. Require a named owner, a ticket reference and an expiry, and have a process that removes it when the date passes.',
      },
      {
        priority: 'high',
        action: 'Enrol every account in the organisation',
        detail:
          'An account created outside the organisation inherits no SCP, no trail and no Config. Auto-enrolment at creation time is what makes the root SCP effective.',
      },
      {
        priority: 'high',
        action: 'Apply the control set in every region, not only the primary one',
        detail:
          'A region enabled later for a migration can become the place an attacker works, because nothing is logged there and no SCP applies. Use a CloudFormation stack or an account baseline that applies everywhere.',
      },
      {
        priority: 'high',
        action: 'Deny iam:PassRole except for roles tagged as deployable',
        detail:
          'PassRole is the pivot from "can run code" to "can run code as someone else", and no IAM-write deny covers it. Restricting it to tagged roles closes the execution edge.',
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
        priority: 'medium',
        action: 'Keep management account credentials offline and use a delegated administrator',
        detail:
          'If the account holding the SCPs is reachable from a workload account, the SCPs are advisory. Isolating it is what makes the guardrail a guardrail.',
      },
      {
        priority: 'medium',
        action: 'Attach permission boundaries to every non-human principal',
        detail:
          'A boundary caps the maximum a principal can ever hold, including permissions added later. It is the second layer for the identities the SCP cannot reach.',
      },
      {
        priority: 'low',
        action: 'Reconcile the guardrail inventory against actual estate state',
        detail:
          'List the accounts, the regions in use and the SCP attachments, and compare them against reality. Drift here is invisible until it is exploited.',
      },
    ],
  },
  checklist: [
    {
      id: 'guard-1',
      text: 'Confirm an SCP denies the IAM write actions at the organisation root.',
      command:
        'aws organizations list-policies --filter PolicyType=SERVICE_CONTROL_POLICY --query "Policies[].Name"',
      expected:
        'A policy exists that denies PutUserPolicy, AttachRolePolicy, CreatePolicyVersion and the boundary actions.',
    },
    {
      id: 'guard-2',
      text: 'Check whether the root SCP is attached to the whole organisation.',
      command:
        'aws organizations describe-effective-policy --policy-type SERVICE_CONTROL_POLICY --target-id o-abc123',
      expected:
        'The effective policy at the root includes the deny. If it does not, some account is outside it.',
    },
    {
      id: 'guard-3',
      text: 'Find every account in the organisation and confirm each is enrolled.',
      command:
        'aws organizations list-accounts --query "Accounts[].{Id:Id,Name:Name,Status:Status,Email:Email}"',
      expected:
        'Every account is ACTIVE and enrolled. A SUSPENDED or outside account is a gap.',
    },
    {
      id: 'guard-4',
      text: 'List every SCP and every exception, and check the exceptions for expiry.',
      command:
        'aws organizations list-policies --filter PolicyType=SERVICE_CONTROL_POLICY --query "Policies[].{Name:Name,Id:Id}"',
      expected:
        'Each exception has a named owner and an expiry date you can point to.',
    },
    {
      id: 'guard-5',
      text: 'Check which regions the account has enabled and where the trail and Config are running.',
      command:
        'aws ec2 describe-regions --all-regions --query "Regions[?OptInStatus==\`opt-in-not-required\` || OptInStatus==\`opted-in\`].RegionName"',
      expected:
        'Every enabled region has a trail, a Config recorder and the SCP applied.',
    },
    {
      id: 'guard-6',
      text: 'Confirm the guardrail catches an IAM write attempt.',
      command:
        'aws iam put-user-policy --user-name probe-user --policy-name probe --policy-document \'{"Version":"2012-10-17","Statement":[]}\'',
      expected:
        'AccessDenied with a message naming the SCP. In a test account only.',
    },
    {
      id: 'guard-7',
      text: 'Check whether the management account is reachable from a workload account.',
      command:
        'aws organizations describe-organization --query "Organization.MasterAccountId"',
      expected:
        'No role in any workload account can assume into the management account without a deliberate, audited process.',
    },
  ],
  references: [
    { label: 'AWS — service control policies', url: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html' },
    { label: 'AWS — policy evaluation logic', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html' },
    { label: 'AWS Organizations — auto-enrolment', url: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_auto.html' },
    { label: 'AWS — permission boundaries', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html' },
  ],
  updated: '2026-11-22',
}
