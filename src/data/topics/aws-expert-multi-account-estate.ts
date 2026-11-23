import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/expert/multi-account-estate',
  title: 'Securing a multi-account estate',
  cloud: 'aws',
  stage: 'expert',
  track: 'Platform',
  summary:
    'Why organisations split into accounts, how the splits create their own attack surface, and how to keep the boundaries meaningful.',
  duration: '35 min',
  difficulty: 5,
  prerequisites: [
    'aws/foundation/identity-and-trust',
    'aws/expert/organizational-guardrails',
  ],
  enables: [],
  mentalModel:
    'An account boundary is only a security boundary if the controls that matter live inside it. Splitting an estate is a way of making the blast radius smaller — and it creates a new surface, made of the cross-account relationships, where that smaller blast radius can be walked straight through.',
  concept: {
    body: `AWS has no global administrator and no global policy. Every account has its own IAM, its own root user, its own audit trail. That is why organisations split into accounts: to make the blast radius of a mistake smaller.

The usual layout, and the reasoning behind each boundary:

- **The management account.** Holds the organisation, the SCPs, the organisation trail and the shared infrastructure. It should have almost nothing running in it. Everything in it is estate-wide.
- **Security accounts.** Centralised logging, GuardDuty, Security Hub, Config. Separated so a compromise of the logging account is not a compromise of the production accounts.
- **Shared infrastructure account.** VPCs that are shared between workloads — Transit Gateway, Network Firewall, shared ECR repositories. This account is unusual because it holds resources that are *used by* other accounts, and the trust relationships into it are the most numerous in the estate.
- **Sandbox accounts.** Where people experiment. The point of the sandbox is to contain the mess, and it only contains it if the controls apply.
- **Workload or production accounts.** One per team or per application, with the blast radius of a mistake confined to that application.

**What the split actually gives you.** Three things, and only three:

1. **A smaller blast radius for mistakes.** A policy mistake in the payments account does not affect the marketing account.
2. **An organisational boundary for teams.** Access requests go to the account owner, not to a global admin.
3. **A place to put controls that need to be centralised.** The organisation trail, the SCP, the shared guardrails.

**What it costs you.** Four things:

1. **Cross-account trust relationships.** Every one is a directed edge in the trust graph, and each one is a path.
2. **More places for a control to be missing.** Every account needs the trail, the Config recorder, the SCP attachment, the guardrails. One account created outside the pattern is a hole.
3. **Shared infrastructure that is hard to scope.** A VPC shared by twenty accounts has twenty trust relationships into it, and the network controls that would protect it are account-scoped.
4. **Operational overhead.** Cross-account role assumption in every pipeline, which is exactly where the OIDC trust misconfigurations live.

**The organisation is the real unit of security, and it has its own failure modes.** Accounts can be created that are not enrolled, so they inherit no SCP and no trail. SCP exceptions can be granted in one account and forgotten. The management account can be reachable from a workload account, in which case the estate-wide controls are advisory. Delegated administrator roles can be granted more broadly than intended.

**Account vending.** The ability to create accounts is itself a privilege worth controlling, because a new account outside the estate pattern inherits nothing. AWS Organizations has a trusted access mechanism for exactly this: a service role that lets an automated process create and enrol accounts in one step.`,
    keyPoints: [
      'The management account should run almost nothing. Everything it holds is estate-wide.',
      'The organisation trail covers every enrolled account, including accounts that did not know they were being logged.',
      'The shared infrastructure account holds the most trust relationships in the estate and is the most commonly under-protected.',
      'An account created outside the enrolment path inherits no SCP, no trail and no guardrails.',
      'Account creation is a privilege: an unenrolled account is a place with no controls.',
      'Cross-account trust is per-account. There is no estate-wide allow list — the graph is the union of every account\'s relationships.',
    ],
    misconceptions: [
      {
        claim: 'Separating accounts automatically contains a breach.',
        truth:
          'It contains a compromise of the workload. It does not contain a compromise of the trust graph, because a trust relationship into an account is an edge that crosses the boundary you thought you had drawn.',
      },
      {
        claim: 'The organisation trail means every account is logged.',
        truth:
          'Only accounts enrolled in the organisation are covered by the organisation trail. An account outside the organisation — created in error, or by an identity in another organisation — is logged by nothing.',
      },
      {
        claim: 'Shared VPCs reduce the number of network rules to manage.',
        truth:
          'They reduce the rules, and they concentrate the trust. A shared VPC has a trust relationship from every account that uses it, and the security groups and route tables are often broader than a per-account VPC would be.',
      },
    ],
  },
  attack: {
    body: `The estate-wide attack is not about any single account. It is about the graph.

The attacker starts in the least-protected account — a sandbox, a development account, an account created by a contractor — and uses the cross-account relationships to move outward until they reach the account that holds the objective.

The most common first move is not a credential attack at all. It is **\`iam:CreateAccount\`** — creating a new account in the organisation, enroling it, and then using the organisation-wide access that the new account inherits from a role that trusts the whole organisation. This is why some SCPs and role trust policies are conditioned on \`aws:PrincipalOrgID\`: convenient, and exactly the wrong convenience for an attacker who can create an account inside the organisation.

The second move is the **shared infrastructure account**, because it is trusted by everything.

The third is the **management account**, because the SCPs live there and the management account has a role that organisations create for exactly the wrong reason.

The fourth is lateral trust: a role in the workload account that trusts a role in the security account, which trusts a role in the management account, which trusts everything.`,
    techniques: [
      {
        name: 'Create an account inside the organisation',
        what:
          'Use account creation to obtain a principal that inherits organisation-wide trust.',
        steps: [
          'Check for iam:CreateAccount, organizations:CreateAccount or the equivalent in the account you hold.',
          'Create an account in the organisation — in AWS, a second account created in the same organisation can land in an OU that inherits the same SCPs.',
          'Enrol it if it is not enrolled automatically.',
          'Look for a trust policy conditioned on aws:PrincipalOrgID that now admits your new account.',
        ],
        impact:
          'A new account inside the trust boundary of every organisation-scoped trust policy in the estate.',
      },
      {
        name: 'Move through the shared infrastructure account',
        what:
          'Use the account that holds the shared VPC and network controls as a hop.',
        steps: [
          'Identify the shared infrastructure account from the trust relationships pointing at it.',
          'Assume a role there, or reach the shared VPC through it.',
          'Use the shared network position to reach the workload accounts that peer with it.',
        ],
        impact:
          'A network position inside the estate, from which the workload accounts are peers rather than unreachable.',
      },
      {
        name: 'Reach the management account',
        what:
          'Find a path into the account that holds the SCPs and the organisation trail.',
        steps: [
          'Enumerate the roles across the estate and find the ones that can be assumed into the management account.',
          'Check whether any of them trusts an entire organisation rather than a specific principal.',
          'Assume it and read the SCP attachments.',
        ],
        impact:
          'Every estate-wide control becomes editable, and the audit trail can be stopped.',
      },
      {
        name: 'Use organisation-scoped trust conditions',
        what:
          'Exploit a trust policy conditioned on PrincipalOrgID to gain access from any account in the organisation.',
        command:
          'aws iam get-role --role-name arn:aws:iam::123456789012:role/Target',
        impact:
          'Every organisation-scoped trust policy becomes reachable, and the count of those policies is the size of the prize.',
      },
      {
        name: 'Find the unenrolled account',
        what:
          'Look for an account in the estate that was never enrolled, or was enrolled without the SCP.',
        steps: [
          'List every account in the organisation and check the enrolment state.',
          'Check which accounts have the root SCP attached.',
          'Look for an account created outside the normal vending path.',
        ],
        impact:
          'An account with no SCP, no organisation trail and no Config — a place where nothing you did applies.',
      },
      {
        name: 'Walk the lateral trust chain',
        what:
          'Follow trust relationships from a low-value account to the high-value one.',
        steps: [
          'From the foothold, enumerate every role it can assume and the roles those can assume.',
          'Build the chain across account boundaries rather than within one account.',
          'Prefer the chain with the fewest steps, even if it crosses more accounts.',
        ],
        impact:
          'Three hops through three accounts can reach an account that no single-account assessment would have flagged.',
      },
    ],
    cases: [
      {
        title: 'Account vending to satisfy an organisation-scoped trust condition',
        source: 'Recurring pattern across cloud security research and red team write-ups',
        impact:
          'In the recurring pattern, a low-privilege account holds iam:CreateAccount, and a role in a production account trusts any principal in the organisation. Creating one new account satisfies the condition and reaches production.',
      },
      {
        title: 'Shared VPC as the lateral movement pivot',
        source: 'Widely documented class of multi-account network exposure',
        impact:
          'In the recurring pattern, the shared infrastructure account is trusted by every workload account and its security groups allow traffic from the whole estate, so one compromised account in a development OU becomes a network foothold into production.',
      },
    ],
  },
  detect: {
    body: `Detecting in a multi-account estate means detecting **at the organisation level**, because the interesting events are the ones that span accounts.

The four signals that matter most:

- **Account creation.** Every new account is a new node in the trust graph. It should be a deliberate, ticketed event.
- **Cross-account assumption.** Which roles are being assumed across account boundaries, and by what. This is the estate's pulse.
- **Enrolment drift.** Accounts that are in the organisation but not covered, or not in the organisation at all.
- **SCP changes.** Changes to the estate-wide controls are the highest-consequence event in AWS.

The fifth, and the one that is most often missing, is a **trust graph inventory** — a maintained list of every cross-account relationship. Without it you cannot answer "what does this account trust", which is the first question of any estate-wide investigation.`,
    signals: [
      {
        signal: 'Account created in the organisation',
        source: 'CloudTrail — management events',
        query: `eventName=CreateAccount\n| stats count() by userIdentity.arn, requestParameters.accountName, requestParameters.email\n| sort count desc`,
        note:
          'Every new account is a new node in the trust graph. Alert on all of them, not just the ones you did not expect.',
      },
      {
        signal: 'Cross-account role assumption',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| where sourceIPAddress not like "10." and sourceIPAddress not like "172.16." and sourceIPAddress not like "192.168."\n| stats count() by requestParameters.roleName, userIdentity.arn\n| sort count desc`,
        note:
          'The estate-wide pulse. Baseline the volume, and the tail is where the interesting activity is.',
      },
      {
        signal: 'SCP or organisation policy changed',
        source: 'CloudTrail — management events',
        query: `eventName in ("UpdatePolicy", "CreatePolicy", "DeletePolicy", "AttachPolicy", "DetachPolicy", "MoveAccount", "CreateOrganizationalUnit")\n| stats count() by userIdentity.arn, eventName\n| sort count desc`,
        note:
          'Moving an account between OUs changes which SCPs apply to it. That is a policy change wearing a different name.',
      },
      {
        signal: 'Account not covered by the estate controls',
        source: 'AWS Config / organisation inventory',
        query: `for each account: effective policy at the OU, organisation trail coverage, Config recorder status, GuardDuty detector status`,
        note:
          'Not an event but a state. Reconcile it on a schedule — drift here is invisible until it is used.',
      },
      {
        signal: 'Trust relationship added to a broad principal',
        source: 'CloudTrail — management events',
        query: `eventName=UpdateAssumeRolePolicy OR eventName=CreateRole\n| where requestParameters.roleName != ""\n| stats count() by userIdentity.arn, requestParameters.roleName`,
        note:
          'A new trust edge is a new path. A trust edge to an entire organisation is a new path to every account in it.',
      },
      {
        signal: 'Guardrail — restrict account creation',
        source: 'SCP / IAM policy',
        query: `SCP Deny: iam:CreateAccount, organizations:CreateAccount except for the account vending pipeline`,
        note:
          'The control that stops the first move of the estate-wide chain. Make account creation a pipeline, not a permission.',
      },
    ],
    posture: [
      'Enable the organisation trail so every enrolled account is logged to the central account.',
      'Vending accounts through a pipeline that enrols them at creation, so no account is ever unenrolled.',
      'Maintain a trust graph inventory — every role, every trusted principal, every account.',
      'Use delegated administrator roles for day-to-day organisation management, and keep the management account credentials offline.',
      'Restrict account creation to the vending pipeline, and deny it by default.',
      'Put the shared infrastructure account under the same controls as the workload accounts, and treat its trust relationships as the highest-sensitivity list in the estate.',
    ],
  },
  fix: {
    body: `The remediation that matters is making the estate boundaries real. The three things that turn an account split into an actual security boundary:

1. **Every account is enrolled and covered.** An unenrolled account is a hole with a name on it.
2. **Account creation is a pipeline.** If a human can create an account, they can create one inside your organisation's trust boundary.
3. **The trust graph is known and reviewed.** Every cross-account edge, with an owner.

After that, the work is reducing the trust graph itself: fewer cross-account relationships, narrower principals, shorter session durations, and trust policies that name a role rather than an organisation.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Restrict account creation to a vending pipeline that enrols automatically',
        detail:
          'Account creation is a privilege because a new account can satisfy an organisation-scoped trust condition. Deny iam:CreateAccount by default and allow it only to the pipeline role.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": [
      "iam:CreateAccount",
      "organizations:CreateAccount"
    ],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'critical',
        action: 'Replace organisation-scoped trust conditions with specific principals',
        detail:
          'A trust policy conditioned on aws:PrincipalOrgID admits every account in the organisation, including one an attacker just created. Condition on aws:PrincipalArn instead.',
        snippet: `{
  "Condition": {
    "StringEquals": {
      "aws:PrincipalOrgID": "o-abc123",
      "aws:PrincipalArn": "arn:aws:iam::123456789012:role/DeployRole"
    }
  }
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Reconcile the estate inventory against actual coverage',
        detail:
          'List every account, check enrolment, effective SCPs, trail coverage, Config recorder and GuardDuty detector. The gaps are usually accounts created during an incident or a migration.',
      },
      {
        priority: 'high',
        action: 'Reduce the number of cross-account trust relationships',
        detail:
          'Each relationship is an edge and an attack path. Where a shared role can be replaced by a workload identity or a narrower role, removing the relationship is better than securing it.',
      },
      {
        priority: 'high',
        action: 'Harden the shared infrastructure account',
        detail:
          'It holds the most trust relationships and the network position into everything. It needs the same trail, Config, GuardDuty and SCP coverage as a production account, and its security groups should be as narrow as the workloads allow.',
      },
      {
        priority: 'medium',
        action: 'Use delegated administrator roles and keep the management account offline',
        detail:
          'Day-to-day organisation management should not require management account credentials, and the management account should not be reachable from a workload account.',
      },
      {
        priority: 'medium',
        action: 'Shorten cross-account session durations',
        detail:
          'A short session limits how long a stolen cross-account credential is useful, and forces the attacker to re-execute the chain, which multiplies the chances of detection.',
      },
      {
        priority: 'low',
        action: 'Review the estate trust graph quarterly',
        detail:
          'Trust relationships accumulate quietly. Every quarter, confirm each edge still has a reason, an owner and a target that needs it.',
      },
    ],
  },
  checklist: [
    {
      id: 'estate-1',
      text: 'List every account in the organisation and check the enrolment state.',
      command:
        'aws organizations list-accounts --query "Accounts[].{Id:Id,Name:Name,Status:Status,Joined:JoinedMethod}"',
      expected:
        'Every account is ACTIVE and enrolled through the same path. A NULL JoinedMethod or an unexpected one is a finding.',
    },
    {
      id: 'estate-2',
      text: 'Check whether the root SCP is effective at every account.',
      command:
        'aws organizations describe-effective-policy --policy-type SERVICE_CONTROL_POLICY --target-id o-abc123',
      expected:
        'The effective policy at the root includes the IAM write deny, and the same applies when queried against an individual account.',
    },
    {
      id: 'estate-3',
      text: 'Find every trust relationship that trusts an entire organisation.',
      command:
        'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {} | grep -l "PrincipalOrgID"',
      expected:
        'Every organisation-scoped trust names a specific principal in the condition as well. An organisation-scoped trust with no PrincipalArn is a hole.',
    },
    {
      id: 'estate-4',
      text: 'Check who can create accounts.',
      command:
        'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/Target \\\n  --action-names iam:CreateAccount organizations:CreateAccount',
      expected:
        'Only the vending pipeline role can create accounts. Any human with the permission can create one inside your trust boundary.',
    },
    {
      id: 'estate-5',
      text: 'Confirm the organisation trail covers every account.',
      command:
        'aws cloudtrail describe-trails --region us-east-1 --query "trailList[].Name" --output text',
      expected:
        'The organisation trail appears alongside the account-level trails, and it is not stoppable from a workload account.',
    },
    {
      id: 'estate-6',
      text: 'Enumerate the accounts that trust the shared infrastructure account.',
      command:
        'aws iam list-roles --query "Roles[].Arn" --output text | xargs -I{} aws iam get-role --role-name {} | grep -B3 -A6 "arn:aws:iam::123456789012:role/SharedInfra"',
      expected:
        'A short list you can justify. Every entry is a network and trust position into the estate.',
    },
    {
      id: 'estate-7',
      text: 'Check whether the management account is reachable from a workload account.',
      command:
        'aws organizations describe-organization --query "Organization.MasterAccountId"',
      expected:
        'No role in any workload account can assume into the management account without a deliberate, audited process.',
    },
    {
      id: 'estate-8',
      text: 'Confirm every account has Config, GuardDuty and a trail.',
      command:
        'aws configservice describe-configuration-recorders --query "ConfigurationRecorders[].name"',
      expected:
        'A recorder in every account. An account without one is an account where nothing is known to have happened.',
    },
  ],
  references: [
    { label: 'AWS Organizations — best practices', url: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best_practices.html' },
    { label: 'AWS Organizations — trusted access for account vending', url: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_trusted_access.html' },
    { label: 'AWS CloudTrail — organisation trails', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-organizational-trails.html' },
    { label: 'AWS Control Tower', url: 'https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html' },
  ],
  updated: '2026-11-22',
}
