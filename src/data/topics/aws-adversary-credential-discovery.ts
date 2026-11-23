import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/adversary/credential-discovery',
  title: 'Credential discovery and enumeration',
  cloud: 'aws',
  stage: 'adversary',
  track: 'Identity & access',
  summary:
    'Turning a single authenticated session into a complete inventory of every credential, principal and secret the account can reach.',
  duration: '35 min',
  difficulty: 3,
  prerequisites: [
    'aws/foundation/identity-and-trust',
    'aws/operator/logging-and-audit',
    'aws/operator/storage-and-data',
  ],
  enables: [
    'aws/adversary/iam-policy-evaluation',
    'aws/adversary/assume-role-trust',
    'aws/redteam/attack-path-chaining',
  ],
  mentalModel:
    'Enumeration is not about finding a secret. It is about building the graph of who holds what, because the account hands you the graph through a handful of read APIs that almost nobody restricts.',
  concept: {
    body: `AWS credentials come in a small number of shapes, and knowing which shape you are holding tells you what you can do next.

**Long-lived access keys.** An access key ID plus a secret access key, created by \`iam:CreateAccessKey\`. They do not expire, they do not appear in CloudTrail when used, and they are the credential most likely to be found in a git repository, a CI variable, a backup, or an AMI.

**Session credentials.** An access key, a secret key and a *session token*, issued by STS. They expire — between 15 minutes and 12 hours by default — and they are recorded in CloudTrail when minted, with the assumed role in \`userIdentity\`.

**Federated credentials.** Issued by STS after a SAML or OIDC assertion. IAM Identity Center, GitHub Actions OIDC and the AWS console all produce these.

**Service-specific credentials.** ECR tokens (short-lived, password-based), RDS Auth tokens, ECS task credentials, EKS cluster user credentials.

**Instance and workload credentials.** The instance profile role's temporary credentials from IMDS, the ECS task role from the container credentials endpoint, the IRSA token from the EKS OIDC provider, and EKS Pod Identity.

**Managed secrets.** Secrets Manager values, SSM SecureString parameters, KMS ciphertext. These are not AWS credentials, but they are usually *other people's* credentials, and often the more valuable ones.

The important structural fact for an attacker: **almost all of this is enumerable through read APIs.** \`iam:list-users\`, \`iam:list-roles\`, \`iam:list-access-keys\`, \`secretsmanager:list-secrets\`, \`ssm:describe-parameters\`, \`ec2:describe-instances\`, \`lambda:list-functions\` — these calls are permitted for almost any principal with even modest IAM read access, because "read the account" and "operate the account" are separate grants and many policies grant the first.

The IAM credential report is the single most efficient enumeration tool in AWS. It returns a CSV with one row per user, including \`mfa_active\`, \`access_key_1_active\`, \`access_key_1_last_rotated\`, \`access_key_1_last_used_date\`, \`password_enabled\`, \`password_last_used\` and \`password_last_changed\`. It tells you who has long-lived credentials and who has not used them in months, which is exactly the set worth targeting.

Also worth knowing: \`aws sts get-caller-identity\` costs nothing and confirms the effective identity of the session, including whether you are a federated session and what the source identity was. Every attacker should start there, and every defender should know what it returns for each of their principals.`,
    keyPoints: [
      'The IAM credential report enumerates every user, their MFA status, their key rotation dates and their last-used dates in one call.',
      'Long-lived access keys are invisible in CloudTrail when used. Session credentials appear only when issued.',
      'Most AWS read APIs are far less restricted than the write APIs that matter, so enumeration is usually the easy part.',
      'Secrets Manager and Parameter Store list secrets by name even when GetSecretValue is denied. The name alone is often enough to know what to target.',
      'Instance profile, task role and IRSA credentials are all retrievable from the workload at runtime, which is the discovery path that does not need API access at all.',
      'Federated credentials record the original session name and source identity, which is how a session attributed to a CI pipeline is distinguished from a stolen one.',
    ],
    misconceptions: [
      {
        claim: 'If GetSecretValue is denied, the secret is safe.',
        truth:
          'The name is usually still listable, and the name tells you what it unlocks. Many secret names contain the environment, the database and the purpose — prod/db-password — which is enough to know what to attack and where.',
      },
      {
        claim: 'Rotating access keys is enough to invalidate a leaked key.',
        truth:
          'It invalidates the key, not the copy. The key material may already be in a snapshot, a git history, a chat message, or an attacker\'s hands, and any data exfiltrated with it is already gone.',
      },
      {
        claim: 'A principal with no write permissions cannot do damage.',
        truth:
          'It can enumerate the entire account, read every secret its policy allows, read every object it can reach, and use the credential report to find a principal that can write. Read access is the reconnaissance phase, not a safe state.',
      },
    ],
  },
  attack: {
    body: `Enumeration in AWS is fast and mostly unauthenticated-looking, because AWS read APIs are cheap and rarely blocked. The workflow has four stages.

**Stage one: confirm who you are.** \`aws sts get-caller-identity\` returns the account, the ARN and the session. If you are a role, the role name tells you which permission set you have and what it was designed for.

**Stage two: build the principal inventory.** Users, groups, roles, managed policies, their attachments. The IAM credential report does the users in one shot.

**Stage three: build the credential inventory.** Access keys per user, secrets, parameters, instance profiles, and what each one is attached to.

**Stage four: read the contents.** Secrets Manager values, parameter values with decryption, S3 objects that contain configuration files, and the environment of every function and task definition.

The goal of all four is a written map: principal → credential → attached policy → reachable resource. Once you have that map, the next action is obvious, and you have already chosen which policy to read next — \`iam-policy-evaluation\` — or which role to assume — \`assume-role-trust\`.

One caution that applies to both sides of this exercise: enumeration calls are logged. A burst of \`iam:list-*\` and \`secretsmanager:list-secrets\` from a principal that does not normally enumerate is a detection signature, and a good defender will notice it.`,
    techniques: [
      {
        name: 'Pull the IAM credential report',
        what: 'Get every user with MFA status, key rotation dates and last-used dates in one CSV.',
        steps: [
          '`aws iam generate-credential-report` returns a report already generated.',
          '`aws iam get-credential-report --query "Content" --output text | base64 -d` prints the CSV.',
          'Filter for `mfa_active` false, `access_key_1_active` true, and a `access_key_1_last_used_date` that is old or empty.',
        ],
        command:
          'aws iam generate-credential-report && aws iam get-credential-report --query "Content" --output text | base64 -d',
        impact:
          'A complete list of human identities, which of them have no MFA, and which of them have a dormant access key. Dormant keys are the ones nobody notices still working.',
      },
      {
        name: 'Enumerate every role and its trust policy',
        what: 'Map the role graph of the account, including cross-account trust.',
        command:
          'aws iam list-roles --query "Roles[].[RoleName,Arn,AssumeRolePolicyDocument.Statement[].Principal]" --output json',
        impact:
          'The role graph is the privilege graph. Roles trusted by external accounts or by wildcards are the entry points.',
      },
      {
        name: 'Enumerate the access keys attached to each user',
        what: 'Find the long-lived credentials in the account and their last-used dates.',
        command:
          'aws iam list-users --query "Users[].UserName" --output text | xargs -I{} aws iam list-access-keys --user-name {}',
        impact:
          'The set of long-lived credentials. Each one is a durable, unlogged way back in after every other foothold is closed.',
      },
      {
        name: 'List and read the secrets',
        what: 'Enumerate the secret stores and pull the values where the policy allows.',
        steps: [
          '`aws secretsmanager list-secrets --query "SecretList[].[Name,ARN]"`.',
          '`aws ssm describe-parameters` for SecureString parameters in Parameter Store.',
          'Read values with `aws secretsmanager get-secret-value --secret-id <name>` and `aws ssm get-parameter --name <name> --with-decryption`.',
        ],
        command:
          'aws secretsmanager list-secrets --query "SecretList[].[Name,CreatedDate]" --output table',
        impact:
          'Database passwords, API keys and tokens. The names alone usually reveal the architecture of the application and what the next target is.',
      },
      {
        name: 'Read the compute environments for embedded credentials',
        what: 'Extract plaintext configuration from functions, task definitions and instances.',
        command:
          'aws lambda get-function-configuration --function-name payments --query "Environment.Variables" --output json',
        impact:
          'Environment variables, third-party tokens, and occasionally a set of AWS credentials that were placed there instead of in the role.',
      },
      {
        name: 'Harvest credentials from a local filesystem or process',
        what: 'Read the CLI configuration, credential process output, and process environment where you already have execution.',
        steps: [
          '`cat ~/.aws/config ~/.aws/credentials` for static profiles.',
          '`aws configure list` for the profiles the CLI is using.',
          'Check the process environment for `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.',
          'Look for `credential_process` entries, which run an arbitrary command to produce credentials.',
        ],
        command: 'aws configure list --profile default',
        impact:
          'On a build agent or a developer workstation this is often a higher-privilege credential than the session you arrived with.',
      },
    ],
    cases: [
      {
        title: 'Access keys committed to a source repository',
        source: 'Recurring pattern in published cloud assessment findings and public breach write-ups',
        impact:
          'Long-lived access keys found in a public repository or a leaked archive were used to enumerate and read the account. Because access key use is not recorded in CloudTrail, the activity left only the API calls it made, not the fact that the credential was stolen.',
        year: 2019,
      },
    ],
  },
  detect: {
    body: `Enumeration shows up as a burst of read calls. The distinguishing feature is not the individual call — most of them are legitimate — but the pattern: many principals, many resources, from an identity that does not normally enumerate.

The signals worth building:

**Enumeration bursts.** \`iam:ListUsers\`, \`iam:ListRoles\`, \`iam:ListAccessKeys\`, \`iam:GetCredentialReport\`, \`secretsmanager:ListSecrets\`, \`ssm:DescribeParameters\` in quick succession from the same principal.

**Credential report access.** \`iam:GenerateCredentialReport\` and \`iam:GetCredentialReport\` are unusual calls. Almost nobody runs them regularly. They are a strong tripwire on their own.

**Key creation.** \`iam:CreateAccessKey\` and \`iam:UpdateAccessKey\` are how an attacker makes enumeration durable. Any call from a principal that does not administer users is worth a page.

**Secret reads.** \`secretsmanager:GetSecretValue\` and \`ssm:GetParameter\` with decryption, from a principal that is not the workload you expect.

**Anomalous use of long-lived keys.** Because access key *use* is not in CloudTrail, you detect it at the API layer: the key appears in \`userIdentity.arn\` as an IAMUser principal, and a human principal making a machine's call pattern is suspicious.

**Source IP and ASN.** A credential used from an IP range you do not recognise is the single most reliable indicator available for stolen keys.`,
    signals: [
      {
        signal: 'The credential report was generated or read',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, sourceIPAddress\n| filter eventName = "GenerateCredentialReport" or eventName = "GetCredentialReport"\n| stats count() by userIdentity.arn, sourceIPAddress`,
        note:
          'Almost nobody runs this on a schedule. Treat it as a deliberate request for a complete identity inventory.',
      },
      {
        signal: 'A burst of identity enumeration calls',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, sourceIPAddress\n| filter eventName in ["ListUsers","ListRoles","ListAccessKeys","ListPolicies","ListGroups","ListRolePolicies","ListAttachedRolePolicies"]\n| stats count() by userIdentity.arn, eventName`,
        note:
          'A single call is normal. Twenty list calls in a minute from one principal is reconnaissance, not administration.',
      },
      {
        signal: 'An access key was created or reactivated',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.userName, requestParameters.accessKeyId\n| filter eventName = "CreateAccessKey" or eventName = "UpdateAccessKey"\n| stats count() by eventName, userIdentity.arn, requestParameters.userName`,
        note:
          'This is how an attacker converts a temporary foothold into durable access. It should be near-zero outside the identity team.',
      },
      {
        signal: 'A secret was read by a principal that does not own the workload',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.secretId, requestParameters.withDecryption\n| filter eventName = "GetSecretValue" or eventName = "GetParameter"\n| stats count() by userIdentity.arn, requestParameters.secretId`,
        note:
          'Baseline the reader set per secret. A new reader on a production secret is one of the highest-value alerts in AWS.',
      },
      {
        signal: 'An IAM user principal making machine-style API calls',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.type, userIdentity.arn, sourceIPAddress, userAgent\n| filter userIdentity.type = "IAMUser"\n| stats count() by userIdentity.arn, sourceIPAddress, userAgent`,
        note:
          'Long-lived key use does not produce an AssumeRole event, so the userAgent and the source IP are your only signals. A static key used from a new IP range is the classic indicator.',
      },
      {
        signal: 'Guardrail — restrict the credential report and bulk enumeration calls',
        source: 'IAM policy / SCP',
        query: `SCP Deny: iam:GenerateCredentialReport, iam:GetCredentialReport, iam:ListAccessKeys for principals that are not in the identity administration group`,
        note:
          'These calls are only needed by a small number of principals. Restricting them removes the fastest enumeration route without affecting workloads.',
      },
    ],
    posture: [
      'Alert on credential report access as a standalone tripwire — it is almost always deliberate.',
      'Track the source IP and ASN for every IAMUser principal. A key used from a new geography is an incident.',
      'Require MFA for every human principal so that a leaked key is not sufficient on its own.',
      'Restrict `iam:ListAccessKeys` and `iam:CreateAccessKey` to the identity administration group.',
      'Use IAM Access Analyzer and Config to identify IAM users that exist without a business owner.',
      'Rotate keys on a schedule and enforce it with an SCP that denies `iam:CreateAccessKey` outside the rotation workflow.',
    ],
  },
  fix: {
    body: `The remediation for credential exposure is not rotation alone. Rotation limits the window; removing long-lived credentials removes the class.

The target state: no human holds a long-lived access key, and every workload gets short-lived credentials from a role. That is achievable with IAM Identity Center plus per-workload roles, and it is the difference between a credential you can audit and one you cannot.

The migration sequence that works:

1. **Inventory.** The credential report gives you every key, its last-used date and its owner. Keys unused for ninety days are candidates for immediate deletion.
2. **Remove the obvious.** Delete keys nobody uses. Delete root keys. Delete keys belonging to deprovisioned staff.
3. **Replace what remains.** Get humans onto Identity Center. Get workloads onto instance profiles, task roles and IRSA.
4. **Prevent recurrence.** An SCP denying \`iam:CreateAccessKey\` outside the provisioning path stops the problem returning.

Then handle the secrets themselves, which are the credential people forget. The problem with a secret in Secrets Manager is rarely the store — it is the read permission.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Delete every unused access key and every root access key',
        detail:
          'The credential report shows the last-used date. A key unused for ninety days is a liability with no operational cost. Root keys are worse: they cannot be constrained by IAM at all.',
        snippet: `aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE`,
        snippetLang: 'bash',
      },
      {
        priority: 'critical',
        action: 'Move human access to IAM Identity Center and retire IAM users',
        detail:
          'Identity Center gives short-lived, centrally revocable, MFA-backed sessions and a complete access log. IAM users with static keys give none of those.',
      },
      {
        priority: 'high',
        action: 'Replace workload access keys with roles',
        detail:
          'Instance profiles for EC2, task roles for ECS and Fargate, IRSA or Pod Identity for EKS, and execution roles for Lambda. The credential is then derived from the workload identity and rotates automatically.',
      },
      {
        priority: 'high',
        action: 'Deny access key creation outside the provisioning path',
        detail:
          'An SCP that denies `iam:CreateAccessKey`, `iam:UpdateAccessKey` and `iam:UpdateLoginProfile` in every account except the identity administration account removes the most durable persistence mechanism in IAM.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:UpdateLoginProfile"],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Restrict who can read secrets and which secrets',
        detail:
          'Scope the read permission to the specific secret ARN rather than `"*"` or a name prefix. Use a customer-managed KMS key so you have a second policy layer and a revocation point.',
        snippet: `{
  "Effect": "Allow",
  "Action": ["secretsmanager:GetSecretValue"],
  "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-password-AbCdEf"
}`,
        snippetLang: 'json',
      },
      {
        priority: 'medium',
        action: 'Rotate secrets on a schedule and on role change',
        detail:
          'Rotation that is not automated does not happen. Enable automatic rotation in Secrets Manager where the credential is stored in a format the Lambda rotation function understands.',
      },
      {
        priority: 'medium',
        action: 'Scan repositories and CI configuration for embedded keys',
        detail:
          'Run a secret scanner over the source tree, the CI configuration and the container images. The goal is to find the key before it is pushed, because a key that reaches a public repository has usually already been used.',
      },
      {
        priority: 'medium',
        action: 'Treat the CLI credential file and credential_process as sensitive',
        detail:
          'If a local profile uses `credential_process`, that command runs with the user\'s privileges and its output is the credential. Audit every profile, and prefer SSO profiles that hold no key material at all.',
      },
      {
        priority: 'low',
        action: 'Remove IAM users that have no activity and no owner',
        detail:
          'Dormant users are credentials waiting for someone to notice them. The credential report plus a Config rule gives you the list on a schedule.',
      },
    ],
  },
  checklist: [
    {
      id: 'cred-1',
      text: 'Confirm who you are and which account you are in.',
      command: 'aws sts get-caller-identity',
      expected:
        'The account id and ARN are ones you expected. An unexpected account id is the first thing to check on any session.',
    },
    {
      id: 'cred-2',
      text: 'Pull the credential report and find users without MFA or with unused keys.',
      command:
        'aws iam generate-credential-report && aws iam get-credential-report --query "Content" --output text | base64 -d',
      expected:
        'Every user with a key either has MFA or has a documented exception. Keys unused for 90 days are deleted.',
    },
    {
      id: 'cred-3',
      text: 'List every access key in the account with its last-used date.',
      command:
        'aws iam list-users --query "Users[].UserName" --output text | xargs -I{} aws iam list-access-keys --user-name {}',
      expected:
        'A short list, each key traceable to a named owner and a workload that still needs it.',
    },
    {
      id: 'cred-4',
      text: 'Enumerate the secrets and confirm which principals read them.',
      command:
        'aws secretsmanager list-secrets --query "SecretList[].[Name,ARN]" --output text && aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue --max-results 50',
      expected:
        'Every secret has a small, stable reader set. Names do not leak environment or database identifiers to anyone with list access.',
    },
    {
      id: 'cred-5',
      text: 'Check whether any function or task definition carries a credential in plaintext.',
      command:
        'aws lambda list-functions --query "Functions[].FunctionName" --output text | xargs -I{} aws lambda get-function-configuration --function-name {} --query "[FunctionName,Environment.Variables]"',
      expected: 'No variable name or value looks like a key, password, token or secret.',
    },
    {
      id: 'cred-6',
      text: 'Confirm the account has no root access keys and no root API activity.',
      command:
        'aws iam list-access-keys --user-name <root-alias> && aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity --max-results 5',
      expected: 'No root keys, and the recent GetCallerIdentity calls are from known principals.',
    },
    {
      id: 'cred-7',
      text: 'Verify that key creation is blocked outside the provisioning path.',
      command:
        'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:user/dev --action-names iam:CreateAccessKey iam:GetCredentialReport',
      expected: 'Both actions are denied for the developer principal.',
    },
  ],
  references: [
    { label: 'AWS IAM credential report', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/credential-reports.html' },
    { label: 'AWS STS API reference', url: 'https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html' },
    { label: 'AWS Secrets Manager', url: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html' },
    { label: 'AWS IAM Identity Center', url: 'https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html' },
  ],
  updated: '2026-11-21',
}
