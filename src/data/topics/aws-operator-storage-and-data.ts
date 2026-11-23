import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/operator/storage-and-data',
  title: 'Storage and data exposure',
  cloud: 'aws',
  stage: 'operator',
  track: 'Storage',
  summary:
    'S3, EBS, RDS and the secret stores: where the data actually sits, how public exposure happens, and the cross-account copy paths that leak it.',
  duration: '35 min',
  difficulty: 3,
  prerequisites: [
    'aws/foundation/identity-and-trust',
    'aws/foundation/network-boundaries',
  ],
  enables: [
    'aws/adversary/credential-discovery',
    'aws/redteam/attack-path-chaining',
  ],
  mentalModel:
    'Storage exposure in AWS is almost never a broken encryption algorithm. It is a permission, a policy condition, or a copy operation that grants a principal access nobody intended — so audit who can read, not whether the bytes are safe at rest.',
  concept: {
    body: `AWS storage is split across services with different security models. You need to know which one you are dealing with before you test it.

**S3** is object storage with a flat namespace. It has no "network" — bucket and object ACLs and bucket policies are the only access control, plus IAM. Four settings on the bucket's Block Public Access configuration do most of the work:

- \`BlockPublicAcls\` — rejects PUTs of ACLs that make objects public.
- \`IgnorePublicAcls\` — ignores any public ACL on existing objects.
- \`BlockPublicPolicy\` — rejects bucket policies that grant public access.
- \`RestrictPublicBuckets\` — restricts cross-account access to buckets that have a public policy or ACL.

All four should be on for every bucket. Object Ownership is now set to \`BucketOwnerEnforced\` on new buckets, which disables ACLs entirely and makes the bucket policy the only grant. Presigned URLs extend the reach of a single object to a bearer token with a lifetime, and the URL itself is the secret — treat it as a credential, log it, and scope it.

**EBS** volumes attach to one instance in one availability zone. A snapshot is a copy in the region; a snapshot can be shared with another AWS account, and the copy is governed by the *destination* account\'s controls, not yours. Encrypted volumes are now the default for new EBS volumes, and shared snapshots of encrypted volumes must be re-encrypted by the recipient or they arrive unencrypted.

**RDS and Aurora** have a \`PubliclyAccessible\` flag that is independent of your security groups. A DB instance in a public subnet with \`PubliclyAccessible: true\` gets a public IP address and is reachable from the internet if the security group permits it. Database snapshots can be shared with other accounts, and Aurora clusters can have cross-region read replicas that copy every row into another region.

**EFS** mounts over NFS inside a VPC. Its security groups are the access control, and because NFS has no per-object IAM, a mount is a grant of access to the whole filesystem.

**The secret stores** are the highest-value data in the estate and the most often exposed. Secrets Manager, SSM Parameter Store (SecureString), KMS, and SSM Session Manager each hold material that unlocks something else. Parameter Store is regional; Secrets Manager is regional too, and both are subject to IAM and, where KMS is involved, a key policy.

**Copy paths are the quiet leak.** Cross-region replication, cross-account replication, snapshot sharing, DB export tasks to S3, Redshift and Athena writing to S3, and \`aws s3 sync\` all move data into a destination that may have weaker controls. The source account's audit trail records the copy, not the copy itself.`,
    keyPoints: [
      'Bucket policies, not object ACLs, are the primary control in S3. Object Ownership of BucketOwnerEnforced disables ACLs entirely.',
      'Block Public Access has four independent toggles. Enabling only some of them leaves the bucket reachable.',
      'A presigned URL is a bearer token. Anyone holding it can read or write the object until it expires.',
      'EBS and RDS snapshots shared with another account are governed by that account\'s controls, not the source account\'s.',
      'A database snapshot is a full copy. Sharing one is sharing all the data in it.',
      'Secrets Manager and Parameter Store are the crown jewels; an IAM path to GetSecretValue is usually the shortest path to everything.',
    ],
    misconceptions: [
      {
        claim: 'Encrypted storage means an attacker with read access learns nothing.',
        truth:
          'Encryption at rest does not help against an authorised read. S3 server-side encryption decrypts for the caller before the policy decision is visible to them, and KMS keys can be granted to a principal directly. The relevant control is who can call GetObject or GetSecretValue.',
      },
      {
        claim: 'A bucket with no policy is safe because it inherits the account policy.',
        truth:
          'It inherits nothing. With no bucket policy, access is exactly what the identity policies grant. An identity policy that allows s3:GetObject on * plus an empty bucket policy equals a public-by-policy bucket.',
      },
      {
        claim: 'Sharing a snapshot does not share the data.',
        truth:
          'A shared snapshot is a copy the recipient can read in their own account. RDS restore from a shared snapshot copies every row, including credentials and personal data.',
      },
    ],
  },
  attack: {
    body: `Storage attacks follow a small set of recurring patterns. The techniques below are ordered from passive to active.

**Anonymous listing.** Historically, \`s3:ListBucket\` was enough to enumerate a bucket without \`s3:GetObject\`. Buckets named after a company, a service or an environment were indexed and listed at scale. Public Access Block and the \`s3:ListBucket\` condition on a public policy now close most of this, but legacy buckets still exist.

**Public object access.** A bucket policy with \`"Principal": "*"\` and \`"Action": "s3:GetObject"\` — often with a condition on \`aws:PrincipalOrgID\` that is missing, or with a condition that is trivially satisfiable. The classic trap is a condition on \`aws:SourceIp\` using \`IpAddress\` instead of \`NotIpAddress\`: \`"IpAddress": {"aws:SourceIp": "1.2.3.4"}\` means "only from 1.2.3.4", which is safe, but \`"NotIpAddress"\` with the wrong CIDR means "from everywhere except", which is not what the author intended.

**Access point and prefix confusion.** Access points give each application a distinct path into a bucket. A bucket policy that grants access to the bucket but is not written with the access point ARN in mind can be bypassed, or the access point policy can grant access the bucket policy did not intend.

**Snapshot sharing.** \`ec2:ModifySnapshotAttribute\` with a \`createVolumePermission\` for another account, or \`rds:ModifyDBSnapshotAttribute\` with \`restore\` pointing at a foreign account ID. Both are one API call and both produce a full copy of the data outside your account.

**Secret theft.** \`secretsmanager:GetSecretValue\` on the database credential, or \`ssm:GetParameter --with-decryption\`, converts an IAM foothold into the application's own credentials.

**Write path abuse.** Writing into a bucket that a Lambda function or a Glue job trusts is an old and reliable technique: the file lands, the trigger fires, and the code runs with the function's role.`,
    techniques: [
      {
        name: 'Test bucket public access without credentials',
        what: 'Attempt anonymous list and read against a candidate bucket.',
        command:
          'curl -s -o /dev/null -w "%{http_code}\\n" https://prod-data.s3.amazonaws.com/ && curl -s https://prod-data.s3.amazonaws.com/ | head -20',
        impact:
          'A 200 on the listing means the bucket is world-readable. A 403 confirms only that this path is closed; it does not confirm the policy is tight.',
      },
      {
        name: 'Enumerate every bucket and its public access posture',
        what: 'List all buckets in the account and pull each Block Public Access configuration.',
        steps: [
          '`aws s3api list-buckets --query "Buckets[].Name"`.',
          'For each bucket, `aws s3api get-public-access-block --bucket <name>` and `aws s3api get-bucket-policy-status --bucket <name>`.',
          'For buckets with a policy, read it with `aws s3api get-bucket-policy --bucket <name>` and check the Principal and the conditions.',
        ],
        command:
          'aws s3api get-public-access-block --bucket prod-data --output json',
        impact:
          'A full inventory of buckets, their encryption settings, their policies and whether they are reachable without a credential.',
      },
      {
        name: 'Read and write with a presigned URL',
        what: 'Use a leaked or issued presigned URL to read or modify an object.',
        command:
          'curl -s "https://prod-data.s3.amazonaws.com/export.csv?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20261119%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261119T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=abcdef0123456789"',
        impact:
          'The URL is the credential. It grants exactly what the signature covers, with no way to revoke it except rotating the signing key or changing the object.',
      },
      {
        name: 'Share an EBS snapshot with another account',
        what: 'Copy a block device into an account you control.',
        command:
          'aws ec2 modify-snapshot-attribute --snapshot-id snap-0abc123 \\\n  --attribute createVolumePermission \\\n  --create-volume-permission \'{"VolumeId":"vol-0abc123","UserId":"123456789012"}\'',
        impact:
          'The recipient can create a volume from the snapshot and mount it. If the source volume held credentials, SSH keys or a database, they now own a copy.',
      },
      {
        name: 'Share a database snapshot and restore it elsewhere',
        what: 'Copy an RDS or Aurora snapshot to a foreign account.',
        command:
          'aws rds modify-db-snapshot-attribute --db-snapshot-identifier prod-db-snap \\\n  --attribute-name restore \\\n  --restore-attribute \'{"RestoreType":"FULL_COPY","TargetAWSAccountId":"123456789012"}\'',
        impact:
          'Every row of the database in a different account, where your audit trail does not reach and your key policy does not apply.',
      },
      {
        name: 'Pull a secret through the API',
        what: 'Convert an IAM foothold into the application credential.',
        command:
          'aws secretsmanager get-secret-value --secret-id prod/db --query SecretString --output text',
        impact:
          'Database passwords, API keys and tokens. The secret is often the real prize, not the data it unlocks.',
      },
    ],
    cases: [
      {
        title: 'Publicly listed storage buckets discovered by bulk scanning',
        source: 'Recurring pattern in published cloud assessment findings and public breach write-ups',
        impact:
          'Buckets left readable without authentication were indexed and enumerated at scale. Object contents included configuration, logs and, in some cases, live credentials that were then used to reach the rest of the estate.',
        year: 2020,
      },
      {
        title: 'Cross-account snapshot sharing as a data exfiltration path',
        source: 'Widely documented cloud misconfiguration class',
        impact:
          'A single attribute change on a snapshot or a database snapshot copied a complete copy of the data into an account the organisation did not control, and the copy did not appear in the source account\'s object access logs.',
        year: 2022,
      },
    ],
  },
  detect: {
    body: `Two log sources carry the data-plane signal for storage. S3 data events in CloudTrail record object-level access, but only if you have enabled S3 data events — by default S3 does not log individual object reads into CloudTrail. That is the single most important configuration fact in this topic: a bucket can be read continuously and CloudTrail will show you nothing at the object level.

S3 server access logging writes a separate log file per bucket, including anonymous requests. It is not on by default and it does not record the identity of a requester who presented a credential — for that you need CloudTrail data events.

CloudTrail management events cover the control plane: \`PutBucketPolicy\`, \`PutBucketAcl\`, \`PutPublicAccessBlock\`, \`DeleteBucketPolicy\`, \`CreateBucket\`, \`ModifySnapshotAttribute\`, \`ModifyDBSnapshotAttribute\`, \`ModifyDBInstance\`. These are how exposure is *created*.

GuardDuty and IAM Access Analyzer add the anomaly layer: Access Analyzer finds buckets that grant public or cross-account access, and it produces a finding with the exact offending statement.`,
    signals: [
      {
        signal: 'Bucket policy written or public access block changed',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.bucketName, requestParameters.policyDocument\n| filter eventName = "PutBucketPolicy" or eventName = "PutPublicAccessBlock" or eventName = "DeleteBucketPolicy" or eventName = "PutBucketAcl"\n| stats count() by eventName, userIdentity.arn, requestParameters.bucketName`,
        note:
          'Any of these four events can change who can read data. Baseline them and alert on changes from outside the platform team.',
      },
      {
        signal: 'Anonymous or unsigned S3 access',
        source: 'S3 server access logs / CloudTrail data events',
        query: `fields @timestamp, eventName, userIdentity.type, sourceIPAddress, requestParameters.key\n| filter eventName = "GetObject" and userIdentity.type = "Anonymous"\n| stats count() by requestParameters.key, sourceIPAddress`,
        note:
          'Requires S3 data events on the bucket. Anonymous requests also show up in the bucket\'s server access log with no requester identity at all.',
      },
      {
        signal: 'Snapshot or database snapshot shared with another account',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.snapshotId, requestParameters.createVolumePermission\n| filter eventName = "ModifySnapshotAttribute" or eventName = "ModifyDBSnapshotAttribute"\n| stats count() by eventName, userIdentity.arn, requestParameters.snapshotId`,
        note:
          'Sharing is rare in normal operation. Any change to share permissions should page someone.',
      },
      {
        signal: 'Secret value read by a principal that never reads secrets',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.secretId\n| filter eventName = "GetSecretValue" or eventName = "GetParameter"\n| stats count() by userIdentity.arn, requestParameters.secretId`,
        note:
          'Secrets are read by a small, stable set of principals. A new principal in this list is one of the highest-value detections in AWS.',
      },
      {
        signal: 'Guardrail — a bucket grants public or external access',
        source: 'IAM Access Analyzer (S3 analyzer)',
        query: `aws accessanalyzer list-analyzed-resources --resource-type "AWS::S3::Bucket" --filter '{"Status":{"eq":["ERROR","WARNING"]}}'`,
        note:
          'Run this against every bucket in every account, and resolve findings to a ticket rather than a dashboard.',
      },
      {
        signal: 'Guardrail — a database instance was made publicly accessible',
        source: 'AWS Config managed rule',
        query: `AWS Config rule RDS_INSTANCE_PUBLIC_ACCESS_CHECK with scope = all RDS DB instances'`,
        note:
          'PubliclyAccessible is a DB instance attribute, not a security group setting, so it needs its own control.',
      },
    ],
    posture: [
      'Turn on S3 data events for every bucket that holds anything interesting. Without them, object reads are invisible in CloudTrail.',
      'Enable server access logging on every bucket and ship the logs to a different account than the bucket.',
      'Run IAM Access Analyzer for S3 account-wide, and route findings into the same queue as other findings.',
      'Enable the AWS Config managed rules for public access, encryption and snapshot sharing across every account.',
      'Deny `s3:PutBucketPolicy` and `s3:PutPublicAccessBlock` through an SCP outside the platform team, so the setting cannot be weakened by a compromised application role.',
      'Log CloudTrail data events to CloudWatch Logs rather than only S3, so they are queryable in the same place as management events.',
    ],
  },
  fix: {
    body: `Storage remediation is mechanical once you have the inventory. The order below goes from "stop the bleeding" to "stop it recurring".

Start with the public posture. Enforcing Block Public Access across the estate is a single API call per bucket and it is reversible; do it even if you believe every bucket is already closed, because belief is not a control.

Then move to encryption and key control. Default SSE-S3 is fine for most data. SSE-KMS with a customer-managed key is right for anything regulated, because it gives you a second place to enforce — the key policy — and a place to revoke. Then check the copy paths, because a perfectly configured bucket still leaks through replication.

The durable fix is structural: separate the account that holds data from the account that runs the application, and give the application account no ability to change bucket policies at all.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Enforce all four Block Public Access settings on every bucket',
        detail:
          'Partial enforcement is the most common gap. Enabling only BlockPublicPolicy leaves a path through object ACLs; enabling only RestrictPublicBuckets leaves cross-account access to a bucket that has a public policy or ACL in some states.',
        snippet: `aws s3api put-public-access-block --bucket prod-data \\\n  --public-access-block-configuration \\\n  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
        snippetLang: 'bash',
      },
      {
        priority: 'critical',
        action: 'Move from object ACLs to bucket policies with Object Ownership set to BucketOwnerEnforced',
        detail:
          'BucketOwnerEnforced disables ACLs entirely, so the bucket policy becomes the only grant and the "a permissive ACL inherited the object" class of bug disappears. It cannot be changed back on a bucket without changing ownership on every object.',
        snippet: `aws s3api put-object-ownership --bucket prod-data \\\n  --ownership-controls Rules=[{ObjectOwnership:BucketOwnerEnforced}]`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Encrypt with a customer-managed KMS key and scope the key policy',
        detail:
          'A customer-managed key gives you a revocation point and a second policy layer. Scope the key policy to the principals that need it and add a key policy deny for anything outside the account, so a public bucket policy cannot be used to read data.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:role/AppRole" },
    "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Stop sharing snapshots and database snapshots with other accounts',
        detail:
          'Sharing creates a copy outside your controls. If you genuinely need cross-account restore, use a role plus an approval workflow rather than open snapshot sharing, and audit the permission on every snapshot.',
        snippet: `aws ec2 modify-snapshot-attribute --snapshot-id snap-0abc123 --attribute createVolumePermission --reset`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Set PubliclyAccessible to false on every database instance and cluster',
        detail:
          'The flag is independent of security groups. Instances should be reachable through a bastion or a VPN, never directly.',
        snippet: `aws rds modify-db-instance --db-instance-identifier prod-db --no-publicly-accessible --apply-immediately`,
        snippetLang: 'bash',
      },
      {
        priority: 'medium',
        action: 'Treat secrets as a separate blast radius',
        detail:
          'Put secrets in Secrets Manager rather than in environment variables, task definitions, user data or SSM plain parameters. Give the reading principal only GetSecretValue on the specific secret, and rotate on a schedule that matches the exposure risk.',
      },
      {
        priority: 'medium',
        action: 'Review every replication and export path',
        detail:
          'S3 CRR and CRAC, RDS export tasks, snapshot sharing, Redshift and Athena output locations, and the CLI\'s own `aws s3 sync` all move data. Require the destination to meet the same encryption and access standard, and log the copies.',
      },
      {
        priority: 'medium',
        action: 'Scope presigned URLs and log their use',
        detail:
          'Presign with the narrowest possible operation and the shortest workable expiry, and put the URL behind a redirector you control so it is not shared verbatim. Log presigning calls so you know which URLs exist.',
      },
      {
        priority: 'low',
        action: 'Enable versioning and object lock for data that must not be destroyed',
        detail:
          'Versioning protects against accidental and malicious deletion; object lock with a retention period protects against an attacker with delete permissions who is also willing to wait.',
      },
    ],
  },
  checklist: [
    {
      id: 'sto-1',
      text: 'Confirm every bucket in the account has all four Block Public Access settings enabled.',
      command:
        'aws s3api list-buckets --query "Buckets[].Name" --output text | xargs -I{} aws s3api get-public-access-block --bucket {}',
      expected:
        'Every bucket returns four "true" values. Any false is a finding to fix before anything else.',
    },
    {
      id: 'sto-2',
      text: 'Check whether S3 data events are enabled on the buckets that matter.',
      command:
        'aws cloudtrail describe-trails --query "trailList[].{Name:Name,S3Data:EventSelectors[].DataResources}"',
      expected:
        'Bucket ARNs appear in DataResources for every bucket you would want to see object reads against.',
    },
    {
      id: 'sto-3',
      text: 'Find every snapshot shared with an account other than yours.',
      command:
        'aws ec2 describe-snapshots --owner-ids self --query "Snapshots[].SnapshotId" --output text | xargs -I{} aws ec2 describe-snapshot-attribute --snapshot-id {} --attribute createVolumePermission',
      expected:
        'Only your own account id appears in the createVolumePermission list for every snapshot.',
    },
    {
      id: 'sto-4',
      text: 'Find every database instance exposed to the internet.',
      command:
        'aws rds describe-db-instances --query "DBInstances[?PubliclyAccessible==true].[DBInstanceIdentifier,Endpoint.Address]"',
      expected: 'An empty result, or a short list of instances that are deliberately public and documented.',
    },
    {
      id: 'sto-5',
      text: 'List every secret and check which principals actually read it.',
      command:
        'aws secretsmanager list-secrets --query "SecretList[].[Name,ARN]" --output text && aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue --max-results 50',
      expected:
        'The set of principals reading each secret is small, stable and matches the workload design.',
    },
    {
      id: 'sto-6',
      text: 'Check for buckets with a policy granting access outside the account.',
      command:
        'aws accessanalyzer list-analyzed-resources --resource-type "AWS::S3::Bucket" --filter \'{"Status":{"eq":["ERROR","WARNING"]}}\'',
      expected:
        'Zero unresolved findings. Every cross-account grant has a documented owner and a reason.',
    },
  ],
  references: [
    { label: 'AWS S3 Block Public Access', url: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html' },
    { label: 'AWS S3 Object Ownership', url: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html' },
    { label: 'AWS EBS snapshot sharing', url: 'https://docs.aws.amazon.com/ebs/latest/userguide/ebs-sharing.html' },
    { label: 'AWS IAM Access Analyzer S3', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-checking-s3.html' },
  ],
  updated: '2026-11-19',
}
