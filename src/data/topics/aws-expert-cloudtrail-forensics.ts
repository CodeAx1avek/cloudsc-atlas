import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/expert/cloudtrail-forensics',
  title: 'CloudTrail forensics',
  cloud: 'aws',
  stage: 'expert',
  track: 'Observability',
  summary:
    'What CloudTrail can and cannot tell you after a compromise — and how to reconstruct a timeline from what it left behind.',
  duration: '35 min',
  difficulty: 5,
  prerequisites: [
    'aws/operator/logging-and-audit',
    'aws/redteam/iam-privilege-escalation',
  ],
  enables: [],
  mentalModel:
    'CloudTrail tells you which API calls were made and who made them. It does not tell you what the calls did, what they returned, or what the data was. Most of the work in cloud forensics is working out which of those three gaps your question actually needs.',
  concept: {
    body: `CloudTrail is the account's record of API calls. Understanding what it contains — and more importantly what it does not — is the difference between a useful investigation and a confident wrong answer.

**What is in the event.** \`eventTime\`, \`eventName\`, \`eventSource\`, \`sourceIPAddress\`, \`userAgent\`, \`userIdentity\` (which carries the type, the ARN, the account, and for assumed roles the \`sessionContext\` with the originating identity and the source identity), \`requestParameters\`, \`responseElements\`, \`errorCode\`, and \`eventID\`.

**What is not in the event, and this matters:**

- **The response body is redacted for most events.** \`responseElements\` is only populated for a small set of events. When \`s3:GetObject\` is recorded as a data event, the event says the object was read; it does not say what was in it.
- **Read paths are not recorded by default.** Only management events are logged unless you configure data events. If the attacker read a secret, that read may not exist anywhere.
- **The data itself is never in the trail.** For an S3 object, the trail records the key. The content is in the object.
- **The trail does not cover the data plane for most services.** API calls to S3, DynamoDB, SQS, Lambda invoke and Secrets Manager are only present if you enabled data events for them.

**Event types.** Management events cover control-plane calls (creating IAM policies, launching instances, creating buckets). Data events cover the reads and writes on resources such as S3 objects, Lambda invocations, DynamoDB items, and Secrets Manager secrets. CloudTrail Lake and Athena over the raw S3 files are the tools for working with the volume.

**Identity resolution is the analytical core.** For an assumed-role session, \`userIdentity.type\` is \`AssumedRole\`, \`userIdentity.arn\` is the role ARN, and \`sessionContext.sessionIssuer.arn\` names the role that was assumed and \`sessionContext.attributes.mfaAuthenticated\` records whether MFA was used. That is how you attribute an action to a human who never had an IAM identity of their own.

**The anti-forensic behaviours to look for.** These are the tells that someone knows they are being watched:

- \`StopLogging\`, \`UpdateTrail\`, \`DeleteTrail\`, \`PutEventSelectors\` — disabling or narrowing logging.
- \`DeleteTrail\` followed by no new events.
- \`CloudTrail:PutEventSelectors\` removing a data event selector.
- Deleting the trail's S3 bucket, or the log delivery role's permissions.
- Logging disabled in a region, or the trail switched to a single region.

**And the tampering with evidence.** \`DeleteTrail\`, \`DeleteFlowLogs\`, \`StopConfigurationRecorder\`, \`DeleteDetector\`, \`UpdateDetector\`, \`DisableSecurityHub\`, \`DeleteLogGroup\`, \`DeleteLogStream\` — the list of "turn off the thing that was watching me" actions is long and it is worth having it memorised.

**The central limitation.** CloudTrail records calls. If the attacker used credentials obtained from somewhere CloudTrail does not watch — an instance metadata read, a leaked key used outside the API, a credential exfiltrated and used from another country — the trail may show the *read* but not the *use*.`,
    keyPoints: [
      'responseElements is empty for most events. The trail records that a call was made, not what it returned.',
      'Data events are off by default. Without them, reads against S3, DynamoDB, Secrets Manager and Lambda are invisible.',
      'sessionContext.sessionIssuer.arn is how you attribute an action to the human behind an assumed role.',
      'The sessionIssuer.arn is the identity that assumed the role; sessionContext.attributes.sourceIdentity is the identity provider detail.',
      'mfaAuthenticated in sessionContext tells you whether MFA was satisfied for the session, which is a strong signal.',
      'The list of "disable the logging" API calls is short, and memorising it is the highest-value forensic skill in this topic.',
      'A credential obtained outside the API — from IMDS, a leak, or another tool — may never appear in CloudTrail at all.',
    ],
    misconceptions: [
      {
        claim: 'CloudTrail records everything that happened in the account.',
        truth:
          'It records API calls, and only the ones you configured. Data plane reads are off by default, response bodies are redacted for most events, and activity inside a container or a shell on a host is entirely outside its view.',
      },
      {
        claim: 'The trail shows what the attacker exfiltrated.',
        truth:
          'It shows which objects were read and when. It does not show the content. If you need to know what was taken, you need the object version history, the server access logs, or the data itself.',
      },
      {
        claim: 'If the trail was deleted, the evidence is gone.',
        truth:
          'Deletion stops future logging, not the historical record. The events already delivered to the S3 bucket remain, and the CloudTrail event history API retains 90 days of management events regardless of what happened to the trail.',
      },
    ],
  },
  attack: {
    body: `The offensive value of CloudTrail is that it is a map of what the account does. Reading the trail tells you what a service is actually used for, which identity does what, and which calls are normal.

But the same knowledge is what an attacker wants to blind themselves against, and that is where the tradecraft lives.

The order is always: blind first, then act. An attacker who acts first leaves a trail; an attacker who disables logging first leaves a gap that you have to notice indirectly.

The second offensive technique is **blending**. Calling legitimate APIs in a volume that matches normal activity is cheap and effective, because most detections are volume-based. The third is **choosing APIs that produce small or redacted events**, which is a smaller set than people expect but is worth knowing.

The fourth is **using the trail against you**: reading it tells you what is logged and what is not, which is a map of the gaps.`,
    techniques: [
      {
        name: 'Disable or narrow the trail',
        what:
          'Stop the logging, or remove the data event selectors that record the reads about to happen.',
        command:
          'aws cloudtrail update-trail --name my-trail --is-logging-enabled=false',
        steps: [
          'Identify which trail covers the account and where its log delivery role writes to.',
          'Either disable the trail, or narrow it with PutEventSelectors so the specific data events are no longer recorded.',
          'Note that CloudTrail event history still retains 90 days of management events, so this blinds the future, not the past.',
        ],
        impact:
          'Everything done afterwards is invisible to the trail. This is the first thing an attacker with the right permission does.',
      },
      {
        name: 'Stop the other logging services',
        what:
          'Turn off Flow Logs, Config, GuardDuty and Security Hub so there is no second source.',
        command:
          'aws configservice stop-configuration-recorder --config-configuration-recorder-name default',
        impact:
          'Removes the corroborating evidence that would otherwise reveal what the trail was blind to.',
      },
      {
        name: 'Delete the log destination',
        what:
          'Remove the S3 bucket the trail delivers to, or break the delivery role.',
        command:
          'aws s3 rb s3://my-central-trail-bucket --force',
        impact:
          'Destroys historical evidence as well as future collection, and is itself a highly visible event.',
      },
      {
        name: 'Read the trail to find the gaps',
        what:
          'Enumerate the log sources and identify what is not being recorded.',
        command:
          'aws cloudtrail describe-trails --region all --query "trailList[].{Name:Name,Multi:IsMultiRegionTrail,Home:HomeRegion}"',
        impact:
          'A map of the surveillance. Knowing which calls are logged tells you which calls are worth making and which are worth avoiding.',
      },
      {
        name: 'Blend with legitimate API activity',
        what:
          'Generate a volume of benign calls that matches the account\'s normal baseline.',
        steps: [
          'Read the trail and find the highest-volume legitimate actions for the identity.',
          'Repeat those actions at a similar rate before or during the malicious activity.',
          'Keep the volume close to baseline — a spike is as detectable as a drop.',
        ],
        impact:
          'Volume-based detections stop firing, and the malicious call is lost in the noise.',
      },
      {
        name: 'Prefer APIs whose events carry little detail',
        what:
          'Choose calls whose CloudTrail event omits request parameters or response elements.',
        impact:
          'The log records that something happened without recording what, which materially slows the investigation.',
      },
    ],
    cases: [
      {
        title: 'Trail stopped before exfiltration',
        source: 'Recurring pattern across cloud incident write-ups',
        impact:
          'In the recurring pattern, the trail is disabled shortly before a large data transfer, and the investigation then has to rely on S3 access logs, VPC Flow Logs and the bucket’s own object access logs — if those were enabled and not also disabled.',
      },
      {
        title: 'Event selectors narrowed to drop data events',
        source: 'Documented anti-forensic technique in cloud tradecraft research',
        impact:
          'In the recurring pattern, the trail keeps running and the alerting looks healthy, but a PutEventSelectors call removes the S3 or Secrets Manager data event. The management events look normal while the reads that matter have stopped being recorded.',
      },
    ],
  },
  detect: {
    body: `Detection here has three layers, and you need all three.

**The control-plane layer** detects the attacker blinding you: the calls that stop or change logging. These are high-confidence, low-volume, and should always page.

**The identity layer** detects behaviour changes: a principal doing something it has never done, or an assumption into an unusual role.

**The data layer** detects the objective: the first read of something, a read from a new source address, a bulk download. This is the layer that only exists if you enabled data events, and it is the layer that tells you what was actually taken.

The fourth piece is the inventory layer, which is not detection but is what makes detection possible: knowing which calls the trail is supposed to record, so you can notice when it records less.

**For an investigation**, the sequence that matters is: establish the time window, resolve the identity, find the first anomalous call, and work forward. Working backwards from a known-bad outcome is usually faster, and CloudTrail's 90-day event history gives you a broad window even if the trail itself was disabled.`,
    signals: [
      {
        signal: 'Logging disabled or changed',
        source: 'CloudTrail — management events',
        query: `eventName in ("StopLogging", "UpdateTrail", "DeleteTrail", "PutEventSelectors", "StartLogging")\n| stats count() by eventName, userIdentity.arn, sourceIPAddress\n| sort count desc`,
        note:
          'The highest-signal event in the whole topic. Alert on every one of these, including the legitimate-looking ones.',
      },
      {
        signal: 'Evidence sources turned off',
        source: 'CloudTrail — management events',
        query: `eventName in ("StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteFlowLogs", "UpdateDetector", "DeleteDetector", "DisableSecurityHub", "DeleteLogGroup", "DeleteLogStream", "DeleteDetector")\n| stats count() by eventName, userIdentity.arn`,
        note:
          'These are the "disable the thing that was watching me" actions. There is almost no benign reason for them at this cadence.',
      },
      {
        signal: 'Bucket or log destination deleted',
        source: 'CloudTrail — management events',
        query: `eventName in ("DeleteBucket", "DeleteObject", "PutBucketPolicy", "PutBucketAcl")\n| where requestParameters.bucketName contains "trail" or requestParameters.bucketName contains "log"\n| stats count() by userIdentity.arn, requestParameters.bucketName`,
        note:
          'Deleting the log destination destroys history as well as future collection, so it is worth alerting on specifically.',
      },
      {
        signal: 'Identity assuming a role it has never assumed before',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| stats dc(userIdentity.arn) as callers by requestParameters.roleName\n| where callers <= 2\n| sort callers asc`,
        note:
          'Low-volume roles with a single caller are the ones worth watching, because a new caller stands out sharply.',
      },
      {
        signal: 'Session without MFA',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRole\n| where sessionContext.attributes.mfaAuthenticated = "false"\n| stats count() by userIdentity.arn, requestParameters.roleName\n| sort count desc`,
        note:
          'Not all sessions require MFA, so baseline first — but an MFA-required role being assumed without MFA is a strong finding.',
      },
      {
        signal: 'First-ever access to a sensitive resource',
        source: 'CloudTrail — data events',
        query: `eventName in ("GetObject", "GetSecretValue", "GetParameter", "GetItem", "GetParameterHistory")\n| stats dc(userIdentity.arn) as actors by resources\n| filter actors <= 2\n| sort actors asc`,
        note:
          'The first read by a new actor is usually where the objective was reached. This query finds it without needing to know what was being read.',
      },
      {
        signal: 'Guardrail — require MFA and log every assumption',
        source: 'IAM / SCP',
        query: `SCP Deny: sts:AssumeRole without sts:MultiFactorAuthPresent for human roles`,
        note:
          'MFA on the assumption means a stolen session token is not sufficient on its own, and it makes the session unattributable without an MFA context.',
      },
    ],
    posture: [
      'Deliver the trail to an S3 bucket in a separate account that workload accounts cannot write to or delete.',
      'Enable log file validation so a tampered or deleted log file can be detected.',
      'Enable data events for S3, Lambda, Secrets Manager, SSM Parameter Store and DynamoDB on the resources that matter.',
      'Keep 400 days of trails on S3, and use Athena or CloudTrail Lake for the volume.',
      'Alert on every logging-disabling API call, with no exceptions and no threshold.',
      'Enable the CloudTrail organisation trail so a compromised account cannot delete the record of itself.',
    ],
  },
  fix: {
    body: `The fix is to make the trail something an attacker cannot reach and something you can rely on.

The structural requirement is separation: the trail writes to an account the attacker does not control. Everything else is tuning on top of that.

The second requirement is coverage: data events for the resources that hold the objective, because a management-only trail answers "what did they change" and not "what did they take".

The third is integrity: log file validation, and an organisation trail that the workload account cannot stop.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Deliver the trail to a separate account the workload account cannot write to',
        detail:
          'A trail in the same account as the workload can be deleted by anyone with iam:DeleteTrail or s3:DeleteBucket on the destination. Central delivery is what makes the record survive a compromise.',
      },
      {
        priority: 'critical',
        action: 'Enable an organisation trail across every account',
        detail:
          'The organisation trail is created in the management account and covers every enrolled account, including accounts that did not know they were being logged. It is the only trail an attacker in a workload account cannot stop.',
      },
      {
        priority: 'high',
        action: 'Enable data events for the resources that hold the objective',
        detail:
          'Management events answer "what changed". Data events answer "what was read". Without them, an exfiltration is invisible even though the log looks complete.',
        snippet: `aws cloudtrail put-event-selectors --trail-name my-trail \\
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":false,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::production-data/"]}]}]'`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Enable log file validation and alert on validation failures',
        detail:
          'Digest validation detects a log file that was modified or deleted after delivery. The alert is the point — the feature alone does nothing.',
        snippet: `aws cloudtrail update-trail --name my-trail --is-log-file-validation-enabled=true`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Deny the trail-disabling actions from workload accounts',
        detail:
          'An SCP that denies StopLogging, DeleteTrail, PutEventSelectors and the S3 delete actions on the log bucket removes the blinding step. Give the logging account its own exception.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:PutEventSelectors",
      "s3:DeleteBucket"
    ],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'medium',
        action: 'Require MFA in the trust condition for human role assumptions',
        detail:
          'It stops a stolen session token being usable on its own, and it leaves mfaAuthenticated in every session so you can prove how the session was obtained.',
      },
      {
        priority: 'medium',
        action: 'Set a retention period that matches your longest realistic dwell time',
        detail:
          'CloudTrail event history is 90 days. An attacker who knows that will wait for the window to pass, so the S3 archive and its retention are what actually matter.',
      },
      {
        priority: 'low',
        action: 'Enable CloudTrail Lake or an Athena query layer over the raw files',
        detail:
          'The volume of events makes interactive queries the difference between investigating in an hour and investigating in a week.',
      },
    ],
  },
  checklist: [
    {
      id: 'ct-1',
      text: 'Confirm the trail is multi-region and covers global service events.',
      command:
        'aws cloudtrail describe-trails --region all --query "trailList[].{Name:Name,Multi:IsMultiRegionTrail,Global:IncludeGlobalServiceEvents,Validation:IsLogFileValidationEnabled}"',
      expected:
        'IsMultiRegionTrail and IncludeGlobalServiceEvents are true, and log file validation is enabled.',
    },
    {
      id: 'ct-2',
      text: 'Confirm the trail delivers to a bucket in a different account.',
      command:
        'aws cloudtrail describe-trails --query "trailList[].S3BucketName" --output text',
      expected:
        'The bucket name contains a different account id than the one you are running in.',
    },
    {
      id: 'ct-3',
      text: 'Confirm data events cover the resources that hold the objective.',
      command:
        'aws cloudtrail describe-event-data-selectors --query "EventDataSelectors[].DataResources" --output text',
      expected:
        'The production buckets, secret stores and parameter stores appear in the selectors.',
    },
    {
      id: 'ct-4',
      text: 'Check whether the workload account can stop logging.',
      command:
        'aws cloudtrail describe-trails --query "trailList[].Name" --output text',
      expected:
        'An SCP denies StopLogging and DeleteTrail for the workload accounts, and the exception is the logging account.',
    },
    {
      id: 'ct-5',
      text: 'Confirm the log bucket cannot be deleted by the account that logs.',
      command:
        'aws s3api get-bucket-policy --bucket my-central-trail-bucket',
      expected:
        'The policy denies s3:DeleteBucket and s3:PutBucketPolicy for the logging account principal.',
    },
    {
      id: 'ct-6',
      text: 'Verify the trail is actually delivering events.',
      command:
        'aws cloudtrail get-log-status --name my-trail',
      expected:
        'LatestDeliveryTime is recent. A trail that looks configured but stopped delivering is worse than no trail.',
    },
    {
      id: 'ct-7',
      text: 'Check whether the organisation trail is running across all accounts.',
      command:
        'aws cloudtrail describe-trails --region us-east-1 --query "trailList[].Name" --output text',
      expected:
        'An organisation trail appears alongside the account-level ones, and it is not stoppable from a workload account.',
    },
    {
      id: 'ct-8',
      text: 'Confirm log file validation is detecting tampering.',
      command:
        'aws cloudtrail describe-trails --query "trailList[].{Name:Name,Validation:IsLogFileValidationEnabled}"',
      expected:
        'Validation is enabled on every trail that writes to the central bucket.',
    },
  ],
  references: [
    { label: 'AWS CloudTrail — user guide', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html' },
    { label: 'AWS CloudTrail — event reference', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-guide.html' },
    { label: 'AWS CloudTrail — data events', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events.html' },
    { label: 'AWS CloudTrail Lake', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html' },
  ],
  updated: '2026-11-22',
}
