import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/foundation/regions-and-availability',
  title: 'Regions, availability zones and the blast radius',
  cloud: 'aws',
  stage: 'foundation',
  track: 'Platform',
  summary:
    'What is global, what is regional, and what happens when a control you thought covered the account is actually only enforced in one region.',
  duration: '30 min',
  difficulty: 2,
  prerequisites: ['aws/foundation/identity-and-trust'],
  enables: [
    'aws/operator/storage-and-data',
    'aws/operator/compute-and-containers',
    'aws/expert/organizational-guardrails',
    'aws/expert/multi-account-estate',
  ],
  mentalModel:
    'AWS splits every service into three scopes — global, regional, and zonal — and every security control inherits that scope. Ask "what is the scope of this control?" before you ask "is this control enabled?".',
  concept: {
    body: `AWS infrastructure is organised in three nested scopes.

**Regions** are separate geographic areas. Each region is isolated in terms of the underlying infrastructure: power, networking, and — critically — identity controls that are configured at the regional level. A security group in \`eu-west-1\` has nothing to do with a security group in \`us-east-1\`. An EC2 instance launched in one region cannot see the other region.

**Availability zones** are isolated data centres within a region. They have independent power and networking, and they are connected to each other with low-latency, high-bandwidth links. An AZ is where you get failure isolation for a single facility. Using two AZs with a Multi-AZ deployment means a single-AZ failure is a non-event; it does not mean a region failure is survivable.

**Zonal resources** are the things that live in one AZ: an EC2 instance, an EBS volume, an Elastic IP, a NAT gateway in a subnet. This is the distinction that bites people. An EBS volume cannot attach to an instance in another AZ. You can move it, but that is a copy.

**Global services** ignore all of this: IAM, Route 53, CloudFront, AWS Organizations, IAM Identity Center, Global Accelerator. An IAM policy is one policy for the whole account. A Route 53 hosted zone is served from every edge location in the world.

**Regional services** are the default. S3, EC2, RDS, Lambda, CloudWatch Logs, EKS, ECS. When you enable a control "for the account" but the service is regional, you have enabled it in one region and not the others. This is the single most common source of false assurance in AWS.

**Multi-region is a data movement problem.** Replication between regions (S3 CRR, RDS read replicas, DynamoDB global tables) copies *data* but not *controls*. A replica in a region with no CloudTrail trail, no Config recorder, and no GuardDuty detector is a copy of your data sitting in an unmonitored jurisdiction. The control plane and the data plane are separate problems, and multi-region estates usually solve the second and forget the first.

**Region selection carries regulatory weight.** Data residency requirements, GDPR, and contractual commitments often bind you to specific regions. Launching a resource in the wrong region is a compliance incident, not just a misconfiguration, and it is hard to reverse — a global service like Route 53 or IAM cannot be region-locked after the fact.

**Opt-in regions** add a further step. Some regions are disabled by default and must be enabled per account, which means an account owner has to explicitly opt in before anything can run there.`,
    keyPoints: [
      'IAM, Route 53, CloudFront and Organizations are global. Everything else is regional unless documented otherwise.',
      'A control applied to a regional service is only applied in one region unless you do the work in each one.',
      'EBS volumes, Elastic IPs and NAT gateways are zonal. Availability zone failure takes a zonal resource with it.',
      'Multi-AZ protects against a data centre failure. It does not protect against a regional failure, and it is not a backup.',
      'Data replication copies data, not logging, monitoring or policy enforcement.',
      'Some regions are opt-in, which means an account owner has to enable them before an attacker can use them as a hiding place.',
    ],
    misconceptions: [
      {
        claim: 'A multi-AZ deployment means the workload is highly available.',
        truth:
          'It means the workload survives the failure of one availability zone. A regional failure — bad deploy, bad Region configuration, legal takedown, network partition — still takes it down.',
      },
      {
        claim: 'An IAM policy applies per region.',
        truth:
          'IAM is global. One policy covers every region, which is good for authorization and means a global mistake is a global mistake.',
      },
      {
        claim: 'CloudTrail is enabled by default everywhere in an account.',
        truth:
          'A basic CloudTrail trail exists in the region where it was created and is not a global record. Multi-region trails, which cover all regions, are an explicit configuration step.',
      },
    ],
  },
  attack: {
    body: `Region scoping gives an attacker a place to stand where your controls are not. This is not exotic. The pattern shows up constantly in cloud assessments.

The classic version: the account has a CloudTrail trail, Config recorder, GuardDuty detector and security group baseline in its home region. The attacker, holding a credential from any source, works in a region where none of those exist. Nothing is logged, nothing is alerted, and nothing is blocked. The attacker creates resources, reads data and exfiltrates it, and the timeline in the home region stays empty.

The second version is **cross-region replication abuse**. An S3 bucket replicates to a bucket in a second account or a second region that has weaker controls. The source bucket is fully audited; the replica is not. Data exfiltration happens through a channel nobody monitors.

The third is **credential scope**. A role's \`MaxSessionDuration\` and the session duration you request are global, but the *reach* of the session is regional — you can only call regional endpoints in regions where the service is available, and STS itself has regional endpoints (\`sts.us-east-1.amazonaws.com\` versus the global \`sts.amazonaws.com\`). An attacker using a regional STS endpoint in an unmonitored region produces an AssumeRole event that a home-region-only trail never records.

The fourth is **resource sprawl**. One of the fastest ways to increase blast radius is to create a resource in a new region. If your SCPs are applied at the account level in every region they should be, a region-scoped SCP still catches it — but SCPs, like everything else, only exist in the regions where the service is enabled.

The fifth is **the gap between the global control and the regional deployment**: a CloudFront distribution with an origin pointing at a regional ALB, where the ALB's security group and the WAF rules are configured in one region and assumed everywhere.`,
    techniques: [
      {
        name: 'Enumerate which regions are actually enabled',
        what: 'Find the regions where you can create resources and where your controls are absent.',
        steps: [
          'List every region and its opt-in status: `aws ec2 describe-regions --all-regions --query "Regions[].[RegionName,OptInStatus]"`.',
          'For each enabled region, check whether a trail, a GuardDuty detector and a Config recorder exist.',
          'The gaps between that list and your intended list are your unmonitored attack surface.',
        ],
        command:
          'aws ec2 describe-regions --all-regions --query "Regions[?OptInStatus==\'opt-in-not-required\' || OptInStatus==\'opted-in\'].RegionName" --output text',
        impact:
          'A precise list of regions where an attacker can create resources, read data and leave no CloudTrail record.',
      },
      {
        name: 'Use a regional STS endpoint to keep the assumption out of the trail',
        what: 'Assume a role through the regional STS endpoint in a region that has no trail.',
        command:
          'aws sts assume-role --endpoint-url https://sts.eu-central-1.amazonaws.com \\\n  --role-arn arn:aws:iam::123456789012:role/Target \\\n  --role-session-name probe --duration-seconds 900',
        impact:
          'The session is valid everywhere. The AssumeRole event lands in a region you are not watching, or nowhere at all.',
      },
      {
        name: 'Exfiltrate through cross-region or cross-account replication',
        what: 'Use a legitimate replication path to move data into an unmonitored destination.',
        command:
          'aws s3api get-bucket-replication --bucket prod-data --output json',
        impact:
          'Data leaves the monitored account through a mechanism the source account believes is governed. The destination bucket may sit in a region or account with no trail, no Config and no detector.',
      },
      {
        name: 'Create resources in a region with weaker controls',
        what: 'Launch compute or storage in the region where your guardrails are thinnest.',
        steps: [
          'Confirm a region is enabled for the account.',
          'Check whether SCPs, Config rules, GuardDuty and the security group baseline apply there.',
          'Create the resource. If the guardrails are regional and unmanaged, nothing stops you.',
        ],
        command:
          'aws ec2 run-instances --region eu-central-1 --image-id ami-0abcdef1234567890 \\\n  --instance-type t3.micro --subnet-id subnet-0abc123',
        impact:
          'Compute in an unmonitored jurisdiction, free of the ingress rules, key policies and logging you rely on elsewhere.',
      },
      {
        name: 'Take advantage of zonal resources being pinned',
        what: 'Note that a resource cannot move without a copy, and use the copy operation as an exfiltration primitive.',
        steps: [
          'Identify a zonal resource with data: a volume, an EBS snapshot, an RDS instance.',
          'Create a snapshot — snapshots are regional and copyable.',
          'Share the snapshot with another account, where the copy is outside your controls.',
        ],
        command:
          'aws ec2 create-snapshot --volume-id vol-0abc123 --description "copy" --tag-specifications \'ResourceType=snapshot,Tags=[{Key=exfil,Value=true}]\'',
        impact:
          'A full copy of the block device in a different account, with no API call against the original data after the snapshot completes.',
      },
    ],
    cases: [
      {
        title: 'Resources created in an unmonitored region',
        source: 'Recurring pattern in published cloud assessment findings and incident retrospectives',
        impact:
          'Because logging, configuration recording and threat detection are configured per region by default, activity in a region that was never set up left no audit trail and triggered no alert, while the source account looked clean.',
        year: 2023,
      },
    ],
  },
  detect: {
    body: `Detection here is mostly about coverage rather than about a clever query. The question is not "did anything happen" but "would I know if anything happened".

Three checks matter.

First, **region coverage of CloudTrail**. \`describe-trails --region all\` returns the trails visible to your credentials across regions. A multi-region trail should be present, and it should be delivering to a bucket you control. If the only trail is a regional one in the home region, you have a gap.

Second, **region coverage of detection services**. GuardDuty detectors and Config recorders are regional. Listing them across regions and diffing against your enabled-region list is the audit.

Third, **resource distribution**. If your estate is supposed to run in three regions and \`aws ec2 describe-instances --region all\` shows instances in six, one of those three is unauthorised.

CloudTrail Lake and Athena over the raw S3 trail files are the right tools for retrospective questions, because they let you query across every region and every account in one place.`,
    signals: [
      {
        signal: 'CloudTrail coverage gap across regions',
        source: 'CloudTrail API — trail inventory',
        query: `aws cloudtrail describe-trails --region all --query "trailList[].{Name:Name,Home:HomeRegion,Multi:IsMultiRegionTrail,Validation:LogFileValidationEnabled}"`,
        note:
          'One multi-region trail plus per-region trails is a reasonable target. A single regional trail means every other region is invisible to you.',
      },
      {
        signal: 'GuardDuty detector missing in an enabled region',
        source: 'GuardDuty API — detector inventory',
        query: `aws guardduty list-detectors --region eu-central-1 --query "DetectorIds"`,
        note:
          'An empty list in a region you use is a detection gap. Automate this diff against describe-regions.',
      },
      {
        signal: 'Resources running in a region outside the approved list',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, eventSource, awsRegion, userIdentity.arn\n| filter awsRegion != "us-east-1" and awsRegion != "eu-west-1"\n| stats count() by awsRegion, eventSource, userIdentity.arn`,
        note:
          'Run this against a multi-region trail or an Athena query over all trail files. It is the fastest way to find shadow infrastructure.',
      },
      {
        signal: 'A trail was stopped, deleted or had logging disabled',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.name\n| filter eventName = "StopLogging" or eventName = "DeleteTrail" or eventName = "UpdateTrail" or eventName = "PutEventSelectors"\n| stats count() by eventName, userIdentity.arn`,
        note:
          'Disabling logging is the classic anti-forensic step. It is also one of the easiest to detect, because the trail that would record it is usually the one being tampered with — which is why trails must be replicated.',
      },
      {
        signal: 'Replication enabled to an unexpected destination',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.bucketName\n| filter eventName = "PutBucketReplication" or eventName = "PutReplicationConfiguration"\n| stats count() by userIdentity.arn, requestParameters.bucketName`,
        note:
          'Reconfiguration of replication is rarer than replication itself, which makes it a good tripwire.',
      },
    ],
    posture: [
      'Run one multi-region organization trail that delivers to a log archive account, and treat per-region trails as a supplement.',
      'Enable GuardDuty and AWS Config in every region the account can use, including opt-in regions before anything runs there.',
      'Keep a written list of approved regions and a quarterly diff between it and what is actually enabled.',
      'Use a regional deny SCP to block resource creation in regions that are not on the list.',
      'Route all AWS service traffic through a central egress inspection point so a region change does not silently change the path.',
      'Use CloudTrail Lake or Athena so that "which regions did this principal touch last quarter" is a query, not an investigation.',
    ],
  },
  fix: {
    body: `Fixing regional sprawl is an inventory problem before it is a technical one. Write down where you are supposed to run, then measure the difference.

The technical work follows a simple pattern: make the intended state the default state. Enable everything in every region you use, so there is no gap to fall into. Then add the SCP that makes the undesired regions unusable.

The order that works in practice:

1. Build the regional inventory. One command gives you the enabled regions; one gives you the trails; one gives you the detectors; one gives you the resources.
2. Close the monitoring gaps in the regions you actually use.
3. Block the regions you do not use.
4. Move the data-plane copy paths under review, because replication is where the controls go missing.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Create a multi-region CloudTrail trail in every account and deliver it to a central log archive',
        detail:
          'A multi-region trail writes events from every region into one place. Without it, an attacker choosing a region is choosing a region with no audit trail. The archive account must be separate so that disabling the source trail does not disable the record.',
        snippet: `aws cloudtrail create-trail --name org-trail --s3-bucket-name central-trail-bucket \\\n  --is-multi-region-trail --include-global-service-events \\\n  --is-log-file-validation-enabled --s3-bucket-policy-filename file://trail-bucket-policy.json`,
        snippetLang: 'bash',
      },
      {
        priority: 'critical',
        action: 'Block resource creation in regions that are not on the approved list',
        detail:
          'An SCP with a deny on the resource-creating actions and a condition on aws:RequestedRegion turns an unmonitored region into a non-existent one. Without it, opt-in regions are one click away.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["ec2:RunInstances", "s3:CreateBucket", "lambda:CreateFunction",
               "ecs:RunTask", "rds:CreateDBInstance", "eks:CreateCluster"],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": { "aws:RequestedRegion": ["us-east-1", "eu-west-1"] }
    }
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Enable GuardDuty, Config and CloudTrail in every region the account uses',
        detail:
          'GuardDuty detectors and Config recorders are per region. Automate the enablement with a StackSet or an Organizations deployment so that a new account or a new region inherits the same coverage.',
      },
      {
        priority: 'high',
        action: 'Inventory and review every replication path',
        detail:
          'S3 cross-region and cross-account replication, RDS read replicas, DynamoDB global tables, and snapshot sharing all move data outside the source account\'s controls. Require the destination to meet the same logging and encryption standard, or do not enable replication.',
      },
      {
        priority: 'high',
        action: 'Separate workloads into accounts per region and per environment',
        detail:
          'Accounts are global but resources are not. Splitting by environment means a compromised workload account in one region cannot touch a different region\'s account, and the account boundary gives you a place to attach a regional SCP.',
      },
      {
        priority: 'medium',
        action: 'Use regional failover deliberately, with the same control set in the standby',
        detail:
          'A standby region that is not patched, logged or monitored is not a failover plan. Apply the same baseline to the standby and rehearse the cutover.',
      },
      {
        priority: 'medium',
        action: 'Route all outbound traffic through a central inspection point',
        detail:
          'Central egress removes the region as a variable: a workload in any region uses the same path, so an attacker cannot choose an unmonitored route by choosing a region.',
      },
      {
        priority: 'low',
        action: 'Check opt-in region status and disable regions you do not use',
        detail:
          'Where a region is not needed, disabling it removes the option entirely rather than relying on a deny to fire.',
      },
    ],
  },
  checklist: [
    {
      id: 'reg-1',
      text: 'List every enabled region in the account.',
      command:
        'aws ec2 describe-regions --all-regions --query "Regions[?OptInStatus!=\'not-opted-in\'].[RegionName,OptInStatus]" --output table',
      expected:
        'Only the regions on the approved list are enabled. Anything else is either approved and undocumented or a gap.',
    },
    {
      id: 'reg-2',
      text: 'Confirm a multi-region CloudTrail trail exists and is logging.',
      command:
        'aws cloudtrail describe-trails --region all --query "trailList[].{Name:Name,Multi:IsMultiRegionTrail,Validation:LogFileValidationEnabled}" && aws cloudtrail get-trail-status --name arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail',
      expected:
        'A multi-region trail with IsLogging true and log file validation enabled.',
    },
    {
      id: 'reg-3',
      text: 'Check for a GuardDuty detector in every enabled region.',
      command:
        'for r in us-east-1 eu-west-1 eu-central-1; do echo -n "$r: "; aws guardduty list-detectors --region $r --query "DetectorIds" --output text; done',
      expected:
        'One detector id in every region you operate in. An empty list in a live region is a detection gap.',
    },
    {
      id: 'reg-4',
      text: 'Find resources running outside the approved regions.',
      command:
        'aws ec2 describe-instances --region all --query "Reservations[].Instances[].[InstanceId,Placement.AvailabilityZone]" --output text',
      expected:
        'Every instance sits in an approved region and an approved availability zone for its tier.',
    },
    {
      id: 'reg-5',
      text: 'List every bucket with replication configured and confirm each destination.',
      command:
        'aws s3api get-bucket-replication --bucket prod-data --output json',
      expected:
        'Every destination is an approved account and region with an equivalent control set, and the source account has reviewed it.',
    },
    {
      id: 'reg-6',
      text: 'Confirm the regional deny SCP is attached at the right place in the organization.',
      command:
        'aws organizations list-policies-for-target --target-id r-abcd --query "Policies[].{Name:Name,Id:Id}"',
      expected:
        'The region deny policy is attached to the root or to every OU that can create resources, not to a single account.',
    },
  ],
  references: [
    { label: 'AWS Regions and availability zones', url: 'https://docs.aws.amazon.com/about-aws/global-infrastructure/regions_az/' },
    { label: 'AWS global services', url: 'https://docs.aws.amazon.com/about-aws/global-infrastructure/global-services/' },
    { label: 'AWS CloudTrail multi-region trails', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html' },
    { label: 'AWS Service Control Policies', url: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html' },
  ],
  updated: '2026-11-19',
}
