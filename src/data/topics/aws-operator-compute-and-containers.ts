import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/operator/compute-and-containers',
  title: 'Compute, containers and serverless',
  cloud: 'aws',
  stage: 'operator',
  track: 'Compute',
  summary:
    'The identity that runs with your code: EC2 instance profiles, ECS task roles, EKS node and pod identities, and the Lambda execution role.',
  duration: '35 min',
  difficulty: 3,
  prerequisites: [
    'aws/foundation/network-boundaries',
    'aws/foundation/regions-and-availability',
  ],
  enables: [
    'aws/adversary/ec2-metadata-service',
    'aws/adversary/serverless-attack-surface',
    'aws/redteam/kubernetes-on-eks',
    'aws/redteam/iam-privilege-escalation',
  ],
  mentalModel:
    'Every compute unit in AWS runs with an identity attached, and that identity — not the code — is what the API authorises. Enumerate the code execution surface and you have enumerated the privilege surface.',
  concept: {
    body: `Each compute service attaches a principal to the workload, and that principal's permissions are the workload's real privilege boundary. Understanding AWS compute means knowing which principal runs where.

**EC2.** An instance gets its identity from an *instance profile*, which is a container for an IAM role. The instance assumes that role through the instance metadata service and receives temporary credentials. The role attached to the instance is what every process inside it can reach. An instance profile with administrator permissions is the single most common AWS privilege escalation: any code execution on the host becomes administrator.

The other sources of instance-level secret material are user data (a common place to leave database passwords), SSH key pairs (a long-lived credential whose private key circulates in tooling and CI), and the baked-in credentials of a custom AMI.

**ECS.** Two roles are in play and they are frequently confused. The *task role* is the identity the application code runs as, and it should be scoped to what the application needs — an S3 bucket, a queue. The *task execution role* is the identity ECS itself uses to pull images, retrieve secrets and write logs; it is not available to the application. A common mistake is granting the execution role application permissions "just in case", which gives the container the wrong identity.

The task definition is the unit of deployment. Its \`containerDefinitions\` carry environment variables, secrets references and log configuration — all of which end up in the ECS DescribeTaskDefinition API response in plaintext for anything that is not a secret reference.

**EKS.** The cluster has three identity layers: the node IAM role (which the kubelet and the node agent use), IRSA service accounts (a pod-specific IAM role via the cluster's OIDC provider), and EKS Pod Identity (a newer mechanism that avoids OIDC entirely). A pod that runs as a service account with an IRSA role reaches exactly that role. A pod that runs as \`system:node\` or with the node role mounted can reach the node role, which is often far broader.

**Lambda.** The execution role is attached to the function and is the function's entire identity. Environment variables are visible to anyone with \`lambda:GetFunctionConfiguration\` in plaintext. Layers are shared code that runs inside the function's environment. Function URLs and API Gateway expose the function as an HTTP endpoint, and the authentication mode on that endpoint is the only thing protecting it.

The unifying point: in every case, the credential lives next to the code. If you can run code, you are the role.`,
    keyPoints: [
      'The instance profile role, task role, node role, IRSA role and Lambda execution role are the privilege boundary, not the code.',
      'ECS task role and task execution role are different identities with different responsibilities. Granting the wrong one is the common bug.',
      'Lambda environment variables are readable in plaintext by anyone with GetFunctionConfiguration.',
      'User data is a frequent home for database passwords that then live in the instance metadata service and in the EC2 console.',
      'SSH key pairs are long-lived credentials and do not expire, rotate or appear in CloudTrail.',
      'EKS pods can reach the node role if the pod runs with elevated Kubernetes permissions or has the node token mounted.',
    ],
    misconceptions: [
      {
        claim: 'The Lambda execution role is only needed to write CloudWatch logs.',
        truth:
          'That is the least privileged version of it. In practice the execution role is often granted S3, SQS, Secrets Manager and KMS because the function needs them, and every one of those permissions is reachable from inside the function.',
      },
      {
        claim: 'A container in ECS runs as the task execution role.',
        truth:
          'The application runs as the task role. The execution role is used by the ECS agent before the container starts. If the container can reach the execution role credentials, the separation has failed.',
      },
      {
        claim: 'Because EKS runs Kubernetes, RBAC handles the cloud permissions.',
        truth:
          'RBAC governs Kubernetes API access; IRSA or Pod Identity governs AWS API access. A pod can have full RBAC and no cloud permissions, or the reverse, and both are common.',
      },
    ],
  },
  attack: {
    body: `Compute attacks are mostly about two questions: what identity does this code run as, and how did I get code execution in the first place.

The first step is enumeration. \`aws ec2 describe-instances\` returns the instance profile for every instance. \`aws ecs describe-task-definitions\` returns every task definition with its environment variables and secrets. \`aws lambda list-functions\` and \`aws lambda get-function-configuration\` return every function with its role and its environment. These calls are usually permitted for any principal with broad read access and they map the entire privilege surface of the estate in seconds.

The second step is credential retrieval, covered in detail in the metadata service topic. On EC2 it is the instance profile role. On ECS it is the task role, and the container credentials endpoint is a different address with a different flow. On EKS it is the IRSA token or the Pod Identity agent.

The third step is abuse of the over-privileged role. A Lambda function with \`lambda:PassRole\` and \`iam:CreateFunction\` is a privilege escalation. An ECS task definition whose task role can call \`iam:CreatePolicyVersion\` is a privilege escalation. An EKS node role with \`iam:CreatePolicyVersion\` is a privilege escalation — and IRSA restricts only the pod, not the node.

The fourth step is persistence in the compute layer itself. \`lambda:CreateFunction\` and \`lambda:UpdateFunctionCode\` give a durable foothold that costs nothing to run. \`ecs:RegisterTaskDefinition\` gives a foothold that restarts with the service. \`ec2:RunInstances\` with user data gives one that survives reboots.

The fifth step is the supply chain: an ECR image with baked-in credentials, a Lambda layer with a hardcoded key, a public AMI, a container image pushed to a repository that a deployment pipeline trusts.`,
    techniques: [
      {
        name: 'Map every compute identity in the account',
        what: 'Enumerate instances, task definitions and functions with the roles they run as.',
        steps: [
          '`aws ec2 describe-instances --query "Reservations[].Instances[].{Id:InstanceId,Profile:IamInstanceProfile.Arn}"`.',
          '`aws ecs list-task-definitions --status ACTIVE` then `aws ecs describe-task-definition --task-definition <arn>` for each.',
          '`aws lambda list-functions --query "Functions[].[FunctionName,Role,LastModified]"`.',
          'Note the roles that appear more than once — shared roles across many workloads mean a single compromise is a fleet compromise.',
        ],
        command:
          'aws lambda list-functions --query "Functions[].[FunctionName,Role,PackageType]" --output table',
        impact:
          'A complete map of which role runs where, which is the map you need to decide what a single foothold is worth.',
      },
      {
        name: 'Read Lambda environment variables and configuration',
        what: 'Pull the plaintext configuration of a function, including its environment variables.',
        command:
          'aws lambda get-function-configuration --function-name payments --query "{Role:Role,Env:Environment.Variables}" --output json',
        impact:
          'Frequently contains API keys, database connection strings, third-party tokens and, occasionally, IAM credentials directly.',
      },
      {
        name: 'Read the task definition for plaintext secrets',
        what: 'Inspect an ECS task definition and read its environment and secrets configuration.',
        command:
          'aws ecs describe-task-definition --task-definition arn:aws:ecs:us-east-1:123456789012:task-definition/app:42 \\\n  --query "taskDefinition.containerDefinitions[].{Name:name,Env:environment,Secrets:secrets}"',
        impact:
          'Environment entries that were set as literals instead of secrets references are readable in full, along with the exact secret names and ARNs the task retrieves.',
      },
      {
        name: 'Launch an instance with a role you want to use',
        what: 'Run a new instance attached to a target instance profile.',
        command:
          'aws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type t3.micro \\\n  --iam-instance-profile Name=AdminDeployProfile --metadata-options HttpTokens=required,HttpEndpoint=enabled \\\n  --user-data file://payload.sh',
        impact:
          'Immediate possession of the target role\'s credentials inside the instance, with no need for code execution on an existing host.',
      },
      {
        name: 'Replace the code of a function you do not own',
        what: 'Update a function\'s code to a payload that returns credentials.',
        command:
          'aws lambda update-function-code --function-name orders \\\n  --zip-file fileb://payload.zip --publish',
        impact:
          'The function now runs your code with its execution role. If the role is broad, you have converted a code permission into a broad AWS session.',
      },
      {
        name: 'Inspect an ECR image for baked-in credentials',
        what: 'Pull an image and search its layers for secrets.',
        steps: [
          '`aws ecr describe-repositories --query "repositories[].repositoryName"`.',
          'Authenticate to ECR with the token the CLI manages for you.',
          'Pull the image and inspect the history and filesystem for AWS keys, `.aws/credentials` files and application secrets.',
        ],
        command:
          'aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com',
        impact:
          'Static credentials in an image survive every redeploy of the image and every revocation of the runtime role, because they are not the runtime role.',
      },
    ],
    cases: [
      {
        title: 'Over-privileged instance profile role turning a single RCE into account access',
        source: 'Recurring pattern in published cloud incident retrospectives and breach write-ups',
        impact:
          'A single instance was compromised through an application flaw. Because the instance profile role had broad permissions, the attacker moved from the application to the AWS API immediately, and the only reason the compromise was contained was that one particular permission was absent.',
        year: 2019,
      },
    ],
  },
  detect: {
    body: `Compute activity appears in CloudTrail as control-plane events: \`RunInstances\`, \`CreateFunction\`, \`UpdateFunctionCode\`, \`RegisterTaskDefinition\`, \`RunTask\`, \`CreateCluster\`, \`PutImage\`, \`CreateLaunchTemplate\`. These tell you what changed. They do not tell you what ran.

For what ran, three sources matter: CloudWatch Logs from the workload itself, VPC Flow Logs for the network side, and the \`userIdentity\` on any API call the workload made — because that identity is the role, and the role is the workload.

The most useful single signal is a **role used from an unexpected source**. If the Lambda execution role \`orders-exec\` normally only ever calls from a function in one account, and you see it calling \`iam:CreatePolicyVersion\`, that is either a bug or a compromise, and either way it is worth a page.

The second is **a compute resource created where none is expected**. CloudTrail \`RunInstances\` with a \`LaunchTemplate\` that contains user data, or \`CreateFunction\` in a region with no other functions, stands out.

The third is **credential material in configuration**. GuardDuty and the IAM Access Analyzer policy validator can find some of it; the rest is a code review and image scanning problem.`,
    signals: [
      {
        signal: 'A function\'s code was replaced',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.functionName, requestParameters.revisionId\n| filter eventName = "UpdateFunctionCode" or eventName = "CreateFunction"\n| stats count() by eventName, userIdentity.arn, requestParameters.functionName`,
        note:
          'Normal deployments also update code. Alert on the principal, not the event — the pipeline identity should be the only one that appears.',
      },
      {
        signal: 'A compute role called an IAM or credential API',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, userIdentity.type\n| filter userIdentity.type = "AssumedRole"\n| filter eventSource = "iam.amazonaws.com" or eventSource = "sts.amazonaws.com" or eventName = "GetSecretValue"\n| stats count() by userIdentity.arn, eventName`,
        note:
          'A workload role that touches IAM or STS is unusual. Workloads consume credentials; they do not normally mint or modify identities.',
      },
      {
        signal: 'An instance launched with user data',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.instanceType, requestParameters.userData\n| filter eventName = "RunInstances" or eventName = "CreateLaunchTemplateVersion"\n| stats count() by userIdentity.arn, requestParameters.instanceType`,
        note:
          'User data frequently contains bootstrap credentials. Pull the userData field from the event and check it directly.',
      },
      {
        signal: 'A task definition changed',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.taskDefinition, requestParameters.containerDefinitions\n| filter eventName = "RegisterTaskDefinition" or eventName = "RunTask"\n| stats count() by userIdentity.arn, requestParameters.taskDefinition`,
        note:
          'A RunTask that references a brand new revision, from a principal that does not usually deploy, is worth investigating.',
      },
      {
        signal: 'An image pushed to a repository',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.repositoryName, requestParameters.imageDigest\n| filter eventName = "PutImage" or eventName = "InitiateLayerUpload"\n| stats count() by userIdentity.arn, requestParameters.repositoryName`,
        note:
          'Images pushed by a principal outside the build pipeline are a supply chain concern. Digest changes on a stable tag are worth a look.',
      },
      {
        signal: 'Guardrail — restrict who can launch compute and mutate functions',
        source: 'AWS Config managed rule / SCP',
        query: `SCP Deny: ec2:RunInstances, lambda:CreateFunction, lambda:UpdateFunctionCode, ecs:RegisterTaskDefinition unless the principal is tagged as a deployment identity'`,
        note:
          'This breaks persistence. Without it, a foothold can always be made durable by writing new code somewhere.',
      },
    ],
    posture: [
      'Give every instance, task, function and node group its own role. A shared role makes every workload a compromise of every workload.',
      'Log CloudTrail data events for Lambda and CloudWatch Logs from every container so that what ran is visible, not just what changed.',
      'Enable GuardDuty Runtime Monitoring for EC2, ECS and EKS — it sees the process and network behaviour inside the workload.',
      'Scan ECR images for embedded credentials as part of the build, and enable ECR image scanning against known vulnerabilities.',
      'Run EKS audit logs to CloudWatch Logs so that pod creation, exec and RBAC changes are queryable.',
      'Alert on any assume-role session whose source is outside the expected CI or workload ranges.',
    ],
  },
  fix: {
    body: `Compute hardening is about making each workload's identity as narrow as the workload's actual job. The measurement is simple: for every compute role, list the resources it can touch and check that each one is one the workload genuinely uses.

The three structural improvements, in order of value:

**One role per workload.** Most estates have a handful of shared roles. One compromised container then has whatever the union of all workloads needed.

**Scoped execution roles with an explicit deny at the boundary.** Lambda execution roles especially tend to accumulate permissions. Use a permission boundary on the role and a resource policy on the KMS key.

**No long-lived credentials anywhere in the compute layer.** Not in user data, not in environment variables, not in images, not in task definitions. Use Secrets Manager references and IRSA/Pod Identity.

The final step is supply chain: image provenance, signed artifacts, and a deployment identity that only CI can use.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Replace broad shared compute roles with one scoped role per workload',
        detail:
          'Scope the role to the exact resources the workload needs: one bucket prefix, one queue, one secret. A shared role means the union of every workload\'s permissions, and the intersection of every workload\'s vulnerabilities.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::app-data/orders/*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'critical',
        action: 'Remove long-lived credentials from user data, environment variables and images',
        detail:
          'Replace inline secrets with Secrets Manager references and give the workload role only the GetSecretValue permission on the specific secret. The secret is then rotatable and auditable; an inline secret is neither.',
        snippet: `{
  "containerDefinitions": [{
    "name": "app",
    "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:1.4.2",
    "secrets": [
      { "name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-password" }
    ]
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Apply a permission boundary to every compute execution role',
        detail:
          'A boundary caps the role even if someone later attaches a permissive managed policy. It is the only control that survives a mistake in the permission itself.',
      },
      {
        priority: 'high',
        action: 'Enforce IMDSv2 with a hop limit of one on every instance and node group',
        detail:
          'IMDSv2 with a hop limit of one means a container on the host cannot obtain the node role\'s credentials from another pod\'s network namespace, and a process on a different host cannot fetch the token at all.',
        snippet: `aws ec2 modify-instance-metadata-options --instance-id i-0abc123 \\\n  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Stop using SSH key pairs as a primary access method',
        detail:
          'Key pairs are long-lived, do not expire, do not appear in CloudTrail and are routinely left in CI variables and image layers. Use IAM Identity Center with session credentials, or SSM Session Manager, which produces an auditable API call.',
      },
      {
        priority: 'medium',
        action: 'Give the ECS task execution role only the permissions ECS needs',
        detail:
          'The execution role needs to pull from ECR, retrieve secrets, and write logs. Nothing else. Application permissions belong on the task role.',
      },
      {
        priority: 'medium',
        action: 'Pin container image tags to digests and scan images at build time',
        detail:
          'A mutable tag means the image a task runs can change without any deployment record. Pinning to a digest plus scanning removes the mutable-supply-chain path.',
        snippet: `aws ecr describe-images --repository-name app --image-ids imageTag=latest`,
        snippetLang: 'bash',
      },
      {
        priority: 'medium',
        action: 'Run EKS with IRSA or Pod Identity, not with the node role exposed to pods',
        detail:
          'Node roles should be limited to what the kubelet needs. Pod-specific identities bound to a single service account in a single namespace keep a compromised pod from reaching the node\'s permissions.',
      },
      {
        priority: 'low',
        action: 'Restrict who can create compute, and where',
        detail:
          'An SCP that denies the compute-creating actions outside deployment identities removes both a persistence mechanism and a data-exfiltration route in one move.',
      },
    ],
  },
  checklist: [
    {
      id: 'cmp-1',
      text: 'Map every instance to its instance profile.',
      command:
        'aws ec2 describe-instances --query "Reservations[].Instances[].{Id:InstanceId,Profile:IamInstanceProfile.Arn,Name:Tags[?Key==`Name`].Value|[0]}" --output table',
      expected:
        'Every workload has its own named profile. One profile shared by many instances is a fleet-wide single point of failure.',
    },
    {
      id: 'cmp-2',
      text: 'List every Lambda function with its execution role and last modification time.',
      command:
        'aws lambda list-functions --query "Functions[].[FunctionName,Role,Runtime,LastModified]" --output table',
      expected:
        'Each function has a distinct role, and the runtime is a currently supported version.',
    },
    {
      id: 'cmp-3',
      text: 'Check whether any function stores credentials in environment variables.',
      command:
        'aws lambda list-functions --query "Functions[].FunctionName" --output text | xargs -I{} aws lambda get-function-configuration --function-name {} --query "[FunctionName,Environment.Variables]"',
      expected:
        'No variable name looks like a key, password, token or secret. Anything that does is moved to Secrets Manager.',
    },
    {
      id: 'cmp-4',
      text: 'Confirm every instance requires IMDSv2.',
      command:
        'aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit]" --output text',
      expected: 'HttpTokens is "required" and the hop limit is 1 everywhere.',
    },
    {
      id: 'cmp-5',
      text: 'Compare the ECS task role and the task execution role for every task definition.',
      command:
        'aws ecs describe-task-definition --task-definition arn:aws:ecs:us-east-1:123456789012:task-definition/app:42 --query "taskDefinition.{Exec:executionRoleArn,Task:taskRoleArn}"',
      expected:
        'The execution role grants ECR, Logs and Secrets access only. Application permissions sit on the task role.',
    },
    {
      id: 'cmp-6',
      text: 'Find the roles attached to more than one compute resource.',
      command:
        'aws lambda list-functions --query "Functions[].Role" --output text | sort | uniq -c | sort -rn | head',
      expected:
        'No role appears more than once. A count above one is the finding to fix.',
    },
    {
      id: 'cmp-7',
      text: 'Check that the EKS node group role is not shared with application pods.',
      command:
        'aws eks describe-nodegroup --cluster-name prod --nodegroup-name ng-1 --query "nodegroup.nodeRole"',
      expected:
        'The node role is limited to EKS bootstrap and read permissions, and application pods use IRSA or Pod Identity.',
    },
  ],
  references: [
    { label: 'AWS EC2 instance profiles', url: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-instance-profiles.html' },
    { label: 'AWS ECS task roles and execution roles', url: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html' },
    { label: 'AWS Lambda execution roles', url: 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html' },
    { label: 'AWS EKS IAM roles for service accounts', url: 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html' },
  ],
  updated: '2026-11-20',
}
