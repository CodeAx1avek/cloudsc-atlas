import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/adversary/ec2-metadata-service',
  title: 'EC2 instance metadata and IMDSv1',
  cloud: 'aws',
  stage: 'adversary',
  track: 'Compute',
  summary:
    'The 169.254.169.254 path from a single server-side request forgery to the instance role credentials, and how IMDSv2 closes it.',
  duration: '35 min',
  difficulty: 4,
  prerequisites: [
    'aws/operator/compute-and-containers',
    'aws/foundation/network-boundaries',
  ],
  enables: [
    'aws/redteam/iam-privilege-escalation',
    'aws/redteam/kubernetes-on-eks',
    'aws/redteam/attack-path-chaining',
  ],
  mentalModel:
    'IMDS is a credential delivery endpoint that rides the same network as the application. Treat it as an unauthenticated API on every workload, and the only questions that matter are whether the request must be authenticated and whether the role behind it is worth having.',
  concept: {
    body: `The EC2 Instance Metadata Service is a link-local HTTP service that every EC2 instance can reach at \`169.254.169.254\`. It answers questions about the instance and, critically, hands out the temporary credentials of the instance profile role.

**The endpoints.** The tree starts at \`/latest/meta-data/\`:

- \`/latest/meta-data/iam/security-credentials/\` — the names of the roles attached to the instance.
- \`/latest/meta-data/iam/security-credentials/<role-name>\` — the credentials: \`AccessKeyId\`, \`SecretAccessKey\`, \`Token\`, and \`Expiration\`.
- \`/latest/meta-data/local-ipv4\`, \`/latest/meta-data/placement/availability-zone\`, \`/latest/meta-data/instance-id\`, \`/latest/meta-data/iam/security-credentials/\` and the tag endpoints.
- \`/latest/meta-data/network/interfaces/macs/<mac>/\` — subnet, VPC and security group identifiers for the interface.
- \`/latest/user-data\` — the user data supplied at launch, which frequently contains bootstrap credentials.
- \`/latest/dynamic/instance-identity/document\` — an instance identity document with the account id, instance id and region, signed by the instance.

**IMDSv1 versus IMDSv2.** IMDSv1 is a plain \`GET\`. Anyone who can reach the address gets the answer, with no authentication and no session. IMDSv2 requires a session token obtained by sending a \`PUT\` to \`/latest/api/token\` with the header \`X-aws-ec2-metadata-token-ttl-seconds\`. The token is then sent as \`X-aws-ec2-metadata-token\` on every subsequent request.

The hop limit is the second half of IMDSv2. The token request carries \`X-aws-ec2-metadata-token-ttl-seconds\` and the response hop limit is set by \`HttpPutResponseHopLimit\` on the instance metadata options. With the hop limit at the default of 1, the token request cannot leave the host, so a container in a different network namespace on the same instance cannot obtain it. Set it to 2 or higher and a container can sometimes obtain it from a process on the same node, which is why the hop limit matters as much as the token.

**Why the endpoint is not filtered by security groups.** It is link-local, not a peer ENI, so security group rules do not apply. Network ACLs can filter it, which is why a NACL deny on \`169.254.0.0/16\` is a useful second layer.

**The containers.** ECS and EKS use a *different* credential endpoint. On ECS with the \`awsvpc\` network mode, the container receives \`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI\` and fetches credentials from \`169.254.170.2\`. The ECS agent and the host reachability are different from EC2 IMDS. On EKS, the node role is on the node's IMDS and IRSA uses the cluster's OIDC provider with a projected service account token. Pod Identity uses a different agent-based flow. Conflating these is a common source of wrong remediation.

**Reachability.** From inside the instance: always. From another host: only if the network routes to it and the hop limit allows it — which is why a misconfigured hop limit turns a local SSRF into a network-reachable credential service. From the internet: not directly, but through an SSRF in an application, a proxy, a container, or a function with a VPC config.`,
    keyPoints: [
      'IMDSv1 is an unauthenticated GET. IMDSv2 requires a PUT-issued session token on every subsequent request.',
      'The hop limit on the token response is what stops a container on the same host from fetching the token.',
      'Security groups do not filter 169.254.169.254. Network ACLs do.',
      'ECS task credentials come from 169.254.170.2, not from 169.254.169.254, and the two have different controls.',
      'Instance profile role credentials are temporary, but they are automatically refreshed for as long as the instance runs — so a foothold does not need to persist the credential.',
      'User data is retrievable from the same endpoint and often contains bootstrap credentials.',
    ],
    misconceptions: [
      {
        claim: 'IMDSv2 stops SSRF from reaching the metadata service.',
        truth:
          'It stops an unauthenticated GET from succeeding. An attacker who can make the application issue a PUT to /latest/api/token and then a GET with that token still reaches the endpoint. IMDSv2 raises the cost of the attack and removes the trivial path; it does not remove the SSRF.',
      },
      {
        claim: 'Blocking 169.254.169.254 in the security group stops it.',
        truth:
          'Security group rules are not evaluated for link-local traffic to the metadata service. The control that works is IMDSv2 with a hop limit of one, plus a network ACL deny as defence in depth.',
      },
      {
        claim: 'The metadata credentials are short-lived, so the exposure window is small.',
        truth:
          'The credential expires, but the instance profile credentials are refreshed automatically and remain valid for the life of the instance. An attacker who obtains them can refresh them by repeating the request, for as long as the instance stays up.',
      },
    ],
  },
  attack: {
    body: `The attack is a chain with three links: reach the endpoint, get credentials, use the credentials. The first link is where most of the work is, and the second is where the impact is decided.

**Link one: reach the endpoint.** The classic route is an SSRF in an application that fetches a user-supplied URL: a webhook receiver, an image proxy, a PDF or document renderer, an XML parser with external entities, an "import from URL" feature, a link preview generator. A second route is a client-side bug: an XSS in the application origin that issues a fetch to the metadata endpoint, which works if the application has CORS headers permissive enough to allow it.

**Link two: get credentials.** With IMDSv1, one GET. With IMDSv2, a PUT for a token and a GET with the token. The result is a JSON blob with an access key, a secret key and a session token.

**Link three: use them.** The session token is part of the credential. Omitting it produces \`InvalidClientTokenId\` or a signature mismatch, which is the usual reason a copied credential does not work.

The chain is amplified by three things: the instance role's permissions (often far broader than the application needs), the ability to run further code on the instance (so the credentials refresh themselves), and the fact that the source IP for subsequent API calls is the instance, not the attacker.

**DNS rebinding** deserves a separate mention because it defeats naive allowlists. If the application validates the hostname against an allowlist and then resolves it separately, an attacker with a DNS server that returns a public IP on the first lookup and \`169.254.169.254\` on the second passes validation and reaches IMDS. The fix is to validate the resolved address, not the hostname, and to block the link-local range at the network layer.

**Hop limit abuse**: if \`HttpPutResponseHopLimit\` is 2 or higher and the instance has multiple pods or containers in bridged mode, a container may be able to obtain the token from the host network namespace, turning a container-only compromise into a node-role compromise.`,
    techniques: [
      {
        name: 'Read the metadata service with IMDSv1',
        what: 'Fetch the instance profile role credentials with a plain GET.',
        steps: [
          '`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns the role name.',
          '`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns the credential JSON.',
          'Export the three fields as AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN.',
        ],
        command:
          'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        impact:
          'Full credentials for the instance profile role. The session token is part of the credential and must be used with it.',
      },
      {
        name: 'Read the metadata service with IMDSv2',
        what: 'Obtain a session token and use it to fetch the credentials.',
        steps: [
          'PUT to the token endpoint with a TTL header.',
          'Include the token in the metadata request as a header.',
          'The credentials response is identical to the IMDSv1 response.',
        ],
        command:
          'TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")\ncurl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        impact:
          'The same credentials as IMDSv1. If this works, IMDSv2 is enabled but the hop limit is loose or the request is originating from the host.',
      },
      {
        name: 'Exploit SSRF to reach the metadata service',
        what: 'Make a server-side application fetch the metadata endpoint on your behalf.',
        steps: [
          'Find a parameter that accepts a URL: a webhook, an image fetch, an avatar download, a document conversion.',
          'Point it at `http://169.254.169.254/latest/meta-data/`.',
          'For IMDSv1, a single request. For IMDSv2, the application must also be able to issue a PUT — many SSRF sinks only support GET, which is the practical difference between the two versions.',
          'Capture the response in an error message, a log, or a rendered preview.',
        ],
        command:
          'curl -s "https://app.example.com/avatar?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"',
        impact:
          'The application fetches credentials it should never be able to see, and the application server\'s role is now in the attacker\'s hands.',
      },
      {
        name: 'Use DNS rebinding to defeat hostname allowlists',
        what: 'Resolve to a permitted hostname first and to the metadata address on the second lookup.',
        steps: [
          'Register a domain with a very short TTL that alternates between a public IP and `169.254.169.254`.',
          'Submit it to a URL-fetching feature that validates the hostname against an allowlist.',
          'The validation lookup gets the public IP; the actual fetch resolves to the metadata service.',
        ],
        command:
          'dig +short metadata.attacker.example A',
        impact:
          'Bypasses application-layer URL validation. The defense has to be at the network layer, where the link-local range is not routable.',
      },
      {
        name: 'Read user data for bootstrap credentials',
        what: 'Fetch the launch-time script, which frequently contains a password.',
        command:
          'curl -s http://169.254.169.254/latest/user-data',
        impact:
          'Database passwords, API tokens and, in older estates, IAM access keys placed in the launch script by a template that nobody reviewed.',
      },
      {
        name: 'Harvest ECS container credentials',
        what: 'Fetch the task role credentials from the container credentials endpoint.',
        steps: [
          'Read `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `AWS_CONTAINER_CREDENTIALS_FULL_URI` from the process environment.',
          'Request the credentials from `169.254.170.2` using the URI and the `Authorization` header when one is present.',
        ],
        command:
          'curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
        impact:
          'The task role, which on ECS is often the application\'s own role. A different address from EC2 IMDS, and the controls are different too.',
      },
    ],
    cases: [
      {
        title: 'Server-side request forgery into the instance metadata service',
        source: 'Public breach disclosures and regulatory filings involving a large financial institution',
        impact:
          'A misconfigured web application firewall rule in front of a modern server-side stack allowed a request to be forwarded to the instance metadata address. The instance role had broad permissions, and the attacker used the credentials to reach data the application itself could not, exposing a very large number of customer records and incurring a substantial regulatory penalty.',
        year: 2019,
      },
      {
        title: 'Over-privileged instance role converting a small foothold into cloud access',
        source: 'Recurring pattern in published cloud incident retrospectives and breach write-ups',
        impact:
          'The recurring pattern across published incidents is the same: an application bug or a credential in a public repository produced one credential, and that credential was a role with far more permission than the workload needed. The role was the real finding.',
        year: 2020,
      },
    ],
  },
  detect: {
    body: `Detecting metadata access is indirect. There is no CloudTrail event for "someone fetched the instance metadata", because the metadata service is not an AWS API and the request never leaves the instance.

Four signals work.

**VPC Flow Logs.** Traffic to \`169.254.169.254\` appears in the flow logs of the subnet. Legitimate SDK behaviour is a small, regular pattern: the SDK refreshes credentials roughly every five minutes from the host, or on demand when a request gets a 401. An SSRF-driven access is a single unusual destination from a process that should not be making AWS API calls at all.

**CloudTrail source IP.** When the instance role's credentials are used, the CloudTrail event has \`sourceIPAddress\` of \`169.254.169.254\` for the *metadata-derived* session in some services, and the public or private IP of the instance for calls made by the SDK from the instance. The signal to look for is a role making API calls it has never made before.

**User agent.** The SDK that fetches instance profile credentials identifies itself in the user agent of subsequent API calls. A distinctive agent appearing against an unusual role or an unusual service is a lead.

**GuardDuty.** GuardDuty has detections for credential theft from the instance metadata service and for suspicious behaviour by the instance role. It is the closest thing to a direct signal and it depends on the detector being enabled in that region.

The prevention signal matters too: an instance whose metadata options still allow IMDSv1 is a standing vulnerability, not an incident.`,
    signals: [
      {
        signal: 'A workload contacted the metadata service',
        source: 'VPC Flow Logs in CloudWatch Logs',
        query: `fields @timestamp, srcAddr, dstAddr, dstPort, action, bytes\n| filter dstAddr = "169.254.169.254"\n| stats count() as calls, sum(bytes) as bytes by srcAddr`,
        note:
          'Compare against the known baseline for that instance. A sudden new source address inside the subnet, or a source that is a container rather than the host, is the lead.',
      },
      {
        signal: 'A role made an API call it has never made before',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress\n| filter userIdentity.type = "AssumedRole"\n| stats count() by userIdentity.arn, eventSource, eventName`,
        note:
          'Baseline each workload role\'s normal API surface. A role that normally calls S3 and suddenly calls IAM or STS is the classic metadata-theft aftermath.',
      },
      {
        signal: 'The instance role session was used from an unexpected source',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, userAgent, eventSource\n| filter sourceIPAddress = "169.254.169.254"\n| stats count() by userIdentity.arn, eventSource, userAgent`,
        note:
          'Calls that carry the metadata address as the source are direct evidence that the credential came from the instance, not from a legitimate client.',
      },
      {
        signal: 'Instance metadata options still allow IMDSv1',
        source: 'AWS Config managed rule / EC2 API',
        query: `aws ec2 describe-instances --query "Reservations[].Instances[?MetadataOptions.HttpTokens!=\'required\'].[InstanceId,MetadataOptions]"`,
        note:
          'This is the standing vulnerability. Every instance should require the token, and the hop limit should be 1.',
      },
      {
        signal: 'Guardrail — require IMDSv2 with a hop limit of one at launch',
        source: 'Launch template and SCP',
        query: `SCP Deny: ec2:RunInstances when the launch template does not set MetadataOptions.HttpTokens=required, and an SCP Deny: ec2:ModifyInstanceMetadataOptions to loosen it`,
        note:
          'Setting it on the instance after the fact means a window where it was wrong. Setting it in the launch template closes the window.',
      },
    ],
    posture: [
      'Require IMDSv2 in the launch template for every instance and node group, with a hop limit of one.',
      'Deny `ec2:ModifyInstanceMetadataOptions` outside the platform team so the setting cannot be loosened.',
      'Enable VPC Flow Logs on every subnet and query specifically for traffic to 169.254.169.254 and 169.254.170.2.',
      'Enable GuardDuty in every region — it has detections for metadata credential theft that nothing else will give you.',
      'Give every instance profile role the minimum permissions the workload needs, and add a permission boundary.',
      'Block link-local ranges in the network ACLs of every subnet that does not need the metadata service at all.',
    ],
  },
  fix: {
    body: `The fix has three parts, and all three are needed.

**Turn on IMDSv2 with a hop limit of one.** The token requirement stops unauthenticated GETs. The hop limit stops a container or a neighbouring pod from obtaining the token. Set it in the launch template, not on the instance, and add an SCP that prevents anyone loosening it.

**Reduce the value of what the endpoint returns.** The instance role should be scoped to what the workload does, and should have a permission boundary. If the metadata endpoint leaks credentials for a role that can only read one S3 prefix, the SSRF is an inconvenience rather than an account compromise.

**Remove the SSRF.** The metadata service is a popular target because applications fetch URLs. That is an application-security problem: validate the resolved address, block link-local and private ranges, and allowlist destinations where you can.

Then check the container equivalents, because ECS and EKS have their own credential paths and their own controls.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Require IMDSv2 with a hop limit of one on every instance',
        detail:
          'The token requirement removes the unauthenticated GET. The hop limit of one means the token request cannot leave the host, so a container in a bridged network namespace cannot fetch it from the node.',
        snippet: `aws ec2 modify-instance-metadata-options --instance-id i-0abc123 \\\n  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled`,
        snippetLang: 'bash',
      },
      {
        priority: 'critical',
        action: 'Set the metadata options in the launch template so new instances are correct from the first boot',
        detail:
          'A template-level default removes the window between launch and hardening, which is the window an attacker with launch permissions would use.',
        snippet: `aws ec2 create-launch-template-version --launch-template-id lt-0abc123 \\\n  --source-version 1 \\\n  --launch-template-data '{"MetadataOptions":{"HttpTokens":"required","HttpPutResponseHopLimit":1,"HttpEndpoint":"enabled"}}'`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Scope the instance profile role and add a permission boundary',
        detail:
          'The credentials in the metadata endpoint are worth exactly what the role is worth. A role that reads one bucket and writes one queue turns an SSRF into a minor incident.',
      },
      {
        priority: 'high',
        action: 'Block link-local and private ranges in the SSRF sink',
        detail:
          'In any application feature that fetches a URL, resolve the hostname and validate the resulting address, and reject link-local, private and metadata ranges. Do not rely on the hostname allowlist, because DNS rebinding defeats it.',
        snippet: `if ipaddress.ip_address(resolved).is_link_local or ipaddress.ip_address(resolved).is_private:
    raise ValueError("blocked address range")`,
        snippetLang: 'text',
      },
      {
        priority: 'high',
        action: 'Deny ec2:ModifyInstanceMetadataOptions outside the platform team',
        detail:
          'An attacker who can reach the instance can weaken its own metadata options. The SCP removes that option.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "ec2:ModifyInstanceMetadataOptions",
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'medium',
        action: 'Move container credentials off the default endpoints',
        detail:
          'ECS and EKS have their own credential paths with their own options. Use the full-URI variant with an authorisation token for ECS so the credentials endpoint is not reachable from an arbitrary container.',
      },
      {
        priority: 'medium',
        action: 'Remove secrets from user data',
        detail:
          'User data is retrievable from the same endpoint. Pass configuration through the instance tags, a Secrets Manager reference or a parameter, and keep user data to a bootstrap script that fetches them.',
      },
      {
        priority: 'medium',
        action: 'Restrict who can read user data and the instance identity document',
        detail:
          'The instance identity document contains the account id and instance id, which is useful for an attacker when mapping the estate. Where you do not need it, disable the endpoint with `http-endpoint disabled` for IPv6-only workloads.',
      },
      {
        priority: 'low',
        action: 'Add a network ACL deny on link-local ranges as defence in depth',
        detail:
          'Security groups cannot do this, but network ACLs can. It is a second layer that catches an IMDSv2 configuration regression.',
      },
    ],
  },
  checklist: [
    {
      id: 'imds-1',
      text: 'Confirm every instance requires IMDSv2 with a hop limit of one.',
      command:
        'aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit]" --output text',
      expected: 'HttpTokens is "required" and the hop limit is 1 on every instance.',
    },
    {
      id: 'imds-2',
      text: 'Confirm the launch templates enforce IMDSv2 for new instances.',
      command:
        'aws ec2 describe-launch-templates --query "LaunchTemplates[].{Id:LaunchTemplateId,Tokens:LaunchTemplateData.MetadataOptions.HttpTokens}"',
      expected: 'Every template has HttpTokens set to required and a hop limit of 1.',
    },
    {
      id: 'imds-3',
      text: 'Test that an unauthenticated metadata request fails from inside the estate.',
      command:
        'curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ ; echo "exit=$?"',
      expected:
        'No role name is returned. A successful response means IMDSv1 is still reachable from somewhere.',
    },
    {
      id: 'imds-4',
      text: 'Check whether the metadata endpoint is still reachable over the network from another subnet.',
      command:
        'aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,MetadataOptions.HttpPutResponseHopLimit]"',
      expected: 'A hop limit of 1 everywhere; a value of 2 or more is the finding.',
    },
    {
      id: 'imds-5',
      text: 'List the instance profile attached to every instance and check the role\'s permissions.',
      command:
        'aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,IamInstanceProfile.Arn]" --output text && aws iam list-attached-role-policies --role-name AppInstanceRole',
      expected:
        'Each instance has its own profile, and the attached policies are scoped to the workload rather than to a broad administrative set.',
    },
    {
      id: 'imds-6',
      text: 'Look for flow log entries to the metadata and container credential addresses.',
      command:
        'aws logs start-query --log-group-name /aws/vpc/flowlogs --start-time 1700000000 --end-time 1700086400 --query-string \'fields @timestamp, srcAddr, dstAddr, action | filter dstAddr = "169.254.169.254" or dstAddr = "169.254.170.2" | stats count() by srcAddr, dstAddr\'',
      expected:
        'Only known SDK sources appear, and the volume matches the expected credential refresh pattern.',
    },
    {
      id: 'imds-7',
      text: 'Confirm that user data does not contain credentials.',
      command:
        'aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,Tags]" --output text',
      expected:
        'No instance was launched with a template whose user data contains a password or key. Review the template directly for anything sensitive.',
    },
  ],
  references: [
    { label: 'AWS EC2 instance metadata categories', url: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html' },
    { label: 'AWS IMDSv2', url: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html' },
    { label: 'AWS ECS container credentials', url: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html' },
    { label: 'AWS EC2 instance metadata options', url: 'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_MetadataOptions.html' },
  ],
  updated: '2026-11-21',
}
