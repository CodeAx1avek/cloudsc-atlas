import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/foundation/network-boundaries',
  title: 'Network boundaries and the VPC',
  cloud: 'aws',
  stage: 'foundation',
  track: 'Network',
  summary:
    'The VPC as a trust boundary: security groups, network ACLs, route tables, VPC endpoints, and the link-local path that skips all of them.',
  duration: '35 min',
  difficulty: 3,
  prerequisites: ['aws/foundation/identity-and-trust'],
  enables: [
    'aws/operator/storage-and-data',
    'aws/operator/compute-and-containers',
    'aws/adversary/ec2-metadata-service',
    'aws/adversary/serverless-attack-surface',
    'aws/redteam/kubernetes-on-eks',
  ],
  mentalModel:
    'A VPC is a routing boundary, not a security boundary. Security comes from security groups and network ACLs evaluated against flow logs — and the one address that ignores almost everything you configured is 169.254.169.254.',
  concept: {
    body: `A VPC is a private address space carved out of a region, divided into subnets, and connected to the internet by an internet gateway. Everything inside it is private unless something deliberately makes it public.

**The moving parts.**

- **Subnets.** A subnet is an address range in one availability zone, with a route table attached. A subnet is "public" only in the sense that its route table sends 0.0.0.0/0 to an internet gateway. Two subnets in the same VPC can have completely different reachability.
- **Route tables.** The routing decision. A route table with a 0.0.0.0/0 route to an internet gateway makes every subnet using it internet-reachable *subject to the firewall*.
- **Security groups.** Stateful, per-resource firewalls with allow/deny rules evaluated per connection. A security group can reference another security group, which is the cleanest way to express "the web tier may talk to the app tier" without CIDR maths. Rules only allow; there is no deny rule, and traffic not explicitly allowed is implicitly dropped.
- **Network ACLs.** Stateless, subnet-level, and evaluated in numeric order, lowest to highest, with an explicit deny at 32767 as the final rule. NACLs see packet headers only, so a rule allowing TCP/443 also needs a rule allowing the ephemeral return port range. This is why NACLs are fiddly and why most estates use them only for a coarse allowlist.
- **NAT gateways.** Egress for private subnets. A NAT gateway hides the number of instances behind one public IP, and the source address in the flow log becomes the NAT gateway's address.
- **Internet gateway, egress-only internet gateway.** The IGW is bidirectional for IPv4 public subnets. The egress-only IGW is for IPv6: outbound only, so an IPv6-enabled instance cannot accept unsolicited inbound connections.
- **VPC peering, Transit Gateway, PrivateLink.** Peering connects two VPCs with a routing relationship; Transit Gateway connects many. PrivateLink (via interface VPC endpoints) publishes a service into your VPC with a private DNS name so traffic never leaves the AWS network.
- **VPC endpoints.** Gateway endpoints for S3 and DynamoDB route through the VPC prefix lists; interface endpoints (powered by PrivateLink) create ENIs in your subnets for services like EC2 API, STS, Secrets Manager, Lambda, ECR or CloudWatch Logs. Interface endpoints have their own endpoint policy — a second, independent IAM layer for the service.

**Where the boundary leaks.**

The most important leak is the link-local service address. The EC2 Instance Metadata Service lives at \`169.254.169.254\`. It is reachable from any instance, any container, any Lambda function with a VPC config, and any ENI in the VPC — and it is not subject to security group rules, because it is not a TCP connection to a peer security group. Traffic to it is link-local and is filtered by hop limit instead. It is also the only path by which an instance profile's role credentials reach the workload.

Second leak: egress. Most security group reviews look at inbound rules. Outbound \`0.0.0.0/0\` on all protocols from every workload is the default state of a default VPC and is what turns a single SSRF into a full data exfiltration channel.

Third leak: VPC endpoints with permissive endpoint policies, and DNS. Route 53 Resolver inside the VPC is a name server that answers for internal and external zones; it is also an exfiltration channel if outbound DNS is unrestricted.

The mental model to carry forward: AWS network controls are *default deny* for inbound security groups and *default allow* for outbound. Attackers plan around that asymmetry.`,
    keyPoints: [
      'Security groups are stateful and only allow. Unmatched traffic is dropped, so there is no rule ordering to reason about.',
      'Network ACLs are stateless and ordered. They need explicit ephemeral return-port rules or they break working traffic.',
      'A subnet is public or private only because of its route table, not because of how it was named or tagged.',
      'VPC endpoints carry their own endpoint policy. That policy can grant access your IAM policy never approved, and can be tightened independently.',
      'The instance metadata service at 169.254.169.254 is link-local and is not filtered by security group rules.',
      'Unrestricted outbound is the default, and it is what makes SSRF useful to an attacker.',
    ],
    misconceptions: [
      {
        claim: 'Security groups block the metadata service.',
        truth:
          'They do not. 169.254.169.254 is link-local, not a peer ENI, so security group rules do not filter it. Hop limit and IMDSv2 token requirements are what control it.',
      },
      {
        claim: 'Private subnets have no internet access.',
        truth:
          'They have egress through a NAT gateway, a NAT instance or an egress-only IGW for IPv6. That egress is usually what an attacker uses to exfiltrate once they have a foothold.',
      },
      {
        claim: 'Network ACLs and security groups are two ways to do the same thing.',
        truth:
          'They operate at different layers and with different semantics. NACLs are subnet-wide and stateless; security groups are per-resource and stateful. A blanket NACL rule can be undone by a later allow, and a security group reference cannot be expressed in a NACL.',
      },
    ],
  },
  attack: {
    body: `Network attacks in AWS are rarely about breaking the network. They are about using the network the way it was designed, or finding the one path that bypasses it.

The dominant technique is **server-side request forgery into the metadata service**. An application that fetches a user-supplied URL will happily fetch \`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>\` unless something stops it. The response is the instance profile's temporary credentials: access key, secret key and session token, in plain JSON, no authentication needed if IMDSv1 is enabled.

The second technique is **egress abuse**. Once an attacker has code execution or an SSRF, unrestricted outbound lets them push data anywhere: to a host they control, to a paste site, to a DNS name they encode the data into. Restricting egress to port 443 on specific destinations and blocking UDP/53 to external resolvers removes most of this.

The third is **direct VPC peering and transit access**. A peer account in a peering relationship can reach your CIDRs, subject to your security groups — and the reciprocal is often forgotten. Many accounts have peering relationships to accounts they no longer remember.

The fourth is **public exposure by accident**: a security group with \`0.0.0.0/0\` on 22, 3389, 3306, 5432 or 6379, and a route table that makes the subnet public. This is the default VPC state that every AWS account starts with, and it is still one of the most common findings.

The fifth is **VPC endpoint policy weakness**: an endpoint policy that allows \`"*"\` on \`"*"\` means any principal in the account that has IAM permissions gets them through the endpoint. Endpoint policies are a second authorization layer, and a permissive one removes the isolation you thought PrivateLink gave you.`,
    techniques: [
      {
        name: 'Read the metadata service through an SSRF',
        what: 'Fetch instance role credentials from a server that fetches attacker-supplied URLs.',
        command:
          'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        impact:
          'Returns the role name attached to the instance profile. A second request returns temporary credentials usable from anywhere until they expire.',
      },
      {
        name: 'Map the VPC and find the exposed tier',
        what: 'Enumerate VPCs, subnets, route tables and security groups to find internet-reachable workloads.',
        steps: [
          'List VPCs: `aws ec2 describe-vpcs --query "Vpcs[].{Id:VpcId,Cidr:CidrBlock}"`.',
          'For each VPC, list subnets and note the subnet ids that carry a public IPv4 address on instances.',
          'List security groups and look for `0.0.0.0/0` on administrative ports.',
          'Confirm reachability with a route table check rather than assuming — a subnet can have a public address and no internet route.',
        ],
        command:
          'aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==\'0.0.0.0/0\']]].{Name:GroupName,Id:GroupId,Vpc:VpcId}"',
        impact:
          'A complete list of internet-reachable resources in the account, usually including an instance or a bastion that was meant to be private.',
      },
      {
        name: 'Inspect VPC endpoint policies',
        what: 'Check whether PrivateLink endpoints are actually restricting anything.',
        command:
          'aws ec2 describe-vpc-endpoints --query "VpcEndpoints[].{Id:VpcEndpointId,Service:ServiceName,Policy:PolicyDocument}"',
        impact:
          'A permissive endpoint policy reopens the service to any principal in the account that has IAM permissions, undoing the isolation the endpoint was bought for.',
      },
      {
        name: 'Enumerate VPC peering and transit gateway attachments',
        what: 'Find the other VPCs that have a routing relationship with this one.',
        command:
          'aws ec2 describe-vpc-peering-connections --query "VpcPeeringConnections[].{Id:VpcPeeringConnectionId,Accepter:AccepterVpcInfo.VpcId,Requester:RequesterVpcInfo.VpcId,Status:VpcPeeringConnectionStatus.Code}"',
        impact:
          'A list of reachable networks, each of which is a separate set of security groups and NACLs you do not control.',
      },
      {
        name: 'Exfiltrate over unrestricted egress',
        what: 'Use a foothold to send data out over DNS or HTTPS.',
        steps: [
          'Confirm outbound is open: check the security group outbound rules and the route table.',
          'Send data over DNS by encoding it in a subdomain, which defeats naive egress allowlists that only inspect ports.',
          'Send data over HTTPS to infrastructure you control if port 443 is open to the internet.',
        ],
        impact:
          'Complete loss of confidentiality for anything the foothold can read, with no need for another exploit.',
      },
    ],
    cases: [
      {
        title: 'Server-side request forgery into the instance metadata service',
        source: 'Recurring pattern in published cloud incident retrospectives and breach write-ups',
        impact:
          'A web application that fetched a user-supplied URL was used to retrieve the instance profile credentials of the host it ran on. Because the role was over-privileged, the attacker reached data the application itself could not.',
        year: 2019,
      },
    ],
  },
  detect: {
    body: `VPC Flow Logs are the primary network signal. They record every flow at the subnet level with source and destination address, port, protocol, byte count and an ACCEPT or REJECT action. Delivered to CloudWatch Logs they are queryable with Logs Insights; delivered to S3 they feed Athena and GuardDuty.

Two signals matter more than the rest: traffic to \`169.254.169.254\`, and traffic to a destination the environment has never talked to. The first tells you a workload reached for credentials. The second tells you it reached for something outside.

The second source is CloudTrail. VPC and security group changes are management events: \`CreateSecurityGroup\`, \`AuthorizeSecurityGroupIngress\`, \`AuthorizeSecurityGroupEgress\`, \`ModifyVpcEndpoint\`, \`CreateVpcPeeringConnection\`, \`DeleteNetworkAclEntry\`. These are how an attacker opens the network after gaining a foothold.`,
    signals: [
      {
        signal: 'A workload contacted the instance metadata service',
        source: 'VPC Flow Logs in CloudWatch Logs',
        query: `fields @timestamp, srcAddr, dstAddr, dstPort, action, bytes\n| filter dstAddr = "169.254.169.254"\n| stats count() as calls, sum(bytes) as bytes by srcAddr, action`,
        note:
          'Normal application traffic rarely touches the metadata service directly. Any hit is either an SDK fetching credentials, which resolves to the instance profile, or something reaching for it.',
      },
      {
        signal: 'Rejected inbound connections to administrative ports',
        source: 'VPC Flow Logs in CloudWatch Logs',
        query: `fields @timestamp, srcAddr, dstAddr, dstPort, action\n| filter action = "REJECT" and dstPort in [22, 3389, 3306, 5432, 6379, 27017]\n| stats count() by dstAddr, dstPort, srcAddr`,
        note:
          'A concentrated burst from one source against one port is scanning. A trickle across many ports is a background worm scanning the whole internet.',
      },
      {
        signal: 'Security group opened to the world',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.groupId, requestParameters.ipPermissions\n| filter eventName = "AuthorizeSecurityGroupIngress" or eventName = "AuthorizeSecurityGroupEgress"\n| stats count() by userIdentity.arn, requestParameters.groupId`,
        note:
          'Baseline the security groups that legitimately receive public ingress. Any other group opening to 0.0.0.0/0 is worth a ticket.',
      },
      {
        signal: 'VPC endpoint or peering connection created',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.vpcId\n| filter eventName = "CreateVpcPeeringConnection" or eventName = "ModifyVpcEndpoint" or eventName = "CreateVpcEndpoint"\n| stats count() by eventName, userIdentity.arn, requestParameters.vpcId`,
        note:
          'A new peering connection is a new trust relationship with someone else\'s firewall rules. An endpoint created with no policy is a default-permit service path.',
      },
      {
        signal: 'Guardrail — require VPC Flow Logs on every subnet',
        source: 'AWS Config managed rule / SCP',
        query: `AWS Config rule VPC_FLOW_LOGS_ENABLED, plus an SCP denying ec2:CreateVpc and ec2:RunInstances when the subnet has no flow log`,
        note:
          'The managed rule tells you about the past; the SCP prevents the next subnet from shipping without visibility.',
      },
    ],
    posture: [
      'Enable VPC Flow Logs on every subnet, in every VPC, and deliver to a central log archive account.',
      'Turn on GuardDuty in every region — it consumes flow logs and adds DNS and runtime detection on top.',
      'Default egress to deny. Workloads should reach named destinations, not 0.0.0.0/0 on all protocols.',
      'Create explicit deny rules for link-local address space in network ACLs so that a future IMDSv1 regression is not fatal.',
      'Use a VPC endpoint for every AWS service a workload needs, with a restrictive endpoint policy, so data-plane calls never leave the VPC.',
      'Review peering relationships and Transit Gateway attachments on a schedule and remove the ones nobody owns.',
    ],
  },
  fix: {
    body: `Network hardening in AWS produces the biggest improvement per unit of effort, because the default posture of a fresh account is wide open and the fix is a small number of explicit rules.

Order it by blast radius. First close the metadata path, because it is the one route that turns a single application bug into a credential. Then close egress. Then clean up inbound. Then harden the endpoints.

You will not get an estate to a defensible state in one pass. The realistic goal is that each new account starts from a safe template and each existing account improves a bounded amount every quarter. The guardrail that makes this stick is an SCP that blocks creating network resources outside the approved patterns, so the bad state cannot be recreated after you clean it up.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Require IMDSv2 on every instance and set the hop limit to one',
        detail:
          'IMDSv2 requires a session token obtained with a PUT request that carries a hop limit of one, so a container or a process on a different host cannot fetch it. Setting HttpTokens to required removes the unauthenticated GET path entirely.',
        snippet: `aws ec2 modify-instance-metadata-options --instance-id i-0abc123 \\\n  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled`,
        snippetLang: 'bash',
      },
      {
        priority: 'critical',
        action: 'Replace default-allow egress with an explicit allowlist',
        detail:
          'Attach a security group to every workload that allows outbound only on the protocols and destinations it needs. Block UDP and TCP port 53 to anything except your own resolver, so DNS tunnelling is not available.',
        snippet: `{
  "IpPermissions": [
    { "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
      "IpRanges": [{ "CidrIp": "10.0.0.0/8" }] }
  ],
  "IpPermissionsEgress": [
    { "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
      "IpRanges": [{ "CidrIp": "0.0.0.0/0" }] }
  ]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Delete the default security group rules and the default VPC',
        detail:
          'The default security group allows all traffic between its members, and the default VPC comes with a security group allowing 0.0.0.0/0 on SSH and RDP to instances that launch with it. Delete both in accounts that do not need them.',
        snippet: `aws ec2 delete-security-group --group-id sg-0abc123`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Give every VPC endpoint a restrictive endpoint policy',
        detail:
          'An interface endpoint without a policy is an open door to the service for any principal with IAM permissions in the account. Scope the policy to the resources the workload actually uses.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Block link-local and metadata traffic at the network ACL layer',
        detail:
          'Security groups cannot filter link-local traffic, but network ACLs can. Denying 169.254.0.0/16 and 169.254.169.254/32 at the subnet edge is a second line of defence if IMDSv2 is ever rolled back.',
      },
      {
        priority: 'medium',
        action: 'Use network ACLs as a coarse deny layer, not as the primary firewall',
        detail:
          'NACLs are stateless and ordered, which makes them easy to configure wrongly. Use them for a simple allowlist of source ranges, and keep the fine-grained rules in security groups.',
      },
      {
        priority: 'medium',
        action: 'Remove stale peering and Transit Gateway attachments',
        detail:
          'Every peering relationship is a trust edge to a network whose controls you do not own. Audit the list quarterly and delete what nobody can name an owner for.',
      },
      {
        priority: 'low',
        action: 'Move public workloads behind CloudFront, an ALB or a NAT-only design',
        detail:
          'Fewer public IPs means less exposed. Where a workload must be reachable, front it with a managed edge service that terminates TLS and gives you a WAF layer.',
      },
    ],
  },
  checklist: [
    {
      id: 'net-1',
      text: 'Confirm every EC2 instance requires IMDSv2 and has a hop limit of one.',
      command:
        'aws ec2 describe-instances --query "Reservations[].Instances[].{Id:InstanceId,Tokens:MetadataOptions.HttpTokens,Hop:MetadataOptions.HttpPutResponseHopLimit}"',
      expected: 'HttpTokens is "required" and the hop limit is 1 on every instance.',
    },
    {
      id: 'net-2',
      text: 'Find security groups with unrestricted inbound or outbound rules.',
      command:
        'aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==\'0.0.0.0/0\']]].{Name:GroupName,Id:GroupId,Vpc:VpcId}"',
      expected:
        'Only deliberate public entry points remain, and outbound rules are on named workloads rather than the default group.',
    },
    {
      id: 'net-3',
      text: 'Check whether every VPC has flow logs on all of its subnets.',
      command:
        'aws ec2 describe-vpc-endpoints --query "VpcEndpoints[].{Id:VpcEndpointId,Service:ServiceName,Policy:PolicyDocument}" && aws ec2 describe-flow-logs --query "flowLogs[].{Resource:ResourceId,Dest:Destination}"',
      expected:
        'One flow log per subnet across the estate, and every endpoint carries a policy that names specific resources.',
    },
    {
      id: 'net-4',
      text: 'List every peering relationship and transit gateway attachment.',
      command:
        'aws ec2 describe-vpc-peering-connections --query "VpcPeeringConnections[].{Id:VpcPeeringConnectionId,Status:VpcPeeringConnectionStatus.Code,Accepter:AccepterVpcInfo.VpcId}"',
      expected:
        'A short list, each with a documented owner and a reason. The reciprocal side of each peering is also reviewed.',
    },
    {
      id: 'net-5',
      text: 'Confirm no subnet with public instances has an open route to the internet.',
      command:
        'aws ec2 describe-route-tables --query "RouteTables[].Routes[?DestinationCidrBlock==\'0.0.0.0/0\'].[GatewayId,SubnetId,NatGatewayId]"',
      expected:
        'Internet-bound routes exist only in the subnets that are meant to be public.',
    },
    {
      id: 'net-6',
      text: 'Test that the metadata service requires a token from inside the estate.',
      command:
        'curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ ; echo "exit=$?"',
      expected:
        'The unauthenticated GET fails or returns nothing useful. A successful role name means IMDSv1 is still reachable.',
    },
  ],
  references: [
    { label: 'AWS VPC documentation', url: 'https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html' },
    { label: 'AWS security group rules', url: 'https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html' },
    { label: 'AWS VPC endpoints', url: 'https://docs.aws.amazon.com/vpc/latest/userguide/privatelink-interface-endpoints.html' },
    { label: 'AWS VPC Flow Logs', url: 'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html' },
  ],
  updated: '2026-11-18',
}
