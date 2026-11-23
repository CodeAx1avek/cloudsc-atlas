import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/redteam/kubernetes-on-eks',
  title: 'Kubernetes on EKS',
  cloud: 'aws',
  stage: 'redteam',
  track: 'Containers',
  summary:
    'The EKS control plane is one identity; the node is another; the pod is a third. Most cluster compromises come from the seams between them.',
  duration: '35 min',
  difficulty: 4,
  prerequisites: [
    'aws/operator/compute-and-containers',
    'aws/adversary/ec2-metadata-service',
  ],
  enables: ['aws/redteam/attack-path-chaining'],
  mentalModel:
    'EKS gives a pod three separate identities — the Kubernetes service account, the IRSA role, and the node role — and an attacker only needs the weakest of the three. Most clusters are compromised through the node, not the control plane.',
  concept: {
    body: `Kubernetes has its own identity system, and AWS adds a second one next to it. Keeping them straight is most of the work.

**Four identities, in order of nesting.**

- The **EKS cluster IAM role** is assumed by the control plane (on managed EKS it is a service-linked role). It manages the cluster, not the pods.
- The **node instance role** is attached to the EC2 worker nodes. It is the role the kubelet and the node agent use. Anything that reaches the node gets this.
- The **pod's Kubernetes service account** is a Kubernetes object. RBAC governs what it can do against the API server. It is not an AWS credential.
- The **IRSA role** (IAM Roles for Service Accounts) is the AWS identity a specific pod can obtain, via a projected OIDC token that Kubernetes mounts into the pod. It is opt-in per service account.

**The confused deputy at the centre of all of it.** By default a pod can reach the EC2 instance metadata service and obtain the *node's* credentials. That means any pod with a container escape, any SSRF in a pod, and any image that gets pulled and run with a flaw gets the node role — which usually has more permissions than the workloads running on it. IRSA exists to stop this by making the pod get its own role instead, but it only helps for pods that are configured to use it. A pod without an IRSA annotation still falls back to the node credentials.

**The three ways into a cluster, in order of how often they are used in real engagements:**

1. **Container escape.** A vulnerability in the container runtime, the kernel, or the application inside the container. From there you are on the node, and you have the node role.
2. **Cluster API abuse.** If you have a service account token and the RBAC bindings are loose, you can list pods, read secrets, or exec into other containers directly through the API server.
3. **The node role.** If you have it, you can call the EKS API, list clusters, and read the cluster's CA data and endpoint — which is enough to talk to the API server directly.

**The API server is the prize.** \`kubectl\` against the EKS endpoint needs a signed token and a certificate. The EKS API exposes \`DescribeCluster\`, which returns the cluster CA and endpoint. The node role has \`eks:DescribeCluster\`. So holding the node role means holding the keys to the API server — this is the single most important relationship in the whole topic.

**EKS Pod Identity** is the newer alternative to IRSA. Instead of the cluster using OIDC and a webhook to inject role credentials, an agent on the node asks EKS what credentials a specific pod should get, and EKS hands them over via a container credential endpoint. The difference matters for detection: with IRSA, a role assumption shows up as an \`AssumeRoleWithWebIdentity\`; with Pod Identity, the credential arrives through a local endpoint and the assumption is invisible in CloudTrail unless you enable the relevant logging.`,
    keyPoints: [
      'The node instance role is usually more privileged than the workloads on the node, and every pod can reach it by default.',
      'eks:DescribeCluster on the node role returns the cluster CA and endpoint, which is enough to talk to the API server.',
      'IRSA only protects pods that use it. A pod without the annotation still falls back to the node credentials.',
      'Kubernetes RBAC governs the API server; IRSA governs AWS. Both are needed, and both are usually configured independently.',
      'The eks:authenticator ConfigMap in kube-system holds the RBAC mappings for the AWS-authenticated identity.',
      'EKS Pod Identity removes the OIDC flow but changes what appears in CloudTrail, so your detection has to match the mechanism in use.',
    ],
    misconceptions: [
      {
        claim: 'Restricting the node role fixes the cluster.',
        truth:
          'It reduces the blast radius of a node compromise but does not close the API server path. If you hold eks:DescribeCluster you still have the endpoint and the CA. Restrict that action separately.',
      },
      {
        claim: 'IRSA means pods cannot reach the instance metadata service.',
        truth:
          'IRSA gives a pod its own role; it does not stop the pod from reaching IMDS. Unless the hop limit is set and the node role is not attached to the instance, the node credentials are still retrievable.',
      },
      {
        claim: 'A pod cannot talk to the Kubernetes API without a kubeconfig.',
        truth:
          'It needs a token and the cluster endpoint, both of which are available to any pod that is allowed to read its own service account token — which is all of them by default.',
      },
    ],
  },
  attack: {
    body: `The chain is: get code execution in a container, then decide whether to escape to the node or work through the Kubernetes API. Both routes are worth checking, and the API route is quieter.

From inside a container, the service account token is usually mounted at \`/var/run/secrets/kubernetes.io/serviceaccount/token\`. With the API server endpoint and CA — both obtainable from the node role or from the environment — you have everything needed to talk to the cluster directly, without \`kubectl\` and without touching the node.

The RBAC checks that matter: can your service account list pods, read secrets, create pods, or exec into containers? \`list\` on secrets across the namespace is the most common high-value find in a real engagement, because it usually returns database passwords, API keys and cloud credentials in one call.

If the API route is closed, the node route is always open: read the instance metadata service from inside the container, take the node role, and use it.`,
    techniques: [
      {
        name: 'Read the node role from inside a container',
        what:
          'Reach the instance metadata service from a compromised pod and take the credentials of the node instance role.',
        command:
          'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        impact:
          'Whatever the node role can do, you can now do — and it usually can describe the cluster, which hands you the API server.',
      },
      {
        name: 'Use the node role to read the cluster connection details',
        what:
          'Call the EKS control plane API to retrieve the cluster endpoint and certificate authority data.',
        command:
          'aws eks describe-cluster --name my-cluster --query "cluster.{endpoint:endpoint,ca:certificateAuthority.data}"',
        impact:
          'The endpoint and CA are the two things you need to talk to the Kubernetes API server directly.',
      },
      {
        name: 'Enumerate the cluster with the pod service account token',
        what:
          'Use the mounted service account token against the API server to see what the pod can reach.',
        command:
          'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\nCA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt\ncurl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \\\n  https://YOUR_CLUSTER_ENDPOINT/api/v1/namespaces/default/pods',
        impact:
          'A complete view of what the service account can read, and in many clusters that includes other pods\' secrets.',
      },
      {
        name: 'Read secrets across namespaces',
        what:
          'List and read Kubernetes secrets if the service account has the verbs.',
        command:
          'kubectl get secrets --all-namespaces -o json | jq -r \'.items[] | "\\(.metadata.namespace)/\\(.metadata.name): \\(.data | to_entries | map("\\(.key)=\\(.value|@base64d)") | join(", "))"\'',
        impact:
          'Database passwords, API keys and cloud credentials, often for applications this pod has nothing to do with.',
      },
      {
        name: 'Exec into another container',
        what:
          'If the service account may create pods, run a privileged pod that mounts the host filesystem.',
        steps: [
          'Check whether the service account can create pods or pods/exec in the namespace.',
          'Create a pod that mounts the host root at /host and runs a shell in privileged mode.',
          'Read the host filesystem, including kubelet credentials and the node role environment.',
        ],
        impact:
          'Full node compromise, and from there the node role and the API server.',
      },
      {
        name: 'Assume the IRSA role of another service account',
        what:
          'If the IRSA role trust policy is broad, use the projected OIDC token to assume it directly.',
        command:
          'aws sts assume-role-with-web-identity --role-arn arn:aws:iam::123456789012:role/Target \\\n  --role-session-name probe --web-identity-token file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token',
        impact:
          'The IRSA role of another workload, without touching that workload at all.',
      },
    ],
    cases: [
      {
        title: 'Node role readable from any pod via IMDS',
        source: 'Widely documented class of container escape and workload vulnerability',
        impact:
          'In the recurring pattern, a single application vulnerability in a pod escalates to the node role, and the node role holds eks:DescribeCluster and broader permissions than the workload ever needed. The entire cluster becomes reachable from one container.',
      },
      {
        title: 'Over-broad IRSA trust policy',
        source: 'Recurring pattern across cloud and Kubernetes security research',
        impact:
          'A trust policy conditioned only on the cluster OIDC issuer and a wildcard subject accepts any service account token the cluster can mint, so a low-privilege pod reaches a high-privilege role without any container escape.',
      },
    ],
  },
  detect: {
    body: `Detection splits into two very different places: the Kubernetes audit log, and CloudTrail.

The Kubernetes audit log records every request to the API server, including which service account made it. That is where you see \`list\` on secrets, \`create\` on pods, and \`exec\` into containers. It is the primary signal for API abuse and it is often not enabled.

CloudTrail records the AWS side: the node role's calls to EKS, and the role assumptions behind IRSA. Notably, EKS control plane operations are logged in CloudTrail by default, but the API server's own audit log is a separate thing that many clusters never turn on.

The most valuable behavioural signal is a service account reading secrets it has never read before, because that service account belongs to a workload that has no business reading them.`,
    signals: [
      {
        signal: 'Kubernetes audit log — secret access',
        source: 'EKS control plane audit log (CloudWatch Logs, log group /aws/eks/<cluster>/cluster)',
        query: `fields @timestamp, user.username, objectRef.resource, verb\n| filter verb in ("list", "watch", "get") and objectRef.resource == "secrets"\n| stats count() by user.username`,
        note:
          'Enable the audit log first. Without it this signal does not exist, and secret enumeration is invisible.',
      },
      {
        signal: 'Kubernetes audit log — pod creation and exec',
        source: 'EKS control plane audit log',
        query: `fields @timestamp, user.username, objectRef.namespace, objectRef.name\n| filter verb in ("create", "exec", "attach") and objectRef.resource == "pods"\n| sort @timestamp desc`,
        note:
          'A pod created outside a deployment pipeline is a strong indicator. Exec into an existing pod from a different service account is stronger.',
      },
      {
        signal: 'Node role calling the EKS control plane',
        source: 'CloudTrail — management events',
        query: `eventName=DescribeCluster\n| where userIdentity.arn like "%:role/AmazonEKSNodeRole" or userIdentity.arn like "%:role/eks-node"\n| stats count() by userIdentity.arn, sourceIPAddress\n| sort count desc`,
        note:
          'The node role describing the cluster is normal for the node agent. Describing it from many distinct source addresses is not.',
      },
      {
        signal: 'IRSA role assumed from an unexpected principal',
        source: 'CloudTrail — management events',
        query: `eventName=AssumeRoleWithWebIdentity\n| stats count() by requestParameters.roleArn, userIdentity.userName\n| sort count desc`,
        note:
          'The role session name usually encodes the service account namespace and name. An unfamiliar name is a finding.',
      },
      {
        signal: 'Pod reaching the instance metadata service',
        source: 'VPC Flow Logs / EKS audit log',
        query: `fields @timestamp, srcAddr, dstAddr\n| filter dstAddr = "169.254.169.254"\n| stats count() by srcAddr`,
        note:
          'A pod that talks to IMDS directly is either using IRSA incorrectly or doing something you want to know about.',
      },
      {
        signal: 'Guardrail — restrict the node role',
        source: 'SCP / permission boundary',
        query: `SCP Deny: eks:DescribeCluster, eks:ListClusters on roles tagged as node roles`,
        note:
          'Removing DescribeCluster from the node role breaks the path from a node compromise to the API server.',
      },
    ],
    posture: [
      'Enable the EKS Kubernetes audit log and send it to a central account.',
      'Remove eks:DescribeCluster from node roles unless a specific tool needs it.',
      'Set IMDSv2 with a hop limit of one on every node so pods cannot reach the node credentials.',
      'Review all IRSA trust policies and confirm the subject claim names a specific namespace and service account.',
      'Enable IRSA or EKS Pod Identity for every workload that does not need the node role.',
      'Restrict Kubernetes RBAC so that no service account can list secrets outside its own namespace.',
    ],
  },
  fix: {
    body: `The fix is to remove the fallbacks. Every default in EKS is permissive on purpose, because the defaults have to work for everybody.

The order below runs from "stops the common chain" to "reduces the blast radius". The first two break the route from a container compromise to the cluster.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Remove eks:DescribeCluster and eks:ListClusters from the node role',
        detail:
          'The node role holding DescribeCluster means a node compromise yields the API server endpoint and CA, which is enough to talk to the cluster directly. Remove it unless a specific agent genuinely needs it.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": [
      "eks:DescribeCluster",
      "eks:ListClusters"
    ],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'critical',
        action: 'Require IMDSv2 with a hop limit of one on every node',
        detail:
          'The hop limit of one means the token request cannot leave the host, so a container in a separate network namespace cannot obtain it. Without this, any pod can still read the node role even where IRSA is configured.',
        snippet: `aws ec2 modify-instance-metadata-options --instance-id i-0abc123 \\\n  --http-tokens required --http-put-response-hop-limit 1 \\\n  --instance-metadata-tags enabled`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Pin the IRSA trust policy subject claim to a specific service account',
        detail:
          'A trust policy conditioned only on the OIDC issuer accepts any token the cluster can mint, which means any pod. Pinning the subject to a namespace and service account is what makes IRSA a per-workload boundary.',
        snippet: `{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.<region>.amazonaws.com/id/ABCDEF"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "<oidc-host>:aud": "sts.amazonaws.com",
      "<oidc-host>:sub": "system:serviceaccount:production:payments-api"
    }
  }
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Tighten Kubernetes RBAC so service accounts cannot read other namespaces',
        detail:
          'The default ClusterRoleBinding for many controllers is broader than needed. Review every RoleBinding that grants list or get on secrets, and scope it to the namespace the workload actually serves.',
      },
      {
        priority: 'medium',
        action: 'Replace the aws-auth ConfigMap with the EKS access entry API',
        detail:
          'The aws-auth ConfigMap is not reconciled, so entries can drift from reality and cannot be audited with IAM. The access entry API gives every Kubernetes identity a mapped IAM role with its own permission boundary and tags.',
      },
      {
        priority: 'medium',
        action: 'Enable the Kubernetes audit log and export it to a central account',
        detail:
          'Secret enumeration, pod creation and exec are all invisible without it. This is the control that makes API abuse investigable after the fact.',
      },
      {
        priority: 'low',
        action: 'Apply admission control to reject privileged pods',
        detail:
          'A policy engine that rejects privileged containers, host mounts and host networking catches the escape attempt at admission rather than after the container is running.',
      },
    ],
  },
  checklist: [
    {
      id: 'eks-1',
      text: 'Confirm the node role cannot describe the cluster.',
      command:
        'aws eks describe-cluster --name my-cluster --query "cluster.endpoint" --no-cli-pager',
      expected:
        'AccessDenied when run with the node role. If it succeeds, the node role is one step closer to the API server than it should be.',
    },
    {
      id: 'eks-2',
      text: 'Check whether nodes require IMDSv2 with a hop limit of one.',
      command:
        'aws ec2 describe-instances --instance-ids i-0abc123 \\\n  --query "Reservations[0].Instances[0].MetadataOptions"',
      expected:
        'HttpTokens is required and HttpPutResponseHopLimit is 1 on every node.',
    },
    {
      id: 'eks-3',
      text: 'List every IRSA role and read its trust policy.',
      command:
        'aws iam list-roles --query "Roles[?contains(RoleName, \`eks\`) || contains(Tags[?Key==\`eks.amazonaws.com/role-service-account\`].Value, \`true\`)].Arn" --output text',
      expected:
        'Each trust policy names a specific service account in the subject condition.',
    },
    {
      id: 'eks-4',
      text: 'Confirm the Kubernetes audit log is enabled and receiving events.',
      command:
        'aws logs describe-log-groups --log-group-name-prefix /aws/eks --query "logGroups[].logGroupName"',
      expected:
        'A cluster log group exists for each cluster, with log types including audit.',
    },
    {
      id: 'eks-5',
      text: 'From a pod, confirm the instance metadata service is not reachable.',
      command:
        'curl -s --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      expected:
        'The request fails or returns nothing. A role name here means the hop limit is wrong.',
    },
    {
      id: 'eks-6',
      text: 'Review which service accounts can list secrets in each namespace.',
      command:
        'kubectl auth can-i list secrets --all-namespaces --as=system:serviceaccount:default:default',
      expected:
        'No for the default and other application service accounts. Only the controllers that need it may say yes.',
    },
    {
      id: 'eks-7',
      text: 'Confirm the cluster has no unused aws-auth ConfigMap entries.',
      command:
        'kubectl get configmap aws-auth -n kube-system -o yaml',
      expected:
        'The ConfigMap is empty or matches the access entry API exactly.',
    },
  ],
  references: [
    { label: 'EKS — IAM roles for service accounts', url: 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html' },
    { label: 'EKS — EKS Pod Identity', url: 'https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html' },
    { label: 'EKS — control plane audit log', url: 'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html' },
    { label: 'EKS — node IAM role', url: 'https://docs.aws.amazon.com/eks/latest/userguide/creating-node-iam-role.html' },
  ],
  updated: '2026-11-22',
}
