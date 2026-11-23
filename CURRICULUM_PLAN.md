# CloudSec Atlas — curriculum plan

Five stages. Each stage has an outcome the reader should be able to state in their
own words. Stages are sequential: a topic's prerequisites are always in the same
or an earlier stage.

Stage ids: `foundation`, `operator`, `adversary`, `redteam`, `expert`

---

## AWS — 15 topics

| # | slug | stage | track | title |
|---|------|-------|-------|-------|
| 1 | aws/foundation/identity-and-trust | foundation | Identity & access | Identity and trust in AWS |
| 2 | aws/foundation/network-boundaries | foundation | Network | Network boundaries and the VPC |
| 3 | aws/foundation/regions-and-availability | foundation | Platform | Regions, availability zones and the blast radius |
| 4 | aws/operator/storage-and-data | operator | Storage | Storage and data exposure |
| 5 | aws/operator/compute-and-containers | operator | Compute | Compute, containers and serverless |
| 6 | aws/operator/logging-and-audit | operator | Observability | Logging and audit trails |
| 7 | aws/adversary/credential-discovery | adversary | Identity & access | Credential discovery and enumeration |
| 8 | aws/adversary/ec2-metadata-service | adversary | Compute | EC2 instance metadata and IMDSv1 |
| 9 | aws/adversary/serverless-attack-surface | adversary | Compute | Serverless attack surface |
| 10 | aws/adversary/iam-policy-evaluation | adversary | Identity & access | Evaluating IAM policies in practice |
| 11 | aws/adversary/assume-role-trust | adversary | Identity & access | Cross-account trust and AssumeRole |
| 12 | aws/redteam/iam-privilege-escalation | redteam | Identity & access | IAM privilege escalation *(already written — exemplar)* |
| 13 | aws/redteam/kubernetes-on-eks | redteam | Containers | Kubernetes on EKS |
| 14 | aws/redteam/attack-path-chaining | redteam | Operations | Chaining cloud weaknesses into a path |
| 15 | aws/expert/organizational-guardrails | expert | Platform | Guardrails that actually hold |
| 16 | aws/expert/cloudtrail-forensics | expert | Observability | CloudTrail forensics |
| 17 | aws/expert/multi-account-estate | expert | Platform | Securing a multi-account estate |

## Azure — 15 topics

| # | slug | stage | track | title |
|---|------|-------|-------|-------|
| 1 | azure/foundation/entra-id-and-tenants | foundation | Identity & access | Entra ID and the tenant |
| 2 | azure/foundation/resource-groups-and-subscription | foundation | Platform | Resource groups, subscriptions and management groups |
| 3 | azure/foundation/network-controls | foundation | Network | Azure networking and NSGs |
| 4 | azure/operator/storage-and-data | operator | Storage | Storage accounts and data exposure |
| 5 | azure/operator/compute-and-containers | operator | Compute | Azure compute, AKS and Functions |
| 6 | azure/operator/monitoring-and-diagnostics | operator | Observability | Azure Monitor, Activity log and Defender |
| 7 | azure/adversary/app-registrations-and-oauth | adversary | Identity & access | App registrations and OAuth consent |
| 8 | azure/adversary/managed-identities | adversary | Identity & access | Managed identities and their permissions |
| 9 | azure/adversary/imds-and-token-theft | adversary | Compute | IMDS and token theft |
| 10 | azure/adversary/role-assignment-escalation | adversary | Identity & access | Azure RBAC role assignment escalation |
| 11 | azure/redteam/azure-ad-privilege-escalation | redteam | Identity & access | Entra ID privilege escalation |
| 12 | azure/redteam/storage-account-takeover | redteam | Storage | Storage account takeover chains |
| 13 | azure/redteam/kubernetes-on-aks | redteam | Containers | Kubernetes on AKS |
| 14 | azure/redteam/attack-path-chaining | redteam | Operations | Chaining Azure weaknesses into a path |
| 15 | azure/expert/landing-zones-and-policy | expert | Platform | Landing zones and Azure Policy |
| 16 | azure/expert/entra-id-forensics | expert | Observability | Entra ID sign-in and audit forensics |
| 17 | azure/expert/multi-tenant-isolation | expert | Platform | Multi-tenant isolation and SaaS |

## GCP — 15 topics

| # | slug | stage | track | title |
|---|------|-------|-------|-------|
| 1 | gcp/foundation/identity-and-projects | foundation | Identity & access | Identity, projects and the resource hierarchy |
| 2 | gcp/foundation/network-boundaries | foundation | Network | VPC networks, firewall rules and Shared VPC |
| 3 | gcp/foundation/iam-model | foundation | Identity & access | The GCP IAM model |
| 4 | gcp/operator/storage-and-data | operator | Storage | Cloud Storage and data exposure |
| 5 | gcp/operator/compute-and-containers | operator | Compute | Compute Engine, GKE and Cloud Run |
| 6 | gcp/operator/audit-logs | operator | Observability | Cloud Audit Logs |
| 7 | gcp/adversary/service-account-credentials | adversary | Identity & access | Service account credentials |
| 8 | gcp/adversary/metadata-server | adversary | Compute | The GCE metadata server |
| 9 | gcp/adversary/iam-privilege-escalation | adversary | Identity & access | GCP IAM privilege escalation |
| 10 | gcp/adversary/oauth-and-api-scopes | adversary | Identity & access | OAuth scopes and service account impersonation |
| 11 | gcp/redteam/kubernetes-on-gke | redteam | Containers | Kubernetes on GKE |
| 12 | gcp/redteam/public-bucket-to-org | redteam | Storage | Public bucket to organisation compromise |
| 13 | gcp/redteam/attack-path-chaining | redteam | Operations | Chaining GCP weaknesses into a path |
| 14 | gcp/expert/organization-policy | expert | Platform | Organization Policy and folder controls |
| 15 | gcp/expert/audit-log-forensics | expert | Observability | Cloud Audit Log forensics |
| 16 | gcp/expert/workload-identity | expert | Platform | Workload Identity Federation |

**Total: 49 topics.** The exemplar (aws/redteam/iam-privilege-escalation) already
exists — do not rewrite it.
