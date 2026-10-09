# Infrastructure overview

Terraform lives in `infra/`. The `environments/dev` root module composes seven modules. Nothing was applied to a real AWS account while building this repository; the configuration is validated (`terraform validate`) and policy-scanned (Checkov), not deployed.

## Modules

| Module | Resources |
|---|---|
| `network` | VPC, 2 AZs, public/app/data subnets, IGW, one NAT gateway, S3 gateway endpoint, REJECT flow logs to CloudWatch, locked-down default security group. The data tier has no default route. |
| `storage` | S3 bucket (versioning, SSE-KMS with bucket key, public access blocked, TLS-only and encryption-required bucket policy, lifecycle for old versions) and the customer managed KMS key with rotation. |
| `database` | RDS PostgreSQL 16 on gp3, encrypted, TLS enforced, private, backups, deletion protection, Performance Insights, enhanced monitoring, **master password managed by RDS in Secrets Manager**. |
| `cache` (optional) | ElastiCache Redis 7 with at-rest and in-transit encryption and an AUTH token held in Secrets Manager. |
| `compute` | ECR (immutable tags, scan on push), application secrets, EC2 t4g.small (IMDSv2, encrypted EBS, no public IP, SSM only), ALB with TLS 1.3 policy and HTTP redirect, rule blocking `/metrics`, `/docs` and `/openapi.json`, least-privilege instance role, chained security groups. |
| `waf` (optional) | WAFv2 with the AWS common, known-bad-inputs and IP-reputation rule groups plus a per-IP rate rule; logging with the Authorization header redacted. |
| `observability` | SNS topic and CloudWatch alarms: ALB 5xx, unhealthy targets, EC2 status, RDS CPU and free storage. |

## Required AWS services

VPC (subnets, NAT, endpoints, flow logs), EC2, ELB (ALB), RDS, S3, KMS, Secrets Manager, ECR, IAM, CloudWatch (logs and alarms), SNS, Systems Manager (Session Manager and the AMI parameter), ACM (a certificate you provide). Optional: ElastiCache, WAFv2, Route 53 for the DNS record.

Prerequisites outside Terraform: an AWS account, an ACM certificate for the public host name, a place to keep Terraform state (S3 bucket with locking), and the application image pushed to ECR.

## Estimated monthly cost

Local development costs nothing and needs no account. The figures below are on-demand list prices for `us-east-1` as I know them, for a lightly used dev environment, 730 hours per month. Prices change; confirm with the [AWS Pricing Calculator](https://calculator.aws/) before relying on them.

| Item | Basis | USD / month |
|---|---|---|
| NAT gateway | $0.045/h, plus $0.045/GB processed | 32.9 |
| ALB | $0.0225/h plus about 1 LCU | 22.3 |
| Public IPv4 addresses | 3 (two for the ALB, one for NAT) at $0.005/h | 11.0 |
| EC2 t4g.small | $0.0168/h | 12.3 |
| EBS 20 GB gp3 | $0.08/GB | 1.6 |
| RDS db.t4g.micro, single AZ | $0.016/h | 11.7 |
| RDS storage 20 GB gp3 | $0.115/GB | 2.3 |
| S3, 100 GB stored | $0.023/GB, requests negligible | 2.5 |
| KMS customer managed key | $1 per key plus requests | 1.5 |
| Secrets Manager | 2 secrets at $0.40 | 0.8 |
| CloudWatch logs, alarms, flow logs | a few GB ingested, 5 alarms | 5.0 |
| ECR | under 1 GB | 0.1 |
| Data transfer out | first 100 GB free, then $0.09/GB | 0 to 5 |
| **Baseline total** | | **about 104** |
| ElastiCache cache.t4g.micro (optional) | $0.016/h | +11.7 |
| WAFv2 (optional) | ACL $5, 4 rules $4, $0.60 per million requests | +10 |
| RDS Multi-AZ (optional) | doubles instance and storage | +14 |

Where the money goes and how to cut it: the NAT gateway and the ALB account for about half the bill. A throwaway environment can place the instance in a public subnet with a locked-down security group and drop the NAT (saves about 33 USD), at the price of the private-subnet posture. Stopping the EC2 instance and RDS overnight, or destroying the stack between sessions, brings a demo down to a few dollars. Production hardening that adds cost: a second instance in the other AZ behind the same ALB, Multi-AZ RDS, one NAT per AZ, WAF, ElastiCache.

## Accepted risks in the reference deployment

Checkov flagged these; each is annotated next to the resource with its reason (`#checkov:skip=`).

| Finding | Why it is accepted here | What to do for production |
|---|---|---|
| No ALB access logs, no S3 server access logs | Each needs an extra log bucket; the application writes its own request and audit logs | Add log buckets, enable CloudTrail S3 data events |
| No cross-region replication, no S3 event notifications | Cost and no consumers | Decide per recovery objective |
| Log retention 30 days | Cost | 365 days for regulated data |
| WAF off by default | Fixed monthly cost | `enable_waf = true` |
| Single Redis node, no failover | Redis holds only counters and the refresh-token allowlist | Replica with automatic failover if forced re-login is unacceptable |
| App secret not on a rotation timer | Rotating the JWT secret signs everyone out | Rotate by runbook; prefer RS256 with key overlap |
| Single EC2 instance | Cost | Auto Scaling group across both AZs; the service is stateless |

## State and environments

The `backend "s3"` block in `environments/dev/versions.tf` is commented out so `terraform init -backend=false` works anywhere. Enable it with a state bucket (versioned, encrypted, `use_lockfile = true`) before the first shared apply. Add `staging` and `prod` directories next to `dev` that call the same modules with their own variables.
