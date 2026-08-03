# AWS IAM Compliance Auditor with AI-Assisted Remediation

A serverless AWS pipeline that automatically audits IAM roles and policies for least-privilege violations, stores findings in S3, and (in progress) uses an LLM to summarize risk and draft remediation — all provisioned with Terraform.

## Status

🚧 In progress — Steps 1–4 complete and verified against a real AWS account. See [Build Log](#build-log).

## Architecture

```
EventBridge (nightly trigger)  [not yet wired up]
        │
        ▼
IAM Audit Lambda ──► scans IAM roles/policies for wildcard violations
        │
        ▼
S3 Findings Store ──► timestamped JSON compliance reports
        │
        ▼
AI Summarizer Lambda ──► calls LLM API to summarize risk + suggest fixes   [not yet built]
        │
        ▼
SNS ──► Slack / Email alert   [not yet built]
```

## Why this project

Most cloud portfolios have a "highly available web app" project. This one instead targets:
- **IAM least-privilege enforcement** — a real security/compliance problem, not a toy CRUD app.
- **AI-assisted operations** — using an LLM to turn raw audit output into a usable, human-readable remediation summary.

## What it currently detects

The audit Lambda flags IAM policy statements that grant **wildcard action AND wildcard resource on an `Allow` effect** (`"Action": "*"`, `"Resource": "*"`) — the highest-severity, clearest-cut least-privilege violation. `Deny` statements are intentionally never flagged, since a broad `Deny` is a safety guardrail, not a risk.

Each finding includes: `finding_id` (a stable hash of role + policy + statement, so the same violation can be tracked as "still open" across runs, not re-reported as new every night), `role_name`, `role_arn`, `policy_name`, `policy_type` (`attached` or `inline`), `statement_sid`, `effect`, `action`, `resource`, `severity`, and `audit_timestamp`.

Run against a real AWS account, it correctly identified two IAM roles with `AdministratorAccess` attached — a genuine finding, not a synthetic test case.

## Tech Stack

| Layer | Tool |
|---|---|
| Infrastructure as Code | Terraform |
| Compute | AWS Lambda (Python 3.12) |
| Storage | Amazon S3 |
| Scheduling | Amazon EventBridge *(planned)* |
| Notifications | Amazon SNS *(planned)* |
| AI Summarization | LLM API *(planned)* |

## Prerequisites

- AWS account with an IAM user that has permissions to create IAM roles, Lambda functions, S3 buckets, EventBridge rules, and SNS topics
- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.5
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) installed and configured (`aws configure`)
- Python 3.12
- An Anthropic API key (or AWS Bedrock access) — needed for the summarizer step, not yet required

## Project Structure

```
iam-compliance-auditor/
├── terraform/
│   ├── main.tf          # provider, S3 bucket, versioning, public access block
│   ├── variables.tf     # aws_region, project_name
│   ├── iam.tf           # least-privilege IAM role + policy for the audit Lambda
│   └── lambda.tf         # archive_file packaging + aws_lambda_function
├── lambda/
│   ├── audit/
│   │   └── handler.py   # role discovery, policy inspection, violation detection, S3 write
│   └── summarizer/       # not yet built
├── README.md
└── .gitignore
```

## Setup

```bash
# 1. Clone and enter the project
git clone <your-repo-url>
cd iam-compliance-auditor/terraform

# 2. Configure AWS credentials
aws configure

# 3. Provision infrastructure
terraform init
terraform plan
terraform apply

# 4. Manually invoke the audit Lambda
aws lambda invoke --function-name iam-compliance-auditor-audit-lambda response.json
cat response.json

# 5. Check the findings report in S3
aws s3 ls s3://<your-findings-bucket>/reports/
```

## Notable design decisions

- **Read-only IAM role, deliberately.** The audit Lambda's IAM policy grants only list/get actions (`iam:ListRoles`, `iam:GetPolicy`, etc.) — no write or modify permissions. Detection and remediation are architecturally separate; this Lambda can never change a policy, only report on it.
- **Policy document caching.** Managed (attached) policies are fetched once per unique policy ARN and cached in memory for the life of the invocation, since many roles in a real account often share the same managed policy (e.g. `AdministratorAccess`). Avoids redundant `GetPolicyVersion` calls and reduces IAM API throttling risk at scale.
- **Timestamped S3 keys, not overwrites.** Every audit run writes a new `reports/<timestamp>.json` object, preserving history so compliance drift can be tracked over time instead of only ever seeing the latest snapshot.
- **Debugged a real least-privilege gap.** The first deployed invocation failed with `AccessDenied` on `iam:GetRolePolicy` — the Terraform policy had `ListRolePolicies` (list inline policy *names*) but not `GetRolePolicy` (fetch an inline policy's actual *document*), an easy gap to miss since local testing used broader personal AWS credentials that masked it. Fixed by adding the missing action once the deployed Lambda's own permissions surfaced the gap.

## Build Log

- [x] Step 1 — Project setup & AWS credentials check
- [x] Step 2 — Terraform: S3 bucket + least-privilege IAM role
- [x] Step 3 — Audit Lambda: role discovery, policy inspection, wildcard-violation detection, S3 write — verified end-to-end against a real AWS account
- [x] Step 4 — Packaged and deployed the audit Lambda via Terraform; diagnosed and fixed a real IAM permissions gap; confirmed successful invocation running entirely in AWS
- [ ] Step 5 — AI Summarizer Lambda
- [ ] Step 6 — Wire up EventBridge + SNS
- [ ] Step 7 — End-to-end test
- [ ] Step 8 — Cleanup & final documentation
