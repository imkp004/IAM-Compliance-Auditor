# AWS IAM Compliance Auditor with AI-Assisted Remediation

A serverless AWS pipeline that automatically audits IAM roles and policies for least-privilege violations, stores findings in S3, and uses Claude (via Amazon Bedrock) to summarize risk and draft remediation — all provisioned with Terraform.

## Status

🚧 In progress — Steps 1–5 complete and verified against a real AWS account. See [Build Log](#build-log).

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
AI Summarizer Lambda ──► Claude (via Amazon Bedrock) drafts risk summary + remediation
        │
        ▼
S3 Summaries Store ──► timestamped plain-text summaries
        │
        ▼
SNS ──► Slack / Email alert   [not yet built]
```

## Why this project

Most cloud portfolios have a "highly available web app" project. This one instead targets:
- **IAM least-privilege enforcement** — a real security/compliance problem, not a toy CRUD app.
- **AI-assisted operations** — using an LLM to turn raw audit output into a usable, human-readable remediation summary, with short alerts pointing to durable detail rather than dumping everything into a chat message.

## What it currently does

**Detection.** The audit Lambda flags IAM policy statements that grant **wildcard action AND wildcard resource on an `Allow` effect** (`"Action": "*"`, `"Resource": "*"`) — the highest-severity, clearest-cut least-privilege violation. `Deny` statements are intentionally never flagged, since a broad `Deny` is a safety guardrail, not a risk. Each finding includes a stable, deterministic `finding_id` (a hash of role + policy + statement) so the same violation can be tracked as "still open" across runs rather than re-reported as new every night.

**Interpretation.** The summarizer Lambda reads a report from S3, sends the findings to Claude Haiku via Amazon Bedrock, and returns a structured markdown risk summary with specific `aws iam` remediation commands per finding, a prioritized action table, and preventive-control recommendations. The summary is written to S3 as its own timestamped record, separate from the raw findings — detection and interpretation are two distinct, independently-testable pipeline stages.

Run against a real AWS account, it correctly identified two IAM roles with `AdministratorAccess` attached — a genuine finding, not a synthetic test case — and produced usable, specific remediation for each.

## Tech Stack

| Layer | Tool |
|---|---|
| Infrastructure as Code | Terraform |
| Compute | AWS Lambda (Python 3.12) |
| Storage | Amazon S3 |
| AI Summarization | Claude (Haiku 4.5) via Amazon Bedrock |
| Scheduling | Amazon EventBridge *(planned)* |
| Notifications | Amazon SNS *(planned)* |

## Prerequisites

- AWS account with an IAM user that has permissions to create IAM roles, Lambda functions, S3 buckets, EventBridge rules, and SNS topics
- AWS account with Bedrock Anthropic model use-case details already submitted (one-time, per-account requirement — see [Bedrock model access notes](#bedrock-model-access-notes))
- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.5
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) installed and configured (`aws configure`)
- Python 3.12

## Project Structure

```
iam-compliance-auditor/
├── terraform/
│   ├── main.tf          # provider, S3 bucket, versioning, public access block
│   ├── variables.tf     # aws_region, project_name
│   ├── iam.tf           # least-privilege IAM roles + policies for both Lambdas
│   └── lambda.tf        # archive_file packaging + both aws_lambda_function resources
├── lambda/
│   ├── audit/
│   │   └── handler.py   # role discovery, policy inspection, violation detection, S3 write
│   └── summarizer/
│       └── handler.py   # S3 read, Bedrock invocation, summary write to S3
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

# 5. Manually invoke the summarizer against a report from step 4
aws lambda invoke \
  --function-name iam-compliance-auditor-summarizer-lambda \
  --cli-binary-format raw-in-base64-out \
  --payload '{"bucket":"<your-bucket>","key":"reports/<timestamp>.json"}' \
  response.json
cat response.json
```

## Bedrock model access notes

Anthropic models on Bedrock require a one-time, per-account "use case details" form before first invocation — separate from standard model access, and not something Terraform can automate. If you see `ResourceNotFoundException: Model use case details have not been submitted for this account`, go to **Bedrock console → Model catalog → select an Anthropic model → Submit use case details**, fill out the short form, and retry after a few minutes.

Also note: some newer Claude models on Bedrock require invocation via an **inference profile** (a region-prefixed model ID, e.g. `us.anthropic.claude-haiku-4-5-20251001-v1:0`) rather than the raw model ID — invoking the base model ID directly returns a `ValidationException` telling you to use an inference profile instead.

## Notable design decisions

- **Read-only IAM role for the audit Lambda, deliberately.** Its policy grants only list/get actions — no write or modify permissions. Detection and remediation are architecturally separate; this Lambda can never change a policy, only report on it.
- **Separate, narrowly-scoped role for the summarizer Lambda.** Different job, different permissions — Bedrock invocation and S3 read/write, no IAM access at all. Same least-privilege discipline applied to a second, unrelated Lambda.
- **Policy document caching in the audit Lambda.** Managed (attached) policies are fetched once per unique policy ARN and cached in memory for the life of the invocation, since many roles in a real account often share the same managed policy (e.g. `AdministratorAccess`). Avoids redundant API calls and reduces IAM throttling risk at scale.
- **Timestamped S3 keys, not overwrites, for both reports and summaries.** Every run writes a new object, preserving history so compliance drift can be tracked over time.
- **Alerts are short; detail lives in S3.** Design choice made in Step 5 for the eventual SNS/Slack integration: an alert channel should say "N critical findings, see s3://.../summaries/&lt;timestamp&gt;.txt," not dump a full markdown report into chat. Alerting is for triage; S3 is for doing the actual work.
- **Debugged multiple real least-privilege gaps, deliberately left narrow rather than over-granting.** Each time a Lambda's code gained a new capability (e.g. the summarizer writing to S3 in addition to reading), the IAM policy needed a matching, explicit update — caught via real `AccessDenied`/`AccessDeniedException` errors on first deployed invocation, not by pre-emptively granting broad permissions to avoid the errors. Includes a genuine Bedrock-specific gotcha: `bedrock:InvokeModel` requires permission on both the inference profile ARN *and* the underlying foundation model ARN, not just one.

## Build Log

- [x] Step 1 — Project setup & AWS credentials check
- [x] Step 2 — Terraform: S3 bucket + least-privilege IAM role
- [x] Step 3 — Audit Lambda: role discovery, policy inspection, wildcard-violation detection, S3 write — verified end-to-end against a real AWS account
- [x] Step 4 — Packaged and deployed the audit Lambda via Terraform; diagnosed and fixed a real IAM permissions gap; confirmed successful invocation running entirely in AWS
- [x] Step 5 — AI Summarizer Lambda: S3 read, Claude via Bedrock, summary written back to S3; deployed via Terraform; diagnosed and fixed two real permission gaps (Bedrock dual-ARN requirement, missing S3 write permission) using AWS's live IAM state as ground truth
- [ ] Step 6 — Wire up EventBridge + SNS
- [ ] Step 7 — End-to-end test
- [ ] Step 8 — Cleanup & final documentation
