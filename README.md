# AWS IAM Compliance Auditor with AI-Assisted Remediation

A fully automated, serverless AWS pipeline that audits IAM roles and policies for least-privilege violations, stores findings in S3, uses Claude (via Amazon Bedrock) to summarize risk and draft remediation, and alerts via email — all provisioned with Terraform, running end-to-end with no manual intervention.

## Status

✅ Complete. The pipeline runs on an unattended daily schedule — confirmed by a real EventBridge-triggered run that produced a matching report + summary and delivered an email alert with no manual invocation. See [Build Log](#build-log).

## Architecture

```
EventBridge (daily schedule)
        │
        ▼
IAM Audit Lambda ──► scans IAM roles/policies for wildcard violations
        │
        ▼
S3 Findings Store ──► timestamped JSON compliance reports
        │
        ▼ (S3 event notification, auto-triggered)
AI Summarizer Lambda ──► Claude (via Amazon Bedrock) drafts risk summary + remediation
        │
        ├──► S3 Summaries Store ──► timestamped plain-text summaries
        │
        └──► SNS ──► Email alert
```

## Why this project

Most cloud portfolios have a "highly available web app" project. This one instead targets:
- **IAM least-privilege enforcement** — a real security/compliance problem, not a toy CRUD app.
- **AI-assisted operations** — using an LLM to turn raw audit output into a usable, human-readable remediation summary, with short alerts pointing to durable detail rather than dumping everything into a notification.
- **A fully autonomous pipeline** — one scheduled trigger cascades through detection, interpretation, and alerting with zero manual steps.

## What it currently does

**Detection.** The audit Lambda flags IAM policy statements that grant **wildcard action AND wildcard resource on an `Allow` effect** (`"Action": "*"`, `"Resource": "*"`) — the highest-severity, clearest-cut least-privilege violation. `Deny` statements are intentionally never flagged. Each finding includes a stable, deterministic `finding_id` (a hash of role + policy + statement) so the same violation can be tracked as "still open" across runs.

**Interpretation.** The summarizer Lambda reads a report from S3, sends the findings to Claude Haiku via Amazon Bedrock, and returns a structured markdown risk summary with specific remediation commands per finding. The summary is written to S3 as its own timestamped record.

**Alerting.** After writing the summary, the summarizer publishes a short message to SNS — finding count and a pointer to the full S3 summary, not the full report itself — which delivers to a subscribed email address.

**Automation.** An EventBridge rule triggers the audit Lambda on a schedule. Writing a new report to S3 automatically triggers the summarizer via an S3 event notification — no manual chaining required.

## Tech Stack

| Layer | Tool |
|---|---|
| Infrastructure as Code | Terraform |
| Compute | AWS Lambda (Python 3.12) |
| Storage | Amazon S3 |
| AI Summarization | Claude (Haiku 4.5) via Amazon Bedrock |
| Scheduling | Amazon EventBridge |
| Event Chaining | S3 Event Notifications |
| Notifications | Amazon SNS (email) |

## Prerequisites

- AWS account with an IAM user that has permissions to create IAM roles, Lambda functions, S3 buckets, EventBridge rules, and SNS topics
- AWS account with Bedrock Anthropic model use-case details already submitted (one-time, per-account requirement — see [Bedrock model access notes](#bedrock-model-access-notes))
- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.5
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) installed and configured (`aws configure`)
- Python 3.12
- A real email address for the SNS subscription (Terraform creates the subscription request; confirming it requires clicking the link AWS emails you)

## Project Structure

```
iam-compliance-auditor/
├── terraform/
│   ├── main.tf          # provider, S3 bucket, versioning, public access block
│   ├── variables.tf     # aws_region, project_name
│   ├── iam.tf           # least-privilege IAM roles + policies for both Lambdas
│   ├── lambda.tf        # archive_file packaging, both aws_lambda_function resources,
│   │                     # EventBridge rule/target, S3 bucket notification, Lambda permissions
│   └── sns.tf            # SNS topic + email subscription
├── lambda/
│   ├── audit/
│   │   └── handler.py   # role discovery, policy inspection, violation detection, S3 write
│   └── summarizer/
│       └── handler.py   # S3 read (with retry), Bedrock invocation, summary write, SNS publish
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

# 3. Set your alert email in sns.tf before applying
#    (edit the `endpoint` value in aws_sns_topic_subscription.email_alert)

# 4. Provision infrastructure
terraform init
terraform plan
terraform apply

# 5. Confirm the SNS email subscription (check your inbox, click the link)

# 6. Trigger the pipeline manually to verify, or just wait for the
#    scheduled EventBridge run
aws lambda invoke --function-name iam-compliance-auditor-audit-lambda response.json
cat response.json

# 7. Everything downstream (summarization, S3 write, email alert)
#    happens automatically within ~30 seconds
```

## Bedrock model access notes

Anthropic models on Bedrock require a one-time, per-account "use case details" form before first invocation. If you see `ResourceNotFoundException: Model use case details have not been submitted for this account`, go to **Bedrock console → Model catalog → select an Anthropic model → Submit use case details**, fill out the short form, and retry after a few minutes.

Some newer Claude models on Bedrock also require invocation via an **inference profile** (a region-prefixed model ID, e.g. `us.anthropic.claude-haiku-4-5-20251001-v1:0`) rather than the raw model ID.

## Notable design decisions & real bugs debugged

This project surfaced several genuine, non-obvious issues worth documenting — the debugging process is arguably more representative of real engineering work than the final code itself:

- **Least-privilege IAM, deliberately, for both Lambdas.** Each Lambda has its own narrowly-scoped role. Every time a Lambda's code gained a new capability, the IAM policy needed an explicit, matching update — never granted broadly "to be safe."
- **Bedrock's dual-ARN permission requirement.** `bedrock:InvokeModel` on an inference profile requires permission on *both* the inference profile ARN *and* the underlying foundation model ARN — granting only one produces a confusing `AccessDenied` that looks like a complete permissions failure.
- **`s3:ListBucket` vs. `s3:GetObject`/`s3:PutObject`.** Without `ListBucket` granted at the bucket level (not `/*`), S3 collapses both "object doesn't exist" and "you're not allowed to know" into the same generic `AccessDenied` — a deliberate security-through-ambiguity design in S3 itself, not a bug, but confusing to debug the first time.
- **S3 event notification keys are URL-encoded.** The root cause of a persistent `NoSuchKey` error that survived multiple retries: S3 event payloads URL-encode object keys, so a `+` in a timestamp-based key (from the UTC offset, e.g. `+00-00`) arrives encoded and must be decoded with `urllib.parse.unquote_plus` before use — otherwise every lookup fails, consistently, regardless of timing.
- **Infinite-loop prevention on S3 event triggers.** The S3 notification triggering the summarizer is filtered to `reports/*.json` only — without that filter, the summarizer writing its own `.txt` summary into the same bucket would re-trigger itself indefinitely.
- **Alerts are short; detail lives in S3.** The SNS message contains only a finding count and an S3 pointer, not the full report — alerting is for triage, S3 is for doing the actual work.
- **Ground-truth debugging over re-reading source files.** When a fix appeared not to take effect, the most reliable diagnostic was querying AWS's actual live state directly (`aws iam get-role-policy`, CloudWatch Logs) rather than re-reading local Terraform files repeatedly.

## Build Log

- [x] Step 1 — Project setup & AWS credentials check
- [x] Step 2 — Terraform: S3 bucket + least-privilege IAM role
- [x] Step 3 — Audit Lambda: role discovery, policy inspection, wildcard-violation detection, S3 write
- [x] Step 4 — Deployed the audit Lambda via Terraform; debugged a real least-privilege gap
- [x] Step 5 — AI Summarizer Lambda: Bedrock integration, summary written to S3; debugged Bedrock dual-ARN and S3 write permission gaps
- [x] Step 6 — Full automation: EventBridge nightly trigger, S3-triggered summarizer, SNS email alerts — debugged a race condition, an `s3:ListBucket` gap, and a URL-encoding bug in S3 event keys; confirmed a real alert email delivered end-to-end
- [x] Step 7 — Validated an unattended scheduled run: EventBridge fired on its own, produced a matching report + summary pair, and delivered an email alert with zero manual invocation
- [x] Step 8 — Cleanup: confirmed no stray S3 objects, confirmed the dummy overprivileged-role test fixture was fully removed, final documentation pass

## Project Summary

Built end-to-end: from an empty AWS account to a scheduled, self-triggering pipeline that detects real IAM security violations, explains them in plain English with an LLM, and alerts a human — without anyone touching it after deployment.

Along the way, this project involved deliberately scoping least-privilege IAM policies for two separate Lambda functions (rather than granting broad permissions to avoid friction), and debugging a series of real, non-obvious AWS issues as each one surfaced: an `iam:GetRolePolicy` gap only visible once running under the Lambda's own role, Bedrock's dual-ARN permission model, S3's `ListBucket`-vs-`GetObject` distinction, a genuine read-after-write race condition, and a URL-encoding bug in S3 event payloads that silently broke the automated trigger chain. Every fix was verified against AWS's actual live state — not just assumed correct because the Terraform file looked right.

## Possible Future Extensions

Not required for this project to be complete, but natural next steps if extended further:
- Additional violation checks beyond wildcard-wildcard (e.g. unused roles/credentials, missing MFA)
- A `terraform destroy`-based teardown script/CI job for full environment cleanup
- CI/CD (e.g. GitHub Actions) so `git push` triggers `terraform plan`/`apply` automatically, instead of running Terraform locally
