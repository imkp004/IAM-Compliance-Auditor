# AWS IAM Compliance Auditor with AI-Assisted Remediation

A serverless AWS pipeline that automatically audits IAM roles and policies for least-privilege violations, stores findings, uses an LLM to summarize risk and draft remediation, and alerts the team — all provisioned with Terraform.

## Status

🚧 In progress — being built step by step. See [Build Log](#build-log) below for progress.

## Architecture

```
EventBridge (nightly trigger)
        │
        ▼
IAM Audit Lambda ──► scans IAM roles/policies for violations
        │
        ▼
S3 Findings Store ──► JSON compliance reports
        │
        ▼
AI Summarizer Lambda ──► calls LLM API to summarize risk + suggest fixes
        │
        ▼
SNS ──► Slack / Email alert
```

## Why this project

Most cloud portfolios have a "highly available web app" project. This one instead targets:
- **IAM least-privilege enforcement** — a real security/compliance problem, not a toy CRUD app.
- **AI-assisted operations** — using an LLM to turn raw audit output into a usable, human-readable remediation summary.

## Tech Stack

| Layer | Tool |
|---|---|
| Infrastructure as Code | Terraform |
| Compute | AWS Lambda (Python) |
| Storage | Amazon S3 |
| Scheduling | Amazon EventBridge |
| Notifications | Amazon SNS |
| AI Summarization | LLM API (Anthropic API or AWS Bedrock) |

## Prerequisites

- AWS account with an IAM user that has permissions to create IAM roles, Lambda functions, S3 buckets, EventBridge rules, and SNS topics
- [Terraform](https://developer.hashicorp.com/terraform/downloads) installed locally
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) installed and configured (`aws configure`)
- Python 3.11+
- An Anthropic API key (or AWS Bedrock access) for the summarizer step

## Project Structure

```
iam-compliance-auditor/
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── iam.tf
├── lambda/
│   ├── audit/
│   │   └── handler.py
│   └── summarizer/
│       └── handler.py
├── README.md
└── .gitignore
```

## Setup

_(Filled in as each step is completed — see Build Log.)_

## Build Log

- [ ] Step 1 — Project setup & AWS credentials check
- [ ] Step 2 — Terraform: S3 bucket + least-privilege IAM roles
- [ ] Step 3 — Audit Lambda: scan IAM roles/policies
- [ ] Step 4 — Deploy & test audit Lambda
- [ ] Step 5 — AI Summarizer Lambda
- [ ] Step 6 — Wire up EventBridge + SNS
- [ ] Step 7 — End-to-end test
- [ ] Step 8 — Cleanup & final documentation
