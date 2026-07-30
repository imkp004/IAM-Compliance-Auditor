# Import Python's built-in logging module so we can write logs
# to CloudWatch in a cleaner way than using print().
import logging
import json
import os
import hashlib
from datetime import datetime, timezone

# Import the AWS SDK for Python so this Lambda can call IAM/S3 APIs.
import boto3


# Get the root logger instance.
# In Lambda, AWS already configures logging handlers for you.
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Create clients once at module level, reused across warm invocations.
iam = boto3.client("iam")
s3 = boto3.client("s3")

# Cache of policy ARN -> policy document, so we never fetch the same
# managed policy's document twice in one run, even if many roles share it.
_policy_document_cache: dict[str, dict] = {}

# The S3 bucket findings get written to. Set as a Lambda environment
# variable in Terraform once we deploy this (see Step 4) — falls back
# to None for now so local testing doesn't require it to be set.
FINDINGS_BUCKET = os.environ.get("FINDINGS_BUCKET_NAME")


def _as_list(value):
    """
    Normalize a field so it is always returned as a list.

    IAM policy fields like Statement, Action, or Resource can appear
    either as a single object/string or as a list, depending on the
    policy shape. This helper makes later logic simpler.
    """
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def find_wildcard_violations(policy_document: dict) -> list[dict]:
    """
    Return statements in a policy document that grant wildcard
    action AND wildcard resource on an Allow effect.

    We consider this a broad permission pattern because it means
    the statement allows all actions on all resources.
    """
    violations = []
    statements = _as_list(policy_document.get("Statement", []))

    for statement in statements:
        effect = statement.get("Effect")
        actions = _as_list(statement.get("Action", []))
        resources = _as_list(statement.get("Resource", []))

        is_wildcard_violation = (
            effect == "Allow"
            and "*" in actions
            and "*" in resources
        )

        if is_wildcard_violation:
            violations.append({
                "Sid": statement.get("Sid", "NO_SID"),
                "Action": actions,
                "Resource": resources,
                "Effect": effect,
            })

    return violations


def get_all_roles() -> list[dict]:
    """
    Fetch all IAM roles in the current AWS account.
    Handles pagination since list_roles caps results per page.
    """
    roles = []
    paginator = iam.get_paginator("list_roles")

    for page in paginator.paginate():
        for role in page.get("Roles", []):
            roles.append({
                "RoleName": role["RoleName"],
                "Arn": role["Arn"],
            })

    return roles


def get_attached_policies_for_role(role_name: str) -> list[dict]:
    """
    Return the managed policies attached to one IAM role
    (names + ARNs only — not the documents yet).
    """
    policies = []
    paginator = iam.get_paginator("list_attached_role_policies")

    for page in paginator.paginate(RoleName=role_name):
        for policy in page.get("AttachedPolicies", []):
            policies.append({
                "PolicyName": policy["PolicyName"],
                "PolicyArn": policy["PolicyArn"],
            })

    return policies


def get_policy_document(policy_arn: str) -> dict:
    """
    Return the JSON policy document for a managed policy ARN.

    Uses a module-level cache so the same policy is never
    fetched twice in one Lambda invocation, even if many
    roles share it.
    """
    if policy_arn in _policy_document_cache:
        return _policy_document_cache[policy_arn]

    policy_meta = iam.get_policy(PolicyArn=policy_arn)
    version_id = policy_meta["Policy"]["DefaultVersionId"]

    version = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id,
    )
    document = version["PolicyVersion"]["Document"]

    _policy_document_cache[policy_arn] = document
    return document


def get_inline_policies_for_role(role_name: str) -> list[dict]:
    """
    Return inline policies embedded directly in one IAM role,
    including their documents.

    No caching is needed here because inline policies belong
    to one role only and are not shared across roles.
    """
    policies = []
    paginator = iam.get_paginator("list_role_policies")

    for page in paginator.paginate(RoleName=role_name):
        for policy_name in page.get("PolicyNames", []):
            result = iam.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )
            policies.append({
                "PolicyName": policy_name,
                "Document": result["PolicyDocument"],
            })

    return policies


def _make_finding_id(role_arn: str, policy_name: str, sid: str) -> str:
    """
    Build a stable, deterministic ID for a finding.

    Same role + policy + statement Sid will always hash to the same
    ID across separate audit runs. This is what lets us later tell
    'this is the same open violation as last night' apart from
    'this is a brand-new violation,' by comparing IDs across reports.
    """
    raw = f"{role_arn}|{policy_name}|{sid}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def audit_role(role: dict, audit_timestamp: str) -> list[dict]:
    """
    Run all policy checks for a single role and return a list of
    fully-structured findings (not just raw statement matches).

    This is where a raw violation (Sid/Action/Resource/Effect) gets
    combined with 'where did this come from' context (role, policy,
    timestamp, severity) to become a usable finding record.
    """
    findings = []
    role_name = role["RoleName"]
    role_arn = role["Arn"]

    # Check attached (managed) policies.
    for attached in get_attached_policies_for_role(role_name):
        document = get_policy_document(attached["PolicyArn"])
        violations = find_wildcard_violations(document)

        for v in violations:
            findings.append({
                "finding_id": _make_finding_id(role_arn, attached["PolicyName"], v["Sid"]),
                "role_name": role_name,
                "role_arn": role_arn,
                "policy_name": attached["PolicyName"],
                "policy_type": "attached",
                "statement_sid": v["Sid"],
                "effect": v["Effect"],
                "action": v["Action"],
                "resource": v["Resource"],
                "severity": "CRITICAL",
                "audit_timestamp": audit_timestamp,
            })

    # Check inline policies.
    for inline in get_inline_policies_for_role(role_name):
        violations = find_wildcard_violations(inline["Document"])

        for v in violations:
            findings.append({
                "finding_id": _make_finding_id(role_arn, inline["PolicyName"], v["Sid"]),
                "role_name": role_name,
                "role_arn": role_arn,
                "policy_name": inline["PolicyName"],
                "policy_type": "inline",
                "statement_sid": v["Sid"],
                "effect": v["Effect"],
                "action": v["Action"],
                "resource": v["Resource"],
                "severity": "CRITICAL",
                "audit_timestamp": audit_timestamp,
            })

    return findings


def run_audit() -> dict:
    """
    Orchestrate the full audit: discover every role, check every
    role's policies, and collect all findings into one report.
    """
    audit_timestamp = datetime.now(timezone.utc).isoformat()
    roles = get_all_roles()
    logger.info("Discovered %d IAM roles", len(roles))

    all_findings = []
    for role in roles:
        all_findings.extend(audit_role(role, audit_timestamp))

    logger.info("Audit complete: %d findings across %d roles", len(all_findings), len(roles))

    return {
        "audit_timestamp": audit_timestamp,
        "roles_scanned": len(roles),
        "finding_count": len(all_findings),
        "findings": all_findings,
    }


def write_report_to_s3(report: dict) -> str:
    """
    Write the audit report to S3 as a timestamped JSON object,
    so each run is preserved separately and builds an audit history.
    """
    if not FINDINGS_BUCKET:
        raise RuntimeError(
            "FINDINGS_BUCKET_NAME environment variable is not set. "
            "This must be configured on the Lambda before it can write reports."
        )

    # e.g. reports/2026-07-30T14-22-01Z.json
    safe_ts = report["audit_timestamp"].replace(":", "-")
    key = f"reports/{safe_ts}.json"

    s3.put_object(
        Bucket=FINDINGS_BUCKET,
        Key=key,
        Body=json.dumps(report, indent=2),
        ContentType="application/json",
    )

    logger.info("Report written to s3://%s/%s", FINDINGS_BUCKET, key)
    return key


def lambda_handler(event, context):
    """
    Lambda entry point. AWS invokes this function when the Lambda runs.
    Runs the full audit and writes the report to S3.
    """
    report = run_audit()
    s3_key = write_report_to_s3(report)

    return {
        "finding_count": report["finding_count"],
        "roles_scanned": report["roles_scanned"],
        "s3_key": s3_key,
    }


if __name__ == "__main__":
    # Local sanity test: run the full audit and print it,
    # WITHOUT writing to S3 (since FINDINGS_BUCKET_NAME likely
    # isn't set in your local shell yet).
    report = run_audit()
    print(json.dumps(report, indent=2))

    # Prove find_wildcard_violations actually catches something,
    # using a hand-written statement that should always match.
    fake_bad_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "TooBroad", "Effect": "Allow", "Action": "*", "Resource": "*"}
        ]
    }
    print("\nFake bad policy test (should show 1 violation):")
    print(json.dumps(find_wildcard_violations(fake_bad_policy), indent=2))