import json
import os
import time
from urllib.parse import unquote_plus

import boto3

s3 = boto3.client("s3")
bedrock = boto3.client("bedrock-runtime")
sns = boto3.client("sns")

MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")


def get_report_from_s3(bucket: str, key: str, retries: int = 3, delay: float = 1.0) -> dict:
    """
    Fetch and parse an audit report JSON object from S3.
    Retries briefly to handle rare read-after-write timing races
    when triggered immediately by an S3 event notification.
    """
    for attempt in range(retries):
        try:
            response = s3.get_object(Bucket=bucket, Key=key)
            body = response["Body"].read().decode("utf-8")
            return json.loads(body)
        except s3.exceptions.NoSuchKey:
            if attempt == retries - 1:
                raise
            time.sleep(delay)


def summarize_findings(findings: list[dict]) -> str:
    """
    Send audit findings to Claude via Bedrock and return a
    plain-English risk summary with remediation suggestions.
    """
    prompt = (
        "You are a cloud security analyst. Given the following IAM "
        "audit findings (JSON), write a concise risk summary and "
        "specific remediation steps for each finding.\n\n"
        f"{json.dumps(findings, indent=2)}"
    )

    response = bedrock.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        }),
    )

    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


def write_summary_to_s3(summary: str, bucket: str, audit_timestamp: str) -> str:
    """
    Write the AI-generated summary to S3 as a text file, using the
    same timestamp as the original report so the two can be linked.
    """
    safe_ts = audit_timestamp.replace(":", "-")
    key = f"summaries/{safe_ts}.txt"

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=summary,
        ContentType="text/plain",
    )

    return key


def publish_alert(bucket: str, summary_key: str, finding_count: int) -> None:
    """
    Publish a short alert to SNS pointing at the full summary in S3,
    rather than dumping the full report into the notification itself.
    """
    if not SNS_TOPIC_ARN:
        return  # allows local/manual testing without SNS configured

    message = (
        f"IAM Compliance Audit: {finding_count} finding(s) detected.\n"
        f"Full summary: s3://{bucket}/{summary_key}"
    )

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="IAM Compliance Audit Results",
        Message=message,
    )


def lambda_handler(event, context):
    """
    Lambda entry point. Supports two trigger shapes:
    - Manual/test invoke: {"bucket": ..., "key": ...}
    - S3 event notification: {"Records": [{"s3": {"bucket": {...}, "object": {...}}}]}
      Note: S3 event keys are URL-encoded (e.g. "+" becomes a literal plus
      sign meaning space), so they must be decoded with unquote_plus
      before use, or lookups will fail with NoSuchKey.
    """
    if "Records" in event:
        record = event["Records"][0]["s3"]
        bucket = record["bucket"]["name"]
        key = unquote_plus(record["object"]["key"])
    else:
        bucket = event["bucket"]
        key = event["key"]

    report = get_report_from_s3(bucket, key)
    summary = summarize_findings(report["findings"])
    summary_key = write_summary_to_s3(summary, bucket, report["audit_timestamp"])
    publish_alert(bucket, summary_key, report["finding_count"])

    return {
        "finding_count": report["finding_count"],
        "summary": summary,
        "summary_s3_key": summary_key,
    }