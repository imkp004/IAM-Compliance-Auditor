import json
import boto3

s3 = boto3.client("s3")
bedrock = boto3.client("bedrock-runtime")

MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


def get_report_from_s3(bucket: str, key: str) -> dict:
    """
    Fetch and parse an audit report JSON object from S3.
    """
    response = s3.get_object(Bucket=bucket, Key=key)
    body = response["Body"].read().decode("utf-8")
    return json.loads(body)


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


def lambda_handler(event, context):
    bucket = event["bucket"]
    key = event["key"]

    report = get_report_from_s3(bucket, key)
    summary = summarize_findings(report["findings"])
    summary_key = write_summary_to_s3(summary, bucket, report["audit_timestamp"])

    return {
        "finding_count": report["finding_count"],
        "summary": summary,
        "summary_s3_key": summary_key,
    }
    
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