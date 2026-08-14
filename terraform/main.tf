terraform {
  required_version = "~>1.15.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~>6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "bucket" {
  bucket = "${var.project_name}-${data.aws_caller_identity.current.id}"
}


resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_lambda_function" "audit_lambda" {
  function_name    = "${var.project_name}-audit-lambda"
  role             = aws_iam_role.audit_lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.audit_lambda_zip.output_path
  source_code_hash = data.archive_file.audit_lambda_zip.output_base64sha256

  environment {
    variables = {
      FINDINGS_BUCKET_NAME = aws_s3_bucket.bucket.bucket
    }
  }
}

data "archive_file" "audit_lambda_zip" {
  type        = "zip"
  source_file = "../lambda/audit/handler.py"
  output_path = "${path.module}/audit_lambda.zip"
}

data "archive_file" "summarizer_lambda_zip" {
  type        = "zip"
  source_file = "../lambda/summarizer/handler.py"
  output_path = "${path.module}/summarizer_lambda.zip"
}

resource "aws_lambda_function" "summarizer_lambda" {
  function_name    = "${var.project_name}-summarizer-lambda"
  role             = aws_iam_role.summarizer_lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.summarizer_lambda_zip.output_path
  source_code_hash = data.archive_file.summarizer_lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.findings_alerts.arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "nightly_audit" {
  name                = "${var.project_name}-nightly-audit"
  description         = "Triggers the IAM audit Lambda once per day"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "nightly_audit_target" {
  rule      = aws_cloudwatch_event_rule.nightly_audit.name
  target_id = "audit-lambda"
  arn       = aws_lambda_function.audit_lambda.arn
}

resource "aws_lambda_permission" "allow_eventbridge_audit" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.nightly_audit.arn
}


resource "aws_lambda_permission" "allow_s3_invoke_summarizer" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.summarizer_lambda.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.bucket.arn
}

resource "aws_s3_bucket_notification" "report_created" {
  bucket = aws_s3_bucket.bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.summarizer_lambda.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "reports/"
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke_summarizer]
}


resource "aws_sns_topic" "findings_alerts" {
  name = "${var.project_name}-findings-alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.findings_alerts.arn
  protocol  = "email"
  endpoint  = "imkp004@gmail.com" # replace with your real email
}