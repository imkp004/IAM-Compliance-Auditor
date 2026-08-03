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