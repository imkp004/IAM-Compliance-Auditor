variable "aws_region" {
  description = "region in which the resource will be created"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "name of the project"
  type        = string
  default     = "iam-compliance-auditor"
}