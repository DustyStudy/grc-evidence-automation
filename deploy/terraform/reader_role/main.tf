terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

variable "trusted_role_arn" {
  description = "ARN of the collector function role (output `function_role_arn` of the parent module)."
  type        = string
}

variable "external_id" {
  description = "ExternalId required to assume this role (confused-deputy protection). Must match `external_id` in the collector config."
  type        = string

  validation {
    condition     = length(var.external_id) >= 16
    error_message = "external_id must be at least 16 characters."
  }
}

variable "role_name" {
  description = "Name of the read-only role created in this account."
  type        = string
  default     = "GrcEvidenceReader"
}

variable "tags" {
  description = "Tags applied to the role."
  type        = map(string)
  default     = {}
}

locals {
  # Keep in sync with ../iam.tf (enforced by tests/test_terraform_consistency.py).
  collector_read_actions = [
    "backup:ListBackupPlans",
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    "config:DescribeConfigurationRecorderStatus",
    "config:DescribeConfigurationRecorders",
    "ec2:DescribeFlowLogs",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeVpcs",
    "ec2:GetEbsEncryptionByDefault",
    "guardduty:GetDetector",
    "guardduty:ListDetectors",
    "iam:GenerateCredentialReport",
    "iam:GetAccountPasswordPolicy",
    "iam:GetAccountSummary",
    "iam:GetCredentialReport",
    "iam:ListEntitiesForPolicy",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "kms:ListKeys",
    "rds:DescribeDBInstances",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:ListAllMyBuckets",
    "securityhub:DescribeHub",
    "sts:GetCallerIdentity",
  ]
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.trusted_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

data "aws_iam_policy_document" "read" {
  statement {
    sid       = "ReadOnlyEvidenceCollection"
    actions   = local.collector_read_actions
    resources = ["*"]
  }
}

resource "aws_iam_role" "reader" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy" "read" {
  name   = "evidence-read-only"
  role   = aws_iam_role.reader.id
  policy = data.aws_iam_policy_document.read.json
}

output "role_arn" {
  description = "Add this to `target_role_arns` in the parent module and to the collector config `accounts`."
  value       = aws_iam_role.reader.arn
}
