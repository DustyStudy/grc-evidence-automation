locals {
  # Read-only actions the AWS collectors use. `grc-evidence permissions` prints the same
  # list from the collector definitions; tests/test_terraform_consistency.py keeps them in sync.
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

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "function" {
  name               = "${var.name}-function"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "function" {
  statement {
    sid       = "WriteLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.function.arn}:*"]
  }

  statement {
    sid       = "WriteEvidence"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/evidence/*"]
  }

  statement {
    sid       = "EncryptEvidence"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt"]
    resources = [aws_kms_key.evidence.arn]
  }

  statement {
    sid       = "ReadOwnAccountConfiguration"
    actions   = local.collector_read_actions
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.target_role_arns) > 0 ? [1] : []

    content {
      sid       = "AssumeMemberAccountReaderRoles"
      actions   = ["sts:AssumeRole"]
      resources = var.target_role_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.secret_arns) > 0 ? [1] : []

    content {
      sid       = "ReadSinkSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = var.secret_arns
    }
  }
}

resource "aws_iam_role_policy" "function" {
  name   = "evidence-collection"
  role   = aws_iam_role.function.id
  policy = data.aws_iam_policy_document.function.json
}
