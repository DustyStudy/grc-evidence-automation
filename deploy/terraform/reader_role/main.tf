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
  sensitive   = true

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
    "acm:ListCertificates",
    "apigateway:GET",
    "backup:ListBackupPlans",
    "cloudformation:ListResources",
    "cloudfront:ListDistributions",
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    "config:DescribeComplianceByConfigRule",
    "config:DescribeConfigRuleEvaluationStatus",
    "config:DescribeConfigRules",
    "config:DescribeConfigurationRecorderStatus",
    "config:DescribeConfigurationRecorders",
    "ec2:DescribeFlowLogs",
    "ec2:DescribeInstances",
    "ec2:DescribeRegions",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeVpcs",
    "ec2:GetEbsEncryptionByDefault",
    "ecr:DescribeRepositories",
    "ecr:GetRegistryScanningConfiguration",
    "eks:DescribeCluster",
    "eks:ListClusters",
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:GetLoadBalancerWebACL",
    "guardduty:GetDetector",
    "guardduty:ListDetectors",
    "iam:GenerateCredentialReport",
    "iam:GetAccountAuthorizationDetails",
    "iam:GetAccountPasswordPolicy",
    "iam:GetAccountSummary",
    "iam:GetCredentialReport",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "identitystore:DescribeGroup",
    "identitystore:DescribeUser",
    "inspector2:BatchGetAccountStatus",
    "inspector2:ListCoverage",
    "inspector2:ListFindingAggregations",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "kms:ListKeys",
    "lambda:GetAccountSettings",
    "rds:DescribeDBInstances",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:ListAllMyBuckets",
    "secretsmanager:ListSecrets",
    "securityhub:DescribeHub",
    "securityhub:DescribeStandards",
    "securityhub:GetEnabledStandards",
    "securityhub:GetFindings",
    "sso:DescribePermissionSet",
    "sso:GetInlinePolicyForPermissionSet",
    "sso:ListAccountAssignments",
    "sso:ListAccountsForProvisionedPermissionSet",
    "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
    "sso:ListInstances",
    "sso:ListManagedPoliciesInPermissionSet",
    "sso:ListPermissionSets",
    "sts:GetCallerIdentity",
    "wafv2:GetWebACL",
    "wafv2:GetWebACLForResource",
  ]
}

data "aws_partition" "current" {}

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
    actions   = setsubtract(local.collector_read_actions, ["apigateway:GET"])
    resources = ["*"]
  }

  # aws.waf_coverage calls GetRestApis and GetStages only. Region is "*" because the
  # collector runs in every configured region.
  statement {
    sid     = "ReadRestApiStages"
    actions = ["apigateway:GET"]
    resources = [
      "arn:${data.aws_partition.current.partition}:apigateway:*::/restapis",
      "arn:${data.aws_partition.current.partition}:apigateway:*::/restapis/*/stages",
    ]
  }

  # Defence in depth: the allow above no longer reaches API keys, but an explicit deny also
  # holds if another policy on this role grants apigateway:GET more widely.
  statement {
    sid     = "DenyApiKeyValues"
    effect  = "Deny"
    actions = ["apigateway:GET"]
    resources = [
      "arn:${data.aws_partition.current.partition}:apigateway:*::/apikeys",
      "arn:${data.aws_partition.current.partition}:apigateway:*::/apikeys/*",
      "arn:${data.aws_partition.current.partition}:apigateway:*::/usageplans/*/keys",
      "arn:${data.aws_partition.current.partition}:apigateway:*::/usageplans/*/keys/*",
    ]
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
