locals {
  # Read-only actions the AWS collectors use. `grc-evidence permissions` prints the same
  # list from the collector definitions; tests/test_terraform_consistency.py keeps them in sync.
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
    sid = "EncryptEvidence"
    # GenerateDataKey: SSE-KMS PutObject. Decrypt: reading the previous manifest and GRC_CONFIG.
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.evidence.arn]
  }

  statement {
    sid       = "ReadOwnAccountConfiguration"
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

  dynamic "statement" {
    for_each = length(var.ssm_parameter_arns) > 0 ? [1] : []

    content {
      sid       = "ReadSinkParameters"
      actions   = ["ssm:GetParameter"]
      resources = var.ssm_parameter_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.ssm_kms_key_arns) > 0 ? [1] : []

    content {
      sid       = "DecryptSinkParameters"
      actions   = ["kms:Decrypt"]
      resources = var.ssm_kms_key_arns
    }
  }
}

resource "aws_iam_role_policy" "function" {
  name   = "evidence-collection"
  role   = aws_iam_role.function.id
  policy = data.aws_iam_policy_document.function.json
}
