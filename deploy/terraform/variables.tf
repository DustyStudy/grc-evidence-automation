variable "name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "grc-evidence"
}

variable "lambda_zip_path" {
  description = "Path to the deployment package built by scripts/build_lambda.py."
  type        = string
}

variable "schedule_expression" {
  description = "EventBridge schedule for evidence collection."
  type        = string
  default     = "cron(0 6 * * ? *)"
}

variable "reserved_concurrent_executions" {
  description = <<-EOT
    Caps how many invocations of the collector can run at once; overlapping runs would
    produce duplicate evidence, so this defaults to 1. Set to -1 (the AWS provider's
    own "unreserved" sentinel; see its docs for aws_lambda_function) to leave the
    function's concurrency unreserved instead. Needed in an account whose Lambda
    concurrent-execution quota is at or near the AWS-wide floor of 10 -- new and
    sandbox accounts commonly start there -- where *any* positive reservation fails
    apply with "decreases account's UnreservedConcurrentExecution below its minimum
    value of [10]". A sane schedule_expression period is, on its own, enough to avoid
    overlap in that case. Do not set this to 0: that disables the function entirely.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.reserved_concurrent_executions != 0
    error_message = "0 disables the function entirely (it can never run). Use -1 for unreserved concurrency."
  }
}

variable "use_fips_endpoint" {
  description = "Make the collector Lambda call FIPS 140 validated AWS endpoints (sets use_fips_endpoint in its config). Overrides any value in collector_config."
  type        = bool
  default     = true
}

variable "collector_config" {
  description = <<-EOT
    Collector configuration (same schema as the YAML config file, minus `sinks`):
    accounts, regions, collectors, parameters, gcp. The S3 evidence bucket created
    by this module is always added as a sink.
  EOT
  type        = any
  default     = {}
}

variable "extra_sinks" {
  description = "Additional sinks, e.g. an http ingestion endpoint. Reference secrets as secretsmanager:<name>, never as literals."
  type        = list(any)
  default     = []

  validation {
    condition = alltrue(flatten([
      for sink in var.extra_sinks : [
        for key in ["token", "client_secret"] :
        try(sink.auth[key], null) == null || can(regex("^(env|secretsmanager|ssm):", sink.auth[key]))
      ]
    ]))
    error_message = "An extra_sinks auth.token or auth.client_secret is a literal. Use a reference starting with env:, secretsmanager: or ssm: so the secret stays out of Terraform state and the Lambda configuration."
  }
}

variable "enable_signing" {
  description = <<-EOT
    Create an asymmetric KMS key (ECC_NIST_P256) and sign each run manifest with it
    (kms:Sign, ECDSA_SHA_256 over the digest). Asymmetric keys cannot be rotated
    automatically; rotate by creating a new key and keeping the old one to verify older runs.
  EOT
  type        = bool
  default     = true
}

variable "target_role_arns" {
  description = "Roles in member accounts (see ./reader_role) that the function may assume."
  type        = list(string)
  default     = []
}

variable "secret_arns" {
  description = "Secrets Manager ARNs the function may read (for http sink credentials)."
  type        = list(string)
  default     = []
  sensitive   = true
}

variable "ssm_parameter_arns" {
  description = "SSM Parameter Store parameter ARNs the function may read (ssm:GetParameter), for sink auth references of the form ssm:/path."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.ssm_parameter_arns : startswith(arn, "arn:")])
    error_message = "Each ssm_parameter_arns entry must be a full ARN (starting with \"arn:\")."
  }
}

variable "ssm_kms_key_arns" {
  description = "Customer-managed KMS key ARNs the function may use to decrypt (kms:Decrypt) SecureString parameters listed in ssm_parameter_arns, for sink auth references. Not needed for parameters encrypted with the AWS-managed aws/ssm key."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.ssm_kms_key_arns : startswith(arn, "arn:")])
    error_message = "Each ssm_kms_key_arns entry must be a full ARN (starting with \"arn:\")."
  }
}

variable "auditor_principal_arns" {
  description = "IAM principal ARNs (roles, users or an account root) that may read evidence objects (s3:GetObject and s3:ListBucket under evidence/, kms:Decrypt through S3) and verify run signatures (kms:Verify, kms:GetPublicKey). Empty adds no statements."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.auditor_principal_arns : startswith(arn, "arn:")])
    error_message = "Each auditor_principal_arns entry must be a full ARN (starting with \"arn:\")."
  }
}

variable "evidence_expiration_days" {
  description = "Days before evidence objects expire. Align with your audit-period and retention policy."
  type        = number
  default     = 730
}

variable "object_lock_days" {
  description = "Required, no default. If > 0, create the bucket with S3 Object Lock and apply this default retention in days. 0 is an explicit opt-out (no Object Lock). Cannot be enabled on an existing bucket."
  type        = number

  validation {
    condition     = var.object_lock_days >= 0 && floor(var.object_lock_days) == var.object_lock_days
    error_message = "object_lock_days must be a whole number >= 0 (0 disables Object Lock)."
  }
}

variable "object_lock_mode" {
  description = "Object Lock retention mode. COMPLIANCE (the default): retention cannot be shortened or removed by anyone, including the account root user, until it expires. GOVERNANCE: can be bypassed by principals holding s3:BypassGovernanceRetention. Ignored when object_lock_days is 0."
  type        = string
  default     = "COMPLIANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the function."
  type        = number
  default     = 365
}

variable "alarm_actions" {
  description = "Required, no default. SNS topic ARNs notified when a run errors or no run starts within a day (either is a gap in evidence). Pass [] explicitly to create the alarms with no notification."
  type        = list(string)
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
