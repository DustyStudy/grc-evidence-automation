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
}

variable "evidence_expiration_days" {
  description = "Days before evidence objects expire. Align with your audit-period and retention policy."
  type        = number
  default     = 730
}

variable "object_lock_days" {
  description = "If > 0, create the bucket with S3 Object Lock and apply this default retention. Cannot be enabled on an existing bucket."
  type        = number
  default     = 0
}

variable "object_lock_mode" {
  description = "GOVERNANCE (can be bypassed with special permission) or COMPLIANCE (cannot be shortened or removed by anyone)."
  type        = string
  default     = "GOVERNANCE"

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
  description = "SNS topic ARNs notified when the function errors (a failed run means a gap in evidence)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
