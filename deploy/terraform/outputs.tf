output "evidence_bucket" {
  description = "Bucket that receives evidence."
  value       = aws_s3_bucket.evidence.id
}

output "kms_key_arn" {
  description = "Key encrypting the evidence bucket and logs."
  value       = aws_kms_key.evidence.arn
}

output "function_name" {
  description = "Collector Lambda function name (invoke manually with {\"dry_run\": true} to test)."
  value       = aws_lambda_function.collector.function_name
}

output "function_role_arn" {
  description = "Trust this role from each member account's reader role (see ./reader_role)."
  value       = aws_iam_role.function.arn
}
