# Terraform: scheduled evidence collector

Deploys the Lambda, EventBridge schedule, KMS-encrypted evidence bucket, least-privilege IAM and an error alarm. Requires Terraform >= 1.6 and AWS provider 6.x.

```bash
python ../../scripts/build_lambda.py     # from this directory; creates ../../dist/grc-evidence-lambda.zip
```

See the root [README](../../README.md#deploy) for a module call. Key inputs:

| Variable | Purpose |
|---|---|
| `lambda_zip_path` | Package from `scripts/build_lambda.py` |
| `collector_config` | Accounts, regions, collector include/exclude, thresholds |
| `extra_sinks` | e.g. an HTTP ingestion sink (secrets by reference) |
| `target_role_arns` | Member-account reader roles the function may assume |
| `secret_arns` | Secrets Manager secrets the function may read (HTTP sink credentials) |
| `object_lock_days`, `object_lock_mode` | Immutability. **Must be chosen at bucket creation.** `COMPLIANCE` mode cannot be shortened or removed by anyone, including you |
| `evidence_expiration_days` | Retention. Align with your audit period and data-retention policy |
| `alarm_actions` | SNS topics for the error alarm |

## Notes

- **Bucket policy:** denies non-TLS access and any upload not using SSE-KMS. The bundled S3 sink always sends the KMS headers; other writers must too.
- **Access logging:** S3 server access logs for the evidence bucket go to a second, SSE-S3 bucket (`<bucket>-logs`), because S3 cannot deliver access logs to an SSE-KMS bucket. The function's `GRC_CONFIG` environment variable is encrypted with the same customer-managed key.
- **Invocation config:** an invocation cannot replace the collector configuration (`{"config": ...}` is rejected) unless you set `GRC_ALLOW_EVENT_CONFIG=true` on the function. Leave it off: the configuration decides which secrets are read and where evidence is sent, and anyone holding `lambda:InvokeFunction` could otherwise redirect both.
- **Reader role** ([`reader_role/`](reader_role)): apply in each member account. It trusts only the function role, and only with the `ExternalId`. It grants the same read-only action list as the function.
- **Verify before scheduling:** `aws lambda invoke --function-name grc-evidence --payload '{"dry_run": true}' --cli-binary-format raw-in-base64-out out.json` collects but writes nothing, so permission errors show up as `error` records in the logs.
- **Region attribute:** the module uses `data.aws_region.current.region` (provider 6.x).
- **State:** the module does not configure a backend. Use your own remote state.
