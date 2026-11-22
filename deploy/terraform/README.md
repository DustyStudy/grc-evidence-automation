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
| `ssm_parameter_arns`, `ssm_kms_key_arns` | SSM parameters the function may read for `ssm:/path` sink auth references, and the customer-managed KMS keys that encrypt them (SecureString). Both default to `[]` |
| `reserved_concurrent_executions` | Defaults to 1 (runs must not overlap). Set to `-1` in an account whose Lambda concurrency quota is at the AWS floor of 10, where any reservation fails apply |
| `object_lock_days`, `object_lock_mode` | Immutability. **Must be chosen at bucket creation**: changing `object_lock_days` between `0` and a positive value later replaces the bucket. `object_lock_days` is **required** (no default); `0` is an explicit opt-out. `object_lock_mode` defaults to `COMPLIANCE`, which cannot be shortened or removed by anyone, including you; `GOVERNANCE` can be bypassed with `s3:BypassGovernanceRetention` |
| `evidence_expiration_days` | Retention. Align with your audit period and data-retention policy. Plan fails if it is shorter than `object_lock_days` |
| `enable_signing` | Default `true`. Creates an asymmetric `ECC_NIST_P256` KMS key (`signing_key_arn` output) and grants the function `kms:Sign` on it, so every run manifest is signed. KMS can't rotate asymmetric keys: to rotate, create a new key and keep the old one to verify older runs |
| `alarm_actions` | **Required** (no default). SNS topics for the error alarm and the missed-run alarm (no invocation in a day; assumes a daily schedule). Pass `[]` explicitly for no notification |

## Notes

- **Bucket policy:** denies non-TLS access and any upload not using SSE-KMS with this stack's customer-managed key. The bundled S3 sink always sends the KMS headers; other writers must too, with `kms_key_id` set to the key ARN (`kms_key_arn` output). An alias or a missing key id is denied.
- **Access logging:** S3 server access logs for the evidence bucket go to a second, SSE-S3 bucket (`<bucket>-logs`), because S3 cannot deliver access logs to an SSE-KMS bucket. The function's `GRC_CONFIG` environment variable is encrypted with the same customer-managed key.
- **Invocation config:** an invocation cannot replace the collector configuration (`{"config": ...}` is rejected) unless you set `GRC_ALLOW_EVENT_CONFIG=true` on the function. Leave it off: the configuration decides which secrets are read and where evidence is sent, and anyone holding `lambda:InvokeFunction` could otherwise redirect both.
- **Reader role** ([`reader_role/`](reader_role)): apply in each member account. It trusts only the function role, and only with the `ExternalId`. It grants the same read-only action list as the function.
- **API Gateway scope:** `apigateway:GET` is granted only on `/restapis` and `/restapis/*/stages` (any region), which is all `aws.waf_coverage` reads, in both the function role and the reader role. API keys stay explicitly denied. A collector that reads another API Gateway resource needs its ARN added to the `ReadRestApiStages` statement in `iam.tf` and `reader_role/main.tf`.
- **Key destroy protection:** the evidence key and the signing key have `prevent_destroy = true`, so `terraform destroy`, a change that replaces either key, or setting `enable_signing = false` after the signing key exists fails at plan. To remove a key deliberately, delete the `lifecycle` block from that `aws_kms_key` in `main.tf` or `signing.tf` first.
- **GovCloud guard:** a `check` block (`govcloud_region`) fails its assertion when the partition is `aws-us-gov` and the provider region is not `us-gov-west-1` or `us-gov-east-1`. It always passes in other partitions. Terraform reports failed checks as warnings on plan and apply; it does not stop the run.
- **Verify before scheduling:** `aws lambda invoke --function-name grc-evidence --payload '{"dry_run": true}' --cli-binary-format raw-in-base64-out out.json` collects but writes nothing, so permission errors show up as `error` records in the logs.
- **Region attribute:** the module uses `data.aws_region.current.region` (provider 6.x).
- **State:** the module does not configure a backend. Use your own remote state.
