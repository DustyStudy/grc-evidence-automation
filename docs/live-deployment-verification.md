# Live deployment verification

This records a real, one-off deployment of `deploy/terraform` into a live AWS
account (a member account of a real AWS Organization), done to verify the
Terraform module and the Lambda it deploys actually work end to end, not just
under CI's `moto`-mocked test suite. It found and fixed one real deployability
bug. Everything below is from an actual run, not a description of intended
behavior.

**Account and finding-level detail is deliberately redacted** — this repo is
public, and the target was a real account in the maintainer's org. What's kept
is the shape and outcome of each step: status codes, resource counts, error
text (generic AWS messages, not account-specific), and pass/fail.

- **Environment:** Windows 11, Python 3.14.7, Terraform 1.15.8, AWS provider
  ~> 6.0 (resolved 6.66.0), against a near-empty sandbox member account
  (default VPC only, no other resources) of a real AWS Organization.
- **Deployed exactly `deploy/terraform`** via a throwaway root module (not
  committed — it's just `module "grc_evidence" { source = "./deploy/terraform" ... }`
  per the root README's example), same-account self-scan (no cross-account
  role assumption exercised in this pass).

## What was deployed and proven

1. `python scripts/build_lambda.py` → a real 833 KiB Lambda zip.
2. `terraform init` / `plan` / `apply` against the live account.
3. `aws lambda invoke ... '{"dry_run": true}'` — checks permissions without
   writing anything.
4. `aws lambda invoke ... '{}'` — a real run, writing to the real S3 sink.
5. Downloaded the S3-written evidence and ran `grc-evidence verify` and
   `grc-evidence report --framework soc2` against it (not CLI-collected
   evidence — evidence the deployed Lambda itself produced).
6. Confirmed SSE-KMS on the written objects via `s3api head-object`.
7. Read the function's CloudWatch Logs and the error alarm's state.
8. Tore the whole deployment down and confirmed the account is clean again.

## The bug this found

The first `terraform apply` failed partway through:

```
Error: setting Lambda Function (grc-evidence-livetest) concurrency: operation error
Lambda: PutFunctionConcurrency, https response error StatusCode: 400, ...
InvalidParameterValueException: Specified ReservedConcurrentExecutions for function
decreases account's UnreservedConcurrentExecution below its minimum value of [10].
```

`deploy/terraform/main.tf` hardcoded `reserved_concurrent_executions = 1` on
the Lambda function, with no variable to override it. `aws lambda
get-account-settings` on the target account confirmed why: `"ConcurrentExecutions":
10` against an AWS platform default of `1000` — this account (new, no usage
history) sits at the AWS-wide floor, where *any* positive reservation is
rejected. There was no workaround short of hand-editing the module. New and
sandbox AWS accounts commonly start at this floor, so this wasn't specific to
one unlucky account.

**Fix:** `reserved_concurrent_executions` is now a module variable (default
`1`, so existing callers see no change). Setting it to `-1` — the AWS
provider's own "leave concurrency unreserved" sentinel for this resource
argument — deploys cleanly in a floor-quota account. See the `CHANGELOG.md`
entry and the updated `deploy/terraform/README.md` variable table.

After the fix, `terraform plan` showed exactly the expected remainder
(`reserved_concurrent_executions = -1` recreates the function, then the
resources that depend on it):

```
Plan: 4 to add, 0 to change, 1 to destroy.
```

and it applied cleanly:

```
Apply complete! Resources: 4 added, 0 changed, 1 destroyed.

Outputs:

evidence_bucket = "grc-evidence-livetest-<account>-us-east-1"
function_name = "grc-evidence-livetest"
function_role_arn = "arn:aws:iam::<account>:role/grc-evidence-livetest-function"
```

(A Lambda concurrency quota increase was also requested on the live account
via `aws service-quotas request-service-quota-increase`, independent of the
code fix, so the account itself is in better shape going forward too.)

## Proof it actually collects and delivers

Dry run (permissions check only, nothing written):

```
$ aws lambda invoke --function-name grc-evidence-livetest --payload '{"dry_run": true}' ...
{"StatusCode": 200, "ExecutedVersion": "$LATEST"}
$ cat out.json
{"run_id": "...", "accounts": ["<redacted>"], "counts": {"not_applicable": 1, "fail": 7, "pass": 5}, "sinks": {}, "dry_run": true}
```

Real run:

```
$ aws lambda invoke --function-name grc-evidence-livetest --payload '{}' ...
{"StatusCode": 200, "ExecutedVersion": "$LATEST"}
$ cat out.json
{"run_id": "...", "accounts": ["<redacted>"], "counts": {"not_applicable": 1, "fail": 7, "pass": 5},
 "sinks": {"s3://grc-evidence-livetest-<account>-us-east-1/evidence": "ok"}, "dry_run": false}
```

13 evidence records + `manifest.json` landed in S3 (all 13 shipped collectors
ran — `aws.backups`, `aws.cloudtrail`, `aws.config_recorder`,
`aws.encryption_at_rest`, `aws.iam_access_keys`, `aws.iam_mfa`,
`aws.iam_password_policy`, `aws.iam_privileged_access`, `aws.kms_rotation`,
`aws.network_exposure`, `aws.s3_security`, `aws.threat_detection`,
`aws.vpc_flow_logs`). `s3api head-object` on the manifest confirmed
`"ServerSideEncryption": "aws:kms"` with the bucket's own customer-managed
key — the bucket policy's `DenyUnencryptedUploads` statement is doing real
work, not just sitting in a plan file.

Downloaded that same S3-written evidence and ran the CLI against it:

```
$ grc-evidence verify ./lambda-evidence-downloaded/dt=.../<run_id>
OK: manifest and all evidence hashes verified

$ grc-evidence report ./lambda-evidence-downloaded/dt=.../<run_id> --framework soc2
# SOC 2 (Trust Services Criteria): control evidence status
Run `<run_id>` (...), accounts: <redacted>
...
| Status | Controls |
|---|---:|
| fail | 7 |
| no_automated_evidence | 26 |
| not_applicable | 2 |
| pass | 3 |
```

CloudWatch Logs for both invocations showed a clean `INIT_START` → `START` →
one `INFO` line with the run summary → `END`/`REPORT` for each, no
tracebacks, no throttling. The error alarm's state after both runs:

```
$ aws cloudwatch describe-alarms --alarm-names grc-evidence-livetest-errors ...
{"State": "OK", "Reason": "Threshold Crossed: 1 datapoint [0.0 ...] was not greater than or equal to the threshold (1.0)."}
```

## Teardown

`terraform destroy` removed 23 of 25 resources immediately; the two versioned
S3 buckets (the evidence bucket and its access-log bucket) failed with the
expected `BucketNotEmpty` — Terraform's `aws_s3_bucket` doesn't force-delete
object versions. Emptied both (15 object versions/delete markers total: the
13 evidence records + manifest + one delivered access-log entry) and
re-ran destroy:

```
Destroy complete! Resources: 2 destroyed.
```

Post-teardown, the account has zero matching S3 buckets, Lambda functions,
IAM roles, KMS aliases, or CloudWatch alarms. The KMS key is in AWS's
mandatory 30-day `PendingDeletion` state (the module's `deletion_window_in_days
= 30`, AWS's own minimum) — normal `terraform destroy` behavior for any KMS
key, not something left running, with a trivial (~$1, one month, one key)
residual cost until it auto-deletes.

## What this does and doesn't prove

It proves the Terraform module deploys, the Lambda runs with real IAM
permissions (not moto's simulated ones), writes real KMS-encrypted evidence
to a real least-privilege-policed S3 bucket, and that evidence round-trips
through `verify` and `report` correctly. It does not prove multi-account role
assumption (`target_role_arns` / `reader_role`), the HTTP sink against a real
endpoint, GCP collection, or unattended operation over the EventBridge
schedule's actual cadence — none of those were exercised in this pass.
