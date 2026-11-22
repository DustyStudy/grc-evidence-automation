# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). While the version is below 1.0, minor releases may change public APIs and the evidence schema.

## [Unreleased]

### Added
- **Nine more collectors** (ACM certificates, Config rules, EKS, Identity Center, Secrets Manager rotation, Security Hub controls, Inspector vulnerability scanning, WAF and CloudFront WAF coverage). They need read actions that the reader role now grants. Re-apply the reader role in each member account before upgrading, or these collectors record `error`.
- **Signed run manifests.** New optional config key `signing: {kms_key_id: ...}`. After sealing, the manifest's SHA-256 is signed with an asymmetric KMS key (`ECC_NIST_P256`, `ECDSA_SHA_256`, `MessageType=DIGEST`) through the FIPS-aware session, and the signature, key ID and algorithm are stored in the manifest. A signing failure fails the run. The per-record and manifest SHA-256 values were unkeyed and stored inside the objects they protect, so anyone able to write the bucket could edit a record and recompute every hash; a signature can't be recomputed without `kms:Sign` on the key.
- **Hash chain across runs.** Each manifest records the previous run's `run_id` and `sha256`, read from the first `s3` or `local` sink before sealing. The first run in an empty store is the genesis. `grc-evidence verify` on a parent directory (or `s3://bucket/prefix`) now checks every run and every link, and reports a deleted, reordered, renamed, forked or rewritten past run.
- **What a result was judged against.** Manifests record the resolved `parameters`, the selected `collectors`, the tool version and `config_sha256`, a hash of the effective config, in which secrets appear only as references.
- `grc-evidence verify --key-id <arn>` pins the signing key (unsigned runs, and a store with no signed run, then fail), `--skip-signature` checks hashes and the chain only, and `verify` accepts `s3://bucket/prefix`.
- Terraform: new `signing.tf` with the signing key, its alias and an `evidence-integrity` role policy (`kms:Sign` limited to `ECDSA_SHA_256` digests, `s3:ListBucket` on the evidence prefix and `s3:GetObject` on run `manifest.json` objects only, for the chain lookup). New variable `enable_signing` (default `true`) and output `signing_key_arn`. Plan now fails when `evidence_expiration_days` is shorter than `object_lock_days`.
- `docs/ARCHITECTURE.md` has a threat model: what the hash, signature, chain, Object Lock and versioning each stop, and what they don't.

### Fixed
- **An account that cannot be assumed no longer reads as pass.** Its `aws.account_access` error now makes every control `error` in the rollup, instead of being invisible while the other accounts' passes show.
- **A run with error records now fails the Lambda invocation** after delivery, so the error alarm fires. Previously an all-error run returned success.
- **A sink that raises any exception** (not only `SinkError`/`ValueError`, for example an unreadable secret or a `KeyError` in the HTTP auth block) is recorded as failed, and later sinks still receive the evidence.
- **GCP collectors in the Lambda** are refused at config load with a clear error. The Lambda artifact does not package the google-cloud libraries, so they used to fail as `error` records. Run GCP from the CLI.
- **Lambda no longer retries failed invocations** (`maximum_retry_attempts = 0`). Each retry wrote a complete duplicate run.
- **Missed-run alarm.** A second alarm fires when the scheduled function is not invoked within a day.

### Changed
- **Breaking, Terraform:** `object_lock_days` and `alarm_actions` have no default and must be set explicitly (`0` and `[]` remain valid). `object_lock_mode` now defaults to `COMPLIANCE`. Previously Object Lock was off and `alarm_actions` notified nobody by default. **Upgrade warning:** an existing deployment with Object Lock enabled that relied on the old `GOVERNANCE` default switches to `COMPLIANCE` on the next apply unless you set `object_lock_mode = "GOVERNANCE"` explicitly. Retention on objects written after that apply is then irreversible until it expires.
- **Terraform:** new `ssm_parameter_arns` and `ssm_kms_key_arns` variables grant the function read access to `ssm:` sink references, which the code already supported but the IAM policy did not allow.
- **Evidence schema 2.0.** `SCHEMA_VERSION` is now `2.0` for records and manifests. Schema `1.0` manifests are still read and verified, are reported as legacy, and don't fail `verify`; a 2.0 run can chain to a 1.0 predecessor.
- **`collect` and the Lambda need read access to the primary sink.** The chain lookup lists and reads the evidence prefix before each run and fails closed. A CLI user whose S3 credentials can only `PutObject` must add `s3:ListBucket` and `s3:GetObject` on the prefix. The Terraform module grants them.
- Run ids now carry microseconds (`20261120T060000123456Z-1a2b3c4d`, was `20261120T060000Z-1a2b3c4d`) so back-to-back runs sort in the order they ran; the chain lookup and `verify` order runs by id. The chain lookup skips run ids that sort after the new run and manifests it can't parse, so a planted future-dated or malformed manifest can't block collection; `verify` still reports it.
- `verify` on a parent directory checks every run under it (including an `aws s3 sync` copy with `dt=` partitions) instead of only the newest, and `report` finds the newest run in such a copy too.
- README production example uses `object_lock_mode = "COMPLIANCE"`. Enabling Object Lock on an existing bucket replaces the bucket, so the module's Object Lock defaults changed only for new deployments (see the breaking change under Unreleased).
- **FIPS endpoints by default.** New top-level config key `use_fips_endpoint` (default `true`; Terraform variable of the same name) makes every AWS client call FIPS 140 validated endpoints: collectors, STS role assumption, the S3 sink and secret lookups. In the commercial partition S3's `ListBuckets` has no FIPS endpoint, so with FIPS on `aws.s3_security` lists buckets through the Cloud Control API in every enabled region. Regions it can't reach over FIPS are reported as MEDIUM findings (`regions_not_enumerated`), and evidence records `bucket_enumeration`. New read-only permissions `cloudformation:ListResources` and `ec2:DescribeRegions` were added to both IAM action lists. FedRAMP boundaries are US-only: bucket listing covers enabled US regions, and other enabled regions are recorded in `regions_out_of_scope` without findings.
- Terraform: the S3 access-log bucket is now versioned (with matching noncurrent-version expiration), so a delete or overwrite of a log object by anyone with write access to that bucket is recoverable instead of silently erasing part of the audit trail of who read or changed evidence.
- CI/CD: `step-security/harden-runner` now runs in `block` mode (was `audit`) with a per-job endpoint allowlist, built from the exact egress observed on real runs. A compromised dependency, action or build step can no longer reach an arbitrary host to exfiltrate data or pull a second-stage payload.

### Fixed
- `aws.iam_password_policy` reported a NIST SP 800-63B-4-compliant policy as failing. It raised a finding for each missing composition rule (upper, lower, number, symbol), but 800-63B-4, which FedRAMP's IA-5 guidance points to, says verifiers "SHALL NOT impose other composition rules". Composition is now only checked when `parameters.password_require_composition` is `true` (default `false`, for programs whose own policy still requires it). `password_min_length` now defaults to 15, 800-63B-4's single-factor minimum, instead of 14. Evidence for policies that already met 14+ characters and all composition rules is unchanged, except that a 14-character minimum is now a finding.
- Terraform: the collector Lambda's `reserved_concurrent_executions` was hardcoded to `1`, so `terraform apply` failed outright in any account whose Lambda concurrent-execution quota is at or near the AWS-wide floor of 10 (new and sandbox accounts commonly start there) with `InvalidParameterValueException: ... decreases account's UnreservedConcurrentExecution below its minimum value of [10]`. There was no workaround short of editing the module. It's now `var.reserved_concurrent_executions` (default `1`, unchanged); set it to `-1` (the AWS provider's own "unreserved" sentinel) to deploy without a reservation. Found deploying the module for real into a fresh AWS account; see [`docs/live-deployment-verification.md`](docs/live-deployment-verification.md).

## [0.1.1] - 2026-09-21

### Added
- Fuzz targets for the integrity-critical code (`fuzz/`): `verify` tamper detection, evidence hashing and the write/read round trip, the report renderer, the config and secret loaders, and the HTTP sink. They run as ordinary tests on a seed corpus and random inputs, and in CI with coverage-guided fuzzing (Atheris). Each target's ability to fail is itself tested.
- Releases attach the attestation bundle (`*.sigstore.json` and `*.intoto.jsonl`) next to the artifacts, so they can be verified offline with `gh attestation verify --bundle`; the release workflow verifies every artifact against it before publishing.
- The Scorecard workflow can be run on demand, and the README explains how to read the score for a solo-maintained project.

### Changed
- CI and the release workflow install Python tooling from hash-pinned, cross-platform requirement files (`requirements/`, generated by `scripts/lock.py` with a pinned `uv`) using `pip install --require-hashes`; a CI job fails if they no longer match `pyproject.toml`. Dependabot does not manage them; refresh with `python scripts/lock.py --upgrade`.

### Fixed
- `grc-evidence verify` crashed (`TypeError`, `KeyError`, `UnicodeDecodeError`) on tampered or malformed files instead of reporting them. A damaged evidence file, manifest or manifest entry is now a reported problem, and loading a damaged run for a report raises `ValueError`.
- Malformed configuration crashed with raw `TypeError`/`ValueError` instead of `ConfigError`. Configuration values, `parameters` and sink options are now type-checked (thresholds must be non-negative integers, `require_securityhub` a boolean, ports valid, headers a mapping of strings). Configs that only worked by accident may now be rejected with a clear message.
- An HTTP sink option such as `allow_insecure_http: "false"` (a truthy string) silently enabled plain HTTP. Boolean options must now be booleans. A malformed URL now raises `SinkError`, and a URL with an `@` in its authority is rejected.
- A secret reference that resolved to JSON `null`, an object, a list or an empty value returned the text `None`, a Python repr or an empty string as the credential. Secrets must now be non-empty strings (numbers are accepted for JSON keys), and a binary secret or an invalid environment variable name is a `SecretError`.
- Untrusted text in evidence (resource names, messages, collector names, run ids) could add markdown links, images, code spans or extra lines to a rendered report. Cells now escape brackets, backticks and backslashes and replace every kind of line break; the "Evidence from" column was previously unescaped.
- Sealing evidence crashed when `data` had keys of mixed types, and identifiers that produce very long file names could not be written. Data is now normalised the way it is stored, so the hash matches after a write/read round trip, and file names are bounded.

## [0.1.0] - 2026-09-21

### Added
- Read-only collectors for AWS (IAM MFA, password policy, access-key hygiene and privileged principals; S3 exposure and encryption; CloudTrail; KMS rotation; EBS/RDS encryption; security-group exposure; GuardDuty and Security Hub; AWS Config; VPC flow logs; backups) and GCP (Cloud Storage and firewall exposure).
- A control crosswalk from every collector to SOC 2 criteria, ISO/IEC 27001:2022 Annex A, NIST SP 800-53 Rev. 5 and the 46 FedRAMP 20x Key Security Indicators (Consolidated Rules 2026.09.13.02), validated in CI. `grc-evidence coverage` reports which controls have automated evidence and which technical controls are gaps; organizational controls are marked as outside what a collector can prove.
- Integrity: every evidence record and run manifest carries a SHA-256, and `grc-evidence verify` detects edited, missing and extra files. A check that cannot run becomes an `error` record, never a silent pass.
- Sinks: local files, S3 (SSE-KMS) and a generic HTTP ingestion sink (bearer or OAuth2 client credentials, retries, idempotency keys, no redirect following).
- Multi-account collection by assuming a read-only role with an `ExternalId`; GovCloud and China ARN partitions are handled.
- Terraform for the collector Lambda (EventBridge schedule, KMS-encrypted versioned bucket with optional Object Lock, least-privilege IAM, error alarm) and for the member-account reader role. A test fails if the Terraform IAM actions drift from the collectors' declared permissions.
- `grc-evidence report` renders a per-framework rollup of collected evidence.

### Build and release
- CI runs lint, type-check and tests on Linux (Python 3.11 to 3.13) and on Windows and macOS (3.11, 3.12), with a 90% coverage floor; validates the crosswalk and generated docs; builds the Lambda package; and validates the Terraform.
- CI builds the sdist and wheel, runs `twine check --strict`, and installs the wheel in a clean environment to confirm it runs and ships its data files.
- Release workflow: pushing a `vX.Y.Z` tag builds the wheel, sdist and Lambda deployment zip, generates a CycloneDX SBOM, attests build provenance and publishes a GitHub Release. It does not upload to PyPI.
- OpenSSF Scorecard workflow (results published to the Scorecard API). Dependency review rejects GPL and AGPL licensed dependencies, and its action is pinned to a commit SHA.
- Issue and pull request templates, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, project URLs in the package metadata, and a test that rejects literal zero-width and bidirectional-control characters in source files.

### Security
- Closed findings from a security scan (see the commit history for details).

[Unreleased]: https://github.com/DustyStudy/grc-evidence-automation/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/DustyStudy/grc-evidence-automation/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/DustyStudy/grc-evidence-automation/releases/tag/v0.1.0
