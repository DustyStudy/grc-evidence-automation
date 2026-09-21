# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). While the version is below 1.0, minor releases may change public APIs and the evidence schema.

## [Unreleased]

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

[Unreleased]: https://github.com/DustyStudy/grc-evidence-automation/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DustyStudy/grc-evidence-automation/releases/tag/v0.1.0
