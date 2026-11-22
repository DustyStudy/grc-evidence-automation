# Security Policy

## Reporting a vulnerability

Please [report a vulnerability privately](https://github.com/DustyStudy/grc-evidence-automation/security/advisories/new) (GitHub: **Security -> Report a vulnerability**) rather than opening a public issue. This is a solo-maintained project with no SLA, so reports are handled as time allows.

Worth reporting: a way for a collector or sink to leak a secret or resource contents into evidence or logs, a path from configuration input to arbitrary code or request forgery, a way to make `verify` pass on modified evidence, or Terraform that grants broader access than documented.

## Design notes relevant to security review

- **Read-only by design.** Collectors call only read/describe/list APIs. The read-action list is kept in sync by hand in three places (the Python collectors and the two Terraform policies). `tests/test_terraform_consistency.py` compares them and rejects write verbs.
- **Cross-account access** uses `sts:AssumeRole`. The member-account role's trust policy requires an `ExternalId` of at least 16 characters (confused-deputy protection) and trusts only the collector's role. The tool sends the ExternalId only when `external_id` is configured, so without it the assume-role call fails and is recorded as an error.
- **No long-lived credentials.** The Lambda uses its execution role. Sink credentials are referenced (`env:`, `secretsmanager:`, `ssm:`), and bare literals in config are rejected.
- **Evidence contains configuration facts, not data.** Records hold counts, booleans and resource identifiers. Account ids and resource names still appear, so treat the evidence store as internal.
- **Integrity, not secrecy from the operator.** SHA-256 hashes detect modification of stored evidence. They do not stop someone with write access to both a record and the manifest from replacing a whole run. For that, use S3 Object Lock (Terraform default: `COMPLIANCE` mode), and keep write access to the bucket narrow. A KMS signature (`signing:` config; enabled by default in Terraform) also stops a writer who lacks `kms:Sign` from re-sealing a run, but only when `grc-evidence verify` pins the key with `--key-id`.
- **HTTP sink:** HTTPS only, credentials never in URLs, redirects never followed, request size capped, retries limited.
- **Terraform:** evidence bucket blocks public access, denies non-TLS and non-KMS writes, is versioned and KMS-encrypted with rotation; the Lambda's CloudWatch log group is KMS-encrypted. The S3 server access-log bucket uses SSE-S3, which S3 access logging requires.

## CI/CD hardening

- Workflows run with `contents: read`; every action, including first-party GitHub actions, is pinned to a full commit SHA with the version in a trailing comment.
- `step-security/harden-runner` runs in block mode with a per-job explicit endpoint allowlist (derived from observed egress on real runs), so a compromised dependency or action cannot exfiltrate data or pull a second-stage payload from an arbitrary host. The release workflow's allowlist was built from equivalent, already-verified CI jobs rather than a live tag run, since it only triggers on a tag push; watch the first release after this change for a blocked-endpoint failure.
- CodeQL on every push/PR and weekly; dependency review on PRs (fails on high-severity findings and on GPL/AGPL licences); Dependabot weekly for GitHub Actions and Terraform. Python locks are not updated by Dependabot; they are refreshed by hand with `scripts/lock.py --upgrade` (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- Releases are built by a tag-triggered workflow that attaches the wheel, sdist, Lambda deployment zip, a CycloneDX SBOM and a build provenance attestation to the GitHub Release. Verify an artifact with `gh attestation verify <file> --repo DustyStudy/grc-evidence-automation`, or offline with the attestation bundle attached to the release: `gh attestation verify <file> --bundle <name>.sigstore.json --repo DustyStudy/grc-evidence-automation`.
- The integrity-critical code (`verify` tamper detection, evidence hashing, the config and secret loaders, the HTTP sink and the report renderer) is fuzzed with Atheris in CI, and the same targets run as regression tests on every change.
- CI installs its Python tooling from hash-pinned requirement files (`pip install --require-hashes`), and a CI job checks they match `pyproject.toml`.
- An OpenSSF Scorecard workflow runs weekly and on pushes to `main`; results are published to the public Scorecard API (api.scorecard.dev).
