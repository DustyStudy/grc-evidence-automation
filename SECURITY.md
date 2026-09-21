# Security Policy

## Reporting a vulnerability

Please [report a vulnerability privately](https://github.com/DustyStudy/grc-evidence-automation/security/advisories/new) (GitHub: **Security -> Report a vulnerability**) rather than opening a public issue. This is a solo-maintained project with no SLA, so reports are handled as time allows.

Worth reporting: a way for a collector or sink to leak a secret or resource contents into evidence or logs, a path from configuration input to arbitrary code or request forgery, a way to make `verify` pass on modified evidence, or Terraform that grants broader access than documented.

## Design notes relevant to security review

- **Read-only by design.** Collectors call only read/describe/list APIs. The Terraform policy is generated from the same action list and tests compare the two in both directions and reject write verbs.
- **Cross-account access** uses `sts:AssumeRole` with a required `ExternalId` (confused-deputy protection). The member-account role trusts only the collector's role.
- **No long-lived credentials.** The Lambda uses its execution role. Sink credentials are referenced (`env:`, `secretsmanager:`, `ssm:`), and bare literals in config are rejected.
- **Evidence contains configuration facts, not data.** Records hold counts, booleans and resource identifiers. Account ids and resource names still appear, so treat the evidence store as internal.
- **Integrity, not secrecy from the operator.** SHA-256 hashes detect modification of stored evidence. They do not stop someone with write access to both a record and the manifest from replacing a whole run. For that, use S3 Object Lock (Terraform option), and keep write access to the bucket narrow.
- **HTTP sink:** HTTPS only, credentials never in URLs, redirects never followed, request size capped, retries limited.
- **Terraform:** evidence bucket blocks public access, denies non-TLS and non-KMS writes, is versioned and KMS-encrypted with rotation; logs are KMS-encrypted.

## CI/CD hardening

- Workflows run with `contents: read`; third-party actions are pinned to full commit SHAs (first-party HashiCorp/GitHub actions that publish major-version tags are noted inline).
- `step-security/harden-runner` runs in audit mode.
- CodeQL on every push/PR and weekly; dependency review on PRs (fails on high-severity findings and on GPL/AGPL licences); Dependabot weekly for Python, GitHub Actions and Terraform.
- Releases are built by a tag-triggered workflow that attaches the wheel, sdist, Lambda deployment zip, a CycloneDX SBOM and a build provenance attestation to the GitHub Release. Verify an artifact with `gh attestation verify <file> --repo DustyStudy/grc-evidence-automation`, or offline with the attestation bundle attached to the release: `gh attestation verify <file> --bundle <name>.sigstore.json --repo DustyStudy/grc-evidence-automation`.
- The integrity-critical code (`verify` tamper detection, evidence hashing, the config and secret loaders, the HTTP sink and the report renderer) is fuzzed with Atheris in CI, and the same targets run as regression tests on every change.
- CI installs its Python tooling from hash-pinned requirement files (`pip install --require-hashes`), and a CI job checks they match `pyproject.toml`.
- An OpenSSF Scorecard workflow runs weekly and on pushes to `main`; results are published to the public Scorecard API (api.scorecard.dev).
