# Architecture and design decisions

## Flow

1. **Trigger.** EventBridge invokes the Lambda on a schedule (or you run `grc-evidence collect`).
2. **Scope.** For each configured account the runner assumes a read-only role (`ExternalId` enforced), confirms the account id from `sts:GetCallerIdentity`, and selects collectors. *Global* collectors (IAM, S3 listing, CloudTrail) run once per account. *Regional* collectors run for every configured region.
3. **Collect.** Each collector returns a `Result` (summary, findings, sanitized facts). The base class converts it into an `Evidence` record, attaches the control crosswalk, and seals it with a SHA-256.
4. **Manifest.** The run gets a manifest listing every record and its hash, what the run was judged against, and a link to the previous run. The manifest is sealed with a SHA-256 and, when `signing.kms_key_id` is set, that hash is signed with an asymmetric KMS key. See [Integrity and threat model](#integrity-and-threat-model).
5. **Deliver.** Every sink is attempted, so one failing sink does not block the others. If any sink failed, the Lambda raises after all sinks have been tried, so the error alarm fires.

## Evidence record

```
collector, provider, title, account, region, collected_at
status         pass | fail | error | info | not_applicable
summary        one line
findings[]     {resource, message, severity}
data           counts and configuration facts (no secrets, no resource contents)
controls       {soc2: [...], iso27001: [...], nist_800_53: [...], fedramp_20x: [...]}
schema_version, sha256
```

The hash covers the canonical JSON (sorted keys, no whitespace) of everything but the hash. `verify` recomputes it.

## Run manifest (schema 2.0)

```
run_id, started_at, finished_at, tool_version, accounts, counts
evidence[]     {id, file, status, sha256}       one entry per record
collectors     collector ids selected for this run
parameters     the resolved thresholds (Parameters) every pass/fail was judged against
config_sha256  SHA-256 of the effective config; secrets appear in it only as references
               (env:, secretsmanager:, ssm:), never as resolved values
previous       {run_id, sha256} of the run before this one in the same store; null = genesis
schema_version "2.0"
sha256         over everything above (canonical JSON), excluding sha256 and signature
signature      {key_id, algorithm: ECDSA_SHA_256, value: base64}, or null when unsigned
```

`parameters`, `collectors`, `tool_version` and `config_sha256` tie a result to the bar it was judged against: a `pass` under `max_access_key_age_days: 365` is not the same claim as a `pass` under `90`, and the manifest now says which one it was. Two runs with the same `config_sha256` ran the same configuration. Secrets belong in `auth` as references; an HTTP sink's `headers` are literal strings, so a credential put there is hashed into `config_sha256` (not stored, but guessable if it is short).

Manifests written before 2.0 (schema `1.0`) are still read and verified. `verify` marks them legacy (no signature, no chain fields) and does not fail them. Their hash is computed over the 1.0 field set, so stored 1.0 manifests verify byte for byte. A 2.0 run may name a 1.0 run as its predecessor, so upgrading continues the existing history instead of starting a new one.

## Integrity and threat model

The evidence store should let an auditor trust that what they sample is what the tool wrote at the time. Each layer closes a different gap, and none is enough alone.

**Hash (per record and per manifest).** An unkeyed SHA-256 stored inside the object it describes. It catches accidental corruption, truncated uploads, and edits by someone who does not recompute the hash. It does **not** stop anyone with write access: they can edit a record, recompute its hash, update the manifest entry and recompute the manifest hash. On its own it is a checksum, not a seal.

**Signature (KMS, per manifest).** After sealing, the runner calls `kms:Sign` (`ECC_NIST_P256`, `ECDSA_SHA_256`, `MessageType=DIGEST`) over the manifest's SHA-256. The private key never leaves KMS. The manifest hash covers every record hash, the previous-run link and the judged-against fields, so one signature covers the whole run. It stops anyone who can write the bucket but cannot call `kms:Sign` on that key: an edited run fails `verify` even if every hash was recomputed. Pin the key when verifying (`--key-id`). Without a pin, `verify` is a consistency check, not proof of origin: a forger can sign with a key of their own and name it in the manifest, or strip signatures and recompute every hash, so `verify` says when the key was not pinned and counts unsigned runs in its result. It also fails an unsigned run that follows a signed one. With a pin, every schema 2.0 run must carry a valid signature from that key, and a store with no signed 2.0 run fails, so rewriting the history as unsigned schema 1.0 manifests doesn't pass.

It does **not** stop a principal that can call `kms:Sign` on the key. In the Terraform module that is only the collector's own role, and that is the residual risk: whoever can act as that role (or rewrite the key policy as an account administrator) can sign anything. Every `Sign` call is a CloudTrail management event, so an auditor can reconcile signatures against runs, and a forged re-signing shows up as an extra call. A signature also does not prove the collected facts were true (a compromised collector signs what it collects), and it does not stop a run from being deleted.

**Hash chain (across runs).** Before sealing, the runner reads the newest completed manifest from the primary durable sink (the first `s3` or `local` sink) and records its `run_id` and `sha256` in `previous`. The first run in an empty store is the genesis. If the lookup fails, the run fails, instead of writing a false genesis that would hide a break. `verify` on a parent directory checks every run and every link, and reports:

- a deleted run in the middle of the history (the next run points at a run that is not there),
- a reordered, renamed or inserted run (a run does not point at the run before it, or claims genesis after earlier runs),
- a rewritten past run (its `sha256` no longer matches what the next run recorded, even if its own hash was recomputed),
- a fork from two overlapping runs (two runs naming the same predecessor).

The lookup only considers runs whose `run_id` sorts before the new run, and skips a manifest it cannot parse. A writer who plants a future-dated or malformed manifest therefore can't block collection forever (under Object Lock the planted object could never be removed). The planted run is still reported by `verify`: an unreadable manifest, or a link that skips a run. Read and permission errors still fail the run.

Run ids start with a UTC timestamp to the microsecond, so back-to-back runs sort in the order they started. Overlapping runs against the same store both link to the same predecessor and show as a fork; the Lambda's concurrency of 1 prevents that, so don't run `collect` in parallel against one store.

It does **not** detect truncation: deleting the newest run(s) leaves nothing pointing at them. Deleting the oldest runs looks the same as lifecycle expiry, so a missing predecessor of the first run in view is a note, not a failure. Without signatures, a writer can recompute the whole chain from the rewritten run forward. With signatures they would have to re-sign every later run, which needs `kms:Sign` and leaves one CloudTrail event per forged run.

**S3 Object Lock.** In `COMPLIANCE` mode no one, including the account root user, can overwrite or delete an object version until its retention ends. This is the layer that *prevents* deletion and truncation, which the other layers can at best detect. `GOVERNANCE` mode can be bypassed by anyone with `s3:BypassGovernanceRetention`, so use `COMPLIANCE` for audit evidence. Object Lock must be enabled when the bucket is created. The module default stays off (`object_lock_days = 0`) because turning it on for an existing bucket makes Terraform replace the bucket. Object Lock does not stop someone writing additional objects (for example a fabricated run under a new key); the chain and the signature catch those.

**Versioning.** Keeps every overwritten or deleted version, so a change is recoverable and visible in the version history. Without Object Lock, anyone with `s3:DeleteObjectVersion` can purge old versions. `verify s3://...` checks current versions only.

**Who did it.** CloudTrail (`kms:Sign` events, plus S3 data events if you enable them) and the S3 server access logs in the separate, versioned access-log bucket record which principal read or changed evidence objects.

| Attacker can | Hash | Signature | Chain | Object Lock (COMPLIANCE) |
|---|---|---|---|---|
| Edit a record without recomputing hashes | detects | detects | | prevents |
| Edit a record and recompute every hash in that run | | detects | detects, once a later run exists | prevents |
| Delete or reorder a past run | | | detects | prevents |
| Delete the newest run | | | | prevents |
| Add a fabricated run | | detects, unless it can call `kms:Sign` | detects | |
| Act as the collector role (`kms:Sign`) | | CloudTrail shows the extra `Sign` calls | detects edits to past runs | prevents changes to written objects |

Production settings: signing on (the module default), `object_lock_mode = "COMPLIANCE"`, `object_lock_days` at least your audit period, `evidence_expiration_days` not shorter than `object_lock_days` (the module rejects a shorter value), and `verify --key-id` pinned to the module's `signing_key_arn` output.

## Decisions

**`error` is not `pass`.** Auditors care about the difference between "we checked and it was fine" and "we could not check". Access-denied, throttling and API failures produce an `error` record with the reason, control rollups treat `error` as incomplete evidence, and a run that cannot assume a member-account role produces an explicit `aws.account_access` error rather than nothing.

**Read-only by construction.** Collectors call only `Describe*`/`Get*`/`List*` style APIs (plus `iam:GenerateCredentialReport`, which creates a report but changes no configuration). A test compares each collector's declared permissions with the Terraform policy in both directions and rejects write-style verbs, so the IAM policy cannot silently grow or shrink away from the code.

**Facts, not contents.** Records hold booleans, counts and resource identifiers. They never read object contents, secret values or user data, which keeps the evidence store low-sensitivity, although resource names and account ids are still worth treating as internal.

**One crosswalk file, validated.** `collector_map.yaml` is data, reviewable by a GRC person without reading Python. CI fails if a mapping refers to a control that is not in `controls.yaml`, if a collector has no mapping, or if the committed coverage doc is out of date.

**Coverage is reported honestly.** Technical controls with no collector are shown as gaps. Organizational criteria are labeled as such and excluded from the "automated" denominator.

**Rollup precedence: fail > error > pass > not_applicable.** A control is only "pass" when at least one relevant check passed and none failed or errored.

**HTTP sink safety.** HTTPS required (an explicit flag exists for local tests), no credentials in URLs, secrets by reference only, redirects are never followed (an `Authorization` header must not be replayed to another host), 4xx fails fast, 429/5xx retry with backoff honoring `Retry-After`, payload size is capped, and every POST carries an idempotency key derived from the content hash.

**S3 sink.** SSE-KMS when a key is configured. Records are written before the manifest, so a manifest's presence marks a complete run. Immutability comes from S3 Object Lock on the bucket (Terraform option), not from application code. The bucket policy denies non-TLS and non-KMS uploads. The collector role can list and read the evidence prefix so it can find the previous run for the chain.

**Fail closed on integrity.** If signing is configured and `kms:Sign` fails, or the previous run cannot be read, the run fails (and the error alarm fires) instead of delivering an unsigned or unchained manifest. The next scheduled run retries.

**Lambda concurrency = 1.** Overlapping runs would double-report the same evidence period, and both would chain to the same predecessor, which `verify` reports as a fork.

## Extending

Add a collector:

```python
@register
class MyCheck(Collector):
    id = "aws.my_check"
    title = "What it checks"
    scope = "regional"                       # or "global"
    permissions = ("service:Describe...",)   # read-only actions

    def collect(self, ctx: Context) -> Result:
        client = ctx.client("service")
        ...
        return Result(summary="...", findings=[Finding(resource, message, Severity.HIGH)], data={...})
```

Then add it to `collector_map.yaml`, add its actions to both Terraform `collector_read_actions` lists, write a moto test, and regenerate the docs. The tests tell you which of those you forgot.

Add a sink: implement `name` and `write(run: RunResult) -> int`, raise `SinkError` on failure, and register it in `runner.build_sinks`.
