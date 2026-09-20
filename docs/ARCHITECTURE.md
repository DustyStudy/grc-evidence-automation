# Architecture and design decisions

## Flow

1. **Trigger.** EventBridge invokes the Lambda on a schedule (or you run `grc-evidence collect`).
2. **Scope.** For each configured account the runner assumes a read-only role (`ExternalId` enforced), confirms the account id from `sts:GetCallerIdentity`, and selects collectors. *Global* collectors (IAM, S3 listing, CloudTrail) run once per account. *Regional* collectors run for every configured region.
3. **Collect.** Each collector returns a `Result` (summary, findings, sanitized facts). The base class converts it into an `Evidence` record, attaches the control crosswalk, and seals it with a SHA-256.
4. **Manifest.** The run gets a manifest listing every record and its hash, itself sealed.
5. **Deliver.** Every sink is attempted, so one failing sink does not block the others. If any sink failed, the Lambda raises after all sinks have been tried, so the error alarm fires.

## Evidence record

```
collector, provider, title, account, region, collected_at
status         pass | fail | error | info | not_applicable
summary        one line
findings[]     {resource, message, severity}
data           counts and configuration facts (no secrets, no resource contents)
controls       {soc2: [...], iso27001: [...], nist_800_53: [...]}
schema_version, sha256
```

The hash covers the canonical JSON (sorted keys, no whitespace) of everything but the hash. `verify` recomputes it.

## Decisions

**`error` is not `pass`.** Auditors care about the difference between "we checked and it was fine" and "we could not check". Access-denied, throttling and API failures produce an `error` record with the reason, control rollups treat `error` as incomplete evidence, and a run that cannot assume a member-account role produces an explicit `aws.account_access` error rather than nothing.

**Read-only by construction.** Collectors call only `Describe*`/`Get*`/`List*` style APIs (plus `iam:GenerateCredentialReport`, which creates a report but changes no configuration). A test compares each collector's declared permissions with the Terraform policy in both directions and rejects write-style verbs, so the IAM policy cannot silently grow or shrink away from the code.

**Facts, not contents.** Records hold booleans, counts and resource identifiers. They never read object contents, secret values or user data, which keeps the evidence store low-sensitivity, although resource names and account ids are still worth treating as internal.

**One crosswalk file, validated.** `collector_map.yaml` is data, reviewable by a GRC person without reading Python. CI fails if a mapping refers to a control that is not in `controls.yaml`, if a collector has no mapping, or if the committed coverage doc is out of date.

**Coverage is reported honestly.** Technical controls with no collector are shown as gaps. Organizational criteria are labeled as such and excluded from the "automated" denominator.

**Rollup precedence: fail > error > pass > not_applicable.** A control is only "pass" when at least one relevant check passed and none failed or errored.

**HTTP sink safety.** HTTPS required (an explicit flag exists for local tests), no credentials in URLs, secrets by reference only, redirects are never followed (an `Authorization` header must not be replayed to another host), 4xx fails fast, 429/5xx retry with backoff honoring `Retry-After`, payload size is capped, and every POST carries an idempotency key derived from the content hash.

**S3 sink.** SSE-KMS when a key is configured. Records are written before the manifest, so a manifest's presence marks a complete run. Immutability comes from S3 Object Lock on the bucket (Terraform option), not from application code. The bucket policy denies non-TLS and non-KMS uploads.

**Lambda concurrency = 1.** Overlapping runs would double-report the same evidence period.

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
