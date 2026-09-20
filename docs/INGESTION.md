# Delivering evidence to a GRC platform

`type: http` posts evidence to any endpoint that accepts JSON. It is written to match the *shape* of what compliance-automation platforms with "custom evidence / custom connection" APIs generally accept (authenticated JSON POSTs, idempotency, batch or per-item), but it is **not verified against any specific vendor's API**. Confirm endpoint, payload schema, rate limits and auth flow with your vendor's current documentation before production use.

## Contract

```yaml
sinks:
  - type: http
    url: https://ingest.example.com/v1/evidence       # https only
    format: bundle                                     # or per_evidence
    auth:
      type: bearer                                     # or oauth2_client_credentials
      token: "secretsmanager:grc/ingest-token#token"
    headers: {X-Tenant: acme}                          # optional static headers
    timeout: 30
    retries: 4
    backoff: 1.0
    payload_template: {source: grc-evidence, data: $payload}   # optional wrapper
    dry_run: false
```

**`bundle`**: one POST per run:

```json
{"run": {"run_id": "...", "started_at": "...", "accounts": ["..."], "counts": {"pass": 9, "fail": 3}, "evidence": [{"id": "...", "file": "...", "status": "...", "sha256": "..."}], "sha256": "..."},
 "evidence": [ { ...evidence record... } ]}
```

**`per_evidence`**: one POST per record (use this if a bundle would exceed the endpoint's size limit; the sink refuses payloads over 5 MB):

```json
{"run_id": "...", "evidence": { ...evidence record... }}
```

**Headers.** `Authorization: Bearer <token>`, `Idempotency-Key: <sha256 of the payload's record or manifest>` (a retried POST is byte-for-byte the same, so the receiver can de-duplicate), `Content-Type: application/json`.

**OAuth2 client credentials.** When configured, the sink first POSTs `grant_type=client_credentials` (plus `scope` if set) to `token_url`, expects `{"access_token": "...", "expires_in": N}`, and caches the token until shortly before it expires. `client_id` and `client_secret` are secret references.

**Failure behavior.** 429 and 5xx retry with exponential backoff (honoring `Retry-After` up to 60 s). Other 4xx fail immediately with the status and the start of the response body. Redirects are never followed. A sink failure does not stop other sinks, and it makes the Lambda invocation fail so the alarm fires.

## Adapting to a specific platform

Choose the smallest thing that works:

1. **Wrap fields** with `payload_template`. `$payload` is replaced by the bundle or per-evidence object; other values are literal.
2. **Put an adapter in front**, a small function or API Gateway route that translates this schema to the vendor's resource model, using each record's `controls` map and `findings`, and forwards with the vendor's SDK. This keeps vendor-specific mapping out of the collectors.
3. **Subclass `HttpSink`** and override `_build_payloads` if you need a different structure per request.

Before pointing this at a real platform, check:

- Does it accept evidence per *test* or *resource*, and how should `collector` + `account` + `region` map onto that identity?
- How does it want pass/fail expressed, and what happens to `error` and `not_applicable`? Do not map `error` to pass.
- Its rate limits, maximum body size, and idempotency semantics.
- Whether findings contain identifiers (account ids, resource names) that your data-handling policy allows in a third-party SaaS.

## Testing without a vendor

`dry_run: true` builds payloads and writes nothing. The test suite runs the sink against a local HTTP server covering bearer, OAuth2, retries, redirects, size limits and templates (`tests/test_runner_sinks_report.py`).
