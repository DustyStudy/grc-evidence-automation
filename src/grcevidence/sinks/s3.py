"""S3 evidence store.

Layout: ``<prefix>/dt=YYYY-MM-DD/<run_id>/<collector>__<account>__<region>.json`` plus
``manifest.json`` (written last). Objects are encrypted with SSE-KMS when a key is
given, otherwise SSE-S3. For immutability, enable S3 Object Lock (default retention)
on the bucket; the Terraform module in ``deploy/terraform`` can do this.

Optional config key ``expected_bucket_owner`` (12-digit account id, quoted) is sent as
``ExpectedBucketOwner`` on every call, so a bucket of the same name recreated in another
account is refused instead of written to. Writes are conditional (``If-None-Match: *``): an
existing key is never overwritten, the write fails instead.
"""

from __future__ import annotations

import json
import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from grcevidence.models import RunResult
from grcevidence.sinks.base import SinkError, chain_candidate


class S3Sink:
    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "evidence",
        kms_key_id: str | None = None,
        region: str | None = None,
        expected_bucket_owner: str | None = None,
        session: Any = None,
    ) -> None:
        import boto3

        if expected_bucket_owner is not None and not (
            isinstance(expected_bucket_owner, str)
            and re.fullmatch(r"[0-9]{12}", expected_bucket_owner)
        ):
            # An unquoted YAML account id is an int and loses leading zeros.
            raise SinkError("expected_bucket_owner must be a 12-digit account id string")
        self._owner: dict[str, Any] = (
            {"ExpectedBucketOwner": expected_bucket_owner} if expected_bucket_owner else {}
        )

        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.kms_key_id = kms_key_id
        self.name = f"s3://{bucket}/{self.prefix}"
        self._s3 = (session or boto3.Session()).client("s3", region_name=region)

    def _put(self, key: str, body: dict[str, Any], sha256: str) -> None:
        kwargs: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": (json.dumps(body, indent=2, sort_keys=True) + "\n").encode(),
            "ContentType": "application/json",
            "Metadata": {"sha256": sha256},
            "IfNoneMatch": "*",  # never overwrite stored evidence
            **self._owner,
        }
        if self.kms_key_id:
            kwargs["ServerSideEncryption"] = "aws:kms"
            kwargs["SSEKMSKeyId"] = self.kms_key_id
        else:
            kwargs["ServerSideEncryption"] = "AES256"
        try:
            self._s3.put_object(**kwargs)
        except ClientError as exc:
            if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 412:
                raise SinkError(
                    f"S3 write to {self.name} refused: {key} already exists "
                    "and stored evidence is never overwritten"
                ) from exc
            raise

    def write(self, run: RunResult) -> int:
        m = run.manifest
        base = f"{self.prefix}/dt={m.started_at[:10]}/{m.run_id}"
        try:
            for ev in run.evidence:
                self._put(f"{base}/{ev.filename}", ev.to_dict(), ev.sha256)
            self._put(f"{base}/manifest.json", m.to_dict(), m.sha256)  # last: marks run complete
        except (ClientError, BotoCoreError) as exc:
            raise SinkError(f"S3 write to {self.name} failed: {exc}") from exc
        return len(run.evidence) + 1

    def _list(self, prefix: str, delimiter: bool) -> list[str]:
        """Sub-prefixes (``delimiter``) or keys under ``prefix``, newest (lexically greatest) first."""
        paginator = self._s3.get_paginator("list_objects_v2")
        if delimiter:
            pages = paginator.paginate(
                Bucket=self.bucket, Prefix=prefix, Delimiter="/", **self._owner
            )
            return sorted(
                (p["Prefix"] for page in pages for p in page.get("CommonPrefixes", [])),
                reverse=True,
            )
        pages = paginator.paginate(Bucket=self.bucket, Prefix=prefix, **self._owner)
        return sorted((o["Key"] for page in pages for o in page.get("Contents", [])), reverse=True)

    def latest_manifest(self, before: str) -> dict[str, Any] | None:
        """Newest well-formed run manifest whose run id sorts before ``before``, else None.

        Walks ``dt=`` partitions newest first, skipping any later than ``before``'s date (a
        future-dated plant), and takes ``<run_id>/manifest.json`` keys newest first (run ids
        start with a UTC timestamp), so it never lists the whole bucket. Only listed keys are
        fetched: a GetObject on a missing key is a 403, not a 404, when s3:ListBucket is granted
        only under an s3:prefix condition.
        """
        newest = f"{self.prefix}/dt={before[:4]}-{before[4:6]}-{before[6:8]}/"
        try:
            for partition in self._list(f"{self.prefix}/dt=", delimiter=True):
                if partition > newest:
                    continue
                for key in self._list(partition, False):
                    run_id, _, name = key[len(partition) :].partition("/")
                    if name != "manifest.json" or not run_id < before:
                        continue
                    raw = self._s3.get_object(Bucket=self.bucket, Key=key, **self._owner)[
                        "Body"
                    ].read()
                    doc = chain_candidate(raw, run_id)
                    if doc is not None:
                        return doc
        except (ClientError, BotoCoreError) as exc:
            raise SinkError(
                f"could not read the latest run manifest from {self.name} ({exc}); the role "
                "needs s3:ListBucket and s3:GetObject on this prefix"
            ) from exc
        return None
