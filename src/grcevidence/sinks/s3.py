"""S3 evidence store.

Layout: ``<prefix>/dt=YYYY-MM-DD/<run_id>/<collector>__<account>__<region>.json`` plus
``manifest.json`` (written last). Objects are encrypted with SSE-KMS when a key is
given, otherwise SSE-S3. For immutability, enable S3 Object Lock (default retention)
on the bucket; the Terraform module in ``deploy/terraform`` can do this.
"""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from grcevidence.models import RunResult
from grcevidence.sinks.base import SinkError


class S3Sink:
    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "evidence",
        kms_key_id: str | None = None,
        region: str | None = None,
        session: Any = None,
    ) -> None:
        import boto3

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
        }
        if self.kms_key_id:
            kwargs["ServerSideEncryption"] = "aws:kms"
            kwargs["SSEKMSKeyId"] = self.kms_key_id
        else:
            kwargs["ServerSideEncryption"] = "AES256"
        self._s3.put_object(**kwargs)

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
