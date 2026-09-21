"""Push evidence to a GRC-platform ingestion API (Vanta/Drata-style, vendor-neutral).

This sink is deliberately generic: it POSTs the toolkit's own JSON schema to a
URL you configure, with bearer or OAuth2 client-credentials auth, retries with
backoff, idempotency keys, and no redirect following (so credentials are never
forwarded to a different host). Vendor APIs differ in endpoint and payload
shape; ``payload_template`` lets you wrap or rename fields, and anything more
involved belongs in a small adapter service or a subclass of ``_build_payloads``.
The vendor-specific mapping is *not* verified here against any live vendor API.

Config example::

    - type: http
      url: https://ingest.example.com/v1/evidence
      format: bundle              # one POST per run   (or: per_evidence)
      auth: {type: bearer, token: "secretsmanager:grc/ingest-token"}
      # or: {type: oauth2_client_credentials, token_url: https://..., client_id: "env:ID",
      #      client_secret: "env:SECRET", scope: "evidence.write"}
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from grcevidence import __version__
from grcevidence.models import RunResult
from grcevidence.secrets import resolve_secret
from grcevidence.sinks.base import SinkError


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
MAX_BODY_BYTES = 5 * 1024 * 1024


class HttpSink:
    def __init__(
        self,
        url: str,
        *,
        auth: dict[str, Any] | None = None,
        format: str = "bundle",  # noqa: A002 - mirrors the config key
        headers: dict[str, str] | None = None,
        payload_template: dict[str, Any] | None = None,
        timeout: float = 30.0,
        retries: int = 4,
        backoff: float = 1.0,
        allow_insecure_http: bool = False,
        dry_run: bool = False,
        session: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(url, str):
            raise SinkError("url must be a string")
        for flag_name, flag in (("allow_insecure_http", allow_insecure_http), ("dry_run", dry_run)):
            # A quoted "false" is a truthy string and would silently enable the option.
            if not isinstance(flag, bool):
                raise SinkError(f"{flag_name} must be true or false")
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError as exc:
            raise SinkError(f"invalid URL: {exc}") from exc
        if parts.scheme != "https" and not (allow_insecure_http and parts.scheme == "http"):
            raise SinkError(
                "HttpSink requires an https URL (set allow_insecure_http only for local testing)"
            )
        if "@" in parts.netloc:
            raise SinkError("credentials must not be embedded in the URL; use the auth block")
        if format not in {"bundle", "per_evidence"}:
            raise SinkError("format must be 'bundle' or 'per_evidence'")
        if headers is not None and not (
            isinstance(headers, dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items())
        ):
            raise SinkError("headers must be a mapping of strings")
        if auth is not None and not isinstance(auth, dict):
            raise SinkError("auth must be a mapping")
        if payload_template is not None and not isinstance(payload_template, dict):
            raise SinkError("payload_template must be a mapping")
        for name, number in (("timeout", timeout), ("backoff", backoff)):
            if isinstance(number, bool) or not isinstance(number, int | float) or number < 0:
                raise SinkError(f"{name} must be a non-negative number")
        if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
            raise SinkError("retries must be a non-negative integer")
        self.url = url
        self.name = f"http:{parts.scheme}://{parts.hostname}{parts.path}"
        self.format = format
        self.auth = auth or {}
        self.headers = dict(headers or {})
        self.template = payload_template
        self.timeout, self.retries, self.backoff = timeout, retries, backoff
        self.dry_run = dry_run
        self._allow_insecure = allow_insecure_http
        self._session = session
        self._sleep = sleep
        self._token: tuple[str, float] | None = None

    # ---------------------------------------------------------------- auth
    def _bearer(self) -> str | None:
        kind = self.auth.get("type")
        if kind is None:
            return None
        if kind == "bearer":
            return resolve_secret(self.auth["token"], self._session)
        if kind == "oauth2_client_credentials":
            if self._token and self._token[1] > time.time() + 30:
                return self._token[0]
            form = {
                "grant_type": "client_credentials",
                "client_id": resolve_secret(self.auth["client_id"], self._session),
                "client_secret": resolve_secret(self.auth["client_secret"], self._session),
            }
            if self.auth.get("scope"):
                form["scope"] = self.auth["scope"]
            token_url = self.auth["token_url"]
            if urllib.parse.urlsplit(token_url).scheme != "https" and not self._allow_insecure:
                raise SinkError("token_url must be https")
            data = self._request(
                token_url,
                urllib.parse.urlencode(form).encode(),
                "application/x-www-form-urlencoded",
                None,
                None,
            )
            payload = json.loads(data)
            self._token = (
                payload["access_token"],
                time.time() + float(payload.get("expires_in", 300)),
            )
            return self._token[0]
        raise SinkError(f"unknown auth type {kind!r}")

    # ------------------------------------------------------------ transport
    def _request(
        self, url: str, body: bytes, content_type: str, bearer: str | None, idem: str | None
    ) -> bytes:
        headers = {
            "Content-Type": content_type,
            "User-Agent": f"grc-evidence/{__version__}",
            **self.headers,
        }
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if idem:
            headers["Idempotency-Key"] = idem
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310 - scheme validated in __init__
            try:
                with _OPENER.open(req, timeout=self.timeout) as resp:  # noqa: S310
                    return bytes(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code == 429 or exc.code >= 500:
                    last = exc
                    hinted = _retry_after(exc)
                    delay = hinted if hinted is not None else self.backoff * (2**attempt)
                else:
                    detail = exc.read()[:200].decode("utf-8", "replace")
                    raise SinkError(f"POST {url} rejected: HTTP {exc.code} {detail}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
                delay = self.backoff * (2**attempt)
            if attempt < self.retries:
                self._sleep(delay)
        raise SinkError(f"POST {url} failed after {self.retries + 1} attempts: {last}")

    # -------------------------------------------------------------- payloads
    def _wrap(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.template:
            return payload
        return {k: (payload if v == "$payload" else v) for k, v in self.template.items()}

    def _build_payloads(self, run: RunResult) -> list[tuple[dict[str, Any], str]]:
        m = run.manifest
        if self.format == "bundle":
            return [
                (
                    self._wrap(
                        {"run": m.to_dict(), "evidence": [e.to_dict() for e in run.evidence]}
                    ),
                    m.sha256,
                )
            ]
        return [
            (self._wrap({"run_id": m.run_id, "evidence": e.to_dict()}), e.sha256)
            for e in run.evidence
        ]

    def write(self, run: RunResult) -> int:
        payloads = self._build_payloads(run)
        if self.dry_run:
            return len(payloads)
        bearer = self._bearer()
        for payload, key in payloads:
            body = json.dumps(payload, sort_keys=True).encode()
            if len(body) > MAX_BODY_BYTES:
                raise SinkError(
                    f"payload is {len(body)} bytes (> {MAX_BODY_BYTES}); use format: per_evidence"
                )
            self._request(self.url, body, "application/json", bearer, key)
        return len(payloads)


def _retry_after(exc: urllib.error.HTTPError) -> float | None:
    value = exc.headers.get("Retry-After") if exc.headers else None
    try:
        return min(float(value), 60.0) if value else None
    except ValueError:
        return None
