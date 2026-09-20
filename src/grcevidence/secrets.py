"""Resolve secret references so credentials never live in config files.

Supported reference forms::

    env:NAME                        environment variable
    secretsmanager:name-or-arn      whole secret string
    secretsmanager:name-or-arn#key  one key of a JSON secret
    ssm:/path/to/parameter          SSM parameter (decrypted)

Bare literals are rejected on purpose.
"""

from __future__ import annotations

import json
import os
from typing import Any


class SecretError(ValueError):
    pass


def resolve_secret(ref: str, session: Any = None) -> str:
    scheme, sep, rest = ref.partition(":")
    if not sep or not rest:
        raise SecretError(
            "secret must be a reference like env:NAME, secretsmanager:ID or ssm:/path (not a literal)"
        )
    if scheme == "env":
        value = os.environ.get(rest)
        if not value:
            raise SecretError(f"environment variable {rest!r} is not set")
        return value
    if scheme in {"secretsmanager", "ssm"}:
        import boto3

        sess = session or boto3.Session()
        if scheme == "ssm":
            return str(
                sess.client("ssm").get_parameter(Name=rest, WithDecryption=True)["Parameter"][
                    "Value"
                ]
            )
        secret_id, _, key = rest.partition("#")
        raw = sess.client("secretsmanager").get_secret_value(SecretId=secret_id)["SecretString"]
        if not key:
            return str(raw)
        try:
            return str(json.loads(raw)[key])
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise SecretError(f"secret {secret_id!r} has no JSON key {key!r}") from exc
    raise SecretError(f"unknown secret scheme {scheme!r}")
