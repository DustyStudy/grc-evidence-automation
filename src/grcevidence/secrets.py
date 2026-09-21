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
        try:
            value = os.environ.get(rest)
        except ValueError as exc:  # e.g. an embedded NUL character
            raise SecretError(f"invalid environment variable name {rest!r}") from exc
        if not value:
            raise SecretError(f"environment variable {rest!r} is not set")
        return value
    if scheme in {"secretsmanager", "ssm"}:
        import boto3

        sess = session or boto3.Session()
        if scheme == "ssm":
            value = sess.client("ssm").get_parameter(Name=rest, WithDecryption=True)["Parameter"][
                "Value"
            ]
            return _non_empty(value, f"ssm parameter {rest!r}")
        secret_id, _, key = rest.partition("#")
        response = sess.client("secretsmanager").get_secret_value(SecretId=secret_id)
        if "SecretString" not in response:  # a binary secret has no string form
            raise SecretError(f"secret {secret_id!r} has no SecretString")
        raw = response["SecretString"]
        if not key:
            return _non_empty(raw, f"secret {secret_id!r}")
        try:
            value = json.loads(raw)[key]
        except (json.JSONDecodeError, KeyError, TypeError, IndexError) as exc:
            raise SecretError(f"secret {secret_id!r} has no JSON key {key!r}") from exc
        if isinstance(value, int | float) and not isinstance(value, bool):
            value = str(value)  # numeric secrets (PINs, ids) are legitimate
        return _non_empty(value, f"key {key!r} of secret {secret_id!r}")
    raise SecretError(f"unknown secret scheme {scheme!r}")


def _non_empty(value: Any, what: str) -> str:
    """A secret must be a non-empty string; never stringify null, a list or an object."""
    if not isinstance(value, str) or not value:
        raise SecretError(f"{what} is empty or is not a string")
    return value
