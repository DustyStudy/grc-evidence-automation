"""IAM policy-document analysis shared by the privileged-access collectors: administrator-
equivalent grants, iam:PassRole on every role, and role trust policies."""

from __future__ import annotations

import json
import re
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import unquote

from grcevidence.models import Severity

# IAM actions that let a principal grant itself anything when allowed on every IAM resource.
# A policy action (which may be a wildcard: "*", "iam:*", "iam:Attach*", "iam:Put*Policy") is
# admin-equivalent when it matches any of them. iam:PassRole is deliberately not listed: it is
# a separate escalation path, reported by pass_role_statements.
ADMIN_ACTIONS = frozenset(
    {
        "iam:attachuserpolicy",
        "iam:attachgrouppolicy",
        "iam:attachrolepolicy",
        "iam:putuserpolicy",
        "iam:putgrouppolicy",
        "iam:putrolepolicy",
        "iam:createpolicyversion",
        "iam:setdefaultpolicyversion",
        "iam:addusertogroup",
        "iam:createaccesskey",
        "iam:updateassumerolepolicy",
    }
)
CONDITIONAL_NOTE = " (grant is conditional: review the Condition)"
_VARIABLE = re.compile(r"\$\{[^}]*\}")  # policy variables such as ${aws:username} contain ":"


def parse_document(document: Any) -> dict[str, Any]:
    """A policy document as a dict. boto3 already decodes IAM documents; raw API strings are
    URL-encoded JSON, and SSO inline policies are plain JSON. An absent document is an error:
    callers that know "no policy" is legitimate must not call this."""
    if isinstance(document, dict):
        return document
    if not document:
        raise ValueError("policy document is empty")
    try:
        parsed = json.loads(document)
    except json.JSONDecodeError:
        parsed = json.loads(unquote(document))
    if not isinstance(parsed, dict):
        raise ValueError("policy document is not a JSON object")
    return parsed


def fetch_document(iam: Any, arn: str) -> Any:
    """The default-version document of managed policy ``arn``."""
    version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    document = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"].get(
        "Document"
    )
    if not document:
        raise ValueError(f"managed policy {arn} has no default version document")
    return document


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _arn_parts(value: Any) -> list[str]:
    return _VARIABLE.sub("var", str(value)).split(":")


def _star(segment: str) -> bool:
    return bool(segment) and set(segment) == {"*"}


def _all_resources(value: Any) -> bool:
    """``"*"`` or a wildcard ARN matching every ARN in a partition (``arn:*``, ``arn:aws:*:*``).

    The partition segment may be anything (a literal, ``*`` or a variable); every later one
    must be a wildcard, and so must the last one."""
    parts = _arn_parts(value)
    return (
        fnmatchcase("arn", parts[0].lower())
        and _star(parts[-1])
        and all(_star(p) for p in parts[2:])
    )


def _all_iam_resources(value: Any) -> bool:
    """Every IAM resource of an account: ``arn:<partition>:iam::<account or *>:*``."""
    parts = _arn_parts(value)
    return _all_resources(value) or (
        len(parts) == 6
        and fnmatchcase("arn", parts[0].lower())
        and (parts[2].lower() == "iam" or _star(parts[2]))
        and (parts[3] == "" or _star(parts[3]))
        and _star(parts[5])
    )


def _all_roles(value: Any) -> bool:
    """Every IAM role of an account: all IAM resources, or ``arn:<partition>:iam::<any>:role/*``
    (also ``role*``, ``r*``: any pattern ending in a wildcard that matches the ``role/`` prefix)."""
    parts = _arn_parts(value)
    return _all_iam_resources(value) or (
        len(parts) == 6
        and fnmatchcase("arn", parts[0].lower())
        and (parts[2].lower() == "iam" or _star(parts[2]))
        and (parts[3] == "" or _star(parts[3]))
        and parts[5].endswith("*")
        and fnmatchcase("role/", parts[5])
    )


def _allow_statements(document: Any) -> list[dict[str, Any]]:
    """The Allow statements of ``document``. Malformed statements raise ``ValueError``."""
    doc = parse_document(document)
    if "Statement" not in doc:
        raise ValueError("policy document has no Statement")
    out = []
    for stmt in _as_list(doc["Statement"]):
        if not isinstance(stmt, dict) or "Effect" not in stmt:
            raise ValueError("policy statement is not an object with an Effect")
        if stmt["Effect"] == "Allow":
            out.append(stmt)
    return out


def _granted(patterns: set[str]) -> set[str]:
    """The admin actions matched by any of the (lower-cased) policy action patterns."""
    return {a for a in ADMIN_ACTIONS if any(fnmatchcase(a, p) for p in patterns)}


def admin_statements(document: Any) -> list[dict[str, Any]]:
    """The statements that make ``document`` administrator-equivalent.

    A statement qualifies when it is ``Allow`` and either
    - covers every resource (``"*"``, a partition-wide wildcard ARN, or any ``NotResource``)
      with an action matching one of ``ADMIN_ACTIONS`` (case-insensitive; ``*``, ``*:*``,
      ``iam:*``, ``iam:Attach*``, ``iam:CreateAccessKey`` ...) or with ``NotAction``, or
    - covers every IAM resource with such an action, or with a ``NotAction`` that does not
      exclude all of them (it can attach AdministratorAccess to itself).
    Conditions do not disqualify a statement; callers record them. Deny statements are not
    subtracted. Malformed statements raise ``ValueError`` rather than reading as "not admin".
    """
    out = []
    for stmt in _allow_statements(document):
        resources = _as_list(stmt.get("Resource", []))
        every = "NotResource" in stmt or any(map(_all_resources, resources))
        every_iam = every or any(map(_all_iam_resources, resources))
        if "NotAction" in stmt:
            excluded = {str(a).lower() for a in _as_list(stmt["NotAction"])}
            grants = every or (every_iam and _granted(excluded) != ADMIN_ACTIONS)
        else:
            actions = {str(a).lower() for a in _as_list(stmt.get("Action", []))}
            grants = every_iam and bool(_granted(actions))
        if grants:
            out.append(stmt)
    return out


def conditional(statements: list[dict[str, Any]]) -> bool:
    """True when every admin-granting statement carries a Condition."""
    return bool(statements) and all("Condition" in s for s in statements)


def pass_role_statements(document: Any) -> list[dict[str, Any]]:
    """The Allow statements granting ``iam:PassRole`` on every role (``"*"``, a wildcard ARN
    matching all roles, or a ``NotResource`` that does not exclude all roles): the holder can
    hand any role to a service and run code as it. Conditions do not disqualify a statement
    and Deny statements are not subtracted, as in :func:`admin_statements`."""
    out = []
    for stmt in _allow_statements(document):
        if "NotResource" in stmt:
            every_role = not any(map(_all_roles, _as_list(stmt["NotResource"])))
        else:
            every_role = any(map(_all_roles, _as_list(stmt.get("Resource", []))))
        key = "NotAction" if "NotAction" in stmt else "Action"
        listed = any(
            fnmatchcase("iam:passrole", str(a).lower()) for a in _as_list(stmt.get(key, []))
        )
        if every_role and listed == (key == "Action"):
            out.append(stmt)
    return out


def _has_external_id(stmt: dict[str, Any]) -> bool:
    condition = stmt.get("Condition")
    if not isinstance(condition, dict):
        return False
    return any(
        str(key).lower() == "sts:externalid"
        for keys in condition.values()
        if isinstance(keys, dict)
        for key in keys
    )


def trust_findings(document: Any, account: str) -> list[tuple[str, Severity]]:
    """(message, severity) for each risky grant in a role trust policy held by ``account``.

    - HIGH: an Allow whose principal is ``"*"`` (or ``{"AWS": "*"}``, or any ``NotPrincipal``)
      with no Condition, so any AWS principal can assume the role.
    - MEDIUM: an Allow for another AWS account (a principal ARN or bare account ID that is not
      ``account``) with no ``sts:ExternalId`` condition (presence only; its value and operator
      are not evaluated).
    Deny statements and service/federated principals are ignored.
    """
    out: dict[str, Severity] = {}
    for stmt in _allow_statements(document):
        principal = stmt.get("Principal", [])
        values = principal.get("AWS", []) if isinstance(principal, dict) else principal
        aws = ["*"] if "NotPrincipal" in stmt else [str(v) for v in _as_list(values)]
        for value in aws:
            parts = value.split(":")
            other = parts[4] if value.startswith("arn:") and len(parts) > 4 else value
            if value == "*":
                if "Condition" not in stmt:
                    out[
                        'Trust policy lets any AWS principal ("*") assume the role, no Condition'
                    ] = Severity.HIGH
            elif other.isascii() and other.isdigit() and other != account:
                if not _has_external_id(stmt):
                    out[
                        f"Trust policy lets AWS account {other} assume the role without an "
                        "sts:ExternalId condition"
                    ] = Severity.MEDIUM
    return list(out.items())
