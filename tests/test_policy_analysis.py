from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from grcevidence.collectors.aws.policy import (
    admin_statements,
    conditional,
    fetch_document,
    parse_document,
)


def _doc(**stmt):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", **stmt}]}


ADMIN = _doc(Action="*", Resource="*")


@pytest.mark.parametrize(
    "document,admin",
    [
        (ADMIN, True),
        (_doc(Action="*:*", Resource="*"), True),
        (_doc(Action="iam:*", Resource="*"), True),
        (_doc(Action="IAM:*", Resource="*"), True),
        (_doc(Action=["s3:GetObject", "*"], Resource=["arn:aws:s3:::b", "*"]), True),
        (_doc(Action="s3:*", Resource="*"), False),
        (_doc(Action="*", Resource="arn:aws:s3:::bucket/*"), False),
        (_doc(NotAction="iam:*", Resource="*"), True),
        (_doc(NotAction="iam:*", Resource="arn:aws:s3:::b"), False),
        (_doc(Action="*", NotResource="arn:aws:s3:::b"), True),
        (
            _doc(
                Action="*", Resource="*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}
            ),
            True,
        ),
        ({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}, False),
        ({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}, True),
        (json.dumps(ADMIN), True),
        (quote(json.dumps(ADMIN)), True),
        (quote(json.dumps(_doc(Action="s3:*", Resource="*"))), False),
        ({"Statement": []}, False),
    ],
)
def test_admin_statements(document, admin):
    assert bool(admin_statements(document)) is admin


@pytest.mark.parametrize(
    "resource,every",
    [
        ("*", True),
        ("arn:*", True),
        ("ARN:*", True),
        ("arn:*:*", True),
        ("arn:aws:*", True),
        ("arn:aws-us-gov:*", True),
        ("arn:aws:*:*:*:*", True),
        ("arn:aws:*:*:*:*:*", True),
        ("arn:${partition}:*", True),
        ("arn:${aws:partition}:*:*", True),
        ("*:*", True),
        ("arn:aws", False),
        ("arn", False),
        ("arn:${partition}", False),
        ("arn:aws:s3:::*", False),
        ("arn:aws:iam::123:user/x", False),
        ("arn:aws:*:", False),
        ("x:*", False),
    ],
)
def test_all_resources_wildcards(resource, every):
    # NotAction iam:* excludes the all-IAM-resources path, so only an all-resources match counts
    assert bool(admin_statements(_doc(NotAction="iam:*", Resource=resource))) is every
    assert bool(admin_statements(_doc(Action="*", Resource=resource))) is every


@pytest.mark.parametrize(
    "action,resource,admin",
    [
        ("iam:*", "arn:aws:iam::*:*", True),
        ("IAM:*", "arn:aws-us-gov:iam::123456789012:*", True),
        ("*", "arn:aws:iam::123456789012:*", True),
        ("*:*", "arn:*:iam::*:*", True),
        ("iam:*", "arn:${partition}:iam::*:*", True),
        ("iam:*", "arn:aws:iam:*:*:*", True),
        ("iam:*", "arn:aws:*::*:*", True),
        ("*", "arn:aws:*:*:123456789012:*", True),
        ("iam:*", "arn:aws:iam::*:role/*", False),
        ("iam:*", "arn:aws:iam::*:user/x", False),
        ("iam:*", "arn:aws:s3:::*", False),
        ("iam:*", "arn:aws:iam:us-east-1:*:*", False),
        ("iam:PassRole", "arn:aws:iam::*:*", False),
        ("s3:*", "arn:aws:iam::*:*", False),
    ],
)
def test_iam_full_access_on_all_iam_resources_is_admin(action, resource, admin):
    assert bool(admin_statements(_doc(Action=action, Resource=[resource]))) is admin


@pytest.mark.parametrize(
    "not_action,admin",
    [("s3:*", True), (["ec2:*", "iam:PassRole"], True), ("iam:*", False), ("*", False)],
)
def test_not_action_on_all_iam_resources(not_action, admin):
    doc = _doc(NotAction=not_action, Resource="arn:aws:iam::*:*")
    assert bool(admin_statements(doc)) is admin


@pytest.mark.parametrize(
    "document,match",
    [
        ({"Statement": ["not-a-statement"]}, "not an object"),
        ({"Statement": "not-a-statement"}, "not an object"),
        ({"Statement": [{"Action": "*", "Resource": "*"}]}, "Effect"),
        ({"Version": "2012-10-17"}, "no Statement"),
        ("", "empty"),
        (None, "empty"),
        ("not json", "Expecting value"),
    ],
)
def test_malformed_documents_raise_instead_of_reading_as_not_admin(document, match):
    with pytest.raises(ValueError, match=match) as exc:
        admin_statements(document)
    assert "not-a-statement" not in str(exc.value)  # no document contents in the message


def test_fetch_document_without_default_document_raises():
    class Iam:
        def get_policy(self, **_kw):
            return {"Policy": {"DefaultVersionId": "v1"}}

        def get_policy_version(self, **_kw):
            return {"PolicyVersion": {"VersionId": "v1"}}

    with pytest.raises(ValueError, match="no default version document"):
        fetch_document(Iam(), "arn:aws:iam::123456789012:policy/p")


def test_conditional_needs_every_granting_statement_conditioned():
    cond = {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"x": {}}}
    plain = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    assert conditional([cond]) is True
    assert conditional([cond, plain]) is False
    assert conditional([]) is False


def test_parse_document_rejects_non_object():
    with pytest.raises(ValueError, match="not a JSON object"):
        parse_document("[1]")
