"""Keep the Terraform IAM policies in lock-step with what the collectors actually call."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from grcevidence.collectors.base import load_all

TF = Path(__file__).resolve().parents[1] / "deploy" / "terraform"


def _actions(tf_file: Path) -> set[str]:
    text = tf_file.read_text(encoding="utf-8")
    block = re.search(r"collector_read_actions\s*=\s*\[(.*?)\]", text, re.DOTALL)
    assert block, f"collector_read_actions not found in {tf_file}"
    return set(re.findall(r'"([a-z0-9-]+:[A-Za-z0-9*]+)"', block.group(1)))


def _required() -> set[str]:
    needed = {a for c in load_all().values() if c.provider == "aws" for a in c.permissions}
    return needed | {"sts:GetCallerIdentity"}


@pytest.mark.parametrize("tf_file", [TF / "iam.tf", TF / "reader_role" / "main.tf"])
def test_terraform_grants_exactly_what_collectors_need(tf_file):
    granted, needed = _actions(tf_file), _required()
    assert needed <= granted, f"{tf_file.name} is missing: {sorted(needed - granted)}"
    assert granted <= needed, f"{tf_file.name} grants unused actions: {sorted(granted - needed)}"


def test_both_modules_share_one_action_list():
    assert _actions(TF / "iam.tf") == _actions(TF / "reader_role" / "main.tf")


def test_no_write_actions_granted_for_collection():
    write_verbs = (
        "Put",
        "Create",
        "Delete",
        "Update",
        "Attach",
        "Detach",
        "Modify",
        "Start",
        "Stop",
        "Enable",
        "Disable",
    )
    for action in _actions(TF / "iam.tf"):
        verb = action.split(":")[1]
        if action == "iam:GenerateCredentialReport":
            continue  # generates a report; does not change configuration
        assert not verb.startswith(write_verbs), action
