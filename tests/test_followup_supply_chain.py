"""Build, lock and release supply-chain guards."""

from __future__ import annotations

import re
from pathlib import Path

from scripts.build_lambda import write_zip

ROOT = Path(__file__).resolve().parents[1]


def test_lambda_lock_is_fully_hashed() -> None:
    text = (ROOT / "requirements" / "requirements-lambda.txt").read_text(encoding="utf-8")
    # one logical line per requirement: join the backslash continuations
    reqs = [
        line
        for line in text.replace("\\\n", " ").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert reqs
    assert all("--hash=sha256:" in line for line in reqs)
    assert [line.split("==")[0] for line in reqs] == ["pyyaml"]


def test_build_lambda_installs_only_from_the_lock() -> None:
    source = (ROOT / "scripts" / "build_lambda.py").read_text(encoding="utf-8")
    assert not re.search(r"pyyaml\s*[<>=~!]", source, re.IGNORECASE)
    assert '"--require-hashes"' in source
    assert "requirements-lambda.txt" in source
    assert "--no-build-isolation" in source


def test_lambda_zip_is_reproducible(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    (stage / "pkg" / "__pycache__").mkdir(parents=True)
    (stage / "pkg" / "b.py").write_text("b = 1\n", encoding="utf-8")
    (stage / "pkg" / "a.py").write_text("a = 1\n", encoding="utf-8")
    (stage / "pkg" / "__pycache__" / "a.pyc").write_bytes(b"x")
    write_zip(stage, tmp_path / "one.zip")
    (stage / "pkg" / "a.py").touch()  # a newer mtime must not change the archive
    write_zip(stage, tmp_path / "two.zip")
    assert (tmp_path / "one.zip").read_bytes() == (tmp_path / "two.zip").read_bytes()

    import zipfile

    infos = zipfile.ZipFile(tmp_path / "one.zip").infolist()
    assert [i.filename for i in infos] == ["pkg/a.py", "pkg/b.py"]
    assert all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in infos)
    assert all(i.external_attr >> 16 == 0o644 for i in infos)


def test_release_requires_a_commit_on_main_and_the_release_environment() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in workflow
    assert "fetch-depth: 0" in workflow
    assert re.search(r"^    environment: release$", workflow, re.MULTILINE)


def test_pre_commit_repos_are_pinned_to_commit_shas() -> None:
    config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    revs = re.findall(r"^\s*rev:\s*(\S+)", config, re.MULTILINE)
    assert len(revs) == config.count("- repo:") == 2
    assert all(re.fullmatch(r"[0-9a-f]{40}", rev) for rev in revs)
