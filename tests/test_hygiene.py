"""Repository hygiene checks that guard against 'Trojan Source' style problems."""

from __future__ import annotations

import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".toml", ".txt", ".cfg", ".ini", ".tf"}
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".terraform",
}
# Control (except tab/newline), format (zero-width, bidirectional overrides) and line/paragraph
# separator characters. Where a test needs one, spell it as an escape sequence in the source.
FORBIDDEN_CATEGORIES = {"Cf", "Zl", "Zp", "Cc"}
ALLOWED = {"\t", "\n", "\r", "\x0c"}


def _text_files():
    for path in ROOT.rglob("*"):
        if path.suffix in TEXT_SUFFIXES and path.is_file():
            if not SKIP_DIRS.intersection(path.relative_to(ROOT).parts):
                yield path


def test_no_invisible_or_bidirectional_characters_in_source_files():
    offenders = []
    for path in _text_files():
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.split("\n"), 1):
            for ch in line:
                if unicodedata.category(ch) in FORBIDDEN_CATEGORIES and ch not in ALLOWED:
                    offenders.append(f"{path.relative_to(ROOT)}:{number} U+{ord(ch):04X}")
                    break
    assert not offenders, "literal invisible/bidi characters (use an escape): " + ", ".join(
        offenders
    )
