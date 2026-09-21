"""Coverage-guided fuzzing of one target with Atheris (libFuzzer).

    pip install atheris
    python fuzz/run_fuzzer.py <target> [corpus_dir] [libFuzzer options]
    python fuzz/run_fuzzer.py verify fuzz/corpus/verify -max_total_time=60

Run from the repository root. Targets are listed in ``fuzz/targets.py``; a crash is an input
that breaks an invariant, and libFuzzer writes it to ``crash-*`` (see ``-artifact_prefix``).
Without Atheris the same targets still run as regression tests in the normal test suite.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import atheris  # noqa: E402

with atheris.instrument_imports():
    from fuzz import targets  # noqa: E402


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in targets.TARGETS:
        sys.exit(f"usage: run_fuzzer.py <{'|'.join(targets.TARGETS)}> [corpus_dir] [options]")
    name = sys.argv.pop(1)
    atheris.Setup(sys.argv, targets.TARGETS[name])
    atheris.Fuzz()


if __name__ == "__main__":
    main()
