# Contributing

Lightweight process; this is a solo-maintained project.

## Setup

```bash
git clone https://github.com/DustyStudy/grc-evidence-automation.git
cd grc-evidence-automation
python -m pip install --require-hashes -r requirements/requirements-dev.txt
python -m pip install --no-build-isolation --no-deps -e .
```

The first command installs the hash-pinned development dependencies, including the build backend (`setuptools`, `wheel`); the second installs this package with that backend instead of downloading an unpinned one. The optional GCP collectors have their own lock: `python -m pip install --require-hashes -r requirements/requirements-gcp.txt`. The Lambda zip (`python scripts/build_lambda.py`) takes its one third-party dependency from `requirements/requirements-lambda.txt`.

## Commit hooks

Secret scanning (gitleaks) and `terraform fmt` run as pre-commit hooks, pinned by commit SHA in `.pre-commit-config.yaml`. Install them once per clone (`terraform` must be on your `PATH`):

```bash
python -m pip install pre-commit
pre-commit install
```

## Before opening a PR

```bash
ruff check src tests fuzz scripts
ruff format src tests fuzz scripts
mypy src
pytest --cov=grcevidence
terraform fmt -recursive deploy/terraform
grc-evidence coverage --format markdown > docs/coverage.md
grc-evidence collectors --format markdown > docs/collectors.md
```

CI runs the tests on Linux on Python 3.11 to 3.13, and on Windows and macOS on Python 3.11 and 3.12, with a 90% coverage floor, and builds the package. Add a line to `CHANGELOG.md` under "Unreleased" for user-visible changes.

## Pinned CI dependencies

CI installs from hash-pinned files in `requirements/` (`pip install --require-hashes -r ...`), so a compromised package on the index cannot change what runs. If you add or change a dependency in `pyproject.toml` (or an `.in` file), regenerate them and commit the result; a CI job fails if they are stale:

```bash
pip install --require-hashes -r requirements/requirements-lock-tools.txt   # pinned uv
python scripts/lock.py             # re-resolve what changed, keep other pins
python scripts/lock.py --upgrade   # move every pin forward
python scripts/lock.py --check     # what CI runs: writes nothing, exits 1 if a file is stale
```

Refresh them with `--upgrade` every so often, and whenever a security alert names a pinned package. Dependabot is deliberately not configured to update them: it bumps single transitive packages in isolation, which leaves the lock inconsistent.

## Fuzz targets

`fuzz/targets.py` holds functions that must keep an invariant for *any* input (tampering with a stored run is always reported, a record survives a write/read round trip with its hash intact, untrusted text cannot inject markup into a report, malformed configuration raises `ConfigError`). They run as ordinary tests on a seed corpus and random inputs. For coverage-guided fuzzing:

```bash
pip install --require-hashes -r requirements/requirements-fuzz.txt   # Atheris; Linux and macOS, Python 3.11 to 3.13
python fuzz/run_fuzzer.py verify fuzz/corpus/verify -max_total_time=60
```

When you change the verifier, the loaders, a sink or the report renderer, add or extend a target for the property you rely on. When a fuzz run finds a crash, add the input as a seed under `fuzz/corpus/<target>/` and a regression test.

## Adding or changing a collector

1. Implement it under `src/grcevidence/collectors/` (see [ARCHITECTURE.md](docs/ARCHITECTURE.md#extending)).
2. Declare `permissions`: only read/describe/list actions.
3. Add it to `data/collector_map.yaml` with the controls it is *relevant to*, using ids that exist in `data/controls.yaml`.
4. Add the actions to both `collector_read_actions` lists in `deploy/terraform`.
5. Write a moto test with a failing and a passing state, plus what happens on `AccessDenied`.
6. Regenerate the docs (above). The tests and CI fail if any step is missing.

## Guidelines

- **Never record secrets or resource contents** in evidence. Facts, counts and identifiers only.
- **Do not turn "could not check" into "pass".** Errors must surface as `error` evidence.
- **Be conservative with mappings.** "Relevant to" is the bar; do not claim a collector satisfies a criterion.
- **No secret-shaped literals** in source or tests.
- Keep the README's claims aligned with what the tests demonstrate, including its limitations.
