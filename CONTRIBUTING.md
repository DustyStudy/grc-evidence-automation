# Contributing

Lightweight process; this is a solo-maintained project.

## Setup

```bash
git clone https://github.com/DustyStudy/grc-evidence-automation.git
cd grc-evidence-automation
python -m pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check src tests scripts
ruff format src tests scripts
mypy src
pytest --cov=grcevidence
terraform fmt -recursive deploy/terraform
grc-evidence coverage --format markdown > docs/coverage.md
grc-evidence collectors --format markdown > docs/collectors.md
```

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
