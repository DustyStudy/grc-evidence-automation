## What and why

## Checklist
- [ ] `ruff check`, `ruff format --check`, `mypy src` and `pytest` pass
- [ ] Collectors declare only read, describe and list permissions, and the Terraform IAM lists match (`grc-evidence permissions`)
- [ ] Control mappings only use ids present in `controls.yaml`; generated docs are regenerated (`docs/coverage.md`, `docs/collectors.md`)
- [ ] No secrets, account ids or real evidence in source, tests or docs
- [ ] README and `SECURITY.md` claims still match what the tests demonstrate
- [ ] `CHANGELOG.md` updated under "Unreleased"
