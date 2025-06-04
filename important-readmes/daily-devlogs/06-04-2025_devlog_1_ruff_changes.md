# CI/CD changes

## Ruff
- Changed line length from 88 to 110 since it seems to be the maximum line length using our documentation and lines of code, trying to be as descriptive as possible
- Also forgot to mention i changed from flake8 to ruff.

## Changes today
 - Using make tools for ensuring code quality in project
 - Linting,formatting,safety,etc.
 - Changed pylint local variable limits to 16
 - Changed security concerns from bandit could have been ignored but still, added better safety compliance.
 - Added comments at safety concerning bits of code for bandit to ignore very low risk.
 - Changing pyproject.toml guidelines constantly seeing what fits best.