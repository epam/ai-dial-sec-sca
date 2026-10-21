# Contributing Guidelines

Thank you for your interest in contributing to this project.

## Contributors Workflow

### Configure pre-commit

1. Install pre-commit using pip (if you haven't already):

    ```bash
    pip install pre-commit
    ```

1. Install the git hook scripts:

    ```bash
    pre-commit install
    ```

To run the checks manually: `pre-commit run --all-files`.

### Run the tests

The tests need Python 3.12 and no network access:

```bash
python -m pip install pytest
python -m pytest test/sca
```

### Creating a Pull Request (PR)

Create a feature branch from `main` and open a PR back to `main`.

PR titles must follow the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/). Use one of the prefixes `fix:`, `feat:`, `docs:`, `test:`, `ci:`, `chore:`. Breaking changes may include `!` after the type/scope, e.g. `<type>!: <description>`.

## Maintainers Workflow

### Releases

Releases are git tags `vX.Y.Z` on `main`. The consumer, the `sca_scheduled.yml` workflow in [epam/ai-dial-ci](https://github.com/epam/ai-dial-ci), pins all actions of this repository to one and the same tag. After tagging a new release, update that pin in `epam/ai-dial-ci` in a single change.
