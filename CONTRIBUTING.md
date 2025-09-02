# Contributing Guide

Thank you for your interest in contributing to Policy as Code!

## Getting Started

- Ensure you have Python 3.9+ and [Pipenv](https://pipenv.pypa.io/en/latest/) installed.

**Install dependencies:**

```bash
pipenv install --dev
```

**Run the CLI:**

```bash
pipenv run main --help
```

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) guidelines.
- Use type hints and docstrings for all functions.
- Use `os.path.join()` for paths and f-strings for formatting.

**Format code with Black:**

```bash
pipenv run fmt
```

## Testing

- Write unit tests for all new features and bug fixes.
- Ensure all tests pass before submitting a pull request:

```bash
pipenv run test
```

## Markdown Linting

- Markdown files should adhere to standard conventions.
- Use a Markdown linter `markdownlint`

Use the following comments to run the linter:

```bash
markdownlint '**.md' --disable MD013
```

## Vendoring Dependencies

- Dependencies are vendored in the `vendor/` directory for reliability and security. See [vendor/README.md](./vendor/README.md).
- To update or add dependencies:
  1. Add or update the dependency using Pipenv.

```bash
pipenv run vendor
```

## Submitting Changes

1. Fork the repository and create a feature branch.
2. Make your changes, following the guidelines above.
3. Run tests and ensure code is formatted.
4. Submit a pull request with a clear description of your changes.

## Community & Support

- Please follow our [Code of Conduct](./CODE_OF_CONDUCT.md).
- For help, see [SUPPORT.md](./SUPPORT.md) or open a GitHub Issue.
