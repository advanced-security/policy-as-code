---
applyTo: "**/*.py"
---

This project is a Python CLI and GitHub Action policy-as-code engine and toolkit.
It uses Python 3.10+ and Pipenv for dependency management, Black for code formatting, and unittest for testing.

## Coding Guidelines

- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines.
- Use type hints for all function signatures.
- Write clear, concise docstrings for all public functions and classes.
- Use `os.path.join()` for all path concatenations.
- Prefer f-strings for string interpolation.
- Ensure cross-platform compatibility (Linux, macOS, Windows).
- Avoid hardcoding paths or platform-specific logic.
- Keep functions small and focused; prefer composition over inheritance.

## Testing & Quality

- Write unit tests for all new features and bug fixes.
- Ensure all tests pass before committing code.
- Maintain good test coverage; aim for 90%+ where practical.
- Use descriptive test names and keep tests isolated.

**Run tests with:**

```bash
pipenv run test
```

**Format code before committing:**

```bash
pipenv run fmt
```

## Documentation

- Document all public APIs and modules with docstrings.
- Update Sphinx documentation in `docs/` for new features or changes.
