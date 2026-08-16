# Contributing to WinSecure

Thank you for your interest in contributing to WinSecure!

## Development Guidelines

1. **Fork and Branch**: Create a feature branch from `main` (`git checkout -b feat/your-feature-name`).
2. **Deterministic & Safe**: All new security inspection modules must be 100% read-only and non-destructive.
3. **Automated Tests**: Ensure all existing tests pass and add unit tests for new scanners in `tests/`.
4. **Code Quality**: Keep code clean, type-annotated, and well-documented.

## Running Tests

```bash
# Run full automated test suite
python run.py test

# Test scan execution with fixture
python run.py scan --fixture fixtures/standard_enterprise.json
```

## Pull Request Process

1. Ensure all tests pass (`python run.py test`).
2. Submit a pull request describing the changes and referencing any relevant issue.
3. Maintainers will review and assist with testing and integration.
