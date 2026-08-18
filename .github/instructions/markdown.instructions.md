---
applyTo: "**/*.md"
---

# Markdown Linting

This project lints Markdown with `markdownlint-cli` (config: `--disable MD013` only; see [CONTRIBUTING.md](../../CONTRIBUTING.md)).

## Important: the CI check lints the whole repo, not your diff

The `Markdown Lint` check (`.github/workflows/markdown.yml`, using `advanced-security/reusable-workflows`) only *runs* when a PR touches at least one `.md` file - but once triggered, it lints `**/*.md` across the **entire repository**, not just the files you changed. If it fails on a file you never touched, that is very likely pre-existing, unrelated debt - check the failure's file path against your diff before assuming you introduced it.

- It is **not** currently a required status check for merging into `main` (only `run (3.10/3.11/3.12/3.13)` and `e2e-tests` are required), so pre-existing failures won't block your PR.
- Still, always fix any violation your own change introduces.
- Before committing Markdown changes, run the same check locally so you're not surprised by CI:

```bash
npx --yes --ignore-scripts markdownlint-cli@0.49.1 '**/*.md' --ignore node_modules --disable MD013
```

If that reports pre-existing errors unrelated to your change, it's safe to leave them for a separate cleanup - just don't add new ones.
