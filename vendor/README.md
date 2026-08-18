# Vendored Dependencies

The Policy as Code engine vendors / stores its dependencies into the repository itself.
This is to prevent issues with in restricted environments that that restricted access to [Pypi][pypi].

_Examples:_

- Require Proxies that aren't configured
- Restricted internet access

## Security

The directory contains code from dependencies and isn't directly modified by the GitHub Field team.
These dependencies are vendored in using the `./update.sh` script.

If security issues are present in a Dependencies, this is handled by [Dependabot][dependabot] and updated using the `./update.sh` script.

If security alert are present / found by a Static Code Analysis tool (CodeQL for example) in this vendor folder, this is not subject the security policy and should be reported to the dependency itself if applicable.

## Automation

Dependabot only ever updates `Pipfile`/`Pipfile.lock` - it never touches this folder (see [#94][issue-94]). The [`Vendor Sync`][vendor-sync-workflow] workflow closes that gap: after `Pipfile.lock` changes on `main` (typically a merged Dependabot PR), it runs `pipenv run vendor` and opens/updates a PR with the resulting `vendor/` diff.

> [!WARNING]
> **TODO(#94):** That PR is opened with the default `GITHUB_TOKEN`, which GitHub deliberately prevents from triggering other workflow runs. The branch-protection-required checks on `main` will **not** start automatically on it, so a maintainer must manually re-run them (or push an empty commit) before merging. Fixing this for good requires a PAT/GitHub App token stored as a repo secret - see the `TODO(#94)` comment in `vendor-sync.yml` for details.

<!-- -->

[pypi]: https://pypi.org/
[dependabot]: https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts
[issue-94]: https://github.com/advanced-security/policy-as-code/issues/94
[vendor-sync-workflow]: ../.github/workflows/vendor-sync.yml
