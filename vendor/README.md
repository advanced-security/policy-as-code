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

<!-- -->

[pypi]: https://pypi.org/
[dependabot]: https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts
