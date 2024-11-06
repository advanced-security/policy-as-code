<!-- markdownlint-disable -->
<div align="center">
<h1>GitHub Policy as Code</h1>

[![GitHub](https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white)][github]
[![GitHub Actions](https://img.shields.io/github/actions/workflow/status/advanced-security/policy-as-code/main.yml?style=for-the-badge)][github-actions]
[![GitHub Issues](https://img.shields.io/github/issues/advanced-security/policy-as-code?style=for-the-badge)][github-issues]
[![GitHub Stars](https://img.shields.io/github/stars/advanced-security/policy-as-code?style=for-the-badge)][github]
[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)][license]

</div>
<!-- markdownlint-restore -->

## Overview

[GitHub's Policy as Code][github] project is designed to allow users and organizations to configure their Risk
threshold for security issues reported by GitHub Advanced Security Platform.
The main goal is to help make sure that before publishing your application to productions, development, etc.
you can validate if the application has any security issues that need to be addressed.

## ✨ Features

- Highly Configurable
- Re-usable across repositories
- Supports all [GitHub Advanced Security][advanced-security] Features
  - [Code Scanning][github-codescanning]
  - [Secret Scanning][github-secretscanning]
  - [Supply chain / Dependabot][github-supplychain]
- Supports GitHub Enterprise Cloud or Server ([see supported features list](#supported-features))
- Pull Request Summary

## ⚡️ Requirements

- Python +3.9

## Usage

### GitHub Actions

Here is how you can quickly setup policy-as-code.

> [!TIP]
> Checkout the GitHub Actions [Policy as Code Examples][examples-actions]

```yaml
# Policy as Code
- name: Advance Security Policy as Code
  uses: advanced-security/policy-as-code@v2.9.0
```

> [!WARNING]
> The GitHub Action does not install Python on the runner. Please checkout at [the `actions/setup-python` Action][python-setup]

### CLI

The Policy as Code project is a self-contained Python based CLI tool.

> [!NOTE]
> All of the Dependencies for [Policy as Code are vendored][vendored] into this repository

**Bash / Zsh:**

```bash
git clone --branch "v2.9.0" https://github.com/advanced-security/policy-as-code.git && cd ./policy-as-code

./policy-as-code --help
```

**Powershell:**

```Powershell
git clone --branch "v2.9.0" https://github.com/advanced-security/policy-as-code.git
cd policy-as-code

.\policy-as-code.ps1 --help
```

> [!TIP]
> Checkout the samples of [how to use / run the cli with examples][examples-cli].

### [GitHub Access Permissions][permissions]

For Policy as Code to work correctly, you need to have the following permissions for the different features:

- [required] Repository Permissions
  - [`security_events: read`][permissions]
    - [Dependabot Alerts][permissions-dependabot]
    - [Code Scanning][permissions-codescanning]
    - [Secret Scanning][permissions-secretscanning]
  - [`content: read`][permissions]
    - [Dependency Graph][permissions-dependencygraph] / [Dependency Licenses][permissions-dependencygraph]
  - [`pull-requests: write`][permissions]
    - Policy as Code Pull Request Summary
- [optional] Policy Repository
  - `content: read` to be able to clone external sources of the policies

**[Action Permissions Example][permissions]:**

```yaml
# workflow or job level
permissions:
  contents: read
  security-events: read
  # pull request summaries
  pull-requests: write
```

## Supported Features

| Feature         | github.com (Br/PR)                      | enterprise server (Br/PR)               | Description                                                                                                |
| :-------------- | :-------------------------------------- | :-------------------------------------- | :--------------------------------------------------------------------------------------------------------- |
| Code Scanning   | :white_check_mark: / :white_check_mark: | :white_check_mark: / :white_check_mark: | Code Scanning is a code analysis tool that scans your code for security vulnerabilities and coding errors. |
| Secret Scanning | :white_check_mark: / :white_check_mark: | :white_check_mark: / :white_check_mark: | Secret Scanning is a code analysis tool that scans your code for secrets.                                  |
| Dependabot      | :white_check_mark: / :white_check_mark: | :x: [2] / :white_check_mark: [3]        | Dependabot is a tool that automates discovery and remediation of vulnerabilities in your dependencies.     |
| Dependencies    | :white_check_mark: / :white_check_mark: | :x: [2] / :white_check_mark: [3]        | Dependencies is a tool that scans your code for dependencies.                                              |
| Licensing       | :white_check_mark: / :white_check_mark: | :x: [2] / :white_check_mark: [3]        | Licensing is a tool that scans your code for licensing issues.                                             |

_Notes:_

1. Br/PR = Branches / Pull Requests
2. :warning: GraphQL API not supported by GitHub Enterprise Server as of `3.7`
3. :white_check_mark: Supported as of [GHES `3.6`](https://docs.github.com/en/enterprise-server@3.6/rest/dependency-graph/dependency-review#get-a-diff-of-the-dependencies-between-commits)

## Policy as Code / PaC

Here is an example of using a simple yet cross-organization using Policy as Code:

```yaml
# Compliance
- name: Advance Security Policy as Code
  uses: advanced-security/policy-as-code@v2.9.0
  with:
    # The owner/repo of where the policy is stored
    policy: GeekMasher/security-queries
    # The local (within the workspace) or repository
    policy-path: policies/default.yml
    # The branch you want to target
    policy-branch: main
```

### PaC Configuration file

The Policy as Code configuration file is very simple yet powerful allowing a user to define 4 types of rules per technologies you want to use.

```yaml
# This is the technology you want to write a rule for
licensing:
  # The four main rules types to do everything you need to do for all things
  #  compliance

  # Warnings will always occur if the rule applies and continues executing to
  #  other rules.
  warnings:
    ids:
      - Other
      - NA
  # Ignores are run next so if an ignored rule is hit that matches the level,
  #  it will be skipped
  ignores:
    ids:
      - MIT License
  # Conditions will only trigger and raise an error when an exact match is hit
  conditions:
    ids:
      - GPL-2.0
    names:
      - tunnel-agent

  # The simplest and ultimate rule which checks the severity of the alert and
  #  reports an issue if the level matches or higher (see PaC Levels for more info)
  level: error
```

#### PaC Levels

There are many different levels of severities with the addition of `all` and `none` (self explanatory).
When a level is selected like for example `error`, all higher level severities (`critical` and `high` in this example) will also be added.

```yml
- critical
- high
- error
- medium
- moderate
- low
- warning
- notes
```

#### PaC Rule Blocks

For each rule you can choose either or both of the two different criteria's matches; `ids` and `names`

You can also use `imports` to side load data from other files to supplement the data already in the rule block

```yaml
codescanning:
  conditions:
    # When the `ids` of the technologies/tool alert matches any one of the ID's in
    #  the list specified, the rule will the triggered and report the alert.
    ids:
      # In this example case, the CodeQL rule ID below will always be reported if
      #  present event if the severity is low or even note.
      - js/sql-injection

      # Side note: Check to see what different tools consider id's verses names,
      #  for example `licensing` considers the "Licence" name itself as the id
      #  while the name of the package/library as the "name"

    # `names` allows you to specify the names of alerts or packages.
    names:
      - "Missing rate limiting"

    # The `imports` allows you to supplement your existing data with a list
    #  from a file on the system.
    imports:
      ids: "path/to/ids/supplement/file.txt"
      names: "path/to/names/supplement/file.txt"
```

#### Wildcards

For both types of criteria matching you can use wildcards to easily match requirements in a quicker way.
The matching is done using a Unix shell-style wildcards module called [fnmatch](https://docs.python.org/3/library/fnmatch.html) which supports `*` for matching everything.

```yaml
codescanning:
  conditions:
    ids:
      - "*/sql-injection"
```

#### Time to Remediate

The feature allows a user to define a time frame to which a security alert/vulnerability of a certain severity has before the alert triggered a violation in the Action.

By default, if this section is not defined in any part of the policy then no checks are done.
Existing policy files should act the same without the new section.

```yaml
general:
  # All other blocks will be inheriting the remediate section if they don't have
  #  their own defined.
  remediate:
    # Only `error`'s and above have got 7 days to remediate according to the
    #  policy. Any time before that, nothing will occur and post the remediation
    #  time frame the alert will be raised.
    error: 7

codescanning:
  # the `codescanning` block will inherit the `general` block
  # ...

dependabot:
  remediate:
    # high and critical security issues
    high: 7
    # moderate security issues
    moderate: 30
    # all other security issues
    all: 90

secretscanning:
  remediate:
    # All secrets by default are set to 'critical' severity so only `critical`
    #  or `all` will work
    critical: 7
```

##### Time to Remediate Examples

- [Time to Remediate Example](examples/policies/time-to-remediate.yml)

#### Data Importing

Some things to consider when using imports:

- Imports appending to existing lists and do not replace a previously generated list.
- Imports are relative to:
  - `Working Directory`
  - `GitHub Action / CLI directory`
  - `Cloned Repository Directory`
- Imports are only allowed from a number of predefined paths to prevent loading data on the system (AKA, path traversal).

## Maintainers / Contributors

- [@GeekMasher](https://github.com/GeekMasher) - Author / Core Maintainer

## Support

Please create [GitHub Issues][github-issues] if there are bugs or feature requests.

This project uses [Sematic Versioning (v2)](https://semver.org/) and with major releases, breaking changes will occur.

## License

This project is licensed under the terms of the MIT open source license.
Please refer to [MIT][license] for the full terms.

<!-- Resources -->

[license]: ./LICENSE
[github]: https://github.com/advanced-security/policy-as-code
[github-issues]: https://github.com/advanced-security/policy-as-code/issues
[github-actions]: https://github.com/advanced-security/policy-as-code/actions

[advanced-security]: https://github.com/features/security
[github-codescanning]: https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning
[github-secretscanning]: https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning
[github-supplychain]: https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-supply-chain-security

[python-setup]: https://github.com/actions/setup-python
[vendored]: https://github.com/advanced-security/policy-as-code/tree/main/vendor/README.md
[examples-actions]: https://github.com/advanced-security/policy-as-code/tree/main/examples/workflows
[examples-cli]: https://github.com/advanced-security/policy-as-code/tree/main/examples/scripts

[permissions]: https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs#overview
[permissions-codescanning]: https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository
[permissions-secretscanning]: https://docs.github.com/en/rest/secret-scanning/secret-scanning#list-secret-scanning-alerts-for-a-repository
[permissions-dependabot]: https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository
[permissions-dependencygraph]: https://docs.github.com/en/graphql/reference/objects#dependencygraphmanifestconnection
