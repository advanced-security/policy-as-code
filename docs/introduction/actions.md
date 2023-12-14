# Actions

Policy as Code is designed primarily to be run as a GitHub Action. This allows you to run Policy as Code on a schedule, or as part of your CI/CD pipeline.

To do this, you can simply add the following to your workflow:

```yaml
# Compliance
- name: Advance Security Compliance Action
  uses: advanced-security/policy-as-code@v2.6.0
```

This runs the policy-as-code action with the default configuration. You can also specify a configuration file to use:

```yaml
- name: Advance Security Compliance Action
  uses: advanced-security/policy-as-code@v2.6.0
  with:
    policy: GeekMaherOrg/security
    policy-branch: main
    policy-path: ./security.yml
```

## Setting Up Python

Policy as Code is written in Python, so you will need to setup Python in your workflow.

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.10'  # minimum supported Python version

- name: Advance Security Compliance Action
  uses: advanced-security/policy-as-code@v2.6.0
```
